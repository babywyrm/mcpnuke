"""In-memory job manager that drives mcpnuke scans for the runner service.

mcpnuke's scan path is synchronous and makes blocking network calls whose
individual timeouts don't add up to a bounded whole — a single probe that
provokes a hung upstream fetch can stall a scan indefinitely. Because Python
threads can't be force-killed, each scan runs in its own **subprocess** that
is hard-terminated if it blows past a wall-clock cap. A small thread pool
supervises those subprocesses so the FastAPI event loop stays responsive and
HTTP handlers only submit/read status.

Results live in memory — adequate for the MVP single-replica deployment; swap
the ``_jobs`` dict for Redis/SQLite when persistence or horizontal scale is
needed.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import queue as _queue
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from mcpnuke.server.models import ScanDepth, ScanJob, ScanRequest, ScanStatus

# Default hard cap for a whole scan job. Overridable per-request via
# ScanRequest.max_seconds, or globally via the env var.
DEFAULT_JOB_TIMEOUT = float(os.getenv("MCPNUKE_RUNNER_JOB_TIMEOUT", "180"))

# spawn keeps behavior identical on Linux (container) and macOS (dev), and
# avoids inheriting the parent's threads/uvicorn state into the child.
_MP_CTX = mp.get_context("spawn")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _probe_opts_for(req: ScanRequest) -> dict:
    """Translate a ScanRequest into mcpnuke probe options.

    Deterministic ordering is forced so portal-launched scans are stable and
    comparable across runs. safe_mode defaults on to keep destructive tool
    invocations off a browser-triggered code path.
    """
    opts: dict = {
        "max_pages": 20,
        "tls_verify": False,
        "deterministic": True,
        "safe_mode": req.safe_mode,
        "no_invoke": False,
        "probe_calls": False,
        "fast": False,
    }
    if req.depth == ScanDepth.fast:
        opts["fast"] = True
    elif req.depth == ScanDepth.deep:
        opts["probe_calls"] = True
    return opts


def _coverage(results: list, coverage_url: str) -> dict:
    """Best-effort cross-project coverage; failures degrade to a note."""
    from mcpnuke.reporting.coverage_report import (
        SchemaMismatchError,
        build_coverage_report,
        fetch_lane_taxonomy,
    )

    try:
        taxonomy = fetch_lane_taxonomy(coverage_url)
        return build_coverage_report(results, taxonomy)
    except SchemaMismatchError as exc:
        return {"error": "schema_mismatch", "detail": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": "unreachable", "detail": f"{type(exc).__name__}: {exc}"}


def _scan_worker(req_dict: dict, q) -> None:
    """Run a single scan in a child process and put the result on the queue.

    Must be a top-level function so it's picklable under the spawn start
    method. Imports are kept inside so spawning the child stays cheap and the
    parent never pays for scanner/rich import at module load.
    """
    try:
        from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS
        from mcpnuke.reporting.by_lane import build_by_lane
        from mcpnuke.reporting.json_out import build_report
        from mcpnuke.scanner import run_parallel

        req = ScanRequest(**req_dict)
        GLOBAL_K8S_FINDINGS.clear()

        results = run_parallel(
            [req.target],
            timeout=req.timeout,
            workers=1,
            verbose=False,
            auth_token=req.auth_token,
            probe_opts=_probe_opts_for(req),
        )
        payload = {
            "report": build_report(results, include_k8s=False),
            "by_lane": build_by_lane(results),
            "coverage": _coverage(results, req.coverage_url) if req.coverage_url else None,
        }
        q.put((True, payload))
    except Exception as exc:  # noqa: BLE001 — surface any failure to the parent
        q.put((False, f"{type(exc).__name__}: {exc}"))


class JobManager:
    """Tracks scan jobs and runs each one in a killable subprocess."""

    def __init__(self, max_workers: int = 2, job_timeout: float | None = None) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="mcpnuke-scan")
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._default_timeout = job_timeout if job_timeout is not None else DEFAULT_JOB_TIMEOUT

    @property
    def active_jobs(self) -> int:
        with self._lock:
            return sum(
                1 for j in self._jobs.values()
                if j.status in (ScanStatus.queued, ScanStatus.running)
            )

    def submit(self, req: ScanRequest) -> ScanJob:
        job_id = uuid.uuid4().hex[:12]
        job = ScanJob(id=job_id, status=ScanStatus.queued, request=req, created_at=_now())
        with self._lock:
            self._jobs[job_id] = job
        self._executor.submit(self._run, job_id)
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[ScanJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def _set(self, job_id: str, **fields) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            self._jobs[job_id] = job.model_copy(update=fields)

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            return
        req = job.request
        timeout = req.max_seconds or self._default_timeout
        self._set(job_id, status=ScanStatus.running, started_at=_now())

        q: mp.Queue = _MP_CTX.Queue()
        # auth_token is Field(exclude=True) so it never serializes into API
        # responses — re-add it here for the worker, which needs the value.
        req_dict = req.model_dump()
        req_dict["auth_token"] = req.auth_token
        proc = _MP_CTX.Process(target=_scan_worker, args=(req_dict, q), daemon=True)
        proc.start()

        # get(timeout) drains the pipe (avoiding the large-result join deadlock)
        # and bounds the wall clock in one shot.
        try:
            ok, payload = q.get(timeout=timeout)
        except _queue.Empty:
            proc.terminate()
            proc.join(5)
            self._set(
                job_id,
                status=ScanStatus.error,
                finished_at=_now(),
                error=f"scan exceeded {timeout:.0f}s wall-clock cap and was terminated",
            )
            return
        finally:
            if proc.is_alive():
                proc.join(5)
                if proc.is_alive():
                    proc.terminate()

        if ok:
            self._set(job_id, status=ScanStatus.done, finished_at=_now(), **payload)
        else:
            self._set(job_id, status=ScanStatus.error, finished_at=_now(), error=payload)
