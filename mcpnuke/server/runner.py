"""In-memory job manager that drives mcpnuke scans for the runner service.

mcpnuke's scan path is synchronous (and prints progress to a module-level
Rich console → container stdout). To keep the FastAPI event loop responsive,
jobs run on a small thread pool; HTTP handlers only submit work and read
status. Results live in memory — adequate for the MVP single-replica
deployment; swap the ``_jobs`` dict for Redis/SQLite when persistence or
horizontal scale is needed.
"""

from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from mcpnuke.server.models import ScanDepth, ScanJob, ScanRequest, ScanStatus


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


class JobManager:
    """Tracks scan jobs and runs them on a bounded worker pool."""

    def __init__(self, max_workers: int = 2) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="mcpnuke-scan")
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

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
        self._set(job_id, status=ScanStatus.running, started_at=_now())

        try:
            # Imported lazily so importing the service module stays cheap and
            # never drags scanner/rich into contexts that only need models.
            from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS
            from mcpnuke.reporting.by_lane import build_by_lane
            from mcpnuke.reporting.json_out import build_report
            from mcpnuke.scanner import run_parallel

            # Reset module-level k8s accumulator so jobs don't bleed into each
            # other (the library was built for one-shot CLI runs).
            GLOBAL_K8S_FINDINGS.clear()

            results = run_parallel(
                [req.target],
                timeout=req.timeout,
                workers=1,
                verbose=False,
                auth_token=req.auth_token,
                probe_opts=_probe_opts_for(req),
            )

            report = build_report(results, include_k8s=False)
            by_lane = build_by_lane(results)

            coverage = None
            if req.coverage_url:
                coverage = self._coverage(results, req.coverage_url)

            self._set(
                job_id,
                status=ScanStatus.done,
                finished_at=_now(),
                report=report,
                by_lane=by_lane,
                coverage=coverage,
            )
        except Exception as exc:  # noqa: BLE001 — surface any scan failure to the caller
            self._set(job_id, status=ScanStatus.error, finished_at=_now(), error=f"{type(exc).__name__}: {exc}")

    @staticmethod
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
