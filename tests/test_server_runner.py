"""Unit tests for the runner's job manager, scan worker, and coverage glue.

JobManager supervises each scan in a spawned subprocess; these tests drive
``_run`` synchronously against a scripted fake worker process, so the
result/error/wall-clock-cap paths are covered deterministically — no real
subprocesses, no network, no load sensitivity. The end-to-end variants
that do spawn subprocesses live in tests/test_server.py.

Skipped automatically when the optional ``server`` extra (fastapi/pydantic)
isn't installed, matching tests/test_server.py.
"""

from __future__ import annotations

import json
import os
import string
import subprocess

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from mcpnuke.reporting.coverage_report import SchemaMismatchError  # noqa: E402
from mcpnuke.server import runner  # noqa: E402
from mcpnuke.server.models import ScanDepth, ScanRequest, ScanStatus  # noqa: E402
from mcpnuke.server.runner import JobManager, _coverage, _probe_opts_for, _scan  # noqa: E402


class _FakeWorker:
    """Stands in for the worker Popen: scripted stdout, or a hang."""

    def __init__(self, result: object = None, raw: str | None = None, hangs: bool = False, returncode: int = 0):
        self._out = raw if raw is not None else json.dumps(result)
        self._hangs = hangs
        self.returncode = returncode
        self.inputs: list[str | None] = []
        self.timeouts: list[float | None] = []
        self.killed = False

    def communicate(self, input: str | None = None, timeout: float | None = None) -> tuple[str, None]:
        self.inputs.append(input)
        self.timeouts.append(timeout)
        if self._hangs and not self.killed:
            raise subprocess.TimeoutExpired("worker", timeout or 0)
        return self._out, None

    def kill(self) -> None:
        self.killed = True


@pytest.fixture
def idle_manager(monkeypatch):
    """A JobManager whose executor never starts work.

    submit() only records the job, so bookkeeping tests spawn nothing;
    the supervision tests drive _run synchronously instead.
    """
    mgr = JobManager()
    monkeypatch.setattr(mgr._executor, "submit", lambda *a, **k: None)
    return mgr


def _drive_run(mgr, job, worker, monkeypatch):
    """Run JobManager._run synchronously against a scripted worker."""
    monkeypatch.setattr(runner, "_spawn_worker", lambda: worker)
    mgr._run(job.id)
    return mgr.get(job.id)


_DONE = [True, {"report": {}, "by_lane": {}, "coverage": None}]


# ---------------------------------------------------------------------------
# JobManager bookkeeping
# ---------------------------------------------------------------------------


def test_submit_assigns_twelve_char_hex_id_and_queues(idle_manager):
    job = idle_manager.submit(ScanRequest(target="http://x"))
    assert len(job.id) == 12
    assert all(c in string.hexdigits for c in job.id)
    assert job.status is ScanStatus.queued
    assert job.created_at
    assert job.started_at is None
    assert idle_manager.get(job.id) is job


def test_get_unknown_job_returns_none(idle_manager):
    assert idle_manager.get("nope") is None


def test_worker_handoff_still_carries_auth_token(idle_manager, monkeypatch):
    """auth_token is Field(exclude=True) so API responses can't leak it; _run
    must re-add it to the worker payload or authenticated scans run anon."""
    job = idle_manager.submit(ScanRequest(target="http://x", auth_token="tok-123"))
    worker = _FakeWorker(_DONE)
    _drive_run(idle_manager, job, worker, monkeypatch)
    assert json.loads(worker.inputs[0])["auth_token"] == "tok-123"


def test_spawn_failure_marks_job_error_instead_of_stuck_running(idle_manager, monkeypatch):
    """If the scan subprocess cannot be started, the job must end in error,
    not strand the supervision thread with the job 'running' forever."""

    def _explode():
        raise OSError("spawn failed")

    job = idle_manager.submit(ScanRequest(target="http://x"))
    monkeypatch.setattr(runner, "_spawn_worker", _explode)
    idle_manager._run(job.id)
    result = idle_manager.get(job.id)
    assert result.status is ScanStatus.error
    assert "failed to start" in (result.error or "")


def test_list_orders_newest_first(idle_manager, monkeypatch):
    times = iter(
        [
            "2026-01-01T00:00:01+00:00",
            "2026-01-01T00:00:02+00:00",
            "2026-01-01T00:00:03+00:00",
        ]
    )
    monkeypatch.setattr(runner, "_now", lambda: next(times))
    a = idle_manager.submit(ScanRequest(target="http://a"))
    b = idle_manager.submit(ScanRequest(target="http://b"))
    c = idle_manager.submit(ScanRequest(target="http://c"))
    assert [j.id for j in idle_manager.list()] == [c.id, b.id, a.id]


def test_active_jobs_counts_only_queued_and_running(idle_manager):
    a = idle_manager.submit(ScanRequest(target="http://a"))
    b = idle_manager.submit(ScanRequest(target="http://b"))
    c = idle_manager.submit(ScanRequest(target="http://c"))
    d = idle_manager.submit(ScanRequest(target="http://d"))
    assert idle_manager.active_jobs == 4
    idle_manager._set(b.id, status=ScanStatus.running)
    idle_manager._set(c.id, status=ScanStatus.done)
    idle_manager._set(d.id, status=ScanStatus.error)
    assert idle_manager.active_jobs == 2  # a queued + b running
    assert a.status is ScanStatus.queued


def test_set_on_unknown_job_is_a_noop(idle_manager):
    idle_manager._set("missing", status=ScanStatus.done)  # must not raise


def test_job_timeout_override_and_default():
    assert JobManager(job_timeout=7.0)._default_timeout == 7.0
    assert JobManager()._default_timeout == runner.DEFAULT_JOB_TIMEOUT


# ---------------------------------------------------------------------------
# JobManager._run — subprocess supervision
# ---------------------------------------------------------------------------


def test_run_success_marks_done_with_payload(idle_manager, monkeypatch):
    job = idle_manager.submit(ScanRequest(target="http://x", max_seconds=30.0))
    payload = {
        "report": {"summary": {"targets": 1}},
        "by_lane": {"schema": "v1"},
        "coverage": None,
    }
    worker = _FakeWorker([True, payload])
    out = _drive_run(idle_manager, job, worker, monkeypatch)

    assert out.status is ScanStatus.done
    assert out.report == {"summary": {"targets": 1}}
    assert out.by_lane == {"schema": "v1"}
    assert out.coverage is None
    assert out.started_at and out.finished_at
    assert json.loads(worker.inputs[0])["target"] == "http://x"
    assert worker.timeouts == [30.0]  # per-request cap wins over the default


def test_run_uses_default_timeout_when_request_has_none(idle_manager, monkeypatch):
    job = idle_manager.submit(ScanRequest(target="http://x"))
    worker = _FakeWorker(_DONE)
    _drive_run(idle_manager, job, worker, monkeypatch)
    assert worker.timeouts == [idle_manager._default_timeout]


def test_run_worker_failure_marks_error(idle_manager, monkeypatch):
    job = idle_manager.submit(ScanRequest(target="http://x"))
    out = _drive_run(idle_manager, job, _FakeWorker([False, "RuntimeError: boom"]), monkeypatch)

    assert out.status is ScanStatus.error
    assert out.error == "RuntimeError: boom"
    assert out.finished_at


def test_run_wall_clock_cap_kills_subprocess(idle_manager, monkeypatch):
    """Deterministic version of the end-to-end hard-timeout test: the worker
    never answers, so it must be killed and the job errored."""
    job = idle_manager.submit(ScanRequest(target="http://x", max_seconds=5.0))
    worker = _FakeWorker(hangs=True)
    out = _drive_run(idle_manager, job, worker, monkeypatch)

    assert out.status is ScanStatus.error
    assert "exceeded 5s wall-clock cap" in out.error
    assert out.finished_at
    assert worker.killed


def test_run_worker_that_dies_without_a_result_marks_error(idle_manager, monkeypatch):
    job = idle_manager.submit(ScanRequest(target="http://x"))
    out = _drive_run(idle_manager, job, _FakeWorker(raw="", returncode=-11), monkeypatch)

    assert out.status is ScanStatus.error
    assert "exited -11 without a result" in out.error


def test_run_unknown_job_returns_before_spawning(idle_manager, monkeypatch):
    spawned: list[bool] = []
    monkeypatch.setattr(runner, "_spawn_worker", lambda: spawned.append(True))
    idle_manager._run("missing")
    assert not spawned


@pytest.mark.skipif(
    not subprocess._USE_POSIX_SPAWN,  # type: ignore[attr-defined]
    reason="this libc cannot posix_spawn for subprocess",
)
def test_worker_is_posix_spawned(monkeypatch):
    """fork() from the threaded runner can segfault the child on macOS."""
    calls: list[str] = []
    real = os.posix_spawn

    def _spy(path, *args, **kwargs):
        calls.append(path)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "posix_spawn", _spy)
    proc = runner._spawn_worker()
    proc.kill()
    proc.communicate()
    assert calls == [runner.sys.executable]


# ---------------------------------------------------------------------------
# _scan — the worker's scan, driven in-process
# ---------------------------------------------------------------------------


def test_scan_success_payload(monkeypatch):
    seen = {}

    def fake_run_parallel(targets, **kwargs):
        seen["targets"] = targets
        seen.update(kwargs)
        return ["sentinel-result"]

    monkeypatch.setattr("mcpnuke.scanner.run_parallel", fake_run_parallel)
    monkeypatch.setattr(
        "mcpnuke.reporting.json_out.build_report",
        lambda results, include_k8s: {"results": results, "include_k8s": include_k8s},
    )
    monkeypatch.setattr(
        "mcpnuke.reporting.by_lane.build_by_lane",
        lambda results: {"schema": "v1"},
    )

    req = ScanRequest(target="http://x", depth=ScanDepth.deep, auth_token="synthetic-token")
    # Mirror JobManager._run's handoff: model_dump strips auth_token
    # (Field exclude=True) so API responses can't leak it; the worker
    # payload re-adds it.
    req_dict = req.model_dump()
    req_dict["auth_token"] = req.auth_token
    ok, payload = _scan(req_dict)

    assert ok is True
    assert payload["report"] == {"results": ["sentinel-result"], "include_k8s": False}
    assert payload["by_lane"] == {"schema": "v1"}
    assert payload["coverage"] is None
    assert seen["targets"] == ["http://x"]
    assert seen["auth_token"] == "synthetic-token"
    assert seen["timeout"] == 25.0
    assert seen["workers"] == 1
    assert seen["verbose"] is False
    assert seen["probe_opts"]["probe_calls"] is True  # deep depth
    assert seen["probe_opts"]["deterministic"] is True


def test_scan_includes_coverage_when_url_set(monkeypatch):
    monkeypatch.setattr("mcpnuke.scanner.run_parallel", lambda *a, **k: [])
    monkeypatch.setattr("mcpnuke.reporting.json_out.build_report", lambda results, include_k8s: {})
    monkeypatch.setattr("mcpnuke.reporting.by_lane.build_by_lane", lambda results: {})
    monkeypatch.setattr(runner, "_coverage", lambda results, url: {"schema": "v1", "url": url})

    req = ScanRequest(target="http://x", coverage_url="http://camazotz:3000")
    ok, payload = _scan(req.model_dump())

    assert ok is True
    assert payload["coverage"] == {"schema": "v1", "url": "http://camazotz:3000"}


def test_scan_surfaces_any_exception_to_parent(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("mcpnuke.scanner.run_parallel", boom)
    assert _scan(ScanRequest(target="http://x").model_dump()) == (False, "RuntimeError: kaboom")


# ---------------------------------------------------------------------------
# _coverage — cross-project report degrades to a note, never a failed job
# ---------------------------------------------------------------------------


def test_coverage_success(monkeypatch):
    seen = {}

    def fake_fetch(url):
        seen["url"] = url
        return {"schema": "v1", "lanes": []}

    monkeypatch.setattr("mcpnuke.reporting.coverage_report.fetch_lane_taxonomy", fake_fetch)
    monkeypatch.setattr(
        "mcpnuke.reporting.coverage_report.build_coverage_report",
        lambda results, taxonomy: {"results": results, "taxonomy": taxonomy},
    )

    out = _coverage(["r"], "http://camazotz:3000")
    assert seen["url"] == "http://camazotz:3000"
    assert out == {"results": ["r"], "taxonomy": {"schema": "v1", "lanes": []}}


def test_coverage_schema_mismatch_degrades_to_note(monkeypatch):
    def raise_mismatch(url):
        raise SchemaMismatchError("schema 'v2' incompatible")

    monkeypatch.setattr("mcpnuke.reporting.coverage_report.fetch_lane_taxonomy", raise_mismatch)
    out = _coverage([], "http://camazotz:3000")
    assert out["error"] == "schema_mismatch"
    assert "v2" in out["detail"]


def test_coverage_unreachable_degrades_to_note(monkeypatch):
    def raise_down(url):
        raise ConnectionError("refused")

    monkeypatch.setattr("mcpnuke.reporting.coverage_report.fetch_lane_taxonomy", raise_down)
    out = _coverage([], "http://camazotz:3000")
    assert out["error"] == "unreachable"
    assert out["detail"] == "ConnectionError: refused"


# ---------------------------------------------------------------------------
# _probe_opts_for — cases beyond the depth mapping covered in test_server.py
# ---------------------------------------------------------------------------


def test_probe_opts_safe_mode_off_and_fixed_defaults():
    opts = _probe_opts_for(ScanRequest(target="http://x", safe_mode=False))
    assert opts["safe_mode"] is False
    assert opts["max_pages"] == 20
    assert opts["tls_verify"] is False
    assert opts["deterministic"] is True
    assert opts["no_invoke"] is False
