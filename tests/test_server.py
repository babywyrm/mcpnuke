"""Tests for the mcpnuke-runner service.

Skipped automatically when the optional ``server`` extra (fastapi/pydantic)
isn't installed, so the core test suite stays dependency-light.
"""

from __future__ import annotations

import importlib
import sys
import time
from unittest import mock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from fastapi.testclient import TestClient  # noqa: E402
from pydantic import ValidationError  # noqa: E402

import mcpnuke.server.app as server_app  # noqa: E402
from mcpnuke.server.app import app  # noqa: E402
from mcpnuke.server.models import HealthResponse, ScanDepth, ScanJob, ScanRequest, ScanStatus  # noqa: E402
from mcpnuke.server.runner import _probe_opts_for  # noqa: E402

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "mcpnuke-runner"
    assert "version" in body
    assert body["active_jobs"] >= 0


def test_probe_opts_depth_mapping():
    fast = _probe_opts_for(ScanRequest(target="http://x", depth=ScanDepth.fast))
    assert fast["fast"] is True
    assert fast["probe_calls"] is False

    deep = _probe_opts_for(ScanRequest(target="http://x", depth=ScanDepth.deep))
    assert deep["fast"] is False
    assert deep["probe_calls"] is True

    std = _probe_opts_for(ScanRequest(target="http://x", depth=ScanDepth.standard))
    assert std["fast"] is False
    assert std["probe_calls"] is False
    assert std["safe_mode"] is True


def test_get_unknown_job_404():
    resp = client.get("/scans/does-not-exist")
    assert resp.status_code == 404


def test_scan_job_hard_timeout():
    """A scan that would otherwise hang must be killed at the wall-clock cap.

    A listening socket that accepts the connection but never replies makes the
    scanner's per-request read block; the job-level max_seconds must terminate
    the subprocess and surface an error rather than running forever.
    """
    import socket

    sink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sink.bind(("127.0.0.1", 0))
    sink.listen(1)  # accept into the backlog, never read/respond
    port = sink.getsockname()[1]
    try:
        resp = client.post(
            "/scans",
            json={
                "target": f"http://127.0.0.1:{port}/mcp",
                "depth": "fast",
                "timeout": 60.0,      # per-request timeout far longer than the cap
                "max_seconds": 5.0,   # the hard wall-clock cap under test
            },
        )
        assert resp.status_code == 202
        job_id = resp.json()["id"]

        deadline = time.time() + 25
        status = None
        while time.time() < deadline:
            poll = client.get(f"/scans/{job_id}")
            status = poll.json()["status"]
            if status in ("done", "error"):
                break
            time.sleep(0.5)

        assert status == "error"
        body = client.get(f"/scans/{job_id}").json()
        assert "wall-clock cap" in (body["error"] or "")
    finally:
        sink.close()


def test_scan_lifecycle_unreachable_target():
    """A scan against an unreachable target should still complete (no MCP
    transport found) rather than erroring the job out."""
    resp = client.post(
        "/scans",
        json={"target": "http://127.0.0.1:1/mcp", "depth": "fast", "timeout": 2.0},
    )
    assert resp.status_code == 202
    job_id = resp.json()["id"]

    deadline = time.time() + 30
    status = None
    while time.time() < deadline:
        poll = client.get(f"/scans/{job_id}")
        assert poll.status_code == 200
        status = poll.json()["status"]
        if status in ("done", "error"):
            break
        time.sleep(0.5)

    assert status == "done"
    body = client.get(f"/scans/{job_id}").json()
    assert body["report"] is not None
    assert body["report"]["summary"]["targets"] == 1
    assert body["by_lane"]["schema"] == "v1"


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


def test_scan_request_defaults():
    req = ScanRequest(target="http://x")
    assert req.depth is ScanDepth.standard
    assert req.safe_mode is True
    assert req.timeout == 25.0
    assert req.max_seconds is None
    assert req.coverage_url is None
    assert req.auth_token is None


def test_scan_request_rejects_blank_target():
    with pytest.raises(ValidationError):
        ScanRequest(target="")


def test_scan_job_defaults_to_no_result_fields():
    job = ScanJob(
        id="x",
        status=ScanStatus.queued,
        request=ScanRequest(target="http://x"),
        created_at="2026-01-01T00:00:00+00:00",
    )
    assert job.started_at is None
    assert job.finished_at is None
    assert job.error is None
    assert job.report is None
    assert job.by_lane is None
    assert job.coverage is None


def test_health_response_defaults():
    body = HealthResponse(version="1.2.3", active_jobs=0)
    assert body.status == "ok"
    assert body.service == "mcpnuke-runner"


def test_status_and_depth_enum_values():
    # These strings are the HTTP API contract; renaming one breaks clients.
    assert [s.value for s in ScanStatus] == ["queued", "running", "done", "error"]
    assert [d.value for d in ScanDepth] == ["fast", "standard", "deep"]


# ---------------------------------------------------------------------------
# HTTP API — validation, routing, and the job lifecycle over a stubbed manager
# ---------------------------------------------------------------------------


class _StubManager:
    """In-memory stand-in for JobManager: records submissions, spawns nothing."""

    def __init__(self):
        self.jobs: dict[str, ScanJob] = {}
        self.active = 0
        self.submitted: list[ScanRequest] = []

    @property
    def active_jobs(self):
        return self.active

    def submit(self, req):
        self.submitted.append(req)
        job = ScanJob(
            id=f"stub{len(self.submitted):08d}",
            status=ScanStatus.queued,
            request=req,
            created_at=f"2026-01-01T00:00:{len(self.submitted):02d}+00:00",
        )
        self.jobs[job.id] = job
        return job

    def get(self, job_id):
        return self.jobs.get(job_id)

    def list(self):
        return sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)


@pytest.fixture
def stub_manager(monkeypatch):
    stub = _StubManager()
    monkeypatch.setattr(server_app, "_manager", stub)
    return stub


def test_create_scan_accepted_shape(stub_manager):
    resp = client.post("/scans", json={"target": "http://x", "depth": "fast"})
    assert resp.status_code == 202
    body = resp.json()
    assert body["id"] in stub_manager.jobs
    assert body["status"] == "queued"
    assert stub_manager.submitted[0].depth is ScanDepth.fast


def test_create_scan_applies_safe_defaults(stub_manager):
    resp = client.post("/scans", json={"target": "http://x"})
    assert resp.status_code == 202
    req = stub_manager.submitted[0]
    assert req.depth is ScanDepth.standard
    assert req.safe_mode is True
    assert req.timeout == 25.0
    assert req.max_seconds is None
    assert req.coverage_url is None
    assert req.auth_token is None


def test_get_scan_returns_full_job(stub_manager):
    job_id = client.post("/scans", json={"target": "http://x"}).json()["id"]
    resp = client.get(f"/scans/{job_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == job_id
    assert body["status"] == "queued"
    assert body["request"]["target"] == "http://x"
    assert body["report"] is None  # populated only once status == done


def test_get_unknown_job_404_detail():
    resp = client.get("/scans/nope")
    assert resp.status_code == 404
    assert "nope" in resp.json()["detail"]


def test_list_scans_newest_first(stub_manager):
    client.post("/scans", json={"target": "http://a"})
    client.post("/scans", json={"target": "http://b"})
    resp = client.get("/scans")
    assert resp.status_code == 200
    assert [j["request"]["target"] for j in resp.json()] == ["http://b", "http://a"]


def test_auth_token_never_leaves_the_api(stub_manager):
    """CWE-200 regression: a caller's bearer token must not be readable back
    through job responses — the API is unauthenticated, so anyone who can
    reach it could otherwise harvest tokens other callers submitted."""
    token = "test-bearer-token-value"
    job_id = client.post(
        "/scans", json={"target": "http://x", "auth_token": token}
    ).json()["id"]

    # The manager still holds the real token for the scan worker...
    assert stub_manager.submitted[0].auth_token == token

    # ...but no API response may contain it.
    assert token not in client.get(f"/scans/{job_id}").text
    assert token not in client.get("/scans").text


def test_auth_token_excluded_from_dump_but_attribute_intact():
    req = ScanRequest(target="http://x", auth_token="tok")
    assert "auth_token" not in req.model_dump()
    assert req.auth_token == "tok"


def test_scan_job_dump_redacts_nested_auth_token():
    job = ScanJob(
        id="x",
        status=ScanStatus.queued,
        request=ScanRequest(target="http://x", auth_token="tok"),
        created_at="2026-01-01T00:00:00+00:00",
    )
    assert "tok" not in str(job.model_dump())


def test_health_reports_active_jobs(stub_manager):
    stub_manager.active = 3
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["active_jobs"] == 3


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"target": ""},
        {"target": "http://x", "timeout": 0.5},
        {"target": "http://x", "timeout": 121.0},
        {"target": "http://x", "max_seconds": 4.0},
        {"target": "http://x", "max_seconds": 1801.0},
        {"target": "http://x", "depth": "ludicrous"},
        {"target": "http://x", "safe_mode": "maybe"},
    ],
    ids=[
        "missing-target",
        "empty-target",
        "timeout-below-min",
        "timeout-above-max",
        "max-seconds-below-min",
        "max-seconds-above-max",
        "unknown-depth",
        "non-boolean-safe-mode",
    ],
)
def test_create_scan_validation_errors_422(payload):
    resp = client.post("/scans", json=payload)
    assert resp.status_code == 422
    assert resp.json()["detail"]


def test_create_scan_accepts_boundary_values(stub_manager):
    low = client.post("/scans", json={"target": "http://x", "timeout": 1.0, "max_seconds": 5.0})
    assert low.status_code == 202
    high = client.post("/scans", json={"target": "http://x", "timeout": 120.0, "max_seconds": 1800.0})
    assert high.status_code == 202


def test_create_scan_malformed_json_422():
    resp = client.post("/scans", content=b"{not json", headers={"content-type": "application/json"})
    assert resp.status_code == 422


@pytest.mark.parametrize(
    "method,path",
    [("post", "/health"), ("put", "/scans"), ("delete", "/scans/x")],
    ids=["post-health", "put-scans", "delete-scan"],
)
def test_unsupported_methods_405(method, path):
    assert getattr(client, method)(path).status_code == 405


def test_cors_allows_any_origin_by_default():
    resp = client.get("/health", headers={"Origin": "http://portal.example"})
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "*"


def test_openapi_lists_the_job_api():
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    assert {"/health", "/scans", "/scans/{job_id}"} <= set(resp.json()["paths"])


# ---------------------------------------------------------------------------
# Entrypoint and version fallback
# ---------------------------------------------------------------------------


def test_run_entrypoint_reads_env(monkeypatch):
    uvicorn = pytest.importorskip("uvicorn")
    called = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: called.update(a=a, k=k))
    monkeypatch.setenv("MCPNUKE_RUNNER_HOST", "127.0.0.1")
    monkeypatch.setenv("MCPNUKE_RUNNER_PORT", "9999")
    monkeypatch.setenv("MCPNUKE_RUNNER_LOG_LEVEL", "debug")

    server_app.run()

    assert called["a"] == ("mcpnuke.server.app:app",)
    assert called["k"] == {"host": "127.0.0.1", "port": 9999, "log_level": "debug"}


def test_run_entrypoint_defaults(monkeypatch):
    uvicorn = pytest.importorskip("uvicorn")
    called = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: called.update(k=k))
    for var in ("MCPNUKE_RUNNER_HOST", "MCPNUKE_RUNNER_PORT", "MCPNUKE_RUNNER_LOG_LEVEL"):
        monkeypatch.delenv(var, raising=False)

    server_app.run()

    assert called["k"] == {"host": "0.0.0.0", "port": 8090, "log_level": "info"}


def test_version_falls_back_when_distribution_metadata_missing():
    # Keep last: reloading the app module rebinds module-level names.
    # test_runner_entry.py purges mcpnuke.server* from sys.modules, and
    # reload() requires the module to be present — restore it first.
    sys.modules.setdefault("mcpnuke.server.app", server_app)
    with mock.patch("importlib.metadata.version", side_effect=Exception("no dist")):
        importlib.reload(server_app)
        assert server_app._VERSION == "0.0.0"
    importlib.reload(server_app)
