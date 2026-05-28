"""Tests for the mcpnuke-runner service.

Skipped automatically when the optional ``server`` extra (fastapi/pydantic)
isn't installed, so the core test suite stays dependency-light.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from fastapi.testclient import TestClient  # noqa: E402

from mcpnuke.server.app import app  # noqa: E402
from mcpnuke.server.models import ScanDepth, ScanRequest  # noqa: E402
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
