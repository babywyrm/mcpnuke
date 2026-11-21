"""SSE and stdio responses arrive on one long-lived stream. If the server
drops it mid-scan, every later call gets no answer, which reads as a check
with nothing to find. The scan must say it is incomplete instead."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Iterator

import httpx
import pytest

from mcpnuke import scanner
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports import sse
from mcpnuke.core.transports.stdio import StdioSession

_BASE = "http://mcp.lab:9000"
_ENDPOINT = b"event: endpoint\ndata: /messages\n\n"


def _session(monkeypatch: pytest.MonkeyPatch, hold: threading.Event | None = None) -> sse.MCPSession:
    """The stream announces its endpoint, then ends at once or when *hold* is set."""

    def stream() -> Iterator[bytes]:
        yield _ENDPOINT
        if hold is not None:
            hold.wait(5)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=stream())
        return httpx.Response(202)

    real = httpx.Client
    monkeypatch.setattr(sse.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    session = sse.MCPSession(_BASE, "/sse", timeout=5)
    assert session.wait_ready(timeout=5)
    return session


def test_dropped_stream_is_recorded_and_calls_fail_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(monkeypatch)
    session._listener.join(5)
    assert session.stream_lost
    t0 = time.time()
    assert session.call("tools/list") is None
    assert time.time() - t0 < 1
    session.close()


def test_our_own_close_is_not_a_lost_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    hold = threading.Event()
    session = _session(monkeypatch, hold)
    session.close()
    hold.set()
    session._listener.join(5)
    assert not session.stream_lost


def test_exited_stdio_server_is_recorded_and_calls_fail_fast() -> None:
    session = StdioSession([sys.executable, "-c", "pass"], timeout=5)
    session._proc.wait(5)
    assert "exited with code 0" in str(session.stream_lost)
    t0 = time.time()
    assert session.call("tools/list") is None
    assert time.time() - t0 < 1
    session.close()


def test_stdio_close_is_not_a_lost_stream() -> None:
    session = StdioSession([sys.executable, "-c", "import time; time.sleep(30)"], timeout=5)
    session.close()
    assert session.stream_lost is None


def test_stdio_scan_with_exited_server_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "enumerate_server", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "run_all_checks", lambda *a, **k: time.sleep(1))
    result = scanner.scan_stdio_target(f"{sys.executable} -c 'import time; time.sleep(0.3)'")
    assert "exited with code 0" in result.check_errors["transport"]


def test_scan_with_dropped_stream_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _session(monkeypatch)
    session._listener.join(5)
    monkeypatch.setattr(scanner, "detect_transport", lambda *a, **k: session)
    monkeypatch.setattr(scanner, "enumerate_server", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "run_all_checks", lambda *a, **k: None)
    result = scanner.scan_target(f"{_BASE}/sse", [])
    assert isinstance(result, TargetResult)
    assert "server closed the event stream" in result.check_errors["transport"]
