"""A redirect off the target's host must not carry the scan's credentials.

httpx drops Authorization and Cookie on a cross-origin redirect but keeps
every other header, so a --header API key followed a target's 307 to any
host it named.
"""

from __future__ import annotations

import httpx
import pytest

from mcpnuke.core import auth
from mcpnuke.core.session import detect_transport
from mcpnuke.core.transports.http import HTTPSession
from mcpnuke.core.transports.sse import MCPSession
from mcpnuke.core.transports.toolserver import ToolServerSession

_TARGET = "http://mcp.lab:9000"
_SECRET_HEADERS: dict[str, str] = {"X-API-Key": "synthetic-key", "Authorization": "Bearer t"}


@pytest.fixture
def evil_saw(monkeypatch) -> list[dict[str, str]]:
    """mcp.lab redirects everything except /test-sse and /same to evil.example.

    /test-sse is not a path transport detection probes, so detection is
    redirected on every attempt.
    """
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "evil.example":
            seen.append({k.lower(): v for k, v in request.headers.items()})
            return httpx.Response(404)
        if request.url.path == "/test-sse":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content=b"event: endpoint\ndata: /messages\n\n",
            )
        if request.url.path == "/same":
            return httpx.Response(200, json={"x-api-key": request.headers.get("x-api-key", "")})
        return httpx.Response(307, headers={"location": "http://evil.example/collect"})

    real = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw)
    )
    return seen


def _leaked(seen: list[dict[str, str]]) -> list[str]:
    return [h[k] for h in seen for k in ("x-api-key", "authorization") if k in h]


def test_http_session(evil_saw) -> None:
    session = HTTPSession(_TARGET, f"{_TARGET}/mcp", headers=dict(_SECRET_HEADERS))
    session.post_raw({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert evil_saw and _leaked(evil_saw) == []


def test_tool_server_session(evil_saw) -> None:
    session = ToolServerSession(_TARGET, f"{_TARGET}/execute", headers=dict(_SECRET_HEADERS))
    session.post_raw({"tool": "x"})
    assert evil_saw and _leaked(evil_saw) == []


def test_sse_session(evil_saw) -> None:
    session = MCPSession(_TARGET, "/test-sse", auth_token="t", extra_headers={"X-API-Key": "synthetic-key"})
    try:
        assert session.wait_ready(timeout=5) and session.post_url
        session.post_raw({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    finally:
        session.close()
    assert evil_saw and _leaked(evil_saw) == []


def test_transport_detection(evil_saw) -> None:
    detect_transport(
        f"{_TARGET}/mcp",
        connect_timeout=2,
        auth_token="t",
        extra_headers={"X-API-Key": "synthetic-key"},
    )
    assert evil_saw and _leaked(evil_saw) == []


def test_auth_detection(evil_saw) -> None:
    auth.detect_auth_requirements(f"{_TARGET}/mcp", extra_headers={"X-API-Key": "synthetic-key"})
    assert evil_saw and _leaked(evil_saw) == []


def test_same_host_keeps_the_headers(evil_saw) -> None:
    session = HTTPSession(_TARGET, f"{_TARGET}/same", headers=dict(_SECRET_HEADERS))
    resp = session.post_raw({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert resp.json() == {"x-api-key": "synthetic-key"}
