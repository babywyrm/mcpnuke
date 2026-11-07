"""The SSE endpoint event may only name the stream's own origin.

Every POST to it carries the bearer token, so a cross-origin endpoint
would let the scanned server send the scanner's credentials elsewhere.
"""

from __future__ import annotations

import httpx
import pytest

from mcpnuke.core.transports import sse

_BASE = "http://mcp.lab:9000"


def _session(monkeypatch, announced: str) -> sse.MCPSession:
    body = f"event: endpoint\ndata: {announced}\n\n".encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body)

    real = httpx.Client
    monkeypatch.setattr(
        sse.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw)
    )
    session = sse.MCPSession(_BASE, "/sse", auth_token="synthetic-token")
    assert session.wait_ready(timeout=5)
    return session


@pytest.mark.parametrize(
    "announced",
    [
        "http://evil.example/messages",
        "https://mcp.lab:9000/messages",
        "http://mcp.lab:9001/messages",
        "//evil.example/messages",
    ],
)
def test_cross_origin_endpoint_is_not_adopted(monkeypatch, announced: str) -> None:
    session = _session(monkeypatch, announced)
    try:
        assert session.post_url == ""
    finally:
        session.close()


@pytest.mark.parametrize(
    ("announced", "expected"),
    [
        ("/messages?session_id=abc", f"{_BASE}/messages?session_id=abc"),
        (f"{_BASE}/messages", f"{_BASE}/messages"),
        # String concatenation turned this into userinfo on evil.example.
        ("@evil.example/messages", f"{_BASE}/@evil.example/messages"),
    ],
)
def test_same_origin_endpoint_is_adopted(monkeypatch, announced: str, expected: str) -> None:
    session = _session(monkeypatch, announced)
    try:
        assert session.post_url == expected
    finally:
        session.close()
