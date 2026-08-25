"""SEP-2243: server must reject Mcp-Method that disagrees with the JSON-RPC body.

Silence on legacy servers and on transports with no header layer. A finding
only when a stateless-via-discover HTTP server returns a JSON-RPC result for
a tools/list body tagged Mcp-Method: tools/call.
"""

from __future__ import annotations

from typing import Any

from mcpnuke.checks.routing_header_binding import check_routing_header_binding
from mcpnuke.core.models import TargetResult
from mcpnuke.core.protocol import LEGACY, STATELESS


class _Resp:
    def __init__(self, status: int, body: dict[str, Any] | None):
        self.status_code = status
        self._body = body

    def json(self) -> dict[str, Any]:
        if self._body is None:
            raise ValueError("not json")
        return self._body


class _HTTP:
    def __init__(
        self,
        *,
        mode: str = STATELESS,
        status: int = 200,
        body: dict[str, Any] | None = None,
        post_url: str = "http://t/mcp",
    ):
        self.protocol_mode = mode
        self.post_url = post_url
        self._status = status
        self._body = body if body is not None else {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        self.payload: dict[str, Any] | None = None
        self.extra_headers: dict[str, str] | None = None

    def post_raw(self, payload, extra_headers=None, timeout=None):
        self.payload = payload
        self.extra_headers = extra_headers
        return _Resp(self._status, self._body)


def _stateless_result() -> TargetResult:
    r = TargetResult(url="http://t/mcp")
    r.protocol_mode = STATELESS
    r.server_info = {"serverInfo": {"name": "t", "version": "1"}, "capabilities": {}}
    return r


def test_mismatch_accepted_is_reported():
    session = _HTTP()
    r = _stateless_result()
    check_routing_header_binding(session, r)
    hits = [f for f in r.findings if f.check == "routing_header_binding"]
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert session.payload is not None
    assert session.payload["method"] == "tools/list"
    assert session.extra_headers is not None
    assert session.extra_headers.get("Mcp-Method") == "tools/call"
    assert session.extra_headers["Mcp-Method"] != session.payload["method"]


def test_jsonrpc_error_is_silent():
    session = _HTTP(body={"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "mismatch"}})
    r = _stateless_result()
    check_routing_header_binding(session, r)
    assert r.findings == []


def test_http_error_is_silent():
    session = _HTTP(status=400, body={"error": "bad request"})
    r = _stateless_result()
    check_routing_header_binding(session, r)
    assert r.findings == []


def test_legacy_is_silent():
    session = _HTTP(mode=LEGACY)
    r = TargetResult(url="http://t/mcp")
    r.protocol_mode = LEGACY
    r.server_info = {"serverInfo": {"name": "legacy"}}
    check_routing_header_binding(session, r)
    assert r.findings == []
    assert session.payload is None


def test_tools_list_fallback_without_discover_is_silent():
    """AUTO can mark STATELESS from a bare tools/list. That is not 2026-07-28."""
    session = _HTTP()
    r = TargetResult(url="http://t/mcp")
    r.protocol_mode = STATELESS
    check_routing_header_binding(session, r)
    assert r.findings == []
    assert session.payload is None


def test_no_post_raw_is_silent():
    class _Stdio:
        protocol_mode = STATELESS

    r = _stateless_result()
    check_routing_header_binding(_Stdio(), r)
    assert r.findings == []


def test_empty_post_url_is_silent():
    session = _HTTP(post_url="")
    r = _stateless_result()
    check_routing_header_binding(session, r)
    assert r.findings == []
    assert session.payload is None


def test_session_none_is_silent():
    r = _stateless_result()
    check_routing_header_binding(None, r)
    assert r.findings == []


def test_post_raw_exception_does_not_crash():
    class _Boom(_HTTP):
        def post_raw(self, payload, extra_headers=None, timeout=None):
            raise RuntimeError("transport down")

    r = _stateless_result()
    check_routing_header_binding(_Boom(), r)
    assert r.findings == []
    assert "routing_header_binding" in r.timings


def test_timing_recorded_when_skipped():
    r = TargetResult(url="http://t/mcp")
    check_routing_header_binding(None, r)
    assert "routing_header_binding" in r.timings
