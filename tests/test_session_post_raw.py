"""Tests for Session.post_raw(), the raw-HTTP escape hatch for header probes.

Checks that need to control transport headers or read the HTTP status directly
cannot go through call(), which owns request ids, retries, and SSE framing.
post_raw() exists for them, and its presence is the capability marker for
"this transport speaks HTTP" — StdioSession deliberately does not define it.
"""

from __future__ import annotations

from unittest.mock import patch

from mcpnuke.core.session import (
    HTTPSession,
    MCPSession,
    StdioSession,
    ToolServerSession,
)

_PAYLOAD = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


class _Resp:
    status_code = 200
    headers: dict = {}
    text = "{}"

    def json(self):
        return {}


def _http_session(**kw) -> HTTPSession:
    return HTTPSession("http://t", "http://t/mcp", verify_tls=False, **kw)


class TestCapabilityMarker:
    def test_http_transports_expose_post_raw(self):
        assert hasattr(HTTPSession, "post_raw")
        assert hasattr(MCPSession, "post_raw")
        assert hasattr(ToolServerSession, "post_raw")

    def test_stdio_does_not_expose_post_raw(self):
        """stdio has no HTTP header layer, so header probes must skip it."""
        assert not hasattr(StdioSession, "post_raw")


class TestHTTPSessionPostRaw:
    def test_posts_to_the_mcp_endpoint(self):
        session = _http_session()
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD)

        assert post.call_args[0][0] == "http://t/mcp"

    def test_sends_the_payload_as_json(self):
        session = _http_session()
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD)

        assert post.call_args.kwargs["json"] == _PAYLOAD

    def test_reuses_session_auth_headers(self):
        """Without the session's auth, a 401 would mean 'no token', not 'DPoP enforced'."""
        session = _http_session(headers={"Authorization": "Bearer tok", "X-Env": "lab"})
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD)

        sent = post.call_args.kwargs["headers"]
        assert sent["Authorization"] == "Bearer tok"
        assert sent["X-Env"] == "lab"

    def test_forwards_captured_session_id(self):
        session = _http_session()
        session._session_id = "sess-1"
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD)

        assert post.call_args.kwargs["headers"]["Mcp-Session-Id"] == "sess-1"

    def test_extra_headers_are_merged(self):
        session = _http_session(headers={"Authorization": "Bearer tok"})
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD, extra_headers={"DPoP": "proof"})

        sent = post.call_args.kwargs["headers"]
        assert sent["DPoP"] == "proof"
        assert sent["Authorization"] == "Bearer tok"

    def test_extra_headers_win_over_session_headers(self):
        session = _http_session(headers={"DPoP": "stale"})
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD, extra_headers={"DPoP": "fresh"})

        assert post.call_args.kwargs["headers"]["DPoP"] == "fresh"

    def test_does_not_mutate_session_headers(self):
        session = _http_session(headers={"Authorization": "Bearer tok"})
        with patch.object(session._client, "post", return_value=_Resp()):
            session.post_raw(_PAYLOAD, extra_headers={"DPoP": "proof"})

        assert "DPoP" not in session._headers

    def test_returns_the_raw_response(self):
        session = _http_session()
        resp = _Resp()
        with patch.object(session._client, "post", return_value=resp):
            assert session.post_raw(_PAYLOAD) is resp

    def test_explicit_timeout_is_forwarded(self):
        session = _http_session()
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD, timeout=3.0)

        assert post.call_args.kwargs["timeout"] == 3.0

    def test_falls_back_to_session_timeout(self):
        session = HTTPSession("http://t", "http://t/mcp", timeout=17.0, verify_tls=False)
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD)

        assert post.call_args.kwargs["timeout"] == 17.0


class TestMCPSessionPostRaw:
    def test_posts_to_the_discovered_endpoint_with_auth(self):
        session = MCPSession("http://t", "/sse", auth_token="tok", verify_tls=False)
        session._stop.set()
        session.post_url = "http://t/messages/abc"

        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD, extra_headers={"DPoP": "proof"})

        assert post.call_args[0][0] == "http://t/messages/abc"
        sent = post.call_args.kwargs["headers"]
        assert sent["Authorization"] == "Bearer tok"
        assert sent["DPoP"] == "proof"


class TestToolServerSessionPostRaw:
    def test_posts_to_the_tool_endpoint(self):
        session = ToolServerSession("http://t", "http://t/invoke", verify_tls=False)
        with patch.object(session._client, "post", return_value=_Resp()) as post:
            session.post_raw(_PAYLOAD, extra_headers={"DPoP": "proof"})

        assert post.call_args[0][0] == "http://t/invoke"
        assert post.call_args.kwargs["headers"]["DPoP"] == "proof"
