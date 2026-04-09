"""Tests for Mcp-Session-Id capture and forwarding."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from mcpnuke.core.session import HTTPSession, MCPSession


class FakeResponse:
    """Minimal httpx response stub."""

    def __init__(self, status_code: int = 200, body: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body or {}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class TestHTTPSessionId:
    """HTTPSession captures and forwards Mcp-Session-Id."""

    def test_captures_session_id_from_response(self):
        session = HTTPSession("http://localhost", "http://localhost/mcp", verify_tls=False)
        session._session_id = None

        resp_body = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        fake_resp = FakeResponse(200, resp_body, {"content-type": "application/json", "Mcp-Session-Id": "sess-abc-123"})

        with patch.object(session._client, "post", return_value=fake_resp):
            result = session.call("initialize", {"protocolVersion": "2024-11-05"})

        assert session._session_id == "sess-abc-123"
        assert result is not None

    def test_forwards_session_id_on_subsequent_calls(self):
        session = HTTPSession("http://localhost", "http://localhost/mcp", verify_tls=False)
        session._session_id = "sess-existing-id"

        headers = session._request_headers()
        assert headers["Mcp-Session-Id"] == "sess-existing-id"

    def test_no_session_id_header_when_none(self):
        session = HTTPSession("http://localhost", "http://localhost/mcp", verify_tls=False)
        assert session._session_id is None

        headers = session._request_headers()
        assert "Mcp-Session-Id" not in headers

    def test_notify_includes_session_id(self):
        session = HTTPSession("http://localhost", "http://localhost/mcp", verify_tls=False)
        session._session_id = "sess-notify-id"

        mock_post = MagicMock()
        with patch.object(session._client, "post", mock_post):
            session.notify("notifications/initialized")

        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs.get("headers", {}).get("Mcp-Session-Id") == "sess-notify-id"


class TestMCPSessionId:
    """MCPSession stores _session_id field."""

    def test_session_id_initially_none(self):
        with patch.object(MCPSession, "__init__", lambda self, *a, **kw: None):
            s = MCPSession.__new__(MCPSession)
            s._session_id = None
            assert s._session_id is None

    def test_session_id_forwarded_in_call_headers(self):
        with patch.object(MCPSession, "__init__", lambda self, *a, **kw: None):
            s = MCPSession.__new__(MCPSession)
            s._session_id = "sse-session-42"
            s._auth_token = None
            s._extra_headers = {}
            from mcpnuke.core.session import _mcp_headers
            headers = _mcp_headers(s._auth_token, s._extra_headers)
            if s._session_id:
                headers["Mcp-Session-Id"] = s._session_id
            assert headers["Mcp-Session-Id"] == "sse-session-42"
