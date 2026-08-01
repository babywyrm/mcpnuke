from unittest.mock import MagicMock, patch

from mcpnuke.core.protocol import LEGACY, STATELESS
from mcpnuke.core.session import HTTPSession


def _response(payload):
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"content-type": "application/json", "Mcp-Session-Id": "sess-1"}
    resp.json.return_value = payload
    resp.text = ""
    return resp


def test_stateless_call_sends_routing_headers():
    session = HTTPSession("http://t", "http://t/mcp", protocol_mode=STATELESS)
    with patch.object(session._client, "post") as post:
        post.return_value = _response({"jsonrpc": "2.0", "id": 1, "result": {}})
        session.call("tools/call", {"name": "search"})

    headers = post.call_args.kwargs["headers"]
    assert headers["Mcp-Method"] == "tools/call"
    assert headers["Mcp-Name"] == "search"
    assert headers["MCP-Protocol-Version"] == "2026-07-28"


def test_stateless_call_omits_session_id_header():
    session = HTTPSession("http://t", "http://t/mcp", protocol_mode=STATELESS)
    with patch.object(session._client, "post") as post:
        post.return_value = _response({"jsonrpc": "2.0", "id": 1, "result": {}})
        session.call("tools/list")
        session.call("tools/list")

    headers = post.call_args.kwargs["headers"]
    assert "Mcp-Session-Id" not in headers


def test_stateless_call_injects_client_info_meta():
    session = HTTPSession("http://t", "http://t/mcp", protocol_mode=STATELESS)
    with patch.object(session._client, "post") as post:
        post.return_value = _response({"jsonrpc": "2.0", "id": 1, "result": {}})
        session.call("tools/call", {"name": "search"})

    params = post.call_args.kwargs["json"]["params"]
    assert params["_meta"]["io.modelcontextprotocol/clientInfo"]["name"] == "mcpnuke"


def test_legacy_call_still_forwards_session_id():
    session = HTTPSession("http://t", "http://t/mcp", protocol_mode=LEGACY)
    with patch.object(session._client, "post") as post:
        post.return_value = _response({"jsonrpc": "2.0", "id": 1, "result": {}})
        session.call("tools/list")
        session.call("tools/list")

    headers = post.call_args.kwargs["headers"]
    assert headers["Mcp-Session-Id"] == "sess-1"
    assert "Mcp-Method" not in headers


def test_legacy_call_does_not_inject_meta():
    session = HTTPSession("http://t", "http://t/mcp", protocol_mode=LEGACY)
    with patch.object(session._client, "post") as post:
        post.return_value = _response({"jsonrpc": "2.0", "id": 1, "result": {}})
        session.call("tools/call", {"name": "search"})

    assert post.call_args.kwargs["json"]["params"] == {"name": "search"}


def test_default_protocol_mode_is_legacy():
    assert HTTPSession("http://t", "http://t/mcp").protocol_mode == LEGACY
