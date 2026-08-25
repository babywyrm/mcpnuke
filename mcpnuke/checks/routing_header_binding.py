"""SEP-2243 routing-header binding.

Stateless Streamable HTTP requires ``Mcp-Method`` (and ``Mcp-Name`` when the
operation has a name) so a gateway can route without reading the body. The
server must reject a request whose headers disagree with the JSON-RPC method.

mcpnuke already sends those headers. This check is the scan: a ``tools/list``
body tagged ``Mcp-Method: tools/call``. A JSON-RPC result means the server
honoured the body and ignored the header — load balancer and app disagree.

Silent when the server is legacy, when ``server/discover`` never ran (AUTO
can mark stateless from a bare ``tools/list``), and when the transport has
no HTTP header layer.
"""

from __future__ import annotations

from typing import Any

from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult
from mcpnuke.core.protocol import (
    MCP_PROTOCOL_VERSION_STATELESS,
    STATELESS,
    inject_meta,
)

_BODY_METHOD: str = "tools/list"
_HEADER_METHOD: str = "tools/call"
_CHECK: str = "routing_header_binding"


def _probeable(session: Any, result: TargetResult) -> bool:
    if session is None:
        return False
    if getattr(session, "protocol_mode", "") != STATELESS:
        return False
    if not result.server_info:
        return False
    return bool(getattr(session, "post_raw", None) and getattr(session, "post_url", ""))


def _rpc_succeeded(resp: Any) -> bool:
    if getattr(resp, "status_code", None) not in (200, 202):
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return isinstance(body, dict) and "result" in body and "error" not in body


def check_routing_header_binding(session: Any, result: TargetResult) -> None:
    with time_check(_CHECK, result):
        if not _probeable(session, result):
            return
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": _BODY_METHOD,
            "params": inject_meta({}, STATELESS),
        }
        extra = {
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION_STATELESS,
            "Mcp-Method": _HEADER_METHOD,
        }
        try:
            resp = session.post_raw(payload, extra_headers=extra, timeout=10)
        except Exception as exc:
            result.note_error(f"{_CHECK} probe error: {exc}")
            return
        if not _rpc_succeeded(resp):
            return
        result.add(
            _CHECK,
            "MEDIUM",
            "Stateless server accepted Mcp-Method that disagrees with the body",
            "SEP-2243 requires the server to reject a request whose "
            "Mcp-Method header does not match the JSON-RPC method. "
            f"This server returned a result for {_BODY_METHOD} tagged "
            f"Mcp-Method: {_HEADER_METHOD}. A gateway routing on the "
            "header and the application parsing the body will disagree.",
            evidence=(
                f"http_status={getattr(resp, 'status_code', '?')} "
                f"body_method={_BODY_METHOD} header_method={_HEADER_METHOD}"
            ),
            skip_transports=["stdio"],
        )
