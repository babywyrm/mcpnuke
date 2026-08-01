"""MCP protocol-mode handling for legacy and stateless (2026-07-28) servers.

The 2026-07-28 spec retires the initialize/initialized handshake and the
Mcp-Session-Id header. Requests are self-describing: client identity travels
in ``params._meta`` and routing information travels in HTTP headers.

Reference: https://blog.modelcontextprotocol.io/posts/2026-07-28/
"""

from __future__ import annotations

from typing import Any

from mcpnuke import __version__

LEGACY: str = "legacy"
STATELESS: str = "stateless"
AUTO: str = "auto"

PROTOCOL_MODES: frozenset[str] = frozenset({LEGACY, STATELESS, AUTO})

MCP_PROTOCOL_VERSION_STATELESS: str = "2026-07-28"

CLIENT_INFO_META_KEY: str = "io.modelcontextprotocol/clientInfo"


def client_info_meta() -> dict[str, Any]:
    """Build the ``_meta`` client-identity block for a stateless request."""
    return {CLIENT_INFO_META_KEY: {"name": "mcpnuke", "version": __version__}}


def inject_meta(params: dict[str, Any] | None, mode: str) -> dict[str, Any]:
    """Return a copy of *params* with stateless ``_meta`` added when required."""
    out: dict[str, Any] = dict(params or {})
    if mode != STATELESS:
        return out
    meta: dict[str, Any] = dict(out.get("_meta") or {})
    meta.update(client_info_meta())
    out["_meta"] = meta
    return out
