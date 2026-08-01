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


_NAME_PARAM_KEYS: tuple[str, ...] = ("name", "uri")


def _header_safe(value: str) -> str:
    """Strip CR/LF so a hostile tool name cannot inject extra headers."""
    return value.replace("\r", "").replace("\n", "").strip()


def routing_headers(
    method: str,
    params: dict[str, Any] | None,
    mode: str,
) -> dict[str, str]:
    """Build the stateless routing headers for a request.

    Returns an empty dict in legacy mode so callers can unconditionally merge.
    """
    if mode != STATELESS:
        return {}

    headers: dict[str, str] = {
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION_STATELESS,
        "Mcp-Method": _header_safe(method),
    }

    for key in _NAME_PARAM_KEYS:
        value = (params or {}).get(key)
        if isinstance(value, str) and value.strip():
            headers["Mcp-Name"] = _header_safe(value)
            break

    return headers
