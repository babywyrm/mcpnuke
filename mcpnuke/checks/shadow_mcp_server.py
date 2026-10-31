"""MCP09: a manifest that recruits an MCP server other than the one scanned.

Shadow MCP servers are a governance problem: a scan of one host cannot
know which other hosts an operator approved. The part that shows up in
a tool list is a description telling the client to attach a second MCP
endpoint. The scanned server's own URL is not that finding.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from mcpnuke.checks.base import time_check, tool_text
from mcpnuke.core.models import TargetResult

_RECRUIT_RE: re.Pattern[str] = re.compile(
    r"\b(?:additional|another|unlisted|shadow|rogue)\s+mcp\s+server\b"
    r".{0,160}?"
    r"(https?://[^\s\"'<>]+)",
    re.IGNORECASE | re.DOTALL,
)
_MCP_PATHS: frozenset[str] = frozenset({"/mcp", "/sse"})


def _foreign_endpoint(url: str, target: str) -> str:
    cleaned = url.rstrip(".,);")
    found = urlsplit(cleaned)
    if found.scheme not in ("http", "https") or not found.netloc:
        return ""
    if (found.path.rstrip("/") or "/") not in _MCP_PATHS:
        return ""
    home = urlsplit(target)
    if home.netloc and found.netloc.lower() == home.netloc.lower():
        return ""
    return cleaned


def check_shadow_mcp_server(result: TargetResult) -> None:
    with time_check("shadow_mcp_server", result):
        for tool in result.tools:
            text = tool_text(tool)
            for match in _RECRUIT_RE.finditer(text):
                endpoint = _foreign_endpoint(match.group(1), result.url)
                if not endpoint:
                    continue
                name = str(tool.get("name", ""))
                result.add(
                    "shadow_mcp_server",
                    "HIGH",
                    f"Tool '{name}' recruits another MCP server",
                    "The manifest tells a client to attach an MCP endpoint "
                    "that is not the server being scanned. That is the "
                    "scanner-visible half of a shadow MCP server.",
                    evidence=endpoint,
                )
                break
