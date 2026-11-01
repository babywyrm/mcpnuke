"""Error leakage: provoke tool errors and flag stack traces, internal
paths, and other implementation detail in the response."""

import json
import re

from mcpnuke.checks.base import (
    time_check,
)
from mcpnuke.checks.tool_probes import _call_tool, _response_text, _should_invoke
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol
from mcpnuke.patterns.probes import (
    ERROR_LEAKAGE_PATTERNS,
)


def _extract_json_strings(text: str) -> list[str]:
    """Try to JSON-decode *text* and recursively collect all string values.

    MCP servers commonly wrap error details inside ``json.dumps()`` within
    TextContent, which escapes characters that our regex patterns expect in
    raw form (e.g. parentheses, newlines).  Extracting the decoded string
    values lets the existing patterns match against the original error text.
    """
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []

    strings: list[str] = []

    def _recurse(v: object) -> None:
        if isinstance(v, str):
            strings.append(v)
        elif isinstance(v, dict):
            for val in v.values():
                _recurse(val)
        elif isinstance(v, list):
            for item in v:
                _recurse(item)

    _recurse(obj)
    return strings


def _match_error_patterns(texts: list[str]) -> re.Match | None:
    """Return the first ERROR_LEAKAGE_PATTERNS match across *texts*."""
    for t in texts:
        for pat in ERROR_LEAKAGE_PATTERNS:
            m = re.search(pat, t, re.IGNORECASE)
            if m:
                return m
    return None


def check_error_leakage(session: MCPSessionProtocol, result: TargetResult, probe_opts: dict | None = None) -> None:
    """Send malformed inputs to tools and look for information disclosure in errors."""
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    with time_check("error_leakage", result):
        invokable = [t for t in result.tools if _should_invoke(t, opts)]
        _log(f"    [dim]    probing {len(invokable)} tools for error leakage[/dim]")
        tool_idx = 0
        for tool in result.tools:
            if not _should_invoke(tool, opts):
                continue
            tool_idx += 1
            name = tool.get("name", "")
            _log(f"    [dim]    [{tool_idx}/{len(invokable)}] {name}[/dim]")
            schema = tool.get("inputSchema", {})
            required = schema.get("required", [])

            # 1) Call with empty args
            resp = _call_tool(session, name, {}, timeout=8)
            text = _response_text(resp)
            if text:
                candidates = [text] + _extract_json_strings(text)
                m = _match_error_patterns(candidates)
                if m:
                    result.add(
                        "error_leakage",
                        "MEDIUM",
                        f"Tool '{name}' leaks info on empty input",
                        f"Leaked: {m.group()[:200]}",
                        evidence=text[:400],
                    )

            # 2) Call with wrong types (numbers where strings expected)
            if required:
                wrong = {p: 99999 for p in required}
                resp = _call_tool(session, name, wrong, timeout=8)
                text = _response_text(resp)
                if text:
                    candidates = [text] + _extract_json_strings(text)
                    m = _match_error_patterns(candidates)
                    if m:
                        result.add(
                            "error_leakage",
                            "MEDIUM",
                            f"Tool '{name}' leaks info on type-mismatched input",
                            f"Leaked: {m.group()[:200]}",
                            evidence=text[:400],
                        )

            # 3) Prototype pollution / __proto__ probe
            resp = _call_tool(
                session, name,
                {"__proto__": {"admin": True}, **(dict.fromkeys(required, "x"))},
                timeout=8,
            )
            text = _response_text(resp)
            if text and "admin" in text.lower() and "true" in text.lower():
                result.add(
                    "error_leakage",
                    "HIGH",
                    f"Tool '{name}' may be vulnerable to prototype pollution",
                    "Server reflected __proto__.admin=True in response",
                    evidence=text[:400],
                )
