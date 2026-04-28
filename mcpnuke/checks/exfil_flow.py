"""Cross-tool data exfiltration flow analysis (MCP-T12).

Classifies tools as data sources vs data sinks and flags
source+sink pairs as potential exfiltration paths. When a session
is available, performs live verification: reads from a source tool,
then attempts to send canary data through a sink tool, confirming
reachability of theoretical exfiltration paths.
"""

import re

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check

from mcpnuke.checks._lane_helpers import lane_tagged

# All findings in this module are scoped to Lane 2 / Transport "B"
# (2026-04-26 by-lane reporting spec).
_add = lane_tagged(lane=2, transport="B")

SOURCE_KEYWORDS = {
    "read", "get", "list", "fetch", "query", "search", "find",
    "export", "dump", "extract", "retrieve", "download", "select",
    "describe", "show", "view", "inspect", "lookup", "scan",
}

SINK_KEYWORDS = {
    "send", "post", "email", "notify", "webhook", "upload",
    "publish", "broadcast", "slack", "message", "forward",
    "transmit", "push", "dispatch", "deliver", "share",
    "tweet", "sms", "chat", "write_external",
}

SENSITIVE_SOURCE_PATTERNS = [
    r"(secret|credential|password|token|key|certificate)",
    r"(user|customer|employee|patient|client)\s+(data|info|record|profile)",
    r"(pii|ssn|credit.card|bank.account)",
    r"(database|db|sql|mongo|redis)\s+(query|read|dump|export)",
    r"(file|config|env)\s+(read|get|list|dump)",
]


def _classify_tool(tool: dict) -> tuple[bool, bool, bool]:
    """Classify a tool as source, sink, or sensitive source."""
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    combined = f"{name} {desc}"
    name_parts = set(re.split(r"[_\-\s]+", name))

    is_source = bool(name_parts & SOURCE_KEYWORDS) or any(
        kw in combined for kw in ("return", "retrieve", "output", "result")
    )
    is_sink = bool(name_parts & SINK_KEYWORDS) or any(
        kw in combined for kw in ("external", "outbound", "remote", "third.party")
    )
    is_sensitive = any(
        re.search(pat, combined, re.IGNORECASE) for pat in SENSITIVE_SOURCE_PATTERNS
    )

    return is_source, is_sink, is_sensitive


EXFIL_CANARY = "MCPV_EXFIL_CANARY_7x9k2"


def _try_source_read(session, tool: dict) -> str | None:
    """Attempt to call a source tool and extract text from the response."""
    from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text
    name = tool.get("name", "")
    args = _build_safe_args(tool)
    resp = _call_tool(session, name, args, timeout=10)
    text = _response_text(resp)
    return text if text and len(text) > 5 else None


def _try_sink_send(session, tool: dict, data: str) -> tuple[bool, str]:
    """Attempt to route canary data through a sink tool.

    Returns (sent, response_text). 'sent' is True if the call succeeded
    (any non-None response), indicating the sink is reachable.
    """
    from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text
    name = tool.get("name", "")
    args = _build_safe_args(tool)
    props = tool.get("inputSchema", {}).get("properties", {})

    # Inject canary into the most likely "content" param
    content_params = [
        p for p in props
        if any(kw in p.lower() for kw in (
            "content", "body", "text", "message", "data", "payload",
        ))
    ]
    if content_params:
        args[content_params[0]] = data
    else:
        first_string = next(
            (p for p, d in props.items() if d.get("type") in (None, "string")),
            None,
        )
        if first_string:
            args[first_string] = data

    resp = _call_tool(session, name, args, timeout=10)
    text = _response_text(resp)
    return resp is not None, text or ""


def check_exfil_flow(result: TargetResult, session=None, probe_opts: dict | None = None):
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    with time_check("exfil_flow", result):
        sources = []
        sinks = []
        sensitive_sources = []

        for tool in result.tools:
            is_source, is_sink, is_sensitive = _classify_tool(tool)
            if is_source:
                sources.append(tool)
            if is_sink:
                sinks.append(tool)
            if is_source and is_sensitive:
                sensitive_sources.append(tool)

        if not sinks:
            return

        for sink in sinks:
            sink_name = sink.get("name", "")

            if sensitive_sources:
                real_sensitive = [s for s in sensitive_sources if s.get("name", "") != sink_name]
                if real_sensitive:
                    source_names = [s.get("name", "") for s in real_sensitive]
                    _add(result, 
                        "exfil_flow",
                        "CRITICAL",
                        f"Exfiltration path: sensitive data → '{sink_name}'",
                        f"Sensitive sources: {source_names}. "
                        f"Sink: '{sink_name}' ({sink.get('description', '')[:100]})",
                    )
            elif sources:
                real_sources = [s for s in sources if s.get("name", "") != sink_name]
                if real_sources:
                    source_names = [s.get("name", "") for s in real_sources[:5]]
                    _add(result, 
                        "exfil_flow",
                        "HIGH",
                        f"Data exfiltration path: {len(real_sources)} source(s) → '{sink_name}'",
                        f"Sources: {source_names}. Data read by source tools could be routed through sink.",
                    )

        # Live verification: attempt source→sink canary transfer
        if session and not opts.get("no_invoke") and sources and sinks:
            _log(f"    [dim]    live exfil verification: {len(sources[:3])} source(s) × {len(sinks[:3])} sink(s)[/dim]")
            for source in sources[:3]:
                source_name = source.get("name", "")
                source_text = _try_source_read(session, source)
                if not source_text:
                    continue

                canary = f"{EXFIL_CANARY}:{source_name[:20]}:{source_text[:30]}"
                for sink in sinks[:3]:
                    sink_name = sink.get("name", "")
                    if sink_name == source_name:
                        continue
                    _log(f"    [dim]      {source_name} → {sink_name}[/dim]")
                    sent, resp_text = _try_sink_send(session, sink, canary)
                    if sent:
                        _add(result, 
                            "exfil_flow",
                            "CRITICAL",
                            f"Live exfil confirmed: '{source_name}' → '{sink_name}'",
                            f"Canary data from source successfully routed to sink. "
                            f"Source returned {len(source_text)} chars; sink accepted payload.",
                            evidence=f"Canary: {canary[:80]}\nSink response: {resp_text[:200]}",
                        )
