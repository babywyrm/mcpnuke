"""Cross-tool data exfiltration flow analysis (MCP-T12).

Classifies tools as data sources vs data sinks and flags
source+sink pairs as potential exfiltration paths.
"""

import re

from mcpredator.core.models import TargetResult
from mcpredator.checks.base import time_check

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


def check_exfil_flow(result: TargetResult):
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
                source_names = [s.get("name", "") for s in sensitive_sources]
                result.add(
                    "exfil_flow",
                    "CRITICAL",
                    f"Exfiltration path: sensitive data → '{sink_name}'",
                    f"Sensitive sources: {source_names}. "
                    f"Sink: '{sink_name}' ({sink.get('description', '')[:100]})",
                )
            elif sources:
                source_names = [s.get("name", "") for s in sources[:5]]
                result.add(
                    "exfil_flow",
                    "HIGH",
                    f"Data exfiltration path: {len(sources)} source(s) → '{sink_name}'",
                    f"Sources: {source_names}. Data read by source tools could be routed through sink.",
                )
