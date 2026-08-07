"""Cross-tool data exfiltration flow analysis (MCP-T12).

Classifies tools as data sources vs data sinks and flags
source+sink pairs as potential exfiltration paths. When a session
is available, performs live verification: reads from a source tool,
then attempts to send canary data through a sink tool, confirming
reachability of theoretical exfiltration paths.
"""

import re

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol

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
    # The dot is a separator too. MCP tools are conventionally namespaced —
    # every tool on the Camazotz target is — and without it `vault.read_secret`
    # splits to {'vault.read', 'secret'}, the verb never appears, and the tool
    # is not seen as a source at all.
    name_parts = set(re.split(r"[_\-\s.]+", name))

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

# Default grace period for a queued sink callback (CanaryListener.await_hits).
_CALLBACK_WAIT_SECONDS: float = 2.0


def _try_source_read(session: MCPSessionProtocol, tool: dict) -> str | None:
    """Attempt to call a source tool and extract text from the response."""
    from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text
    name = tool.get("name", "")
    args = _build_safe_args(tool)
    resp = _call_tool(session, name, args, timeout=10)
    text = _response_text(resp)
    return text if text and len(text) > 5 else None


def _is_failure(resp: dict | None) -> bool:
    """True when the sink refused the payload.

    `_call_tool` returns the response whenever the JSON-RPC round trip
    completes, so a refusal arrives as a value, not an exception. Treating any
    non-None response as success turned "permission denied" into confirmed
    exfiltration.
    """
    if resp is None:
        return True
    if resp.get("error"):
        return True
    result = resp.get("result")
    return isinstance(result, dict) and bool(result.get("isError"))


def _try_sink_send(session: MCPSessionProtocol, tool: dict, data: str) -> tuple[bool, str]:
    """Attempt to route canary data through a sink tool.

    Returns (accepted, response_text). 'accepted' means the sink took the
    payload without reporting an error — not that the data was observed
    leaving, which needs an out-of-band oracle the scanner does not have.
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
    return not _is_failure(resp), text or ""


def check_exfil_flow(
    result: TargetResult,
    session: MCPSessionProtocol | None = None,
    probe_opts: dict | None = None,
):
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
                        taxonomy_id="MCP-T12",
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
        oast = opts.get("oast")
        callback_wait = float(opts.get("oast_wait", _CALLBACK_WAIT_SECONDS))
        if session and not opts.get("no_invoke") and sources and sinks:
            _log(f"    [dim]    live exfil verification: {len(sources[:3])} source(s) × {len(sinks[:3])} sink(s)[/dim]")
            for source in sources[:3]:
                source_name = source.get("name", "")
                source_text = _try_source_read(session, source)
                if not source_text:
                    continue

                for sink in sinks[:3]:
                    sink_name = sink.get("name", "")
                    if sink_name == source_name:
                        continue
                    _log(f"    [dim]      {source_name} → {sink_name}[/dim]")

                    # A token minted for this one pair. If a request for it ever
                    # arrives, the target reached an address that existed
                    # nowhere else, which no tool response can counterfeit.
                    token = oast.issue() if oast else ""
                    canary = f"{EXFIL_CANARY}:{source_name[:20]}:{source_text[:30]}"
                    if oast:
                        canary = f"{canary} {oast.url_for(token)}"

                    accepted, resp_text = _try_sink_send(session, sink, canary)
                    if not accepted:
                        continue

                    callbacks = (
                        oast.await_hits(token, wait=callback_wait) if oast else []
                    )
                    if callbacks:
                        first = callbacks[0]
                        _add(result,
                            "exfil_flow",
                            "CRITICAL",
                            f"Live exfil confirmed: '{source_name}' → '{sink_name}'",
                            f"The payload routed through the sink carried a URL minted "
                            f"for this pair alone, and the target requested it. Egress is "
                            f"observed out of band, not inferred from the sink's reply: "
                            f"data read by '{source_name}' left the target.",
                            evidence=(
                                f"Callback: {first.method} {first.path} from {first.peer}\n"
                                f"Body: {first.body[:200]}"
                            ),
                        )
                    else:
                        _add(result,
                            "exfil_flow",
                            "CRITICAL",
                            f"Live exfil path: '{source_name}' → '{sink_name}'",
                            f"Sink accepted a payload carrying {len(source_text)} chars "
                            f"read from the source, without reporting an error. "
                            f"Delivery is not observed — no callback was received — so "
                            f"this establishes the path is callable end to end, not that "
                            f"data reached a third party.",
                            evidence=f"Canary: {canary[:80]}\nSink response: {resp_text[:200]}",
                        )
