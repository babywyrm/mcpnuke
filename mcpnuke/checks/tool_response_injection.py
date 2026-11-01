"""Tool response injection: invoke tools and scan what they return for
injection, exfiltration, and cross-tool manipulation."""

import re

from mcpnuke.checks.base import (
    ERROR_REFLECTION_SUFFIX,
    grade_reflection,
    response_is_error,
    time_check,
)
from mcpnuke.checks.tool_probes import (
    _build_extended_args,
    _build_safe_args,
    _call_tool,
    _generate_claude_args,
    _response_text,
    _scan_response_threats,
    _should_invoke,
)
from mcpnuke.core.constants import DEFAULT_CLAUDE_MODEL
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol
from mcpnuke.patterns.probes import (
    CROSS_TOOL_PATTERNS,
    REFLECTION_PAYLOAD,
)


def check_tool_response_injection(
    session: MCPSessionProtocol,
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Call each tool with safe inputs and scan responses for injection / manipulation.

    Also detects input reflection — if a tool echoes user input back in the
    response, it's an indirect injection conduit (attacker-controlled text
    ends up in the LLM context via tool output).
    """
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    with time_check("tool_response_injection", result):
        tool_names = {t["name"].lower() for t in result.tools}
        invokable = [t for t in result.tools if _should_invoke(t, opts)]
        _log(f"    [dim]    scanning {len(invokable)} tools for response injection[/dim]")

        for idx, tool in enumerate(result.tools):
            if not _should_invoke(tool, opts):
                continue
            name = tool.get("name", "")
            _log(f"    [dim]    [{idx+1}/{len(invokable)}] {name}[/dim]")
            # Arg generation tiers:
            # safe_mode → Tier 0: required-only (minimal footprint)
            # --claude  → Tier 2: Claude generates semantically adversarial args
            # default   → Tier 1: heuristic extended args
            if opts.get("safe_mode"):
                args = _build_safe_args(tool)
            elif opts.get("claude"):
                claude_model = opts.get("claude_model", DEFAULT_CLAUDE_MODEL)
                args = _generate_claude_args(tool, session, model=claude_model)
            else:
                args = _build_extended_args(tool)

            resp = _call_tool(session, name, args)
            text = _response_text(resp)
            if not text:
                continue

            # Cache response for reuse by downstream checks (response_credentials)
            cache = opts.setdefault("_response_cache", {})
            cache[name] = text

            threats = _scan_response_threats(text)
            for category, severity, detail in threats:
                result.add(
                    "tool_response_injection",
                    severity,
                    f"Tool '{name}' response: {category}",
                    detail,
                    evidence=text[:500],
                )

            # LLM-augmented classification for responses that regex couldn't classify
            if not threats and opts.get("claude") and len(text) >= 50:
                try:
                    from mcpnuke.core.llm import classify_probe_response
                    classification = classify_probe_response(
                        name, "tool_response",
                        text,
                        model=opts.get("claude_model", DEFAULT_CLAUDE_MODEL),
                        log=opts.get("_log"),
                    )
                    if classification == "malicious":
                        result.add(
                            "tool_response_injection",
                            "HIGH",
                            f"[AI] Tool '{name}' response classified as malicious",
                            "LLM classification detected manipulation that regex missed",
                            evidence=text[:500],
                        )
                except Exception:
                    pass

            # Cross-tool manipulation: does the response tell the LLM to call another tool?
            for pat in CROSS_TOOL_PATTERNS:
                for m in re.finditer(pat, text, re.IGNORECASE):
                    ref = m.group(1).lower()
                    if ref in tool_names and ref != name.lower():
                        result.add(
                            "cross_tool_manipulation",
                            "HIGH",
                            f"Tool '{name}' output directs LLM to invoke '{m.group(1)}'",
                            "Response attempts cross-tool orchestration",
                            evidence=text[:400],
                        )

            # Input reflection — probe string params in the same pass
            props = tool.get("inputSchema", {}).get("properties", {})
            for pname, pdef in props.items():
                if pdef.get("type") not in (None, "string"):
                    continue
                probe_args = {**args, pname: REFLECTION_PAYLOAD}
                refl_resp = _call_tool(session, name, probe_args, timeout=8)
                refl_text = _response_text(refl_resp)
                if refl_text and REFLECTION_PAYLOAD in refl_text:
                    # Subtraction is meaningless here — an echo *is* the finding.
                    # What matters is where it landed: in successful output it
                    # is a conduit into the LLM context, in a rejection it is a
                    # server naming the input it refused.
                    in_error = response_is_error(refl_resp)
                    # Not `severity`: the threat loop above binds that name as
                    # a plain str, and this one is optional.
                    refl_graded = grade_reflection(
                        "HIGH",
                        reflected_in_error=in_error,
                        policy=opts.get("error_reflection", "downgrade"),
                    )
                    if refl_graded:
                        refl_severity, annotate = refl_graded
                        title = f"Tool '{name}' reflects input via param '{pname}'"
                        detail = (
                            "User-controlled text appears verbatim in tool output — "
                            "indirect injection vector: attacker content can reach "
                            "the LLM through this tool's response"
                        )
                        if annotate:
                            title += ERROR_REFLECTION_SUFFIX
                            detail = (
                                "The tool echoed the probe while rejecting the call. "
                                "Naming refused input is normal; this only reaches an "
                                "LLM if the client forwards error text as context."
                            )
                        result.add(
                            "tool_response_injection",
                            refl_severity,
                            title,
                            detail,
                            evidence=f"Sent: {REFLECTION_PAYLOAD}\nReflected in: {refl_text[:300]}",
                        )
                    break
