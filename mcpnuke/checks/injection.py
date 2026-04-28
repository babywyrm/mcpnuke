"""Prompt injection, tool poisoning, indirect injection, active injection checks."""

import re

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke
from mcpnuke.patterns.rules import (
    INJECTION_PATTERNS,
    POISON_PATTERNS,
)
from mcpnuke.patterns.probes import (
    ACTIVE_INJECTION_PAYLOADS,
    SYSTEM_PROMPT_INDICATORS,
    CONTENT_TOOL_KEYWORDS,
    CONTENT_PARAM_KEYWORDS,
    INDIRECT_INJECTION_PROBES,
)

from mcpnuke.checks._lane_helpers import lane_tagged

# All findings in this module are scoped to Lane 2 / Transport "A"
# (2026-04-26 by-lane reporting spec).
_add = lane_tagged(lane=2, transport="A")


def check_prompt_injection(result: TargetResult):
    with time_check("prompt_injection", result):

        def _scan(text: str, location: str):
            for pat in INJECTION_PATTERNS:
                if re.search(pat, text, re.IGNORECASE):
                    _add(result, 
                        "prompt_injection",
                        "CRITICAL",
                        "Prompt injection payload detected",
                        f"Location: {location}",
                        evidence=f"Pattern: {pat}\nText: {text[:300]}",
                    )
                    return

        for tool in result.tools:
            name = tool.get("name", "")
            _scan(tool.get("description", ""), f"tool description: '{name}'")
            _scan(name, f"tool name: '{name}'")
            for prop, pdef in (
                tool.get("inputSchema", {}).get("properties", {}).items()
            ):
                _scan(
                    pdef.get("description", ""),
                    f"tool '{name}' param '{prop}'",
                )

        for r in result.resources:
            _scan(
                r.get("description", ""),
                f"resource '{r.get('uri','')}'",
            )
            _scan(r.get("name", ""), f"resource name '{r.get('uri','')}'")

        for p in result.prompts:
            _scan(
                p.get("description", ""),
                f"prompt '{p.get('name','')}'",
            )
            _scan(p.get("name", ""), "prompt name")


def check_tool_poisoning(result: TargetResult):
    with time_check("tool_poisoning", result):
        for tool in result.tools:
            name = tool.get("name", "")
            full = tool.get("description", "") + " " + str(
                tool.get("inputSchema", {})
            )

            for pat in POISON_PATTERNS:
                if re.search(pat, full, re.IGNORECASE | re.DOTALL):
                    _add(result, 
                        "tool_poisoning",
                        "CRITICAL",
                        f"Tool poisoning indicator in '{name}'",
                        f"Pattern: {pat}",
                        evidence=full[:400],
                    )
                    break

            for ch in tool.get("description", ""):
                if ord(ch) in range(0x200B, 0x2010) or ord(ch) == 0xFEFF:
                    _add(result, 
                        "tool_poisoning",
                        "CRITICAL",
                        f"Invisible Unicode in tool '{name}'",
                        "Possible hidden instructions via Unicode steganography",
                        evidence=repr(tool["description"][:200]),
                    )
                    break


def check_indirect_injection(session, result: TargetResult, probe_opts: dict | None = None):
    with time_check("indirect_injection", result):
        # Phase 1: scan resource contents (original behavior)
        for resource in result.resources:
            uri = resource.get("uri", "")
            try:
                resp = session.call(
                    "resources/read", {"uri": uri}, timeout=15
                )
                if not resp or "result" not in resp:
                    continue
                for content in resp["result"].get("contents", []):
                    text = content.get("text", "") or content.get("blob", "")
                    if not text:
                        continue
                    for pat in INJECTION_PATTERNS + POISON_PATTERNS:
                        if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                            _add(result, 
                                "indirect_injection",
                                "CRITICAL",
                                f"Indirect prompt injection in resource '{uri}'",
                                f"Pattern: {pat}",
                                evidence=text[:400],
                            )
                            break
                    for u in re.findall(r"https?://[^\s'\"<>]+", text):
                        if any(
                            kw in u
                            for kw in [
                                "webhook",
                                "ngrok",
                                "burp",
                                "requestbin",
                                "pipedream",
                                "canarytokens",
                                "interactsh",
                            ]
                        ):
                            _add(result, 
                                "indirect_injection",
                                "HIGH",
                                f"Exfiltration URL in resource '{uri}'",
                                evidence=u,
                            )
            except Exception:
                pass

        # Phase 2: probe content-processing tools with embedded injection
        for tool in result.tools:
            if not _should_invoke(tool, probe_opts or {}):
                continue
            name = tool.get("name", "").lower()
            desc = tool.get("description", "").lower()
            if not any(kw in name or kw in desc for kw in CONTENT_TOOL_KEYWORDS):
                continue

            props = tool.get("inputSchema", {}).get("properties", {})
            content_params = [
                p for p in props
                if any(kw in p.lower() for kw in CONTENT_PARAM_KEYWORDS)
                and props[p].get("type") in (None, "string")
            ]
            if not content_params:
                continue

            base_args = _build_safe_args(tool)

            for target_param in content_params:
                for probe in INDIRECT_INJECTION_PROBES:
                    test_args = {**base_args, target_param: probe}
                    resp = _call_tool(session, tool["name"], test_args, timeout=8)
                    text = _response_text(resp)
                    if not text:
                        continue

                    for pat in INJECTION_PATTERNS + POISON_PATTERNS:
                        if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                            _add(result, 
                                "indirect_injection",
                                "CRITICAL",
                                f"Indirect injection via content tool '{tool['name']}'",
                                f"Probe in param '{target_param}' triggered injection in response",
                                evidence=f"Probe: {probe[:80]}\nResponse: {text[:300]}",
                            )
                            break

                    if "INDIRECT_CONFIRMED" in text:
                        _add(result, 
                            "indirect_injection",
                            "CRITICAL",
                            f"Indirect injection: tool '{tool['name']}' follows embedded instructions",
                            f"Content-processing tool executed injected instruction via '{target_param}'",
                            evidence=f"Probe: {probe[:80]}\nResponse: {text[:300]}",
                        )
                        break


def check_active_prompt_injection(session, result: TargetResult, probe_opts: dict | None = None):
    """Send injection payloads as tool inputs and confirm the server follows them.

    Goes beyond static prompt_injection (metadata-only) by actively testing whether
    injection payloads sent through tool parameters cause the server to follow
    injected instructions, leak system prompts, or accept role overrides.
    """
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    with time_check("active_prompt_injection", result):
        invokable = [t for t in result.tools if _should_invoke(t, opts)]
        _log(f"    [dim]    testing {len(invokable)} tools for active prompt injection[/dim]")

        for idx, tool in enumerate(invokable):
            name = tool.get("name", "")
            props = tool.get("inputSchema", {}).get("properties", {})
            string_params = [
                p for p, d in props.items() if d.get("type") in (None, "string")
            ]
            if not string_params:
                continue

            _log(f"    [dim]    [{idx + 1}/{len(invokable)}] {name}[/dim]")
            target_param = string_params[0]
            base_args = _build_safe_args(tool)
            found = False

            for payload_info in ACTIVE_INJECTION_PAYLOADS:
                test_args = {**base_args, target_param: payload_info["payload"]}
                resp = _call_tool(session, name, test_args, timeout=8)
                text = _response_text(resp)
                if not text:
                    continue

                indicator = payload_info.get("indicator")
                if indicator and indicator in text:
                    _add(result, 
                        "active_prompt_injection",
                        "CRITICAL",
                        f"Active injection: server follows injected instructions via '{name}'",
                        f"Category: {payload_info['category']}, param: {target_param}",
                        evidence=f"Sent: {payload_info['payload'][:120]}\nGot: {text[:300]}",
                    )
                    found = True
                    break

                if payload_info["category"] in ("system_prompt_leak", "constraint_bypass"):
                    for pat in SYSTEM_PROMPT_INDICATORS:
                        if re.search(pat, text, re.IGNORECASE):
                            _add(result, 
                                "active_prompt_injection",
                                "CRITICAL",
                                f"System prompt leak via active injection in '{name}'",
                                f"Category: {payload_info['category']}, param: {target_param}",
                                evidence=f"Sent: {payload_info['payload'][:120]}\nGot: {text[:300]}",
                            )
                            found = True
                            break
                    if found:
                        break
