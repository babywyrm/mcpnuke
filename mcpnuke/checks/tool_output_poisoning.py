"""MCP-T02: Tool output poisoning (indirect prompt injection).

Static + behavioral check that detects tools whose responses contain embedded
instructions that could manipulate a downstream agent. This is the MCP-specific
variant of indirect prompt injection — the tool's *output* (not input) carries
the payload.

If an MCP tool's response contains instruction-like content (override commands,
role markers, system prompts), any agent that reads that response as context is
vulnerable to having its behavior overridden.

Lane 2 (Delegated) / Transport A (MCP JSON-RPC).

---

MCP-T03: Credential forwarding in tool calls.

Static check that detects tools whose schema accepts credential-like parameters
(tokens, keys, passwords, secrets) that could be forwarded to attacker-controlled
endpoints. If a tool takes a `token` or `api_key` parameter AND also accepts a
`url` or `endpoint` parameter, an attacker can redirect credentials to their own
server.

Lane 2 (Delegated) / Transport A (MCP JSON-RPC).
"""

from __future__ import annotations

import re

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import (
    _build_safe_args,
    _call_tool,
    _response_text,
    _should_invoke,
)
from mcpnuke.core.models import TargetResult

_add = lane_tagged(lane=2, transport="A")

# ── MCP-T02: Tool output poisoning ───────────────────────────────────────────

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]", re.IGNORECASE),
    re.compile(r"system:\s*you\s+(are|must|should)", re.IGNORECASE),
    re.compile(r"from\s+now\s+on,?\s+(always|never|do\s+not)", re.IGNORECASE),
    re.compile(r"(override|bypass|disable)\s+(safety|security|filter)", re.IGNORECASE),
]


def check_tool_output_poisoning(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Detect instruction-injection patterns in tool responses (MCP-T02).

    Invokes tools with benign inputs and scans responses for embedded
    instructions that could manipulate a downstream agent consuming the output.
    """
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)

    with time_check("tool_output_poisoning", result):
        targets = [t for t in result.tools if _should_invoke(t, opts)]
        if not targets:
            return

        _log(f"    [dim]    scanning {len(targets)} tool outputs for injection patterns[/dim]")

        for tool in targets:
            name = tool.get("name", "")
            args = _build_safe_args(tool)
            resp = _call_tool(session, name, args)
            text = _response_text(resp)

            if not text:
                continue

            for pattern in _INJECTION_PATTERNS:
                match = pattern.search(text)
                if match:
                    _add(
                        result,
                        "tool_output_poisoning",
                        "HIGH",
                        f"Tool output contains injection pattern: '{name}' ({pattern.pattern[:40]})",
                        f"Tool '{name}' returned output containing an instruction-injection pattern (matched: '{match.group()}'). Indirect prompt injection via tool output poisoning.",
                        evidence=text[:500],
                        taxonomy_id="MCP-T02",
                    )
                    break  # One finding per tool


# ── MCP-T03: Credential forwarding ───────────────────────────────────────────

_CREDENTIAL_PARAM_KEYWORDS = frozenset({
    "token", "api_key", "apikey", "key", "secret", "password", "credential",
    "auth", "bearer", "access_token", "refresh_token", "jwt", "session",
})

_ENDPOINT_PARAM_KEYWORDS = frozenset({
    "url", "endpoint", "host", "server", "target", "destination", "webhook",
    "callback", "redirect", "forward", "proxy",
})


def check_credential_forwarding(
    result: TargetResult,
) -> None:
    """Detect tools that accept both credentials and endpoints (MCP-T03).

    A tool that takes a credential parameter (token, key, secret) AND an
    endpoint parameter (url, host, webhook) can be abused to forward
    credentials to an attacker-controlled server.
    """

    with time_check("credential_forwarding", result):
        for tool in result.tools:
            name = tool.get("name", "")
            props = tool.get("inputSchema", {}).get("properties", {})
            param_names = set(p.lower() for p in props)

            cred_params = [
                p for p in props
                if any(kw in p.lower() for kw in _CREDENTIAL_PARAM_KEYWORDS)
            ]
            endpoint_params = [
                p for p in props
                if any(kw in p.lower() for kw in _ENDPOINT_PARAM_KEYWORDS)
            ]

            if cred_params and endpoint_params:
                severity = "CRITICAL"
                _add(
                    result,
                    "credential_forwarding",
                    severity,
                    f"Credential forwarding risk: '{name}' accepts credentials ({', '.join(cred_params)}) AND endpoints ({', '.join(endpoint_params)})",
                    f"Tool '{name}' accepts both credential and endpoint parameters, enabling credential theft by design.",
                    taxonomy_id="MCP-T03",
                )
            elif cred_params and not endpoint_params:
                # Tool takes credentials but has no attacker-controlled endpoint.
                # Still worth noting if the tool's description mentions external calls.
                desc = tool.get("description", "").lower()
                if any(w in desc for w in ("fetch", "send", "post", "forward", "webhook", "http")):
                    _add(
                        result,
                        "credential_forwarding",
                        "HIGH",
                        f"Credential parameter in externally-calling tool: '{name}' ({', '.join(cred_params)})",
                        f"Tool '{name}' accepts credential parameters and makes external calls — credential exposure risk.",
                        taxonomy_id="MCP-T03",
                    )
