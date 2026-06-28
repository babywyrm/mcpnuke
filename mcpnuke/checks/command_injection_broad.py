"""MCP-T05: Command injection via tool arguments.

Behavioral check that tests ALL tools with string parameters for command
injection — not just tools with shell-like names (that's shell_injection.py /
MCP-T54). This is the broader class: any tool that processes a string argument
through a system shell, subprocess, or eval path is vulnerable, regardless of
whether its name suggests execution.

The check sends shell metacharacter payloads in string parameters and analyzes
responses for indicators of successful injection (canary markers echoed back,
unexpected command output, error messages revealing shell parsing).

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

# Metacharacter payloads with unique canaries
_CMD_INJECTION_PAYLOADS = [
    {
        "payload": "test; echo MCPNUKE_T05_SEMICOLON",
        "indicator": "MCPNUKE_T05_SEMICOLON",
        "category": "semicolon_chain",
    },
    {
        "payload": "test$(echo MCPNUKE_T05_SUBSHELL)end",
        "indicator": "MCPNUKE_T05_SUBSHELL",
        "category": "subshell_expansion",
    },
    {
        "payload": "test`echo MCPNUKE_T05_BACKTICK`end",
        "indicator": "MCPNUKE_T05_BACKTICK",
        "category": "backtick_expansion",
    },
    {
        "payload": "test | echo MCPNUKE_T05_PIPE",
        "indicator": "MCPNUKE_T05_PIPE",
        "category": "pipe_injection",
    },
    {
        "payload": "test && echo MCPNUKE_T05_AND",
        "indicator": "MCPNUKE_T05_AND",
        "category": "and_chain",
    },
    {
        "payload": "test\necho MCPNUKE_T05_NEWLINE",
        "indicator": "MCPNUKE_T05_NEWLINE",
        "category": "newline_injection",
    },
]

# Error patterns that reveal shell parsing even without successful execution
_SHELL_ERROR_PATTERNS = [
    re.compile(r"sh:\s*\d+:\s*.*not found", re.IGNORECASE),
    re.compile(r"bash:\s*.*command not found", re.IGNORECASE),
    re.compile(r"/bin/sh:.*syntax error", re.IGNORECASE),
    re.compile(r"unexpected\s+token.*\|", re.IGNORECASE),
    re.compile(r"Permission denied.*sh", re.IGNORECASE),
]

# Tools to skip (already covered by shell_injection.py / MCP-T54)
_SKIP_SHELL_TOOLS = frozenset({
    "shell", "exec", "subprocess", "command", "cmd", "invoke",
    "worker", "spawn", "run", "bash", "sh",
})


def _is_shell_named(tool: dict) -> bool:
    """Check if tool is already covered by shell_injection.py."""
    name = tool.get("name", "").lower()
    return any(kw in name for kw in _SKIP_SHELL_TOOLS)


def _get_string_params(tool: dict) -> list[str]:
    """Get all string-typed parameters from a tool schema."""
    props = tool.get("inputSchema", {}).get("properties", {})
    return [
        p for p in props
        if props[p].get("type") in (None, "string")
    ]


def check_command_injection_broad(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Probe all tools for command injection via string params (MCP-T05).

    Unlike shell_injection.py (MCP-T54) which targets shell-named tools,
    this checks ANY tool with string parameters — catching injection in
    tools that don't obviously suggest execution (e.g. search, query,
    filename, path parameters that get passed to a subprocess internally).
    """
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)

    with time_check("command_injection_broad", result):
        # Test tools NOT already covered by shell_injection.py
        targets = [
            t for t in result.tools
            if not _is_shell_named(t)
            and _get_string_params(t)
            and _should_invoke(t, opts)
        ]
        if not targets:
            return

        _log(f"    [dim]    probing {len(targets)} non-shell tools for command injection[/dim]")

        for tool in targets:
            name = tool.get("name", "")
            string_params = _get_string_params(tool)

            for param in string_params[:3]:  # Limit to first 3 string params per tool
                for probe in _CMD_INJECTION_PAYLOADS:
                    args = _build_safe_args(tool)
                    args[param] = probe["payload"]

                    resp = _call_tool(session, name, args)
                    text = _response_text(resp)

                    if not text:
                        continue

                    # Check for canary in response
                    if probe["indicator"] in text:
                        _add(
                            result,
                            "command_injection_broad",
                            "CRITICAL",
                            f"Command injection in '{name}' via param '{param}' ({probe['category']})",
                            (
                                f"Tool '{name}' passes parameter '{param}' through a shell "
                                f"or subprocess without sanitization. The metacharacter payload "
                                f"'{probe['category']}' successfully injected and the canary "
                                f"marker appeared in the response."
                            ),
                            evidence=f"Payload: {probe['payload']}\nResponse: {text[:300]}",
                            taxonomy_id="MCP-T05",
                        )
                        return  # One confirmed injection per tool is sufficient

                    # Check for shell error patterns (weaker signal but still indicates shell parsing)
                    for err_pattern in _SHELL_ERROR_PATTERNS:
                        if err_pattern.search(text):
                            _add(
                                result,
                                "command_injection_broad",
                                "HIGH",
                                f"Shell parsing detected in '{name}' via param '{param}'",
                                (
                                    f"Tool '{name}' appears to pass parameter '{param}' through "
                                    f"a shell — a shell error message was returned in response "
                                    f"to metacharacter input, indicating the parameter reaches "
                                    f"a command interpreter even if injection didn't fully succeed."
                                ),
                                evidence=f"Payload: {probe['payload']}\nResponse: {text[:300]}",
                                taxonomy_id="MCP-T05",
                            )
                            return
