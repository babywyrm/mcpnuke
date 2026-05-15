"""Transport D shell injection probes.

Behavioral check that actively tests subprocess-wrapping tools for shell
command injection vulnerabilities.  Targets tools whose names or parameter
names suggest shell/subprocess execution (shellwrap, subprocess, exec, cmd).

Sends shell metacharacter payloads and analyzes responses for evidence of
successful injection (unexpected output, exit code 0 with metacharacters,
injected command output echoed back).

Lane 3 (Machine Identity) / Transport D (Subprocess).
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

_add = lane_tagged(lane=3, transport="D")

_SHELL_TOOL_KEYWORDS = frozenset({
    "shell", "exec", "subprocess", "command", "cmd", "invoke",
    "worker", "spawn", "run", "bash", "sh", "wrap",
})

_SHELL_PARAM_KEYWORDS = frozenset({
    "command", "cmd", "args", "extra_args", "base_cmd",
    "shell", "exec", "script", "operation",
})

_INJECTION_PAYLOADS = [
    {
        "payload": "; echo MCPNUKE_SHELL_INJECTED",
        "indicator": "MCPNUKE_SHELL_INJECTED",
        "category": "semicolon_chain",
    },
    {
        "payload": "$(echo MCPNUKE_SUBSHELL_INJECTED)",
        "indicator": "MCPNUKE_SUBSHELL_INJECTED",
        "category": "subshell_expansion",
    },
    {
        "payload": "`echo MCPNUKE_BACKTICK_INJECTED`",
        "indicator": "MCPNUKE_BACKTICK_INJECTED",
        "category": "backtick_expansion",
    },
    {
        "payload": "| echo MCPNUKE_PIPE_INJECTED",
        "indicator": "MCPNUKE_PIPE_INJECTED",
        "category": "pipe_chain",
    },
    {
        "payload": "&& echo MCPNUKE_AND_INJECTED",
        "indicator": "MCPNUKE_AND_INJECTED",
        "category": "and_chain",
    },
]

_DANGEROUS_BASE_PAYLOADS = [
    {
        "base_cmd": "bash -c id",
        "indicator_pattern": r"uid=\d+",
        "category": "dangerous_base_bash",
    },
    {
        "base_cmd": "sh -c 'echo MCPNUKE_SH_EXEC'",
        "indicator_pattern": r"MCPNUKE_SH_EXEC",
        "category": "dangerous_base_sh",
    },
]


def _is_shell_tool(tool: dict) -> bool:
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    combined = f"{name} {desc}"
    return any(kw in combined for kw in _SHELL_TOOL_KEYWORDS)


def _find_injectable_params(tool: dict) -> list[str]:
    props = tool.get("inputSchema", {}).get("properties", {})
    return [
        p for p in props
        if any(kw in p.lower() for kw in _SHELL_PARAM_KEYWORDS)
        and props[p].get("type") in (None, "string")
    ]


def check_shell_injection(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Probe subprocess-wrapping tools for shell command injection."""
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)

    with time_check("shell_injection", result):
        targets = [
            t for t in result.tools
            if _is_shell_tool(t) and _should_invoke(t, opts)
        ]
        if not targets:
            return

        _log(f"    [dim]    testing {len(targets)} shell-related tools for injection[/dim]")

        for tool in targets:
            name = tool.get("name", "")
            injectable = _find_injectable_params(tool)
            if not injectable:
                continue

            base_args = _build_safe_args(tool)

            for param in injectable:
                for payload_info in _INJECTION_PAYLOADS:
                    test_args = {**base_args, param: payload_info["payload"]}
                    resp = _call_tool(session, name, test_args, timeout=10)
                    text = _response_text(resp)
                    if not text:
                        continue

                    if payload_info["indicator"] in text:
                        _add(
                            result,
                            "shell_injection",
                            "CRITICAL",
                            f"Shell injection via '{name}' param '{param}'",
                            f"Category: {payload_info['category']} — "
                            f"injected command output found in response",
                            evidence=(
                                f"Payload: {payload_info['payload']}\n"
                                f"Response: {text[:300]}"
                            ),
                        )
                        break

            _probe_dangerous_base(session, result, tool, base_args, _log)


def _probe_dangerous_base(
    session,
    result: TargetResult,
    tool: dict,
    base_args: dict,
    _log,
) -> None:
    """Test if the tool allows dangerous base commands (bash, sh)."""
    props = tool.get("inputSchema", {}).get("properties", {})
    base_param = None
    for p in props:
        if p.lower() in ("base_cmd", "command", "cmd", "base_command"):
            base_param = p
            break
    if not base_param:
        return

    name = tool.get("name", "")
    for probe in _DANGEROUS_BASE_PAYLOADS:
        test_args = {**base_args, base_param: probe["base_cmd"]}
        resp = _call_tool(session, name, test_args, timeout=10)
        text = _response_text(resp)
        if not text:
            continue

        if re.search(probe["indicator_pattern"], text):
            denied_indicators = ("denied", "not allowed", "blocked", "forbidden", "allowlist")
            if any(ind in text.lower() for ind in denied_indicators):
                continue

            _add(
                result,
                "shell_injection",
                "HIGH",
                f"Dangerous base command accepted by '{name}'",
                f"Category: {probe['category']} — {probe['base_cmd']} executed successfully",
                evidence=f"Command: {probe['base_cmd']}\nResponse: {text[:300]}",
            )
