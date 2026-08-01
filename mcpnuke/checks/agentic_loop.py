"""MCP-T10: Agentic loop exploitation / resource exhaustion.

Static + behavioral check that detects tools capable of triggering unbounded
recursive invocations, self-referential calls, or resource exhaustion via
fan-out patterns.

Attack patterns detected:
1. Tools that accept tool-name/function-name parameters (can invoke arbitrary
   other tools, enabling recursive chains)
2. Tools whose descriptions suggest they invoke other tools or trigger
   additional actions (orchestration tools without depth limits)
3. Tools that accept count/repeat/batch parameters without bounds (fan-out)
4. Behavioral: tools whose responses contain tool-call-like JSON patterns
   that could trigger an agent to recurse

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

# Parameter names suggesting tool/function invocation (meta-tools)
_META_TOOL_PARAMS = frozenset({
    "tool_name", "function_name", "tool", "function", "action",
    "method", "operation", "task_name", "invoke", "call",
    "target_tool", "next_tool", "chain", "pipeline",
})

# Parameter names suggesting unbounded repetition
_REPEAT_PARAMS = frozenset({
    "count", "repeat", "iterations", "batch_size", "num_requests",
    "concurrency", "parallel", "fan_out", "max_retries",
})

# Description keywords suggesting orchestration/recursion
_ORCHESTRATION_KEYWORDS = frozenset({
    "invoke", "call another", "trigger", "chain", "pipeline",
    "orchestrate", "delegate", "fan-out", "recursive",
    "schedule", "dispatch", "forward to", "route to",
})

# Patterns in tool output that look like tool-call instructions
_TOOL_CALL_PATTERNS = [
    re.compile(r'"tool_call":\s*\{', re.IGNORECASE),
    re.compile(r'"function_call":\s*\{', re.IGNORECASE),
    re.compile(r'"name":\s*"[a-z_]+".*"arguments":\s*\{', re.IGNORECASE),
    re.compile(r'<tool_call>|<function_call>', re.IGNORECASE),
    re.compile(r'\{"tool":\s*"[a-z_]+"', re.IGNORECASE),
]


def check_agentic_loop(
    result: TargetResult,
) -> None:
    """Detect tools that enable recursive invocation or resource exhaustion (MCP-T10).

    Static analysis of tool schemas for patterns that could allow an attacker
    to trigger unbounded tool chains, recursive invocations, or resource
    exhaustion via fan-out.
    """
    with time_check("agentic_loop", result):
        for tool in result.tools:
            name = tool.get("name", "")
            desc = (tool.get("description", "") or "").lower()
            props = tool.get("inputSchema", {}).get("properties", {})

            # Check 1: tool accepts a tool-name/function-name parameter
            meta_params = [p for p in props if p.lower() in _META_TOOL_PARAMS]
            if meta_params:
                _add(
                    result,
                    "agentic_loop",
                    "HIGH",
                    f"Meta-tool '{name}' accepts tool/function name parameter ({', '.join(meta_params)})",
                    (
                        f"Tool '{name}' accepts parameters that specify which tool or function "
                        f"to invoke ({', '.join(meta_params)}). An attacker can use this to "
                        f"trigger arbitrary tool chains or recursive invocations without "
                        f"depth limits."
                    ),
                    taxonomy_id="MCP-T10",
                )

            # Check 2: unbounded repetition parameters without maxValue
            repeat_params = [p for p in props if p.lower() in _REPEAT_PARAMS]
            for rp in repeat_params:
                schema = props[rp]
                has_max = "maximum" in schema or "maxValue" in schema
                if not has_max:
                    _add(
                        result,
                        "agentic_loop",
                        "MEDIUM",
                        f"Unbounded repetition in '{name}' via param '{rp}'",
                        (
                            f"Tool '{name}' accepts a repetition parameter '{rp}' without "
                            f"a maximum constraint. An attacker can set this to a very large "
                            f"number to exhaust resources (CPU, memory, API calls, tokens)."
                        ),
                        taxonomy_id="MCP-T10",
                    )

            # Check 3: description suggests orchestration (only if no stronger signal)
            if any(kw in desc for kw in _ORCHESTRATION_KEYWORDS) and not meta_params:
                _add(
                    result,
                    "agentic_loop",
                    "LOW",
                    f"Orchestration tool '{name}' may enable recursive chains",
                    (
                        f"Tool '{name}' description suggests it invokes or delegates to "
                        f"other tools/services. Without explicit depth limits, this "
                        f"creates a recursive invocation surface."
                    ),
                    taxonomy_id="MCP-T10",
                )


def check_agentic_loop_behavioral(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Behavioral: detect tool-call patterns in responses (MCP-T10).

    Invokes tools and checks whether responses contain JSON structures that
    look like tool-call instructions — which could cause an agent to recurse.
    """
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)

    with time_check("agentic_loop_behavioral", result):
        targets = [t for t in result.tools if _should_invoke(t, opts)]
        if not targets:
            return

        for tool in targets[:5]:  # Limit to 5 tools max
            name = tool.get("name", "")
            args = _build_safe_args(tool)
            resp = _call_tool(session, name, args)
            text = _response_text(resp)

            if not text:
                continue

            for pattern in _TOOL_CALL_PATTERNS:
                if pattern.search(text):
                    _add(
                        result,
                        "agentic_loop_behavioral",
                        "HIGH",
                        f"Tool '{name}' response contains tool-call pattern",
                        (
                            f"Tool '{name}' returned output containing a structure that "
                            f"resembles a tool-call instruction. If a downstream agent "
                            f"parses this response as actionable, it could trigger "
                            f"recursive invocations or unintended tool chains."
                        ),
                        evidence=text[:300],
                        taxonomy_id="MCP-T10",
                    )
                    break
