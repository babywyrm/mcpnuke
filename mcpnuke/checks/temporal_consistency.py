"""Temporal consistency: call the same tool repeatedly and flag
responses that turn malicious after the first calls."""

import re
import time

from mcpnuke.checks.base import (
    time_check,
)
from mcpnuke.checks.tool_probes import (
    _build_safe_args,
    _call_tool,
    _response_text,
    _scan_response_threats,
    _should_invoke,
)
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol
from mcpnuke.patterns.probes import (
    RESPONSE_INJECTION_PATTERNS,
)


def check_temporal_consistency(
    session: MCPSessionProtocol,
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Call the same tool repeatedly and detect behavioral drift or escalation."""
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    with time_check("temporal_consistency", result):
        capped = result.tools[:5]
        invokable = [t for t in capped if _should_invoke(t, opts)]
        _log(f"    [dim]    temporal probing {len(invokable)} tools × 3 calls each[/dim]")
        tool_idx = 0
        for tool in capped:
            if not _should_invoke(tool, opts):
                continue
            tool_idx += 1
            name = tool.get("name", "")
            _log(f"    [dim]    [{tool_idx}/{len(invokable)}] {name}[/dim]")
            args = _build_safe_args(tool)

            responses: list[str] = []
            for _ in range(3):
                resp = _call_tool(session, name, args, timeout=8)
                responses.append(_response_text(resp))
                time.sleep(0.5)

            # Escalating injection: more injection indicators in later responses
            counts = [
                sum(1 for p in RESPONSE_INJECTION_PATTERNS if re.search(p, t, re.IGNORECASE))
                for t in responses
            ]
            if counts[-1] > counts[0] and counts[-1] > 0:
                result.add(
                    "temporal_consistency",
                    "CRITICAL",
                    f"Tool '{name}' shows escalating injection across calls",
                    f"Injection indicator counts per call: {counts}",
                    evidence=responses[-1][:400],
                )

            # Wild response length divergence (same input, very different output)
            lens = [len(r) for r in responses if r]
            if len(lens) >= 2 and min(lens) > 10 and max(lens) > 3 * min(lens):
                result.add(
                    "temporal_consistency",
                    "MEDIUM",
                    f"Tool '{name}' gives wildly inconsistent responses to identical input",
                    f"Response lengths: {lens}",
                )

            # New threats appearing in later calls but not the first
            first_threats = {d for _, _, d in _scan_response_threats(responses[0])} if responses[0] else set()
            for later in responses[1:]:
                if not later:
                    continue
                for cat, sev, detail in _scan_response_threats(later):
                    if detail not in first_threats:
                        result.add(
                            "temporal_consistency",
                            sev,
                            f"Tool '{name}' introduced new threat on subsequent call",
                            f"New: {cat} — {detail}",
                            evidence=later[:300],
                        )
