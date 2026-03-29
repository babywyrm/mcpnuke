"""Rate limiting and abuse resistance checks."""

import re
import time

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke
from mcpnuke.patterns.rules import RATE_LIMIT_PATTERNS

RAPID_BURST_COUNT = 10
RAPID_BURST_WINDOW = 2.0


def check_rate_limit(result: TargetResult):
    """Flag tools that suggest no rate limiting or unbounded invocations (static)."""
    with time_check("rate_limit", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + str(tool.get("inputSchema", {}))
            )

            for pat in RATE_LIMIT_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    result.add(
                        "rate_limit",
                        "MEDIUM",
                        f"Rate limit concern in tool '{name}'",
                        f"Pattern suggests unbounded or unthrottled usage: {pat}",
                        evidence=combined[:300],
                    )
                    break


def check_behavioral_rate_limit(
    session, result: TargetResult, probe_opts: dict | None = None,
):
    """Behavioral rate limit test: rapid-fire calls to detect missing throttling.

    Picks a safe, low-side-effect tool and fires RAPID_BURST_COUNT calls in
    quick succession. If all succeed without 429/throttle errors, flags it.
    """
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    with time_check("behavioral_rate_limit", result):
        safe_tools = [
            t for t in result.tools
            if _should_invoke(t, opts) and not re.search(
                r"(delete|remove|drop|kill|exec|run|send|write|deploy|maintenance)",
                t.get("name", ""), re.IGNORECASE,
            )
        ]
        if not safe_tools:
            return

        target = safe_tools[0]
        name = target.get("name", "")
        args = _build_safe_args(target)
        _log(f"    [dim]    burst-testing '{name}' with {RAPID_BURST_COUNT} rapid calls[/dim]")

        successes = 0
        t0 = time.time()
        for _ in range(RAPID_BURST_COUNT):
            resp = _call_tool(session, name, args, timeout=5)
            text = _response_text(resp)
            if text and "rate" not in (text or "").lower() and "throttl" not in (text or "").lower():
                successes += 1
        elapsed = time.time() - t0

        if successes >= RAPID_BURST_COUNT and elapsed < RAPID_BURST_WINDOW * 3:
            result.add(
                "behavioral_rate_limit",
                "MEDIUM",
                f"No rate limiting: {successes}/{RAPID_BURST_COUNT} rapid calls succeeded in {elapsed:.1f}s",
                f"Tool '{name}' accepted all burst calls with no throttling or 429 response",
            )
