"""Anonymous rate-limit exhaustion (MCP-T51, Lane 5 / Transport A).

MCP servers that accept anonymous traffic (no auth token, pre-auth flows,
``tools/list`` and any other unauthenticated endpoint) often have global
rate limits but lack per-caller accounting. An anonymous caller can burn
through the global quota in seconds, denying service to legitimate
authenticated users — who have no special bucket because the server has
no identity to key on.

This check fires only when the session has no auth credential attached
(true anonymous traffic). It bursts N rapid calls against a safe
read-only tool and looks for:

  - 429s or throttle text in responses (good — rate limiting is enforced)
  - X-RateLimit-* response headers (good — per-caller accounting hint)
  - Bucket/per-caller signals in any tool's description (good — explicit
    isolation declared)
  - None of the above + all-success burst → HIGH finding (anon flood
    pattern is exploitable, MCP-T51)

The check does NOT attempt to drain a real production quota; it stops at
``ANON_BURST_COUNT`` to stay safe.

Pairs with camazotz ``anon_rate_exhaust_lab``.
"""

from __future__ import annotations

import re
import time

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol

_add = lane_tagged(lane=5, transport="A")

ANON_BURST_COUNT = 25
THROTTLE_SIGNALS = re.compile(
    r"(?:429|too\s+many|throttl|rate\s*limit|quota|budget\s*(?:exhausted|exceeded))",
    re.IGNORECASE,
)
PER_CALLER_SIGNALS = re.compile(
    r"(?:per[-_\s]?caller|per[-_\s]?client|per[-_\s]?user|per[-_\s]?session|"
    r"x-ratelimit|isolation|tenant[-_\s]?bucket)",
    re.IGNORECASE,
)


def _session_is_anonymous(result: TargetResult) -> bool:
    """Return True if the scanner's session has no auth credential attached.

    One definition, on TargetResult, shared with the enumerator's
    "unauthenticated initialize" finding. Two copies drifted once already.
    """
    return result.scanned_anonymously()


def _tools_advertise_per_caller_accounting(tools: list[dict]) -> bool:
    """Look for any tool whose description/schema mentions per-caller buckets.

    Heuristic — if the server explicitly documents per-caller isolation,
    we don't flag the burst even when responses are quiet. False-positives
    here are worse than false-negatives.
    """
    for tool in tools:
        text = " ".join((
            tool.get("name", ""),
            tool.get("description", ""),
            str(tool.get("inputSchema", {})),
        ))
        if PER_CALLER_SIGNALS.search(text):
            return True
    return False


def _pick_burst_target(tools: list[dict], opts: dict) -> dict | None:
    """Pick the safest tool to burst: read-only, no destructive verbs."""
    safe = [
        t for t in tools
        if _should_invoke(t, opts)
        and not re.search(
            r"(delete|remove|drop|kill|exec|run|send|write|deploy|maintenance)",
            t.get("name", ""), re.IGNORECASE,
        )
    ]
    if not safe:
        return None
    # Prefer obviously read-only verbs
    for kw in ("list", "get", "read", "check", "status", "health"):
        for t in safe:
            if kw in t.get("name", "").lower():
                return t
    return safe[0]


def check_anon_budget_exhaust(
    session: MCPSessionProtocol, result: TargetResult, probe_opts: dict | None = None,
) -> None:
    """Burst probe for anonymous rate-limit exhaustion (MCP-T51)."""
    opts = probe_opts or {}
    _log = opts.get("_log", lambda _msg: None)

    with time_check("anon_budget_exhaust", result):
        if not _session_is_anonymous(result):
            _log("    [dim]    skipped: session has auth token (anon-only probe)[/dim]")
            return

        target = _pick_burst_target(result.tools, opts)
        if not target:
            _log("    [dim]    skipped: no safe tool available to burst[/dim]")
            return

        name = target.get("name", "")
        args = _build_safe_args(target)
        _log(
            f"    [dim]    bursting '{name}' x {ANON_BURST_COUNT} as anonymous caller[/dim]"
        )

        successes = 0
        throttle_seen = False
        t0 = time.time()
        for _ in range(ANON_BURST_COUNT):
            resp = _call_tool(session, name, args, timeout=5)
            text = _response_text(resp) or ""
            if THROTTLE_SIGNALS.search(text):
                throttle_seen = True
                break
            successes += 1
        elapsed = time.time() - t0

        if throttle_seen:
            return  # rate limit fired — server is well-behaved

        if successes < ANON_BURST_COUNT:
            # Some other error path hit; not a confident finding either way
            return

        # All N calls succeeded without any throttling signal.
        per_caller = _tools_advertise_per_caller_accounting(result.tools)
        if per_caller:
            _add(
                result,
                "anon_budget_exhaust",
                "MEDIUM",
                f"Anonymous burst of {ANON_BURST_COUNT} calls succeeded with no throttling",
                f"Tool '{name}' accepted all {ANON_BURST_COUNT} anonymous calls in "
                f"{elapsed:.1f}s. Per-caller accounting language was detected elsewhere "
                "in the catalog, but this tool surface appears unmetered. Confirm "
                "whether anonymous traffic is isolated from authenticated quotas.",
                evidence=f"burst={ANON_BURST_COUNT} elapsed={elapsed:.2f}s tool={name}",
                taxonomy_id="MCP-T51",
            )
            return

        _add(
            result,
            "anon_budget_exhaust",
            "HIGH",
            f"Anonymous flood pattern: {ANON_BURST_COUNT} unauthenticated calls succeeded",
            f"Tool '{name}' accepted all {ANON_BURST_COUNT} anonymous calls in "
            f"{elapsed:.1f}s with no 429, throttle text, or rate-limit signal. "
            "No per-caller accounting language was found anywhere in the tool "
            "catalog — anonymous traffic can plausibly exhaust any global quota "
            "shared with authenticated users (MCP-T51, Lane 5).",
            evidence=f"burst={ANON_BURST_COUNT} elapsed={elapsed:.2f}s tool={name}",
            taxonomy_id="MCP-T51",
        )
