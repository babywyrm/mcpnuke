"""Helpers for tagging findings with agentic-identity lane + transport.

Each check module that maps cleanly onto a single lane uses ``lane_tagged()``
to get a ``result.add`` wrapper that auto-fills ``lane=`` and ``transport=``
for every emission. This keeps the per-finding tagging out of the call sites
and centralizes the lane vocabulary in one place.

Usage:

    # at module top
    from mcpnuke.checks._lane_helpers import lane_tagged
    _add = lane_tagged(lane=2, transport="A")

    # inside a check function
    _add(result, "prompt_injection", "HIGH", "...", evidence=...)

The wrapper preserves all positional + keyword args of TargetResult.add(),
so existing call sites just substitute ``result.add(`` → ``_add(result, ``.

Vocabulary: see camazotz/frontend/lane_taxonomy.py::LANES (schema v1) +
agentic-sec/docs/identity-flows.md.
"""

from __future__ import annotations

from typing import Callable

from mcpnuke.core.models import Finding, TargetResult


def lane_tagged(lane: int, transport: str = "A") -> Callable[..., Finding | None]:
    """Return a ``result.add`` wrapper that pre-fills lane + transport kwargs.

    Per-call kwargs win — passing an explicit ``lane=`` or ``transport=`` to
    the returned function overrides the defaults set here.
    """
    def _add(result: TargetResult, *args, **kwargs) -> Finding | None:
        kwargs.setdefault("lane", lane)
        kwargs.setdefault("transport", transport)
        return result.add(*args, **kwargs)
    return _add
