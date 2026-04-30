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

Lane vocabulary
---------------

Lane is one of 1–5 (Human Direct, Delegated, Machine, Agent-Chain,
Anonymous). See ``camazotz/frontend/lane_taxonomy.py::LANES`` (schema v1)
and ``agentic-sec/docs/identity-flows.md`` for the canonical definitions.

Transport vocabulary
--------------------

Transport is one of five string codes, defined in
``camazotz/frontend/lane_taxonomy.py::TRANSPORT_DEFINITIONS``:

    A   MCP JSON-RPC                            (the common case)
    B   Direct wire API (REST / gRPC / GraphQL) (non-MCP wire)
    C   In-process SDK / library                (no process boundary)
    D   Subprocess / native binary              (added 2026-04-28)
    E   Native LLM function-calling (non-MCP)   (added 2026-04-28)

Default ``transport="A"`` is correct for the majority of mcpnuke checks
that probe the MCP wire directly. Override per-call when a check
specifically targets one of the other transports (e.g. a check that
inspects an upstream Direct API would use ``transport="B"``).

Codes D and E were ratified in
`camazotz ADR 0001 <https://github.com/babywyrm/camazotz/blob/main/docs/adr/0001-five-transport-taxonomy.md>`_.
The wrapper accepts any string for ``transport`` — there is no runtime
validation here; reporting modules treat unknown codes as their own
bucket in ``--by-lane`` output.
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
