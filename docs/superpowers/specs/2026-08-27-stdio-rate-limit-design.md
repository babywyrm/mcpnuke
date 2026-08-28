# stdio `behavioral_rate_limit` — keep, tag MCP-T27

**Status:** Approved 2026-08-27
**Date:** 2026-08-27
**Follows:** ROADMAP false-positive “still open” row; docs/oss-target-baseline.md

## Problem

`behavioral_rate_limit` fires MEDIUM on every stdio target (fixture + five
OSS servers). Auth-shaped checks were filtered off stdio because a pipe has
no credential boundary. This check was parked: weaker than that class, not
empty.

## Decision

Keep the finding on stdio. An agent in a loop can hammer a local server.
That is not a statement about a missing auth header. Tag it `MCP-T27` like
the static `rate_limit` sibling so `--by-lane` does not dump it in
Uncategorized.

Do not skip stdio. Do not drop severity. Do not add a fixture throttle —
that would hide the rest of the harness.

## Non-goals

- Live DVMCP / Camazotz (HTTP; this is a stdio FP call).
- Changing HTTP or stdio FP ceilings.
- New check module.
- T22 / T23.
