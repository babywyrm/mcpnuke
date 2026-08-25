# SEP-2243 routing header binding

**Status:** Approved 2026-08-25 (next spec-surface slice after list cache)
**Date:** 2026-08-25
**Follows:** `2026-08-25-mcp-spec-surface-gap-map-design.md`

## Problem

mcpnuke already *sends* `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name`
on stateless HTTP (Speak: yes). It does not *scan* whether the server rejects
a request whose headers disagree with the JSON-RPC body (Scan: no).

The 2026-07-28 spec (SEP-2243) requires that disagreement be rejected so a
load balancer routing on `Mcp-Method` and the application parsing the body
cannot be desynchronized.

This is current spec, not a Wait-column SEP.

## Non-goals

- Tasks, ETags, HTTP/2-over-stdio, WIF, CIMD, elicitation.
- Relabeling `protocol_robustness` (unknown method / empty `tools/call`).
- Changing a shipped `taxonomy_id`.
- Probing `Mcp-Name` via a real `tools/call` (would invoke a tool).

## Behavior

New check `routing_header_binding` (light behavioral, honor `--no-invoke`).

1. Skip unless all of: session is not None, `protocol_mode == stateless`,
   `result.server_info` is non-empty (discover succeeded, not the
   tools/list-only fallback), and the transport has `post_raw` + `post_url`.
2. POST `tools/list` with `Mcp-Method: tools/call` (body and header disagree).
   Body is otherwise a well-formed stateless list request (`_meta` included).
3. Finding **MEDIUM** only when HTTP 200/202 carries a JSON-RPC `result`
   and no `error`. JSON-RPC errors and non-2xx are silence (correct reject).
4. Absence of the headers on a *legacy* server is not a finding.
5. stdio is not probeable (no header layer).

## FP

Reference target speaks initialize (legacy) and has empty discover. Probe
does not run. HTTP and stdio FP ceilings stay put.

## Tests

`tests/test_routing_header_binding.py`: positive (200+result), reject
(JSON-RPC error, HTTP 4xx), skip (legacy, no post_raw, empty server_info,
no_invoke is orchestrator-level), mismatch actually sent, timing, exception
does not crash.
