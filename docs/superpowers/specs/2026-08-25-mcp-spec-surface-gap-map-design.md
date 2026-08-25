# MCP spec surface gap map

**Status:** Approved 2026-08-25 (docs-only; no checks this cycle)
**Date:** 2026-08-25
**Follows:** `2026-08-11-distribution-design.md`
**Sources:** [MCP roadmap](https://modelcontextprotocol.io/development/roadmap)
(last updated 2026-08-22), [blog post](https://blog.modelcontextprotocol.io/posts/mcp-roadmap/)

## Problem

The MCP Core Maintainers published a 6–12 month roadmap on 2026-08-22 with
five priority areas. mcpnuke already speaks the **2026-07-28** spec
(stateless mode, `server/discover`, SEP-2243 routing headers) and has DPoP
probes. Almost none of the new surface is in the scanner, and two pieces of
the *current* spec are spoken only in part and never scanned.

Without a map, the next check work will either (a) relabel an existing cousin
(`webhook_persistence`, `agentic_loop`, `notification_abuse`) as the new
primitive, or (b) start probing SEPs that have not shipped. Both are
regressions: the first is a false claim, the second is a guess that will
bit-rot when the WG changes the wire format.

## Non-goals (this cycle)

- No new check modules, patterns, or protocol framing.
- No `taxonomy_id` edits (`shell_injection` T54, evidence-only T06/T43).
- No agentic-sec hub sync (separate, after this lands).
- No implementation plan for Wait-column rows.

## Shape

| File | Job |
|------|-----|
| `docs/spec-surface.md` | Source of truth. Five areas. Speak / Scan / Ready. Adjacent checks named. |
| `ROADMAP.md` | Compact table pointing at that doc. Taxonomy map unchanged. Near-term gains a later item, not a this-commit item. |
| `README.md` | One row in the reference table. |
| `tests/test_docs_current.py` | `spec-surface.md` in the expected-docs list; headings locked so a stub cannot replace it. |
| `CHANGELOG.md` | `[Unreleased]` docs entry. |

## Rubric

Three columns, nothing fuzzier:

- **Speak** — does mcpnuke’s client implement the wire feature?
- **Scan** — is there a check whose *subject* is that feature, not a cousin?
- **Ready** — can we write that check against today’s spec without guessing a SEP?

**Ready** is the later-build queue. **Wait** is not a backlog item yet.

## Classifications (measured 2026-08-25)

### Already in 2026-07-28, ignored — first later slices

1. **List caching (SEP-2549).** `ttlMs` / `cacheScope` on list results and
   resource reads. `enumerator._paginated_list` follows `nextCursor` and
   never reads cache fields. Speak: partial. Scan: none. **Ready.**
2. **Dual `tools/call` body.** `_response_text` in `tool_probes.py` reads
   `content` when it is a list and returns. If both `content` and
   `structuredContent` are present, the structured half is not scanned. If
   `content` is absent, the whole result is `json.dumps`’d, so structured
   output is scanned only as an accident of serialization. Speak: partial.
   Scan: none as a subject. **Ready.**

### Spoken and scanned — keep, do not relabel

- Stateless 2026-07-28: `core/protocol.py`, `server/discover`, routing
  headers, `--protocol-mode`.
- DPoP: three RFC 9449 probes. Subject is bearer-binding, not agent
  identity. `taxonomy_id` still evidence-only (known, deferred).
- Tool-arg webhooks: `webhook_persistence`. Not protocol event channels.
- Unsolicited server requests: `notification_abuse`
  (`sampling/createMessage`, `roots/list`). Explicitly ignores
  `notifications/*`.
- Unbounded recursion: `agentic_loop`. Not Tasks.
- Full-catalog recon: `schema_overdisclosure`. Opposite of progressive
  discovery; when that ships, this check’s assumption breaks.

### Wait — spec not stable enough to probe

- Tasks (SEP-2663) toward core
- Server-initiated event channels / `subscriptions/listen`
- HTTP/2 over stdio (new binding; today’s `StdioSession` is newline-delimited
  JSON-RPC, not HTTP)
- ETags on tool results
- WIF (SEP-1933), ID-JAG, RFC 8693 token exchange
- Progressive discovery, primitive-annotation adoption, file-upload WG
- Area 5 SDK DX, except a future “capability advertised vs implemented”
  check if the extension contract lands

## Later building, zero regressions

When we leave docs-only:

1. Pick one **Ready** row. Not a Wait row. Not a cousin with a new name.
2. TDD: failing tests first, including a clean-target case so the FP
   harness would catch a noisy check.
3. Ship only if: full `pytest`, ruff, mypy at the CI ceiling, HTTP FP
   ceiling, stdio FP ceiling, OSS snapshots unchanged or re-triaged in
   writing.
4. Do not change a shipped `taxonomy_id` in the same PR as a new
   spec-surface check.

A new check that raises an FP ceiling is a regression even if the suite
is green.

## Test plan (this cycle)

- `tests/test_docs_current.py`: `spec-surface.md` exists; the five area
  headings and the Speak/Scan/Ready rubric are present; the two Ready
  rows are named.
- Full docs tests green. No check-module tests change.
