# MCP spec surface

How mcpnuke sits against the [MCP roadmap of 2026-08-22](https://modelcontextprotocol.io/development/roadmap). This is the map. It is not a check inventory — that is [docs/checks.md](checks.md) — and it is not the attack-taxonomy coverage target — that is [ROADMAP.md](../ROADMAP.md).

The scanner already speaks the **2026-07-28** spec: stateless mode, `server/discover`, SEP-2243 routing headers, `--protocol-mode`. Almost none of the next 6–12 months is in the client or the checks. Two pieces of the *current* spec are spoken only in part and never scanned. Those two are the first things to build later. Everything else waits for a Working Group to ship a wire format.

## Contents

- [How to read this map](#how-to-read-this-map)
- [Ready queue](#ready-queue)
- [Spoken and scanned](#spoken-and-scanned)
- [1. Agentic messaging primitives](#1-agentic-messaging-primitives)
- [2. HTTP-native transport unification and hardening](#2-http-native-transport-unification-and-hardening)
- [3. Agent identity and enterprise-ready security](#3-agent-identity-and-enterprise-ready-security)
- [4. Improved primitives](#4-improved-primitives)
- [5. Improved SDK developer experience](#5-improved-sdk-developer-experience)
- [Adjacent checks](#adjacent-checks)
- [Later, with zero regressions](#later-with-zero-regressions)
- [Sources](#sources)

## How to read this map

Three columns, nothing fuzzier:

| Column | Meaning |
|--------|---------|
| **Speak** | Does mcpnuke’s client implement the wire feature? |
| **Scan** | Is there a check whose *subject* is that feature, not a cousin? |
| **Ready** | Can we write that check against today’s spec without guessing a SEP? |

**Ready** is the later-build queue. **Wait** is not a backlog item yet. Relabeling a cousin check as the new primitive is a false claim, not coverage.

## Ready queue

The two 2026-07-28 gaps that were Ready without guessing a SEP are done:

- Dual `tools/call` body — `_response_text` reads `structuredContent`.
- List caching — enumerator stores `ttlMs` / `cacheScope` per list page;
  `list_cache` samples up to five `resources/read` URIs when invocation is
  allowed. Invalid values MEDIUM; mixed cacheScope across pages of one list
  HIGH. Absence is not a finding. Mixed scope across different resource URIs
  is not a page mismatch.

ETags, Tasks, HTTP-over-stdio, and WIF stay Wait. See [Later, with zero regressions](#later-with-zero-regressions).

## Spoken and scanned

Keep. Do not relabel as the new work.

| Surface | Speak | Scan | Notes |
|---------|-------|------|-------|
| Stateless 2026-07-28 | Yes | Partial | `core/protocol.py`: routing headers, `params._meta` client identity, `--protocol-mode {auto,legacy,stateless}`. Enumerator probes `initialize` then `server/discover` then bare `tools/list`. |
| Unauthenticated `server/discover` | Yes | Yes | Lane 5 / Transport A finding, skipped on stdio. |
| DPoP (RFC 9449) | Yes | Yes | Three probes: no proof, malformed proof, missing `htm`/`htu` binding. Subject is bearer-binding, not agent identity. `taxonomy_id` is still evidence-only (known, deferred). |
| Pagination | Yes | Yes | `nextCursor` up to `--max-pages`; truncated lists emit LOW `enumeration`. |
| Dual `tools/call` body | Yes | Yes | `_response_text` reads `content` blocks and `structuredContent`. Done 2026-08-25. |
| List caching (SEP-2549) | Yes | Yes | Enumerator keeps per-page `ttlMs` / `cacheScope`. `list_cache` samples up to five `resources/read` URIs (skipped under `--no-invoke`). Silent when the fields are absent. Invalid TTL/scope is MEDIUM; mixed cacheScope across pages of one list is HIGH. Mixed scope across different resource URIs is not that finding. |

## 1. Agentic messaging primitives

Work that runs for minutes, servers that push, a way to steer mid-flight. The roadmap’s stated risk: three answers to “the server isn’t done yet” that do not share a lifecycle. mcpnuke has cousins for two of those answers and speaks none of the new primitives.

| Deliverable | Speak | Scan | Ready | Notes |
|-------------|-------|------|-------|-------|
| Tasks extension (SEP-2663), toward core | No | No | Wait | No `tasks/get`, `tasks/update`, `tasks/cancel`. `agentic_loop` is unbounded *tool recursion*, not a task handle. |
| `subscriptions/listen` | No | No | Wait | |
| Progress notifications | Ignored | No | Wait | `notification_abuse` explicitly skips `notifications/*`. |
| Server-initiated event channels / webhooks | No | No | Wait | Protocol push, not a tool argument. Adjacent: `webhook_persistence`. |
| Multi round-trip requests (SEP-2322) / elicitation on stateless servers | No | No | Wait | No elicitation client. `notification_abuse` catches unsolicited `sampling/createMessage` and `roots/list` — the old server-initiated *request* pattern, which this SEP replaces. |
| Composition review (Tasks × Triggers × Transports) | n/a | n/a | Wait | Nothing to probe until the WGs publish a composed lifecycle. |

## 2. HTTP-native transport unification and hardening

A remote MCP server is an HTTP workload as of 2026-07-28. Local servers still speak a second design. mcpnuke has the same split: four transports, two pipelines.

| Deliverable | Speak | Scan | Ready | Notes |
|-------------|-------|------|-------|-------|
| Streamable HTTP / SSE as HTTP workloads | Yes | Partial | Keep | `HTTPSession`, `MCPSession` (SSE). Auth, DPoP, and TLS checks are HTTP-family only. |
| JSON-RPC over stdio | Yes | Yes, with transport-aware auth | Keep | `StdioSession`: newline-delimited JSON-RPC. Not HTTP. Three auth-shaped checks already suppressed here. |
| HTTP/2 over stdio (single binding) | No | No | Wait | A **new** binding when it ships. Today’s stdio session is not a preview of it. Unifying would collapse two pipelines; do not start that guess. |
| List caching (`ttlMs` / `cacheScope`, SEP-2549) | Yes | Yes | **Done** | Silent when omitted. Invalid values MEDIUM; mixed cacheScope across pages of one list HIGH. `resources/read` sampled (cap 5, honor `--no-invoke`). Mixed scope across URIs is not a page mismatch. |
| ETags on primitive results, including tool calls | No | No | Wait | Roadmap item, not in 2026-07-28. |
| Standardized error handling across surfaces | Partial | Partial | Keep | `protocol_robustness` flags unknown methods that return success and `tools/call` with no params that returns a result. Not a full error-code matrix. |
| Capability scoping for tool lists after SEP-2575 | No | No | Wait | Enumerator always asks for the full catalog. `schema_overdisclosure` assumes that catalog is complete. |
| Secure server configuration options | No | No | Wait | |

## 3. Agent identity and enterprise-ready security

MCP authorization still assumes a person with a browser at consent time. The next callers are agents: cloud workloads with their own identity, acting for an absent user, or spawning sub-agents with narrower authority.

| Deliverable | Speak | Scan | Ready | Notes |
|-------------|-------|------|-------|-------|
| DPoP, finalized and widely adopted | Yes (RFC 9449 probes) | Yes (bearer-binding) | Keep / extend later | Agent Identity WG is still forming. When the MCP DPoP SEP freezes, add probes — do not replace the RFC 9449 ones until the wire is the same. |
| Workload Identity Federation (SEP-1933) | No | No | Wait | |
| ID-JAG (Identity Assertion JWT Authorization Grant) / Enterprise-Managed Authorization | No | No | Wait | |
| RFC 8693 token exchange | No | No | Wait | |
| Human-presence attestation (interactive vs headless) | No | No | Wait | Under discussion, not a deliverable yet. |
| Person-style OAuth that mcpnuke already has | Yes | Partial | Keep | CLI: `--oidc-url`, client credentials, token introspection. Checks: `jwt_*`, `theft`, `scope_pollution`. These are not agent identity. |

2026-07-28 also shipped issuer validation, issuer-bound client credentials, and CIMD as the preferred registration path. mcpnuke does not probe CIMD or issuer-bound client credentials as subjects. That is a current-spec gap, but it is not on the Ready queue until we can name a safe, low-FP probe — OAuth metadata is a famous source of noise.

## 4. Improved primitives

Tool calling has held up. Result handling has not: `tools/call` may return `content` and `structuredContent` together, and clients diverge on which the model sees. Large catalogs make the model pay for tools the user has not asked about.

| Deliverable | Speak | Scan | Ready | Notes |
|-------------|-------|------|-------|-------|
| Dual result body (`content` + `structuredContent`) | Yes | Yes, via `_response_text` | **Done** | Content-list early return used to drop `structuredContent`. Poisoning, credential, and injection checks inherit the extractor. |
| Core Primitives WG redesign of `tools/call` | n/a | n/a | Wait | Do not guess the replacement contract. |
| Progressive discovery | No | No | Wait | Enumerator ingests the full catalog. `schema_overdisclosure` (MCP-T50) is recon against that full list — the **opposite** assumption. When progressive discovery ships, that check’s threat model changes: a small entry point may be the new anonymous surface, and a hidden catalog may be the new hide. |
| Primitive annotations (audience / priority, SEP-2200) | No | No | Wait | Roadmap says most implementers have not adopted them. Scanning for absence would fire on almost every server. |
| File uploads / filesystem-like resources (range reads, hierarchical listing) | Partial | Partial | Wait | `resources/list` + `resource_poisoning`. No range-read client. |

## 5. Improved SDK developer experience

Spec and conformance suite as the source of truth for SDKs and quickstarts. Mostly not a scanner’s job.

| Deliverable | Speak | Scan | Ready | Notes |
|-------------|-------|------|-------|-------|
| Extension contract (which role binds, what SDKs must support, auth as its own area) | Partial | Partial | Wait | `server/discover` stores `capabilities`. We flag anonymous discover. We do not compare advertised extensions to implemented methods. |
| Generated Tier 1 SDK experiment | n/a | n/a | Out of scope | |
| Reference servers / quickstarts freshness | n/a | n/a | Out of scope | |

One future scan, if and only if the extension contract lands: capability advertised versus method actually implemented. Same shape as `protocol_robustness`, scoped to declared extensions.

## Adjacent checks

These look like the new work. They are not. Building the new primitive means a new subject, not a new name on these.

| Check | What it actually is | What it is not |
|-------|---------------------|----------------|
| `webhook_persistence` | Tool args / names that accept a callback URL | Protocol event channels, `subscriptions/listen` |
| `notification_abuse` | Unsolicited `sampling/createMessage` and `roots/list` | Tasks, progress notifications, SEP-2322 elicitation |
| `agentic_loop` | Unbounded tool recursion / fan-out | A task handle with `tasks/get` |
| `schema_overdisclosure` | Secrets and recon in a full `tools/list` | Progressive discovery |
| `dpop_enforcement` | RFC 9449 proof on an HTTP request | WIF, ID-JAG, token exchange, agent identity |
| `sdk_cache_tamper` | Client SDK token cache on disk | List-result `ttlMs` / `cacheScope` |
| `protocol_robustness` | Unknown method / empty `tools/call` | Standardized error codes across Tasks, events, and HTTP |

## Later, with zero regressions

When we leave docs-only:

1. Pick one **Ready** row. Not a Wait row. Not a cousin with a new name.
2. TDD: failing tests first, including a clean-target case so the false-positive harness would catch a noisy check.
3. Ship only if all of these hold: full `pytest`, `ruff check .` at zero, `mypy mcpnuke/` at or below the CI ceiling, HTTP FP ceiling, stdio FP ceiling, OSS snapshots unchanged or re-triaged in writing.
4. Do not change a shipped `taxonomy_id` in the same PR as a new spec-surface check.

A new check that raises an FP ceiling is a regression even if the suite is green. The three harnesses are documented in [docs/false-positive-baseline.md](false-positive-baseline.md) and [docs/oss-target-baseline.md](oss-target-baseline.md).

## Sources

- Roadmap (2026-08-22): https://modelcontextprotocol.io/development/roadmap
- Announcement: https://blog.modelcontextprotocol.io/posts/mcp-roadmap/
- 2026-07-28 release: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- Tasks extension: [SEP-2663](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2663-tasks-extension.md)

Measured against mcpnuke 6.16.0 (`enumerator.py`, `protocol.py`, `checks/tool_probes.py`, `checks/dpop_enforcement.py`, `core/session.py` StdioSession).
