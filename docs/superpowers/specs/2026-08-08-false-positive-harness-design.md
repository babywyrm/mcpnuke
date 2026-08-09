# False-Positive Harness Design

**Date:** 2026-08-08
**Status:** Implemented (2026-08-09) — see
[docs/false-positive-baseline.md](../../false-positive-baseline.md)

**Depends on:** `checks/__init__.py` (`run_all_checks`), `core/session.py`
(`detect_transport`), `core/enumerator.py` (`enumerate_server`)

## Problem

mcpnuke has ~69 checks in a typical full scan and no measurement of how many of
them fire against a server that is **not** vulnerable.

Clean-case coverage today is per-check unit negatives (`test_*_clean`), each
asserting that one check stays quiet on one fabricated `TargetResult`. That
catches a check that is obviously broken. It cannot catch the failure mode that
actually costs users trust: the *aggregate*. Thirty checks each contributing one
plausible-looking MEDIUM produces a report that buries the real finding, and no
single unit test fails.

Slice D fixtures do not close this. They assert ranking and policy contracts
over finding sets we hand-authored; they never ask the scanner to *produce* a
finding set. Nothing exercises the real pipeline over a socket in default CI —
`DVMCP_LIVE=1` and `CAMAZOTZ_LIVE=1` are opt-in and both point at deliberately
vulnerable targets, so neither can answer "how quiet are we on a good server?"

False-positive rate is the primary adoption blocker. A scanner that cries
CRITICAL at a well-built server costs an operator more than the vulnerability it
might have caught.

## Goal

A **reference hardened MCP target** plus an end-to-end test that runs the real
scan pipeline against it in **default CI** (no Docker, no external lab, no env
gate), asserting:

1. Zero CRITICAL or HIGH findings outside a written expected-findings list
2. Total findings at or under a ceiling that ratchets downward

This becomes the first true end-to-end test in the default suite.

## Why hardened, not inert

An inert server (echo, add, no auth surface, no dangerous capability) reaches
zero findings trivially and proves nothing, because no real deployment looks
like that.

The reference target is instead what a competent team ships: tools powerful
enough to be worth attacking — file read, outbound HTTP — that are correctly
scoped and validated. That is exactly where false positives hurt, because a
check keying on capability rather than on misconfiguration cannot tell this
server apart from a vulnerable one. If mcpnuke is quiet here, the quiet is worth
something.

## Design

### Reference target (`tests/reference_target/server.py`)

Speaks **Streamable HTTP**: a single `POST /mcp` endpoint accepting JSON-RPC
(`initialize`, `tools/list`, `tools/call`), built on the Python standard
library's `http.server`. Streamable HTTP is chosen over SSE because it avoids
event-stream and endpoint negotiation; the server is a test fixture and should
be boring.

Stdlib rather than FastAPI, despite FastAPI being present for
`mcpnuke/server/app.py`: FastAPI lives in the optional `server` extra, and both
CI jobs install only `--extra dev`. A FastAPI target would be unimportable in
CI, the test would skip, and the harness would measure nothing — the exact
failure it exists to prevent. The stdlib handler also matches the pattern
already used by `tests/test_teleport_checks.py`, and works unchanged on
Python 3.11–3.13.

`detect_transport` probes SSE paths before POST paths. Serving at `/mcp` and
handing the test `http://127.0.0.1:<port>/mcp` puts that path first in both
orderings, and non-matching local probes fail immediately rather than waiting
out a timeout.

**Tools** — useful enough to be worth attacking, and correctly built:

| Tool | Capability | Hardening |
|------|-----------|-----------|
| `docs.search` | Read-only text search | Fixed corpus, no user-controlled path |
| `file.read` | Reads a file | Confined to an allowlisted directory; traversal and absolute paths rejected |
| `http.fetch` | Outbound HTTP | Domain allowlist; private, loopback, and link-local ranges refused |
| `ticket.create` | Write | Schema-validated fields; no interpolation into any sink |

**Hygiene properties** — the invariants that make it clean, each one the
negative of a check family mcpnuke implements:

- No credentials, keys, or internal URLs in tool descriptions or schemas
- Tool definitions stable across calls (no rug pull, no redefinition)
- Injection payloads treated as data — never echoed into output, never reflected
  as instructions
- Errors return structured JSON-RPC errors, never stack traces, internal paths,
  or dependency versions
- Requires a bearer token; unauthenticated calls are rejected

The token is **generated at fixture setup**, never committed, so the harness
adds no secret-shaped strings to the repo. Requiring auth also means the
auth-gated check lanes run rather than silently skipping, which is the point —
a skipped lane cannot demonstrate quiet.

### The test (`tests/test_false_positives.py`)

A session-scoped fixture starts the server in-process on an ephemeral port. The
test then runs the real pipeline exactly as a scan would:

```
detect_transport(url) → enumerate_server(session, result) → run_all_checks(...)
```

Assertions:

1. **No unexpected high-severity findings.** Every CRITICAL and HIGH must match
   an entry in the expected-findings list, or the test fails.
2. **Ceiling.** Total findings must not exceed `FP_CEILING`.

Failure output names the check and title of each unexpected finding, so a
contributor who trips it knows which check to look at without rerunning
anything.

### Expected findings, and the rule that keeps the number honest

The expected-findings list and `FP_CEILING` are module-level constants in
`tests/test_false_positives.py`, not a separate data file — they are assertions,
they belong next to the assertion, and keeping them in Python lets each entry
carry its reason inline:

```python
_FP_CEILING: int = 0  # set from the first triaged run; ratchets down only

# check name → why a finding here is legitimate, not a false positive
_EXPECTED: dict[str, str] = {
    "excessive_permissions": "http.fetch is genuinely outbound-capable; "
                             "capability inventory is true and worth surfacing",
}
```

**Every entry carries a written reason**. An entry is only legitimate when the finding is a true statement about
the server that an operator would want to see — a capability inventory note on
`http.fetch`, for instance, is true and worth surfacing.

**The default response to a new finding here is to fix the check, not to add an
entry.** This harness exists to find bugs in mcpnuke, and it will find them on
first run. Without that rule the ceiling becomes a place to park false positives
and the number stops meaning anything.

`FP_CEILING` ratchets downward only, mirroring the `MYPY_CEILING` convention
that `CONTRIBUTING.md` already documents: a change that lowers the count lowers
the ceiling in the same PR to lock the win in.

### Risks and mitigations

**CI runtime.** ~69 checks including behavioral probes against a local server.
Expected to be seconds, but if it proves slow the mitigation is a session-scoped
server shared across assertions, not dropping coverage. Measure before deciding.

**Flakiness.** Timing-sensitive checks could produce intermittent findings.
Any check that proves inherently unstable here gets excluded explicitly with a
recorded reason, never by loosening the ceiling.

**State mutation.** Behavioral probes call tools with hostile arguments,
including `ticket.create`. The server keeps writes in per-process memory and is
never shared between test sessions, so probe order cannot affect results.

## Non-goals

- Scanning public third-party MCP servers. `tests/test_public_targets.py`
  already exists behind `MCP_PUBLIC_TARGETS=1` and only enumerates. Extending it
  into a measured FP audit is a **follow-up**; third-party availability must
  never gate CI.
- Replacing DVMCP. This measures false positives; DVMCP measures true positives.
  Both are needed and neither substitutes for the other.
- Docker or compose assets. The target runs in-process.
- New CLI flags, new checks, or changes to severities and `risk_score`.

## Success criteria

- Reference server speaks enough MCP for `detect_transport` and
  `enumerate_server` to succeed without special-casing
- Full pipeline runs against it in the default suite, no env gate
- Zero unexpected CRITICAL or HIGH
- Every expected-finding entry has a written reason
- The first run's triage is recorded: which findings were scanner bugs and got
  fixed, which were legitimate and got entries
