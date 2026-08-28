# Transport-Aware Auth Checks

**Status:** Implemented 2026-08-10
**Date:** 2026-08-10
**Follows:** `2026-08-09-error-reflection-severity-design.md`

## Outcome, and where it differed from this design

Shipped across six commits. Two deliberate deviations, both discovered during
implementation:

1. **A third check was in the class.** `native_function_identity_erasure`
   (MEDIUM) gates on the same raw `_raw_token` test and also fired on 5 of 5
   servers. It was not in the hand triage; the new stdio gate found it on its
   first run, which is the case for having the gate. Fixed the same way, in
   its own commit with its own tests.
2. **`anon_budget_exhaust` returns early instead of using
   `skip_transports`.** `skip_transports` filters at `result.add`, i.e. after
   the check has run. That check's body is a burst of 25 live calls, so
   filtering the finding would have kept every one of them and simply hidden
   the output — the worst of both. Its test asserts zero calls, not zero
   findings.

Result across the five pinned servers: 185 findings → 170, 34 HIGH → 24,
CRITICAL unchanged at 18. The re-snapshot was a pure deletion — 75 lines
removed, none added — so nothing but the three intended checks moved.

`behavioral_rate_limit` was named in the original triage as part of this class
and was **not** fixed. See the closing section.

## Problem

Two checks report an authentication failure on a transport that has no
authentication. Measured across the five pinned servers in
[docs/oss-target-baseline.md](../../oss-target-baseline.md), each fires exactly
once per server — **10 HIGH findings, on every stdio scan, unconditionally**:

| Check | Severity | Module | Fires on |
|-------|----------|--------|----------|
| `anon_budget_exhaust` | HIGH | `checks/anon_budget_exhaust.py` | 5 of 5 |
| `pre_auth_injection` | HIGH | `checks/taxonomy_coverage.py` | 5 of 5 |

Both gate on "did this scan carry a credential". Over stdio the answer is always
no, because stdio is a pipe to a subprocess the scanner launched itself. There
is no credential to carry, no boundary to bypass, and no second caller whose
quota could be exhausted. `pre_auth_injection`'s claim — "N tools available
without authentication" — is true of every stdio server that has ever existed.

**A finding that fires 100% of the time on a transport carries no information.**
It is also actively harmful here: stdio is the transport most users have, since
Claude Desktop, Cursor and effectively every local MCP server use it. Anyone
scanning their own setup currently gets two HIGH findings on a clean server.

### Nothing is lost by suppressing them

`behavioral_rate_limit` fires MEDIUM on all five of the same servers and is not
auth-gated. The observation "nothing is throttling this" survives; only the
auth-flavoured duplicate of it goes away.

### The mechanism already exists and is already proven

`result.add()` takes `skip_transports`, and the enumerator's `auth` finding
uses it:

```python
result.add(
    "auth", "HIGH", "Unauthenticated MCP initialize accepted",
    ...
    skip_transports=["stdio"],
)
```

`auth` is absent from all five stdio snapshots, which proves `result.transport`
is set correctly in the real scan path — this is measured, not assumed.

`skip_transports` has **exactly one caller in the codebase**. One finding was
made transport-aware and the sweep was never done.

## Approach

Three lines of behaviour change, plus an invariant strong enough that the next
instance of this cannot reach a release.

### 1. Suppress, do not downgrade

Both checks gain `skip_transports=["stdio"]` on their `add` calls:
`anon_budget_exhaust` has two (HIGH and MEDIUM), `pre_auth_injection` has one.

Suppression rather than the LOW-severity downgrade used for error reflection,
because the two cases differ. A reflected payload leaves genuine residual
doubt — a server can return `isError` and still be compromised — so the finding
stays visible and the operator judges it. Here there is no doubt: the finding is
true by construction of the transport. A LOW would be noise with no
discriminating power, and it would appear on every stdio scan forever.

This means no operator override, which cuts against the flexibility of
`--error-reflection`. Accepted deliberately: `auth` set this precedent, and a
flag to re-enable a finding that is always true is a flag nobody should use.

Both checks route through `add` wrappers (`lane_tagged`, `_add_l2`) that forward
`**kwargs`, so no refactoring is needed. `pre_auth_injection` remains a static
check — the filter reads `result.transport`, so no session parameter is
required.

### 2. A stdio reference target, not a source-inspection test

The obvious invariant is to assert that every auth-shaped check declares
`skip_transports`. Rejected: it tests how the code is written rather than what
it does, and it needs a hand-maintained list of which checks count as
"auth-shaped" — exactly the kind of list that goes stale silently.

Instead, extend the false-positive harness to cover stdio. `tests/reference_target/`
already holds the tool schemas (`tools.py`) and hardened handlers
(`tools_runtime.py`), wrapped today in an HTTP server. A stdio variant is a
subprocess that reads JSON-RPC from stdin and dispatches to **the same**
handlers. No ports, no auth token, no network.

The gate then asserts what we actually want — *a clean stdio server measures
clean* — in default CI, hermetically, on the transport most users have and the
current harness does not touch. It would have caught both of these on day one.

The reuse is what makes this affordable. Writing a second hardened server from
scratch would not be worth it; wrapping existing tested handlers in a different
transport is roughly one module and a fixture.

### 3. Leave the duplicated anonymity test alone

`check_pre_auth_injection` tests `result.auth_context.get("_raw_token")`
directly instead of calling `result.scanned_anonymously()` — a third private
copy of a test the codebase has already been burned by twice, as
`anon_budget_exhaust.py` complains in its own comments.

Not fixed here. `scanned_anonymously()` is stricter, also consulting
`jwt_claims_summary`, `oidc_url` and `introspection_active`, so switching could
silently delete findings on HTTP targets with OIDC configured. That is a
behaviour change on the transport this work is explicitly not touching, and it
belongs in its own change with its own tests. Recorded here so the next person
finds the reasoning rather than the bug.

## Testing

**`pre_auth_injection` has no test file at all** — nothing in `tests/`
references it. It gets one before it is touched; modifying an untested check is
the real hazard in this work.

| Test | Asserts |
|------|---------|
| `tests/test_pre_auth_injection.py` (new) | Fires on an HTTP scan with no credential; silent on stdio; silent when a token was supplied |
| `tests/test_anon_budget_exhaust.py` (extend) | Silent on stdio; existing HTTP behaviour unchanged |
| `tests/test_false_positives_stdio.py` (new) | A clean stdio server produces no unexpected findings |
| `tests/test_reference_target.py` (extend) | The stdio server speaks the protocol: initialize, tools/list, tools/call |

Existing `test_anon_budget_exhaust.py` builds an HTTP URL and never sets
`transport`, which defaults to `"unknown"`; the filter fails open, so those
tests are unaffected either way.

### Regression surface, checked

| Risk | Finding |
|------|---------|
| DVMCP live suite | Connects only over `http://host:port/sse`. No stdio anywhere. Unaffected. |
| HTTP FP harness | Reference target is HTTP with a token, so both checks already skip. The 5-finding ceiling does not move. |
| OSS snapshots | Lose 10 findings. Expected; re-capture and update the baseline doc. |
| Slice D goldens | `tests/fixtures/scans/dvmcp_challenge_shapes.json` names both checks, but it is static input to the priority ranker, so ranking behaviour does not change. |

## Expected result

Across the five pinned servers: **185 findings → 175, and HIGH 34 → 24.**
CRITICAL is untouched at 18. The auth-on-stdio class recorded as open in
[docs/oss-target-baseline.md](../../oss-target-baseline.md) closes, leaving no
known-unfixed class on those targets.

The new stdio gate will very likely report findings of its own on first run.
That is the point. Following the rule already set by the HTTP harness: fix the
check, and only add to an expected-list when the finding is genuinely true of
the server, with a written reason.

### Measured

**170, not 175.** HIGH landed on 24 exactly as predicted; the extra five are
the `native_function_identity_erasure` MEDIUMs, which this design had not
identified. The gate did report a finding of its own on first run, and it was
that check.

One class does **not** close: `behavioral_rate_limit` still fires on all five
targets. This design inherited the original triage's grouping of it with the
auth checks, and that grouping was wrong. Missing authentication on a pipe is
vacuous; an absent rate limit is not, because an agent stuck in a loop really
can hammer a local server. The remedy it implies — throttling a subprocess
against its only caller — is still questionable, but that is a judgement about
what the check is for, and it deserves its own decision rather than being
carried along by a change about authentication. Closed 2026-08-27: keep, tag
MCP-T27. See [2026-08-27-stdio-rate-limit-design.md](2026-08-27-stdio-rate-limit-design.md).
