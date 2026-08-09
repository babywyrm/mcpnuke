# False-Positive Baseline

How quiet mcpnuke is against a server that is **not** vulnerable.

Measured by `tests/test_false_positives.py`, which runs the real pipeline
(`detect_transport` → `enumerate_server` → `run_all_checks`) against the
hardened reference target in `tests/reference_target/`. It runs in default CI —
no Docker, no external lab, no environment gate.

## Current baseline

**2026-08-09 — 4 findings, 0 unexpected.** Scan takes ~22s.

| Severity | Check | Why it is legitimate |
|----------|-------|----------------------|
| HIGH | `excessive_permissions` | `http.fetch` really can reach the network. Capability inventory is true and worth surfacing; the priority ranker collapses it so it cannot bury a proved finding. |
| HIGH | `dpop_not_enforced` | The target uses a plain bearer token and does not implement RFC 9449, so a stolen token is replayable. Deliberate: DPoP is uncommon enough that requiring it would stop the target resembling a real server. |
| MEDIUM | `ssrf_probe` | `http.fetch` accepts a URL parameter. The finding says "SSRF **surface**", which is accurate — every probe was refused by the host allowlist. |
| MEDIUM | `behavioral_rate_limit` | The target has no rate limiting. True. Adding it was rejected because throttling the scanner would reduce what the rest of the harness can measure. |

## What the first run found

The first run produced **13 findings, 6 of them CRITICAL or HIGH**, against a
server that requires authentication and refuses every probe. Nine were removed.

### Scanner bugs — fixed

**`auth` claimed unauthenticated access on an authenticated scan** (`6049835`).
The finding fired on `mode == LEGACY` alone, which only means the handshake
worked. A scan run with `--auth-token`, against a server that requires that
token, was reported as "accepted initialize with no credentials". This is the
most expensive shape of false positive: it tells an operator their access
control is missing while it is working, and the report offers nothing to
contradict it. The anonymity test now lives on `TargetResult` so the enumerator
and `anon_budget_exhaust` share one definition.

**`code_execution` matched parameter names by substring** (`3d73ee9`). `query`
was in the execution-like keyword list, so every search tool earned a HIGH; and
because matching was substring-based, `country_code`, `zipcode`, and
`status_code` all matched `code`. Names now match by token, and ambiguous ones
(`query`, `code`, `statement`, `payload`) fire only when the tool text says it
executes, evaluates, or speaks SQL. Removing this also cleared a **CRITICAL
`multi_vector`** finding derived from it — the more expensive half of the bug,
since a false positive manufactured a second, louder finding.

**DPoP reported one fact three times** (`30955b8`). A server that does not
implement DPoP returns 200 to all three probes by construction, so probes 2 and
3 could not fail independently of probe 1. Every plain-bearer server collected
three HIGH findings, two of which inferred the proof header was "decorative" on
a server that never claimed to support DPoP. Probes 2 and 3 now run only after
probe 1 shows the server demands a proof — the case where they are damning
rather than redundant.

### Fixture bugs — the harness was wrong

**Three findings were the harness lying to correct checks.**
`pre_auth_injection`, `anon_budget_exhaust`, and
`native_function_identity_erasure` all guard on `result.auth_context`, which the
CLI populates from `--auth-token` and the scanner copies onto the result. The
first version of the fixture never set it, so it presented an authenticated scan
as an anonymous one. The checks were right and would have been "fixed" into
being wrong.

Worth recording because it is the harness's own most likely failure mode: a
fixture that misrepresents how the scanner is really driven produces findings
that look exactly like scanner bugs.

### Target hardening — the checks were right

**Unbounded string parameters and a malformed `tools/call`** (`623246e`).
`schema_risk` flagged three string parameters with no `maxLength`, and
`protocol_robustness` caught `tools/call` with no params returning a success
envelope instead of a JSON-RPC error. Both were fixed in the target rather than
excused in the expected list.

## The rule

When a finding appears here, **the default response is to fix the check.**
Adding an entry to `_EXPECTED` is the exception and requires a written reason a
reviewer can disagree with. Without that rule the ceiling becomes somewhere to
park false positives and the number stops meaning anything.

`_FP_CEILING` ratchets down only, the same convention as `MYPY_CEILING`.

## Open questions

- **Is `dpop_not_enforced` really HIGH?** It fires on every plain-bearer server,
  which is nearly all of them, and a finding that always fires carries little
  information. The redundancy fix took it from three findings to one; whether
  the severity should also fall is a separate judgement, deliberately not made
  in the same change.
- **`behavioral_rate_limit` on a server with no rate limiting** is true, but
  rate limiting is arguably the gateway's job rather than the MCP server's.

## Not covered

Real public MCP servers. `tests/test_public_targets.py` exists behind
`MCP_PUBLIC_TARGETS=1` and only enumerates. Measuring false positives against
third-party servers is worth doing, but their availability must never gate CI,
so it is separate work.
