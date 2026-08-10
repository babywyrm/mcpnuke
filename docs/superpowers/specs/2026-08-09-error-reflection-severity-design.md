# Error-Reflection Severity

**Status:** Implemented (2026-08-10) — see
[docs/oss-target-baseline.md](../../oss-target-baseline.md)
**Date:** 2026-08-09
**Follows:** `2026-08-09-oss-target-fp-harness-design.md`

> **Implementation note.** The counts below (187 findings, ~83 in this class)
> describe the state when this was written. Implementation found a sharper
> discriminator than the `isError` test proposed here: every affected check
> matched a marker that was *part of the payload it sent*, so subtracting a
> verbatim echo of the payload separates compliance from an echo, and works
> even where `isError` is absent. `isError` remains a required second
> condition. Measured result: 61 findings re-graded, CRITICAL 49 → 18.

## Problem

Measuring mcpnuke against five real open-source MCP servers
([docs/oss-target-baseline.md](../../oss-target-baseline.md)) produced 187
findings, of which roughly half are suspected false positive. The largest
single class — **83 findings** — has one root cause.

A probe sends a path containing a canary. The server **rejects it** and names
the offending input in its error message:

```
Repository not found: /tmp/MCPNUKE_CANARY_123
```

The check finds its canary in the response and reports reflection. The server
did exactly the right thing — refused bad input, and said which input it
refused — and scored a HIGH for it.

| Check | Findings | Module |
|-------|----------|--------|
| `active_prompt_injection` | 26 | `checks/injection.py` |
| `tool_response_injection` | 24 | `checks/tool_probes.py` |
| `input_sanitization` | 22 | `checks/tool_probes.py` |
| `prompt_injection_t01` | 7 | `checks/prompt_injection_t01.py` |
| `command_injection_broad` | 4 | `checks/command_injection_broad.py` |

The triage document groups these as classes 1, 3 and 4 and quotes ~72 for the
three largest; 83 is the same set with the two smaller checks included.

None of these inspect `isError`. `_response_text` flattens a successful result
and a rejection into the same string, and every consumer above treats the two
identically.

### This bug was already found once

`exfil_flow.py` carries the fix and the reason, in its own words:

```python
def _is_failure(resp: dict | None) -> bool:
    """True when the sink refused the payload.

    `_call_tool` returns the response whenever the JSON-RPC round trip
    completes, so a refusal arrives as a value, not an exception. Treating any
    non-None response as success turned "permission denied" into confirmed
    exfiltration.
    """
```

`chain_replay.py` has a byte-identical copy under a different name. Neither was
propagated to the probe checks, and there is no shared definition to propagate
from — the same duplication that produced the tokenizer bug fixed earlier today.

## Goal

Stop scoring a correct refusal as a vulnerability, without losing the real
findings that also live inside error responses, and let the operator decide how
much an error-wrapped reflection is worth.

## Design

### 1. One shared error helper

`response_is_error(resp: dict | None) -> bool` moves to
`mcpnuke/checks/base.py`, beside `tool_text` and `time_check`. The two private
copies in `exfil_flow.py` and `chain_replay.py` are deleted and import it.

Layering is already established: `core/chain_replay.py` imports from
`checks/tool_probes` today.

A test asserts there is exactly one definition, in the style of the existing
invariant tests.

### 2. Downgrade, not suppress

When a finding's evidence came from a response with `isError: true`, the
finding is emitted at **LOW** and its title states where it came from —
`... (reflected in error response)`.

It stays in console output and in JSON. Suppression was rejected: a server can
return `isError: true` **and** be genuinely compromised, and hiding the
response means never seeing it.

### 3. The operator chooses the weighting

```
--error-reflection {downgrade,keep,suppress}    (default: downgrade)
```

- `downgrade` — LOW and retitled. The default.
- `keep` — today's behaviour exactly. Needed by anyone diffing against a
  pre-change baseline, and by anyone who disagrees with our judgment.
- `suppress` — drop the finding. For a quiet report, chosen knowingly.

Threaded through `probe_opts`, the way `safe_mode` already is. Follows the
existing `choices=` convention in `cli.py`.

### 4. Exemptions — what stays at full severity

Downgrading everything inside an error response would trade false positives for
false negatives. Two categories are exempt.

**Execution evidence, as distinct from reflection.** The question is whether the
server echoed *the input* or *the result of the input*. `uid=0(root)` in the
response means the payload ran; a trailing `isError` does not undo that.

Operationally the two are already distinguishable, because these checks match
on different things. `command_injection_broad` tests both `probe["indicator"]`
— a marker that only appears if the command *executed* — and, separately, an
`err_pattern` for shell error text. Matches on the former are execution and
keep their severity; matches that amount to the payload appearing verbatim are
reflection and get downgraded. Where a check has no such separation today,
adding one is part of the work rather than a reason to skip the exemption.

**Credential and secret leakage.** A password in an error string is a leak
whether or not the call succeeded. `response_credentials` and `error_leakage`
are untouched by this work.

### 5. Chaining must respect severity — without this the fix does nothing

`check_multi_vector` and `check_attack_chains` both build their vector set as:

```python
checks_hit = {f.check for f in result.findings}
```

There is **no severity filter**. A finding demoted to LOW still counts as a
fully active attack vector, so the CRITICAL `multi_vector` would keep firing
off precisely the findings we just graded weak. Downgrading alone would reduce
the count and leave the loudest symptom untouched.

A check therefore counts as an active vector only when it has at least one
finding at **MEDIUM or above**. This stands on its own merits: a CRITICAL
"multi-vector attack" claim should not rest on evidence we ourselves graded
LOW.

This carries the most regression risk in the design and needs explicit DVMCP
verification — a genuine chain whose component vectors are all LOW would stop
being reported.

## Verification

- **OSS snapshots before and after.** The measured effect, as a reviewable
  diff. Expect ~83 findings to move HIGH/CRITICAL → LOW, plus the derived
  `multi_vector` and `attack_chain` findings they were feeding.
- **DVMCP true positives keep their severity.** The main risk. 161 tests across
  8 files touch these checks. A server that genuinely follows an injected
  instruction must stay HIGH or CRITICAL.
- **The hardened fixture does not move.** `_FP_CEILING` stays at 5.
- **`--error-reflection keep` reproduces today's output exactly**, which is
  what makes the change auditable rather than a matter of trust.

## Non-goals

- **The auth-on-stdio class** (~15 findings: `pre_auth_injection`,
  `anon_budget_exhaust`, `behavioral_rate_limit` on a transport with no auth
  boundary). Real, separate, needs transport-awareness rather than severity
  work.
- **Rewriting the probes' detection logic.** This changes how a reflection is
  *weighted*, not how it is *found*.
- **`schema_risk` volume** (44 findings). Accurate, low value, already
  collapsed by the priority ranker.

## Success criteria

1. One definition of `response_is_error`, with a test enforcing it.
2. Error-wrapped reflections report at LOW, retitled, on all five OSS targets.
3. `multi_vector` and `attack_chain` no longer fire on LOW-only evidence.
4. Every DVMCP injection true positive keeps its current severity.
5. `--error-reflection keep` reproduces the pre-change snapshots byte for byte.
6. Full suite green; `_FP_CEILING` unchanged at 5.
