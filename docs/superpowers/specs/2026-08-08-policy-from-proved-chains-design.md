# Policy from Proved Chains Design (Slice B)

**Date:** 2026-08-08  
**Status:** Implemented  
 
**Slice:** B of actionable-results roadmap (A → C → B → D)  
**Depends on:** Slice A/C Priority Actions (proof tiers); existing `--generate-policy`

## Problem

`--generate-policy` turns scan findings into a **NullfieldPolicy** YAML
(`apiVersion: nullfield.io/v1alpha1`) via `FINDING_TO_ACTION` and a single
tool-name extractor. Proved multi-hop findings — especially
`llm_chain_replay` (out-of-band / chain reproduced) and live
`exfil_flow` — already name paths like `vault.read → net.send` in finding
detail, but the generator often emits **nothing** for those checks (no
`FINDING_TO_ACTION` entry for `llm_chain_replay`) or only one tool.

Operators who trust Priority Actions still get a weak or empty policy for
the highest-proof issues.

## Goal

When generating policy, proved chain / live-exfil findings produce
**flexible, hop-aware rules**:

| Hop | Nullfield action | Intent |
|-----|------------------|--------|
| **Sink** (last tool in the path) | `DENY` | Cut the egress / composition exit |
| **Source(s)** (earlier hops) | `HOLD` (timeout → DENY) | Human-gate feeders without hard-blocking every reader |

Reason strings cite proof strength (e.g. out-of-band, chain reproduced,
live exfil confirmed) so the YAML is auditable.

## Target-agnostic invariant

Same as Priority Actions: parse **mcpnuke finding shapes** only (check,
title markers, detail path syntax). No Camazotz, DVMCP, lab host, or
challenge-specific special cases in `mcpnuke/policy/`. Labs remain test
oracles only.

## Non-goals

- Changing Priority Actions ranking or impact/fix/verify prose
- Mapping every CRITICAL check into policy
- Encoding true “composition” semantics in nullfield (unsupported; we
  approximate with DENY sink + HOLD source)
- New CLI flag in this slice (`--policy-chain-mode` deferred)
- Treating “callable end-to-end (composition unproven)” or unconfirmed
  “Live exfil path” as proved for policy emission

## Design

### Proved finding gate

Emit hop-aware rules only when:

1. `check == "llm_chain_replay"` and title indicates
   - out-of-band confirmed, or
   - `Chain reproduced`
2. `check == "exfil_flow"` and title indicates `Live exfil confirmed`

All other findings keep today’s `FINDING_TO_ACTION` behavior unchanged.

### Path extraction

Chain-replay already writes tools into detail as:

```text
… (tool_a → tool_b → tool_c). …
```

Add a pure helper (e.g. `_extract_tool_path(finding) -> list[str]`) that:

1. Prefers an arrow-separated path (`→` or `->`) of ≥2 valid tool tokens
2. Else falls back to existing `_extract_tool_name` → a single-element list
3. Returns `[]` if nothing extractable (skip; do not invent tools)

Last element = sink; preceding = sources.

### Rule emission

For each proved finding with a non-empty path:

- Sink → `PolicyRule(action="DENY", tool_names=[sink], reason=…)`
- Each source → `PolicyRule(action="HOLD", tool_names=[source],
  hold={"timeout": "5m", "onTimeout": "DENY"}, reason=…)`

Suggested reason fragments (stable for tests):

- `proved chain sink (out-of-band)`
- `proved chain source (out-of-band)`
- `proved chain sink (reproduced)`
- `proved chain source (reproduced)`
- `proved live exfil sink`
- `proved live exfil source`

Prefix with `mcpnuke: ` as today.

Single-tool fallback: emit **DENY** only (no HOLD), reason notes
`single-tool proved finding`.

### Merge with existing generator

Keep `ACTION_PRIORITY` strictest-wins per tool:

`DENY` > `HOLD` > `SCOPE` > `ALLOW(+budget)`.

If a sink is already DENY from `webhook_persistence`, it stays DENY;
append the proved-chain reason when merging reasons (same pattern as
today). Default deny `*` rule remains last.

Order of processing: existing check-mapped findings first, then proved
hop rules (or interleaved — outcome must be identical given strictest
wins). Prefer one clear pass: collect candidates from both sources, then
merge.

### Module layout

Prefer extending `mcpnuke/policy/generator.py` (+ small helpers) rather
than a new package. Keep credential/check pattern invariants untouched.
Optionally add `mcpnuke/policy/chains.py` if the path parser + gate
exceed ~80 lines — only if clarity wins.

### CLI / docs

No new flags. Document in `CHANGELOG.md`, `QUICKSTART.md` (policy loop),
and `docs/cli-reference.md` that proved chains yield DENY sink + HOLD
sources. Docs tests: guard a stable phrase if `TestChainReplayDocsCurrency`
or policy docs currency already exists; otherwise add a focused assertion
in `tests/test_docs_current.py` / policy tests.

## Tests (`tests/test_policy_generation.py` or sibling)

Minimum:

1. OOB chain detail `a → b` → DENY `b`, HOLD `a`
2. Reproduced chain same shape
3. Live exfil confirmed `source → sink` in title/detail → DENY sink, HOLD source
4. Callable / unproven chain → no hop-aware rules from that finding
5. Single extractable tool on proved finding → DENY that tool only
6. Conflict: webhook DENY on sink + proved chain → still DENY sink
7. AST/string ban: no lab host / Camazotz / DVMCP in `mcpnuke/policy/`
8. Serialization still valid NullfieldPolicy YAML

Camazotz / DVMCP JSON oracles optional smoke (not required in CI): generate
policy from recorded deep-scan findings and assert sink DENY appears for
OOB paths when tool names parse.

## Success criteria

- Proved multi-hop findings produce DENY(sink) + HOLD(source*) in YAML
- Unproved composition does not
- Existing policy tests stay green; strictest-wins preserved
- Target-agnostic invariant held
- Full suite green before commit; push deferred until operator asks
