# Lab Baselines Design (Slice D)

**Date:** 2026-08-08  
**Status:** Implemented  
 
**Slice:** D of actionable-results roadmap (A → C → B → D)  
**Depends on:** Slice A/C (`reporting/priority.py`), Slice B (`policy/generator.py`)

## Problem

Slices A–C ship proof-ranked Priority Actions, guidance, and hop-aware
`--generate-policy`. Nothing in CI proves those contracts still hold against
realistic finding sets. Differential `--baseline` only detects *change*, not
“OOB must still outrank capability spam.”

## Goal

A **regression harness** that:

1. Loads **minimal committed scan fixtures** (findings only)
2. Re-runs `rank_priority_actions` and `generate_policy`
3. Asserts stable contracts (proof tier on top, guidance non-empty, hop DENY/HOLD)

Labs (Camazotz, DVMCP) are **oracles that seed fixtures**. Production code
stays target-agnostic. Golden-image VMs (warbird / hammerhand / artifice) are
**out of scope** — they are not assumed MCP-facing.

## Target-agnostic invariant

Fixtures may contain lab-shaped findings as data. Assertions key on **finding
shapes** (check, title markers, arrow paths), never on hostname allowlists in
`mcpnuke/reporting/` or `mcpnuke/policy/`. Any MCP-shaped scan that emits the
same shapes must satisfy the same contracts.

## Design

### Fixtures

Path: `tests/fixtures/scans/` (gitignored exception for `*.json` here).

Minimal schema per file:

```json
{
  "name": "proved_chain_outranks_capability_spam",
  "description": "OOB + reproduced + excessive_permissions pile",
  "findings": [
    {
      "check": "...",
      "severity": "...",
      "title": "...",
      "detail": "...",
      "taxonomy_id": ""
    }
  ]
}
```

- No `evidence` blobs (secret surface).
- Target URL fixed to `http://fixture.example/mcp` when materializing `Finding`s.
- Seeded from Camazotz / DVMCP deep scans, then trimmed to the findings needed
  for the asserts (not full 475-finding dumps).

### Offline tests (`tests/test_lab_baselines.py`)

Always run in CI:

1. **Camazotz-shaped proved scan** — top `priority_actions[0].reason` is
   out-of-band (or reproduced if no OOB in fixture); score ≥ 800; guidance
   non-empty; `excessive_permissions` not rank 1 when OOB present.
2. **Proved multi-hop policy** — `generate_policy` DENYs sink, HOLDs source.
3. **DVMCP-shaped challenge findings** — ranking produces non-empty guidance;
   no crash; unproven composition does not invent hop DENYs.
4. **Lab-string ban** — reaffirm `priority.py` / `policy/` have no lab host
   special cases (shared with existing tests or duplicated once).

### Optional live smoke

Gated:

- `CAMAZOTZ_LIVE=1` against `http://localhost:8080/mcp` (or `CAMAZOTZ_URL`)
- existing `DVMCP_LIVE=1` remains for challenge transport tests

Live Slice D asserts are soft: if an OOB/reproduced finding exists in the live
result, it must appear in the top priority actions. Skip (not fail) when the
lab is down.

### Non-goals

- Scanning warbird / hammerhand / artifice / lombardi
- Requiring NUC-hosted MCP for CI
- New CLI flags
- Changing risk_score or raw finding severities
- Full-scan golden diffs (too brittle / large)

## Success criteria

- Offline fixture tests green in full suite
- Fixtures small and secret-free
- Live gates optional
- A/C/B contracts cannot regress silently
