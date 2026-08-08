# Priority Actions Design

**Date:** 2026-08-08  
**Status:** Implemented (Slice A)  
**Slice:** A of actionable-results roadmap (A → C → B → D)

## Problem

Deep scans produce hundreds of findings at the same CRITICAL severity. On
Camazotz, `excessive_permissions` alone contributed 148 of 475 findings while
the highest-value signals — out-of-band chain egress, reproduced attack chains —
were buried in the same bucket. Users need a short, ordered list of what to fix
first, ranked by *proof*, without changing how individual checks emit severity
(which would break existing CI score expectations).

## Goal

After every scan, surface a **Priority Actions** list: the top N things to fix
first, ordered by evidence strength. Raw `findings[]` and `risk_score()` stay
unchanged.

## Target-agnostic invariant

Priority Actions rank **mcpnuke’s own finding shapes** (check name, title
markers, severity) — never hostnames, lab tool names, Camazotz/DVMCP IDs, or
challenge-specific strings. Any MCP target a red or blue teamer points at
(cloud SaaS, internal stdio server, K8s service, personal VM) gets the same
ranking rules. Camazotz, DVMCP, and operator VMs are **test oracles**, not
special cases in production code.

Success on a random target still means: proved chains (OOB / reproduced)
outrank capability inventory spam when both are present; if the scan only
found schema noise, the list honestly reflects that.

## Non-goals (this slice)

- Remediation / fix / verify prose on each action (Slice C)
- Stronger `--generate-policy` from proved chains (Slice B)
- Lab baseline harness (Slice D)
- Changing check severity assignments or `SEVERITY_WEIGHTS`

## Design

### Ranking module

New module: `mcpnuke/reporting/priority.py`

```python
@dataclass(frozen=True)
class PriorityAction:
    rank: int
    score: int
    reason: str          # why this rank (e.g. "out-of-band egress confirmed")
    title: str
    check: str
    severity: str
    target: str
    taxonomy_id: str
    finding_index: int   # index into TargetResult.findings, or -1 if collapsed
    collapsed_count: int # >1 when several findings were rolled up
```

```python
def rank_priority_actions(
    findings: list[Finding],
    *,
    limit: int = 10,
) -> list[PriorityAction]:
    ...
```

Pure function. No I/O, no LLM. Deterministic given the same finding list.

### Proof tiers (descending score)

| Tier | Score | Detection (any match) |
|------|------:|------------------------|
| OOB / live egress | 1000 | `check == "llm_chain_replay"` and title contains `out-of-band confirmed`; or `check == "exfil_flow"` and title contains `Live exfil confirmed` |
| Chain reproduced | 800 | `check == "llm_chain_replay"` and title contains `Chain reproduced` |
| Linked attack_chain | 700 | `check == "attack_chain"` |
| AI-judged movement | 600 | `check == "llm_chain_replay"` and title contains `AI-judged` |
| Live path (unconfirmed egress) | 500 | `check == "exfil_flow"` and title contains `Live exfil path` |
| High-signal behavioral | 400 | `check` in frozenset `{tool_response_injection, ssrf_probe, sdk_cache_tamper, deep_rug_pull}` and severity is CRITICAL or HIGH |
| Other CRITICAL / HIGH | 200 / 100 | residual findings by severity |
| MEDIUM / LOW | 40 / 10 | residual findings by severity |

A finding matches at most one tier (first match in the table order wins).  
Within a tier, tie-break: higher `SEVERITY_WEIGHTS`, then `check` ascending, then `title` ascending (stable).

### Collapse rules

Always collapse into **one** action per `(target, check)`:

- `excessive_permissions` (any count ≥ 1)

Also collapse when count for that check on the target is ≥ 5:

- `remote_access`
- `code_execution`
- `token_theft`

Collapsed action:

- `title`: `"{check}: {n} findings — review dangerous capability surface"`
- `reason`: `"collapsed capability noise ({n} findings)"`
- `score`: tier for that check’s max severity, **minus** 50 (so a single OOB always outranks a collapsed pile)
- `finding_index`: index of the first finding in the group
- `collapsed_count`: n

Non-collapsed findings each become their own candidate action.

### Limit

Default `limit=10`. Console and JSON both use the same default. No new CLI flag in slice A (can add `--priority-limit` later if needed).

### Console

In `reporting/console.py`, after the severity summary counts and before (or instead of only listing) raw attack-chain bullets, print:

```
Priority actions (fix these first)
  1. [CRITICAL] …title…  — out-of-band egress confirmed
  2. …
```

Omit the section entirely when `rank_priority_actions` returns empty (no findings).

### JSON

In `reporting/json_out.py`, each target object gains:

```json
"priority_actions": [
  {
    "rank": 1,
    "score": 1000,
    "reason": "out-of-band egress confirmed",
    "title": "...",
    "check": "llm_chain_replay",
    "severity": "CRITICAL",
    "taxonomy_id": "MCP-T51",
    "finding_index": 12,
    "collapsed_count": 1
  }
]
```

### Docs

- `docs/ai-analysis.md` — one short paragraph under Phase 4 / reporting: Priority Actions rank by proof.
- `docs/scan-modes.md` or methodology — one line that deep AI scans feed the priority list.
- `CHANGELOG.md` — Added bullet.
- Guard phrase in `TestChainReplayDocsCurrency` or a sibling docs test if we add a stable keyword (`priority actions`).

## Testing (TDD)

New file: `tests/test_priority_actions.py`

Minimum cases:

1. **OOB beats capability spam** — one `llm_chain_replay` OOB CRITICAL + 50 `excessive_permissions` CRITICAL → rank 1 is the OOB; collapsed permissions appear once, lower.
2. **Collapse** — 10 `excessive_permissions` → exactly one action with `collapsed_count == 10`.
3. **Reproduced vs AI-judged** — reproduced ranks above AI-judged.
4. **Live exfil confirmed vs path** — confirmed above unconfirmed path.
5. **Limit** — 20 diverse findings, `limit=5` → len == 5, ranks 1..5.
6. **Empty** — no findings → `[]`.
7. **JSON wiring** — `target_to_dict` (or equivalent) includes `priority_actions` with expected keys.
8. **Console** — capturing print output includes `Priority actions` when findings present; omitted when empty.

Wire tests use existing `Finding` / `TargetResult` constructors; no live network.

## Success criteria

- Synthetic fixture (no lab names required): one OOB chain finding + many
  `excessive_permissions` → top action is the OOB finding.
- Optional live oracles (Camazotz, DVMCP, operator VMs): same ranking behavior
  when those scans produce the same finding shapes — used to validate, not to
  specialize the ranker.
- Full related unit suite green; `ruff` clean on touched files.
- Existing risk scores and finding counts unchanged for the same scan inputs.

## Follow-on (not this PR)

- **C:** `impact` / `fix` / `verify` fields on `PriorityAction` (and optional Finding enrichment).
- **B:** policy generator prefers deny rules from priority_actions[0:N].
- **D:** lab baseline asserts `priority_actions[0].reason` matches OOB/reproduced on golden Camazotz flags.
