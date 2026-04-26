# `--by-lane` and `--coverage-report` — Design

**Date:** 2026-04-26
**Status:** Design pending review, implementation pending
**Related:**
- [Identity Flow Framework](https://github.com/babywyrm/agentic-sec/blob/main/docs/identity-flows.md) (agentic-sec hub)
- Camazotz `/api/lanes` schema v1 ([babywyrm/camazotz PR shipping 2026-04-26](https://github.com/babywyrm/camazotz))
- Companion spec: `nullfield/docs/specs/2026-04-26-per-lane-policy-templates.md`

---

## Goal

Teach mcpnuke to speak the **agentic-identity lane vocabulary** so its scan
output can be grouped by lane (for human review) and intersected with a
target camazotz deployment's coverage (for cross-project reporting).

Three concrete deliverables:

1. **Lane + transport on every `Finding`.** Add `lane: int | None` and
   `transport: str | None` fields to the `Finding` dataclass and backfill
   every existing check so its emissions populate them.
2. **`mcpnuke --by-lane`** — a new CLI flag that groups findings by lane
   (1–5), shows per-lane severity tallies, and highlights lanes where
   checks fired but expected ones didn't. Text and JSON output.
3. **`mcpnuke --coverage-report <camazotz-url>`** — a new CLI flag that
   fetches `GET /api/lanes` (schema v1) from a running camazotz instance
   and emits a cross-project coverage report intersecting mcpnuke's
   finding catalog with camazotz's lane distribution.

## Non-Goals

- Changing any check's detection logic. This is a *labelling + reporting*
  change, not a coverage-improvement change.
- A GUI. `--by-lane` output is text (default) or JSON (`--json`).
- Running policy generation from `--coverage-report`. That already exists
  under `--generate-policy`; this is a diagnostic, not a remediation.
- Teaching what each lane *is*. See `agentic-sec/docs/identity-flows.md`.

## Constraints

- **Lane IDs and transport codes must match camazotz.** Source of truth is
  `camazotz/frontend/lane_taxonomy.py::LANES` and the schema v1 endpoint
  at `GET /api/lanes`. Valid lane IDs: `1..5`. Valid transports: `A`, `B`,
  `C`. Do not invent new ones in this repo.
- **Backwards compatibility.** Existing consumers of the JSON report must
  not break when `lane` and `transport` fields appear as nullable additions
  to each finding.
- **Offline by default.** `--by-lane` works against any scan (no network
  dependency). Only `--coverage-report` needs a reachable camazotz.

---

## Deliverable 1 — Lane and transport on every finding

### Dataclass change

`mcpnuke/core/models.py`:

```python
@dataclass
class Finding:
    target: str
    check: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""
    lane: int | None = None          # 1..5 or None if not lane-scoped
    transport: str | None = None     # "A" | "B" | "C" or None
```

Both new fields default to `None` so existing check emissions remain valid
until they opt in. Serialization: `None` → JSON `null`, not omitted, so
downstream tooling can tell "not labelled" from "no field present".

### Per-check backfill

Every file under `mcpnuke/checks/` gets its emissions updated to pass the
appropriate `lane=` and `transport=` arguments based on what that check
actually probes. The implementation plan will ship the full mapping table;
the spec commits to the vocabulary, not each individual assignment.

Indicative examples (not the full list):

| Check | `lane` | `transport` | Rationale |
|-------|--------|-------------|-----------|
| OIDC discovery / scope analysis | 1 | A | Direct human OIDC |
| Token exchange audience confusion | 2 | A | Delegated flow |
| Teleport proxy discovery | 3 | A | Machine identity |
| `act` chain depth probe | 4 | A | Agent chain |
| Pre-auth `tools/list` enumeration | 5 | A | Anonymous |
| SSRF against `/api/*` direct routes | 1 | B | Human, direct API |
| Supply chain via loaded SDK | 3 | C | Machine, SDK |

### Non-lane-scoped checks stay `lane=None`

Not every check is lane-scoped. Rate limiting, TLS hygiene, generic HTTP
surface checks may be lane-agnostic. Those keep `lane=None, transport=None`
and report under an "Uncategorized" bucket in `--by-lane`.

---

## Deliverable 2 — `mcpnuke --by-lane`

### Text output

```
$ mcpnuke --targets http://example/mcp --fast --no-invoke --by-lane

=== Lane 1 — Human Direct (human-direct, transport A) ===
  HIGH   oidc.discovery       — /.well-known/openid-configuration exposed without TLS
  MED    scope.analysis       — Token scopes wider than requested
  Coverage: 2 checks fired / 3 lane-1 checks exist (1 did not fire)

=== Lane 2 — Delegated (delegated, transport A) ===
  HIGH   token.audience       — Downstream token carries parent audience
  Coverage: 1 / 2

=== Lane 3 — Machine (machine, transport A+C) ===
  CRIT   teleport.role.escalation — Bot role grants admin scope
  Coverage: 1 / 4

=== Lane 4 — Chain (chain, transport A) ===
  (no findings fired)
  Coverage: 0 / 2  ← GAP

=== Lane 5 — Anonymous (anonymous) ===
  INFO   tools.list.preauth   — tools/list reachable without authentication
  Coverage: 1 / 1

=== Uncategorized ===
  LOW    tls.cipher.weak      — Weak cipher suite advertised
  (not lane-scoped)
```

### JSON output (`--json --by-lane`)

```json
{
  "schema": "v1",
  "by_lane": {
    "1": {
      "slug": "human-direct",
      "transports_hit": ["A"],
      "findings": [ ... ],
      "checks_fired": 2,
      "checks_defined": 3
    },
    "2": { ... },
    ...
    "uncategorized": { "findings": [ ... ] }
  }
}
```

The `checks_defined` count comes from mcpnuke's own check registry
(self-contained — does not require camazotz to be reachable).

---

## Deliverable 3 — `mcpnuke --coverage-report <camazotz-url>`

### Behavior

```
$ mcpnuke --targets http://example/mcp --fast --no-invoke \
    --coverage-report http://camazotz.example:3000

Fetching lane taxonomy from http://camazotz.example:3000/api/lanes ...
schema=v1, 5 lanes, 32 labs indexed

=== Cross-project coverage ===

Lane 1 — Human Direct
  camazotz: 6 primary labs, transports present [A, B]
  mcpnuke:  3 lane-1 checks, 2 fired on this scan
  Gap:      camazotz declares Transport C gap; no lane-1 check probes SDK surface → aligned

Lane 2 — Delegated
  camazotz: 12 primary labs, transports present [A, B]
  mcpnuke:  2 lane-2 checks, 1 fired
  Gap:      no lane-2 check covers `audienceMustNarrow`; camazotz oauth_delegation_lab would flag this

Lane 4 — Chain
  camazotz: 6 primary labs, transports present [A]
  mcpnuke:  2 lane-4 checks, 0 fired
  Gap:      check did not fire — either chain is disabled or check regressed
...

=== Summary ===
  mcpnuke covers 4/5 lanes on this target
  Lane 4 has the largest covered-not-firing gap
  Recommended next checks to add: [lane-2 audienceMustNarrow, lane-3 Transport C]
```

### Implementation sketch

1. `httpx.get(<base>/api/lanes)` with explicit timeout.
2. Validate `schema == "v1"`; refuse to proceed on mismatch with a clear
   error ("camazotz schema vX incompatible; mcpnuke supports v1 — update
   one side").
3. Intersect `body["lanes"]`, `body["coverage"]`, `body["labs"]` with
   mcpnuke's in-memory finding set produced by the current scan.
4. Emit either human-readable text (default) or JSON (`--json`).

### Failure modes

| Failure | Behavior |
|---------|----------|
| `/api/lanes` unreachable | Fail fast, exit non-zero, clear error message |
| Schema version mismatch | Fail fast with version number + update guidance |
| Scan produced zero findings | Report emits "no scan data to intersect" + lane listing only |
| Check with `lane=None` | Reported under "Uncategorized" in the cross-report |

---

## Implementation Surface

### New files

- `mcpnuke/reporting/by_lane.py` — grouping + text/JSON renderers
- `mcpnuke/reporting/coverage_report.py` — schema v1 client + intersector
- `tests/test_by_lane_report.py`
- `tests/test_coverage_report.py`

### Modified files

- `mcpnuke/core/models.py` — `lane` and `transport` on `Finding`
- `mcpnuke/cli.py` — two new flags: `--by-lane`, `--coverage-report`
- Every file under `mcpnuke/checks/` — pass `lane=`/`transport=` where
  appropriate (`None` elsewhere)
- `README.md` — document the two new flags
- `QUICKSTART.md` — add a "Coverage report against a camazotz target"
  section
- `CHANGELOG.md`

### Tests

- Unit: grouping correctness, schema-v1 parsing, version-mismatch rejection.
- Integration: scan a local camazotz via Docker Compose, run
  `--coverage-report http://localhost:3000`, assert the output names all
  five lanes and correctly flags Lane 4 as the widest gap (per the
  migrated camazotz corpus at the time of shipping).
- Regression: existing JSON output schema remains readable by prior
  consumers (new nullable fields, no renames, no removals).

---

## Acceptance Criteria

1. `mcpnuke --by-lane` groups findings by lane, shows per-lane severity
   counts and a "fired / defined" coverage fraction.
2. `mcpnuke --json --by-lane` emits the structured variant with the
   documented `schema: "v1"` wrapper.
3. `mcpnuke --coverage-report <camazotz-url>` fetches schema v1 from
   camazotz, intersects with the finding catalog, and emits a report
   that names every lane camazotz knows about.
4. Schema mismatch (`schema != "v1"`) fails loudly with guidance.
5. Every check in `mcpnuke/checks/` has an explicit `lane` and
   `transport` value (possibly `None`) — no silent defaults.
6. Existing JSON consumers still parse the report (nullable-only
   additions, verified by a contract test).

---

## Ecosystem Coupling

- **Lane IDs + slugs + transport codes** are the vocabulary published by
  camazotz `/api/lanes` schema v1. If that vocabulary changes, this spec
  moves with it.
- **Reporting format** must remain forward-compatible enough for the
  `feedback-loop.sh` script (in `agentic-sec/scripts/`) and any future
  CI integrations.
- **nullfield** integration: the per-lane starter policies defined in the
  companion nullfield spec will (in a later iteration, not this spec)
  be addressable by mcpnuke's `--generate-policy --by-lane` output —
  calling that out so we don't accidentally paint ourselves into a
  non-composable corner.

Three repos, one vocabulary, one feedback loop.

---

## Out of Scope (Future)

- Live streaming of lane coverage to an external dashboard.
- Auto-submitting coverage reports to a central agentic-sec registry.
- Historical trend reporting (scan N vs scan N-1 per lane).
- Per-lane baseline storage (baselines today are scan-wide, not lane-scoped).
