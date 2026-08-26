# Taxonomy field honesty

**Status:** Approved 2026-08-26 (track 1 of proofing/modernizing)
**Date:** 2026-08-26
**Follows:** ROADMAP.md coverage callout; `tests/test_taxonomy_coverage_claim.py`

## Problem

Coverage claims 40/57 IDs. Two of those IDs never reach `Finding.taxonomy_id`:

- `ssrf_probe` is MCP-T06 in its docstring and is the SSRF check; findings omit the field. T06 is only counted because `profile.py`’s schema example contains `"threat_id": "MCP-T06"` (the ROADMAP “profile” story).
- `dpop_enforcement` puts MCP-T43 in the evidence dict only.

SARIF tags and `--by-lane` read the field, so both threats are invisible there.

`shell_injection` emits MCP-T54. `lanes.yaml` defines T54 as unauthenticated inference backend exposure (`inference_backend.py` already owns that). T53 is shell command wrapping. The static cousin `shell_wrapping_injection` already emits T53; the behavioral probe should match.

## Behavior

1. Every `ssrf_probe` finding sets `taxonomy_id="MCP-T06"`.
2. Every DPoP finding sets `taxonomy_id="MCP-T43"` (evidence may still mention the id).
3. `shell_injection` findings set `taxonomy_id="MCP-T53"`, including the dangerous-base HIGH.
4. `test_taxonomy_coverage_claim.py`: evidence-only set is empty. Coverage numerator stays 40 (same IDs, now structural).
5. ROADMAP callout records the three as fixed. Historical tables stay labeled stale.

## Non-goals

- Wait-column SEPs. CIMD. 6.17.0 (next commit after this is green).
- Rewriting every stale ROADMAP ID table in this slice.
