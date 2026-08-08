# Priority Actions Slice C — Impact / Fix / Verify

**Date:** 2026-08-08  
**Status:** Implemented  

**Depends on:** Slice A (`reporting/priority.py`)

## Goal

Each `PriorityAction` carries operator-ready guidance:

- **impact** — what an attacker gains if unfixed  
- **fix** — concrete control change (auth, deny, sanitize, network)  
- **verify** — how to re-scan or probe to confirm the fix  

Target-agnostic: templates keyed by mcpnuke `check` + proof `reason` (and optional `taxonomy_id`), never lab tool names.

## Design

Extend `PriorityAction` with `impact`, `fix`, `verify` (non-empty strings).  
`guidance_for(check, reason, *, taxonomy_id="", collapsed=False)` in
`reporting/priority.py` (or `action_guidance.py`). Console prints them
indented under each rank; JSON includes the three keys.

Default fallback when check unknown: generic harden / re-scan guidance so
new checks never produce blank actions.
