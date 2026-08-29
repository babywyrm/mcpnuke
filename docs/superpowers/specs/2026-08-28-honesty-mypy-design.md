# Honesty leftovers that earn their keep

**Status:** Approved 2026-08-28
**Date:** 2026-08-28
**Follows:** T22/T23; ROADMAP “honesty leftovers” + mypy ratchet

## In

- **`credential_in_schema` carries MCP-T07.** The module already claims T07;
  the finding did not. `--by-lane` and SARIF can see schema secrets the same
  way they see response secrets. Coverage count stays 42/57 (T07 already
  attributed).
- **`delegation_depth` stops matching `nested` / `depth` / `hop` alone.**
  Those fired on `@modelcontextprotocol/server-filesystem` `create_directory`
  (“nested directory”) and similar. Require a delegation signal: `delegate`,
  `*_agent`, or params `agent_id` / `target_agent` / `delegate_to`. Weak
  words only count next to agent/delegat language. Camazotz
  `delegation_depth.*` names still match.

## Out

- Tagging `code_execution` or aggregates — still not one Atlas ID.
- T11 — needs two auth contexts; not this slice.
- Inventing a multi-hop behavioral probe.

## Also

Lower `MYPY_CEILING` to the measured `uv run mypy mcpnuke/` count.
