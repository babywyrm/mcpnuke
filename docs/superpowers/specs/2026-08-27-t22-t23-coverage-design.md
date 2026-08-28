# T22 / T23 static coverage

**Status:** Approved 2026-08-27 (next after stdio rate-limit)
**Date:** 2026-08-27
**Follows:** ROADMAP remaining true gaps T22/T23

## Problem

MCP-T22 (Execution Context Forgery) has no check. MCP-T23 (Credential
Isolation & Sidecar Tampering) was listed as “tag `credential_in_schema`”
which would be a lie: that check is hardcoded secrets in `tools/list`
(MCP-T07), not sidecar isolation.

## Decision

Two thin static detectors in `taxonomy_coverage.py`, same shape as T34/T35.

- **T22 `execution_context_forgery`** — HIGH when a tool takes a caller-supplied
  identity *substitution* parameter (`on_behalf_of`, `as_user`, `acting_as`,
  `claimed_identity`, `execution_context`, `run_as_user`, `impersonate_user`,
  `actor_id`, …), including camelCase (`onBehalfOf`). Bare `user_id` is not
  T22. Tool *names* are not matched (avoids `as_user` inside `has_users`).
  Lane 4.
- **T23 `sidecar_credential_tamper`** — HIGH when name/description pair
  sidecar with secret/credential/token/broker, or params named
  `secret_mount` / `credential_broker` / `sidecar`. Not a generic
  `volume_mount` or a logging sidecar. Do not retag `credential_in_schema`.
  Lane 2.

Silent on the reference target (`file.read`, `http.fetch`, …). FP ceilings
unchanged.

## Non-goals

- Behavioral probes / live Camazotz lab exploits.
- Retagging `credential_in_schema` as T23.
- Version bump.
