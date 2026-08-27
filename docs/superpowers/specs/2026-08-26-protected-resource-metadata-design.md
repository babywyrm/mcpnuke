# Protected resource metadata and CIMD advertisement

**Status:** Implemented 2026-08-26
**Date:** 2026-08-26
**Follows:** `docs/spec-surface.md` (CIMD/issuer gap)

## Problem

MCP 2026-07-28 made RFC 9728 Protected Resource Metadata mandatory for
resource servers, deprecated DCR in favour of CIMD, and required issuer-bound
client credentials. mcpnuke speaks none of that as a *scan subject*.

CIMD itself is an authorization-server fetch of a client-hosted HTTPS
`client_id` URL. Issuer-bound credentials and RFC 9207 `iss` on the
authorization *response* are client homework. Neither is a thing we can
probe on an MCP resource server without pretending to be an OAuth client.

What we can see from outside, with the same silence-when-absent rule as
`list_cache`:

1. The RFC 9728 document (WWW-Authenticate `resource_metadata` or
   `/.well-known/oauth-protected-resource`).
2. The AS metadata flag `client_id_metadata_document_supported`.

## Non-goals

- Flagging missing PRM (would fire on almost every server).
- Relabeling `jwt_issuer` as RFC 9207.
- Registering a CIMD `client_id`, DCR, WIF, ID-JAG, token exchange.
- Changing a shipped `taxonomy_id`.
- Stdio (no HTTP well-known).

## Behavior

New check `protected_resource_metadata` (HTTP only, runs under `--no-invoke`).

1. Skip without `post_url`.
2. If `post_raw` exists, send `tools/list`. On HTTP 401/403, parse
   `resource_metadata` from `WWW-Authenticate` and try that URL first.
3. Then well-known path insertion, then root well-known (MCP order).
4. A document counts as PRM only if it is JSON with a non-empty `resource`
   string. HTML, 404, and other JSON are silence; try the next URL.
5. PRM with missing/empty `authorization_servers` → HIGH (MCP MUST include it).
6. An `authorization_servers` URL that is not HTTPS and not loopback → MEDIUM.
7. Fetch the first AS metadata (RFC 8414 then OIDC well-known). If
   `issuer` in the document differs from the issuer URL → HIGH, stop.
8. If that document has `registration_endpoint` and
   `client_id_metadata_document_supported` is not true → MEDIUM
   (DCR advertised, CIMD not). Pre-registration-only AS (neither field)
   is silence.

No `taxonomy_id`. Lane 5 / transport A.

## FP

Reference HTTP fixture and OSS stdio targets have no PRM → 0 new findings.
A new finding that raises the HTTP FP ceiling is a regression.
