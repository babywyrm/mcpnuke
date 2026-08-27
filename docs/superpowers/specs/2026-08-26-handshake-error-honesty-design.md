# Handshake error honesty

**Status:** Approved 2026-08-26 (live Camazotz/NUC)
**Date:** 2026-08-26

## Problem

NUC NodePort `:30080` returns HTTP 200 and JSON-RPC

`{"error":{"code":-32001,"message":"identity verification failed"}}`

`HTTPSession.call` returns that body. `negotiate_protocol` only treats
`"result"` as success, so all three probes fail, and `enumerate_server`
emits `init` / **No response to MCP initialize**. Transport detection
already succeeded. The server answered.

## Behavior

When every handshake probe fails:

- All probes returned `None` → keep **No response to MCP initialize**.
- At least one probe returned a JSON-RPC `error` object → `init` HIGH,
  lane 5 / transport A. Title and detail include the code and message.
  Do not say "no response".
- A later probe that returns `result` still wins (existing fallback).

## Non-goals

- Retargeting the Camazotz Service (`targetPort` 9090 vs 8080).
- New check names. CIMD. Taxonomy tagging of other checks (next commit).
