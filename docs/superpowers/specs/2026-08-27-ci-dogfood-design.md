# CI dogfood (CLI against the reference target)

**Status:** Implemented 2026-08-27
**Date:** 2026-08-27
**Follows:** ROADMAP near-term "CI dogfood"

## Problem

`tests.yml` runs pytest, ruff, and mypy. It never runs the `mcpnuke` CLI.
`.github/workflows/mcp-security-scan.yml` also fires on this repo's push/PR
and defaults to `http://localhost:8080/mcp`, which is not a server in CI.
That is not a self-scan; it is a miss.

The false-positive harness already drives `enumerate_server` + `run_all_checks`
against `tests/reference_target/`. The missing piece is the console entry
point: JSON out, `--fail-on none`, `--auth-token`.

## Non-goals

- Live DVMCP / Camazotz / `--claude` / Bedrock in default CI.
- Changing the HTTP or stdio FP ceilings.
- A Python-version matrix for the dogfood job (pytest already covers 3.11–3.13).
- PyPI publish.

## Behavior

1. `tests/test_cli_dogfood.py` starts the in-repo HTTP reference target and
   runs `python -m mcpnuke --fast --no-invoke --fail-on none --json`. Exit 0,
   JSON has a target with tools, CRITICAL/HIGH findings are only those the
   FP harness already allows.
2. Same for `--stdio` against `tests.reference_target.stdio_server`.
3. `tests.yml` gains a named `dogfood` job that runs that test file so the
   GitHub check is visible.
4. `mcp-security-scan.yml` is `workflow_call` only. Consumers still pass
   `target`. This repo no longer pretends to scan `:8080`.

## FP

The CLI scan uses `--fail-on none` so known HIGH findings (DPoP, filesystem,
network) do not fail CI. Unexpected HIGH still fails the pytest assertion.
