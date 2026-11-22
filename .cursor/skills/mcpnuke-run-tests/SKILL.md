---
name: mcpnuke-run-tests
description: >-
  Run mcpnuke's test suite, interpret failures, and fix issues. Use when
  running tests, debugging test failures, or verifying changes in mcpnuke.
---

# Run mcpnuke Tests

## Quick Reference

All commands use `uv run` — no venv activation needed.

```bash
# Full suite
uv run pytest tests/ -v

# Specific test file
uv run pytest tests/test_dvmcp.py -v

# Specific test class
uv run pytest tests/test_dvmcp.py::TestDVMCPChallenge1PromptInjection -v

# Specific test
uv run pytest tests/test_dvmcp.py::TestDVMCPChallenge1PromptInjection::test_ignore_instructions_payload -v

# Stop on first failure
uv run pytest tests/ -v -x

# With output capture disabled (see print statements)
uv run pytest tests/ -v -s
```

## Test Categories

| File | What it tests | Needs network? |
|------|--------------|----------------|
| `test_dvmcp.py` | All 10 DVMCP challenges (offline) | No |
| `test_dvmcp.py::TestDVMCPLive` | Live DVMCP servers; each scan must finish complete | Yes (`DVMCP_LIVE=1`, `DVMCP_HOST`, `DVMCP_PORT_OFFSET`) |
| `test_lab_baselines.py` (live tests) | Live camazotz; static and safe invoke scans must finish complete | Yes (`CAMAZOTZ_LIVE=1`, `CAMAZOTZ_URL`) |
| `test_oss_targets.py` | Real OSS servers over stdio; snapshot match and complete scan | Yes (`MCPNUKE_OSS_TARGETS=1`) |
| `test_cli.py` | CLI argument parsing | No |
| `test_diff.py` | Differential scanning | No |
| `test_patterns.py` | Regex pattern matching | No |
| `test_rate_limit.py` | Rate limit check | No |
| `test_prompt_leakage.py` | Prompt leakage check | No |
| `test_supply_chain.py` | Supply chain check | No |
| `test_checks_integration.py` | Cross-check integration | No |
| `test_k8s.py` | K8s checks and discovery | No |
| `test_fast_sampling.py` | Tool scoring and sampling | No |
| `test_webhook_persistence.py` | Webhook persistence check | No |
| `test_response_credentials.py` | Response credential check | No |
| `test_exfil_flow.py` | Exfil flow check | No |
| `test_config_tampering.py` | Config tampering check | No |
| `test_credential_in_schema.py` | Schema credential check | No |
| `test_ssrf_probe.py` | SSRF probe check | No |
| `test_actuator_probe.py` | Actuator probe check | No |
| `test_public_targets.py` | Live public MCP servers | Yes (`MCP_PUBLIC_TARGETS=1`) |

## Interpreting Failures

### Import errors
Package not installed. Fix:
```bash
cd ~/mcpnuke && uv sync --all-extras
# Or just re-run quickstart:
./quickstart.sh --skip-tests
```

### Assertion errors in checks
A check isn't finding what it should. Look at:
1. The pattern in `patterns/rules.py` — does it match the test input?
2. The check function — is it scanning the right fields?
3. The test data — does the tool description actually contain the pattern?

### conftest.py fixtures
- `target_result` — TargetResult with one safe tool
- `result_with_tools` — factory: `result_with_tools([{...tool dicts...}])`

## After Fixing

Always re-run the full suite before committing:
```bash
uv run pytest tests/ -v --tb=short
```

Expected: 163+ passed, 36 skipped, 0 failed.

## Superpowers Integration

- **verification-before-completion** — always run the full suite before claiming work is done
- **systematic-debugging** — if a test fails, read the error, form a hypothesis, verify before fixing
- **test-driven-development** — when adding new checks, write tests FIRST
