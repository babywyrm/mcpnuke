---
name: mcpredator-run-tests
description: >-
  Run mcpredator's test suite, interpret failures, and fix issues. Use when
  running tests, debugging test failures, or verifying changes in mcpredator.
---

# Run mcpredator Tests

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
| `test_dvmcp.py::TestDVMCPLive` | Live DVMCP servers | Yes (`DVMCP_LIVE=1`) |
| `test_cli.py` | CLI argument parsing | No |
| `test_diff.py` | Differential scanning | No |
| `test_patterns.py` | Regex pattern matching | No |
| `test_rate_limit.py` | Rate limit check | No |
| `test_prompt_leakage.py` | Prompt leakage check | No |
| `test_supply_chain.py` | Supply chain check | No |
| `test_checks_integration.py` | Cross-check integration | No |
| `test_k8s.py` | K8s checks and discovery | No |
| `test_public_targets.py` | Live public MCP servers | Yes (`MCP_PUBLIC_TARGETS=1`) |

## Interpreting Failures

### Import errors
Package not installed. Fix:
```bash
cd ~/mcprowler && uv pip install -e ".[dev]"
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

Expected: 115 passed, 36 skipped, 0 failed.
