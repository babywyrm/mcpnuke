---
name: mcpnuke-add-check
description: >-
  Create a new mcpnuke security check module end-to-end: pattern file,
  check function, wire into run_all_checks, add tests, update changelog.
  Use when adding a new security check to mcpnuke.
---

# Add a New mcpnuke Check

## Gather Info

1. **Check name** — snake_case (e.g. `jwt_audience`, `ssrf_probe`)
2. **Check type** — static (metadata only) or behavioral (calls tools)
3. **What it detects** — one sentence
4. **Severity** — CRITICAL / HIGH / MEDIUM / LOW
5. **Taxonomy ID** — MCP-T## from the playbook (if applicable)

## File Locations

```
mcpnuke/
├── patterns/rules.py          # Static regex patterns
├── patterns/probes.py         # Behavioral probe payloads
├── checks/
│   ├── __init__.py            # run_all_checks() — wire new check here
│   ├── your_check.py          # New check module
│   └── base.py                # time_check helper
├── core/constants.py          # ATTACK_CHAIN_PATTERNS — add chains here
tests/
├── test_your_check.py         # Unit tests
├── test_dvmcp.py              # DVMCP integration tests
```

## Step-by-Step

### 1. Add patterns (if static check)

Edit `mcpnuke/patterns/rules.py`:

```python
YOUR_CHECK_PATTERNS = [
    r"pattern_one",
    r"pattern_two",
]
```

### 2. Create the check module

Create `mcpnuke/checks/your_check.py`:

```python
"""Description of what this check detects."""

import re

from mcpnuke.core.models import ProbeOpts, TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.patterns.rules import YOUR_CHECK_PATTERNS


def check_your_check(result: TargetResult):
    with time_check("your_check", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name + " "
                + tool.get("description", "")
                + " " + str(tool.get("inputSchema", {}))
            )
            for pat in YOUR_CHECK_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    result.add(
                        "your_check",
                        "SEVERITY",
                        f"Finding title for tool '{name}'",
                        f"Detail: {pat}",
                        evidence=combined[:300],
                    )
                    break
```

For **behavioral checks**, accept `session` and `probe_opts`:

```python
def check_your_check(session, result: TargetResult, probe_opts: ProbeOpts | None = None):
    opts = probe_opts or {}
    with time_check("your_check", result):
        # Call tools, analyze responses
        pass
```

### 3. Wire into run_all_checks

Edit `mcpnuke/checks/__init__.py`:

1. Add import at top:
```python
from mcpnuke.checks.your_check import check_your_check
```

2. Add call in appropriate phase:
   - **Static checks** section (always run)
   - **Behavioral checks** section (gated on `not no_invoke`)
   - **Deep probes** section (gated on `not no_invoke`, accept `probe_opts`)

### 4. Add attack chain patterns (if applicable)

Edit `mcpnuke/core/constants.py`, add to `ATTACK_CHAIN_PATTERNS`:

```python
("your_check", "code_execution"),
("input_sanitization", "your_check"),
```

### 5. Write tests

Create `tests/test_your_check.py`:

```python
"""Tests for your_check."""

import pytest
from mcpnuke.core.models import TargetResult
from mcpnuke.checks.your_check import check_your_check


def test_your_check_positive(result_with_tools):
    r = result_with_tools([{
        "name": "vuln_tool",
        "description": "Description that matches pattern",
        "inputSchema": {},
    }])
    check_your_check(r)
    assert any(f.check == "your_check" for f in r.findings)


def test_your_check_clean(result_with_tools):
    r = result_with_tools([{
        "name": "safe_tool",
        "description": "Nothing suspicious here",
        "inputSchema": {},
    }])
    check_your_check(r)
    assert not any(f.check == "your_check" for f in r.findings)


def test_your_check_timing(result_with_tools):
    r = result_with_tools([{"name": "x", "description": "y", "inputSchema": {}}])
    check_your_check(r)
    assert "your_check" in r.timings
```

### 6. Run tests

```bash
uv run pytest tests/test_your_check.py tests/test_checks_integration.py -v
```

### 7. Update CHANGELOG.md

Add under `[Unreleased]` → `### Added`.

## Workflow Integration

This skill works with superpowers:
- **test-driven-development** — write tests (step 5) BEFORE the check module (step 2). RED first.
- **verification-before-completion** — run full suite before claiming done.
- **systematic-debugging** — if tests fail, form hypothesis before changing code.

## Checklist

- [ ] Patterns added to `rules.py` or `probes.py`
- [ ] Tests written FIRST and failing (TDD RED phase)
- [ ] Check module created in `checks/` (TDD GREEN phase)
- [ ] Imported and called in `checks/__init__.py`
- [ ] Attack chains added to `constants.py` (if applicable)
- [ ] Full test suite passing: `uv run pytest tests/ -v`
- [ ] CHANGELOG updated
