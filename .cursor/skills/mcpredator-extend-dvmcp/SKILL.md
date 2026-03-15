---
name: mcpredator-extend-dvmcp
description: >-
  Add new DVMCP challenge test classes to mcpredator's test suite following
  the established pattern. Use when adding tests for a new vulnerability
  type or DVMCP challenge.
---

# Extend mcpredator DVMCP Tests

## Test File

All DVMCP tests live in `tests/test_dvmcp.py`.

## Existing Structure

```python
# Helpers
def _make(tools, url=..., resources=None, prompts=None) -> TargetResult
def _checks_found(result) -> set[str]
def _severities(result) -> set[str]

# Per-challenge classes
class TestDVMCPChallenge1PromptInjection:     # Ch1, port 9001
class TestDVMCPChallenge2ToolPoisoning:        # Ch2, port 9002
class TestDVMCPChallenge3Permissions:          # Ch3, port 9003
class TestDVMCPChallenge4RugPull:              # Ch4, port 9004
class TestDVMCPChallenge5TokenTheft:           # Ch5, port 9005
class TestDVMCPChallenge6CodeExecution:        # Ch6, port 9006
class TestDVMCPChallenge7RemoteAccess:         # Ch7, port 9007
class TestDVMCPChallenge8RateLimitAndLeakage:  # Ch8, port 9008
class TestDVMCPChallenge9SupplyChain:          # Ch9, port 9009
class TestDVMCPChallenge10MultiVector:         # Ch10, port 9010

# Pipeline integration
class TestDVMCPFullPipeline:

# Live tests (skipped by default)
class TestDVMCPLive:
```

## Adding a New Challenge Class

### Template

```python
class TestDVMCPChallengeNYourCheck:
    """DVMCP Challenge N: description."""

    def test_positive_case(self):
        """Tool with vuln pattern should be flagged."""
        r = _make([{
            "name": "vuln_tool",
            "description": "Description containing vulnerable pattern",
            "inputSchema": {"properties": {}},
        }])
        check_your_check(r)
        assert "your_check" in _checks_found(r)
        assert "EXPECTED_SEVERITY" in _severities(r)

    def test_variant(self):
        """Different variant of the same vuln class."""
        r = _make([{
            "name": "another_tool",
            "description": "Different trigger pattern",
            "inputSchema": {"properties": {"param": {"type": "string"}}},
        }])
        check_your_check(r)
        assert "your_check" in _checks_found(r)

    def test_clean_tool_not_flagged(self):
        """Clean tool should not trigger this check."""
        r = _make([{
            "name": "safe_tool",
            "description": "Completely benign tool",
            "inputSchema": {"properties": {}},
        }])
        check_your_check(r)
        assert "your_check" not in _checks_found(r)
```

### Guidelines

1. **Import** your check at the top of the file with the other imports
2. **3-5 tests per class** — positive cases, variants, and one clean/negative case
3. **Use `_make()`** helper, not raw `TargetResult` construction
4. **Assert both** check name and severity
5. **Test data should be realistic** — mirror what a real MCP server might expose

### Adding Live Tests

Add a parametrized port to `TestDVMCPLive` if adding a new challenge server:

```python
DVMCP_PORTS = list(range(9001, 9011))  # extend range if needed
```

## Run

```bash
uv run pytest tests/test_dvmcp.py -v
```
