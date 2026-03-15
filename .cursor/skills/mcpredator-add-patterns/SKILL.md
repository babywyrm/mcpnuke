---
name: mcpredator-add-patterns
description: >-
  Add new regex detection patterns to mcpredator's pattern libraries with
  test coverage. Use when adding new patterns to rules.py or probes.py,
  or when extending detection for a vulnerability class.
---

# Add mcpredator Patterns

## Pattern Files

| File | Purpose | Used By |
|------|---------|---------|
| `mcpredator/patterns/rules.py` | Static regex for metadata analysis | Static checks (injection, permissions, theft, etc.) |
| `mcpredator/patterns/probes.py` | Probe payloads and response analysis | Behavioral checks (tool_probes, resource_poisoning) |

## Adding Static Patterns

### 1. Define the pattern list in `rules.py`

```python
YOUR_PATTERNS = [
    r"pattern_one",
    r"pattern_two",
]
```

Pattern guidelines:
- Use raw strings (`r"..."`)
- Case-insensitive matching is done by the caller (`re.IGNORECASE`)
- Use `\s+` for whitespace, `\b` for word boundaries
- Use `.{0,30}` for bounded wildcards (not `.*`)
- Test each pattern against both positive and negative examples

### 2. Add tests in `tests/test_patterns.py`

```python
def test_your_patterns_match():
    text = "String that should match"
    matches = [p for p in YOUR_PATTERNS if re.search(p, text, re.IGNORECASE)]
    assert len(matches) >= 1


def test_your_patterns_no_false_positive():
    text = "Normal safe string"
    matches = [p for p in YOUR_PATTERNS if re.search(p, text, re.IGNORECASE)]
    assert len(matches) == 0
```

### 3. Run tests

```bash
uv run pytest tests/test_patterns.py -v
```

## Adding Probe Payloads

### In `probes.py`

Injection probes (sent to tools):
```python
YOUR_PROBES = [
    f"payload_with_{CANARY}",
    "payload_two",
]
```

Response analysis patterns (checked in tool output):
```python
YOUR_RESPONSE_PATTERNS = [
    r"pattern_to_find_in_responses",
]
```

Rules:
- Probes should be **safe** — they test for vuln without causing damage
- Use the `CANARY` string (`MCP_PROBE_8f4c2a`) to detect reflection
- Response patterns use the same regex conventions as `rules.py`

## Existing Pattern Sets (reference)

| Name | Count | Purpose |
|------|-------|---------|
| `INJECTION_PATTERNS` | 19 | Prompt injection in metadata |
| `POISON_PATTERNS` | 11 | Hidden instructions, exfil hints |
| `DANGEROUS_TOOL_PATTERNS` | 8 categories | Dangerous capabilities |
| `TOKEN_THEFT_PATTERNS` | 10 | Credential exfiltration |
| `CODE_EXEC_PATTERNS` | 9 | Code execution indicators |
| `RATE_LIMIT_PATTERNS` | 5 | Missing rate limiting |
| `PROMPT_LEAKAGE_PATTERNS` | 8 | Prompt exposure |
| `SUPPLY_CHAIN_PATTERNS` | 9 | Dynamic package install |
| `RAC_PATTERNS` | 6 categories | Remote access |
| `RESPONSE_INJECTION_PATTERNS` | 11 | Injection in tool responses |
| `ERROR_LEAKAGE_PATTERNS` | 9 | Info disclosure in errors |
| `CREDENTIAL_CONTENT_PATTERNS` | 11 | Actual secrets in content |
