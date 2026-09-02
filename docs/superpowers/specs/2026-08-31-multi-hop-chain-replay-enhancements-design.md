# Multi-Hop Attack Chain Replay & OAST Verification Enhancements Design

## 1. Overview & Goals

mcpnuke's Phase 4 attack chain replay engine (`--chain-replay`) executes multi-tool attack hypotheses generated during Phase 3 or synthesized from tool topologies. The engine validates whether data actually flows across tool boundaries from sensitive sources to dangerous sinks or out-of-band (OAST) egress points.

This enhancement addresses key limitations in the existing replay engine:
1. **Field-Aware Placeholder Extraction**: Enables JSON-path selectors (`{{stepN.output.field.subfield}}`, `{{stepN.output.items[0]}}`) and transform filters (`|b64`, `|b64decode`, `|urlencode`, `|urldecode`, `|strip`, `|json`) to handle tools that return structured envelopes.
2. **Deterministic-First with Dynamic LLM Fallback**: If deterministic path resolution fails on unstructured text, a fast LLM adapter extracts the required parameter without failing the chain.
3. **Enhanced Data Movement & OAST Exfiltration Tracking**: Tracks extracted and transformed fragments in downstream arguments and correlates callback queries/bodies against leaked tokens to prove actual data movement.

---

## 2. Architecture & Data Flow

```
Proposed Chain (Phase 3 LLM or Synthesizer)
   │
   ▼
Replay Step Execution Loop:
   ├── 1. Deterministic Placeholder & Transform Evaluation
   │      - {{stepN.output}} (Full raw output)
   │      - {{stepN.output.path.to.key}} (JSON path / dictionary indexing)
   │      - {{stepN.output.array[0].id}} (List index extraction)
   │      - Filters: |b64, |b64decode, |urlencode, |urldecode, |strip, |json
   │      - {{oast.url}} (Canary URL generation)
   │
   ├── 2. Dynamic LLM Parameter Extraction (Fallback)
   │      - If deterministic extraction fails or output is unstructured text,
   │        query LLM backend (if configured) to adapt output to target parameter
   │
   ├── 3. Execute Step against MCP Session
   │      - Call tool with resolved arguments
   │      - Capture response text and error state
   │      - Register output fragments into tracked token registry
   │
   └── 4. Step Failure & Safety Handling
          - Refuse dangerous tools under --safe-mode
          - Halt cleanly on tool errors
   │
   ▼
Summarize Run & Verdict Generation:
   ├── Tier 1: Out-of-band Egress Confirmed (OAST callback verified with tracked fragment)
   ├── Tier 2: Reproduced End-to-End (Tracked token verified in downstream tool request)
   ├── Tier 3: Callable End-to-End (All steps succeeded, no data movement proven)
   └── Tier 4: Halted / Refused
```

---

## 3. Detailed Component Specifications

### 3.1 Extended Placeholder Syntax & Parser
The template resolver parses expressions of the form:
`{{step<index>.output[.<path>][|<filter>]}}`

Supported components:
- **Index**: Integer index of prior step in the current replay run (`0` to `current_step - 1`).
- **Path**: Dot-separated keys and bracketed indices (e.g., `user.tokens[0].access_token`).
  - Automatically parses JSON strings from raw response text (stripping markdown code fences if present).
  - Traverses nested `dict` and `list` structures safely without `eval()`.
- **Filters**:
  - `b64`: Base64 encode the string value.
  - `b64decode`: Base64 decode string value.
  - `urlencode`: URL percent-encode string value.
  - `urldecode`: URL percent-decode string value.
  - `strip`: Strip leading/trailing whitespace.
  - `json`: Serialize value to compact JSON string.

### 3.2 Dynamic LLM Step Adapter
When deterministic placeholder resolution encounters unstructured text and cannot resolve the requested parameter path:
- Function: `_dynamic_extract_arg(backend, tool_name, param_name, param_desc, source_text, model, log)`
- Prompt: Compact extraction prompt asking for only the target parameter value from the provided source text.
- Fallback: If dynamic extraction fails or is disabled, leave template untouched or use safe default.

### 3.3 Data Movement & OAST Exfiltration Verification
- **Fragment Registration**:
  - Every resolved placeholder value $\ge 4$ characters is recorded in `ChainRun.tracked_fragments`.
- **In-Band Verification (`_data_moved`)**:
  - Checks if any registered fragment appears inside any downstream step's `request_args`.
- **OAST Callback Verification**:
  - When an OAST callback matches `run.oast_token`, inspect `callback.query`, `callback.path`, and `callback.body` to confirm if any `tracked_fragments` were carried out-of-band.

---

## 4. Error Handling & Security Guarantees

1. **Safe Parsing**: Path resolution uses recursive dictionary/list lookups with strict type checks; no arbitrary expressions or execution.
2. **Non-Recursive Replacement**: Template substitution is single-pass to prevent expansion loops from poisoned tool responses.
3. **Safe Mode Enforcement**: Steps invoking dangerous tools under `--safe-mode` halt before tool execution.

---

## 5. Testing Strategy

1. **Unit Tests (`tests/test_chain_replay_transforms.py`)**:
   - Dotted JSON path extraction from JSON responses and JSON markdown blocks.
   - List indexing (`items[0].name`).
   - Filters: `|b64`, `|b64decode`, `|urlencode`, `|urldecode`, `|strip`, `|json`.
   - Data movement tracking for transformed and extracted values.
   - OAST callback verification with exfiltrated data payload matching.
   - Dynamic LLM extraction fallback with mock LLM backend.
2. **Regression & Safety Tests**:
   - Verify all existing `test_chain_replay*.py` tests pass without breakage.
   - Full suite execution: `uv run pytest tests/ -v`.
   - Linter and typecheck: `uv run ruff check .` and `uv run mypy mcpnuke/`.
