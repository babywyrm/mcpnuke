"""Tests for Ollama LLM backend."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from mcpnuke.core.llm import LLMFinding
from mcpnuke.core.llm_ollama import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL,
    OllamaBackend,
    cluster_findings,
)


def test_ollama_backend_defaults():
    backend = OllamaBackend(host="http://localhost:11434")
    assert backend.host == "http://localhost:11434"
    assert backend.model == DEFAULT_MODEL
    assert DEFAULT_MAX_TOKENS == 4096


def test_ollama_truncation_warning():
    backend = OllamaBackend(host="http://localhost:11434", model="test-model")
    logs = []
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "message": {"content": '[{"severity": "HIGH", "title": "Truncated Finding", "taxonomy_id": "MCP-T01"}]'},
        "done_reason": "length",
        "eval_count": 4096,
        "prompt_eval_count": 100,
    }
    with patch("httpx.post", return_value=mock_resp):
        findings = backend.analyze_tools([{"name": "test"}], "test-model", log=logs.append)
    assert any("truncated" in log.lower() for log in logs)
    assert len(findings) == 1
    assert findings[0].taxonomy_id == "MCP-T01"


def test_ollama_exhausted_during_thinking_warning():
    backend = OllamaBackend(host="http://localhost:11434", model="thinking-model")
    logs = []
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "message": {"content": "", "thinking": "Let me think about this..."},
        "done_reason": "length",
        "eval_count": 4096,
        "prompt_eval_count": 100,
    }
    with patch("httpx.post", return_value=mock_resp):
        findings = backend.analyze_tools([{"name": "test"}], "thinking-model", log=logs.append)
    assert any("exhausted" in log.lower() or "truncated" in log.lower() for log in logs)
    assert len(findings) == 0


def test_ollama_connect_error():
    backend = OllamaBackend(host="http://localhost:11434", model="test-model")
    with (
        patch("httpx.post", side_effect=httpx.ConnectError("Connection refused")),
        pytest.raises(RuntimeError, match="Cannot reach Ollama"),
    ):
        backend.analyze_tools([{"name": "test"}], "test-model")


def test_ollama_timeout_error():
    backend = OllamaBackend(host="http://localhost:11434", model="test-model")
    with (
        patch("httpx.post", side_effect=httpx.TimeoutException("Read timed out")),
        pytest.raises(RuntimeError, match="timed out"),
    ):
        backend.analyze_tools([{"name": "test"}], "test-model")


def test_cluster_findings_consensus():
    per_model = {
        "qwen3:14b": [
            LLMFinding(severity="HIGH", title="Injection A", detail="d1", taxonomy_id="MCP-T01"),
            LLMFinding(severity="CRITICAL", title="Exfil B", detail="d2", taxonomy_id="MCP-T12"),
        ],
        "granite4.2:8b": [
            LLMFinding(severity="HIGH", title="Injection Alt", detail="d3", taxonomy_id="MCP-T01"),
        ],
    }
    ensemble = cluster_findings(per_model)
    assert len(ensemble) == 2
    consensus = [e for e in ensemble if e.is_consensus]
    candidates = [e for e in ensemble if not e.is_consensus]
    assert len(consensus) == 1
    assert consensus[0].finding.taxonomy_id == "MCP-T01"
    assert consensus[0].consensus_count == 2
    assert "[CONSENSUS 2x]" in consensus[0].to_llm_finding().title
    assert len(candidates) == 1
    assert candidates[0].finding.taxonomy_id == "MCP-T12"
    assert "[CANDIDATE]" in candidates[0].to_llm_finding().title


def _backend_with_text(text: str) -> tuple[OllamaBackend, MagicMock]:
    backend = OllamaBackend(host="http://localhost:11434", model="test-model")
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "message": {"content": text},
        "done_reason": "stop",
        "eval_count": 100,
        "prompt_eval_count": 100,
    }
    return backend, mock_resp


def test_ollama_backend_exposes_chain_replay_hooks():
    """Phase 4 getattrs these on the backend; a missing hook silently no-ops,
    which is how --chain-replay with --ollama-analysis reported 0 of 0."""
    backend = OllamaBackend(host="http://localhost:11434")
    for hook in ("propose_chains", "judge_chain_run", "revise_chain"):
        assert callable(getattr(backend, hook, None)), f"OllamaBackend missing {hook}"


def test_ollama_propose_chains_parses_steps():
    text = (
        '[{"severity": "HIGH", "title": "read then exfil", "detail": "d",'
        ' "taxonomy_id": "MCP-T12",'
        ' "steps": [{"tool": "read_file", "args": {"path": "/etc/passwd"}},'
        '           {"tool": "fetch_url", "args": {"url": "{{step0.output}}"}}]}]'
    )
    backend, mock_resp = _backend_with_text(text)
    with patch("httpx.post", return_value=mock_resp):
        chains = backend.propose_chains(
            [{"name": "read_file"}, {"name": "fetch_url"}],
            [{"title": "f", "detail": "d"}],
            model="test-model",
        )
    assert len(chains) == 1
    assert chains[0].title == "read then exfil"
    assert len(chains[0].steps) == 2


def test_ollama_propose_chains_empty_findings_short_circuits():
    backend, _ = _backend_with_text("[]")
    with patch("httpx.post") as mock_post:
        chains = backend.propose_chains([{"name": "t"}], [], model="test-model")
    assert chains == []
    mock_post.assert_not_called()


def test_ollama_judge_chain_run_parses_verdict():
    backend, mock_resp = _backend_with_text('{"moved": true, "why": "base64 of step0 in step2"}')
    with patch("httpx.post", return_value=mock_resp):
        moved, why = backend.judge_chain_run("chain", "transcript", model="test-model")
    assert moved is True
    assert "base64" in why


def test_ollama_judge_chain_run_bad_json_is_not_movement():
    backend, mock_resp = _backend_with_text("not json")
    with patch("httpx.post", return_value=mock_resp):
        moved, why = backend.judge_chain_run("chain", "transcript", model="test-model")
    assert moved is False
    assert why == ""


def test_ollama_revise_chain_returns_first_parseable():
    text = (
        '[{"title": "fixed", "steps": [{"tool": "a", "args": {}},'
        ' {"tool": "b", "args": {"x": "{{step0.output}}"}}]}]'
    )
    backend, mock_resp = _backend_with_text(text)
    chain = MagicMock()
    chain.title = "broken"
    with patch("httpx.post", return_value=mock_resp):
        revised = backend.revise_chain(chain, "transcript", [{"name": "a"}], model="test-model")
    assert revised is not None
    assert revised.title == "fixed"


def test_ollama_revise_chain_none_when_unparseable():
    backend, mock_resp = _backend_with_text("[]")
    chain = MagicMock()
    chain.title = "broken"
    with patch("httpx.post", return_value=mock_resp):
        revised = backend.revise_chain(chain, "transcript", [{"name": "a"}], model="test-model")
    assert revised is None


def test_ollama_propose_chains_retries_once_on_prose():
    """Assessment-sized contexts make local models answer with a prose summary;
    the backend must nudge once and parse the corrected reply."""
    backend = OllamaBackend(host="http://localhost:11434", model="test-model")
    prose = MagicMock()
    prose.json.return_value = {
        "message": {"content": "The provided JSON data outlines..."},
        "done_reason": "stop",
    }
    valid = MagicMock()
    valid.json.return_value = {
        "message": {
            "content": '[{"title": "c", "steps": [{"tool": "a", "args": {}},'
            ' {"tool": "b", "args": {"x": "{{step0.output}}"}}]}]'
        },
        "done_reason": "stop",
    }
    with patch("httpx.post", side_effect=[prose, valid]) as mock_post:
        chains = backend.propose_chains(
            [{"name": "a"}, {"name": "b"}], [{"title": "f", "detail": "d"}], model="test-model"
        )
    assert mock_post.call_count == 2
    nudge_payload = mock_post.call_args_list[1].kwargs["json"]
    assert "previous reply was prose" in nudge_payload["messages"][0]["content"]
    assert len(chains) == 1
    assert chains[0].title == "c"


def test_ollama_propose_chains_no_retry_when_first_parse_succeeds():
    text = (
        '[{"title": "c", "steps": [{"tool": "a", "args": {}},'
        ' {"tool": "b", "args": {"x": "{{step0.output}}"}}]}]'
    )
    backend, mock_resp = _backend_with_text(text)
    with patch("httpx.post", return_value=mock_resp) as mock_post:
        chains = backend.propose_chains(
            [{"name": "a"}, {"name": "b"}], [{"title": "f", "detail": "d"}], model="test-model"
        )
    assert mock_post.call_count == 1
    assert len(chains) == 1
