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
