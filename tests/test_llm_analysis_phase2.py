"""Tests for LLM analysis Phase 2 response handling."""

from __future__ import annotations

from dataclasses import dataclass

from mcpnuke.checks.llm_analysis import run_llm_analysis, _resolve_phase2_workers
from mcpnuke.core.models import TargetResult


class _DummyConsole:
    def print(self, _msg: str) -> None:
        return


class _FakeSession:
    def __init__(self, response: dict | None) -> None:
        self._response = response

    def call(self, _method: str, _params: dict, timeout: float = 10.0) -> dict | None:
        return self._response


@dataclass
class _FakeFinding:
    severity: str
    title: str
    detail: str
    taxonomy_id: str = ""


class _FakeLLMBackend:
    def __init__(self, response_findings: list[_FakeFinding] | None = None) -> None:
        self.response_findings = response_findings or []
        self.response_payloads: list[str] = []

    def analyze_tools(self, tools: list[dict], model: str, log) -> list[_FakeFinding]:
        return []

    def analyze_findings(self, tools: list[dict], findings: list[dict], model: str, log) -> list[_FakeFinding]:
        return []

    def analyze_response(
        self,
        tool_name: str,
        tool_description: str,
        response_text: str,
        model: str,
        log,
    ) -> list[_FakeFinding]:
        self.response_payloads.append(response_text)
        return self.response_findings


def _result_for_tool(name: str = "short.tool") -> TargetResult:
    result = TargetResult(url="http://localhost:8080/mcp")
    result.tools = [
        {
            "name": name,
            "description": "Tool under test",
            "inputSchema": {"properties": {}},
        }
    ]
    return result


def test_phase2_analyzes_short_text_response() -> None:
    """Short-but-non-empty text should still be sent to LLM in Phase 2."""
    session = _FakeSession({"result": {"content": [{"type": "text", "text": "ok"}]}})
    result = _result_for_tool("short.response")
    backend = _FakeLLMBackend([_FakeFinding(severity="HIGH", title="AI signal", detail="short response analyzed")])

    run_llm_analysis(
        session,
        result,
        probe_opts={"claude_max_tools": 1},
        console=_DummyConsole(),
        llm_backend=backend,
    )

    assert backend.response_payloads, "Phase 2 should analyze short responses instead of skipping"
    assert any(f.check == "llm_response_analysis" for f in result.findings)


def test_phase2_uses_fallback_payload_for_structured_empty_content() -> None:
    """If extracted text is empty but raw response has structure, analyze fallback payload."""
    session = _FakeSession(
        {
            "result": {
                "content": [{"type": "text", "text": ""}],
                "meta": {"hint": "follow tool instructions"},
            }
        }
    )
    result = _result_for_tool("structured.empty")
    backend = _FakeLLMBackend()

    run_llm_analysis(
        session,
        result,
        probe_opts={"claude_max_tools": 1},
        console=_DummyConsole(),
        llm_backend=backend,
    )

    assert backend.response_payloads, "Phase 2 should analyze structured responses even when text is empty"
    assert "meta" in backend.response_payloads[0]


def test_phase2_skips_truly_empty_response() -> None:
    """Phase 2 should still skip responses with no usable content."""
    session = _FakeSession(None)
    result = _result_for_tool("empty.response")
    backend = _FakeLLMBackend()

    run_llm_analysis(
        session,
        result,
        probe_opts={"claude_max_tools": 1},
        console=_DummyConsole(),
        llm_backend=backend,
    )

    assert not backend.response_payloads


def test_phase2_parallel_workers_analyze_all_candidates() -> None:
    """Phase 2 should support parallel response analysis workers."""
    result = TargetResult(url="http://localhost:8080/mcp")
    result.tools = [
        {"name": "tool.one", "description": "A", "inputSchema": {"properties": {}}},
        {"name": "tool.two", "description": "B", "inputSchema": {"properties": {}}},
    ]
    backend = _FakeLLMBackend()
    session = _FakeSession({"result": {"content": [{"type": "text", "text": "ok"}]}})

    run_llm_analysis(
        session,
        result,
        probe_opts={"claude_max_tools": 2, "claude_phase2_workers": 2},
        console=_DummyConsole(),
        llm_backend=backend,
    )

    assert len(backend.response_payloads) == 2


def test_resolve_phase2_workers_forces_single_in_deterministic_mode() -> None:
    workers = _resolve_phase2_workers({"claude_phase2_workers": 4, "deterministic": True})
    assert workers == 1
