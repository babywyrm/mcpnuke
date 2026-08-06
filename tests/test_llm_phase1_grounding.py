"""Phase 1 re-derives what the scanner already measured, and contradicts it.

On DVMCP challenge 5 the deterministic check reported HIGH: "Confusable tool
names: 'get_user_role' vs 'get_user_roles' ... name similarity 96% ...
descriptions also near-identical". Phase 1 looked at the same two tools and
reported LOW: "Redundant/duplicate tool surface increases attack surface" — the
same observation, downgraded to a hygiene complaint, in the same report.

Phase 1 runs after the deterministic checks, so those findings are already on
the result when it is called; it simply is not given them. Two consequences: it
spends its budget restating conclusions the scanner reached more precisely, and
when it disagrees it files a quieter duplicate instead of an argument.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from mcpnuke.checks.llm_analysis import run_llm_analysis
from mcpnuke.core import llm
from mcpnuke.core.models import TargetResult


class _DummyConsole:
    def print(self, _msg: str) -> None:
        return


class _FakeSession:
    def call(self, _method: str, _params: dict, timeout: float = 10.0) -> dict | None:
        return None


@dataclass
class _FakeFinding:
    severity: str
    title: str
    detail: str
    taxonomy_id: str = ""


class _CapturingBackend:
    def __init__(self) -> None:
        self.tool_call: dict = {}

    def analyze_tools(self, tools, model, log, known_findings=None) -> list:
        self.tool_call = {"tools": tools, "known_findings": known_findings}
        return []

    def analyze_findings(self, tools, findings, model, log) -> list:
        return []

    def analyze_response(self, tool_name, tool_description, response_text, model, log) -> list:
        return []


def _challenge5_result() -> TargetResult:
    result = TargetResult(url="http://localhost:9005/sse")
    result.tools = [
        {"name": "get_user_role", "description": "Get the role of a user", "inputSchema": {}},
        {"name": "get_user_roles", "description": "Get the roles of a user", "inputSchema": {}},
    ]
    result.add(
        "tool_shadowing",
        "HIGH",
        "Confusable tool names: 'get_user_role' vs 'get_user_roles'",
        detail="Name similarity 96%; descriptions near-identical.",
    )
    return result


class TestPhase1IsToldWhatTheScannerFound:
    def _capture(self) -> _CapturingBackend:
        backend = _CapturingBackend()
        run_llm_analysis(
            _FakeSession(),
            _challenge5_result(),
            probe_opts={"claude_max_tools": 0},
            console=_DummyConsole(),
            llm_backend=backend,
        )
        return backend

    def test_the_existing_findings_are_passed(self):
        known = self._capture().tool_call["known_findings"]

        assert known, "phase 1 was given nothing the scanner had already found"

    def test_the_shadowing_finding_is_among_them(self):
        known = self._capture().tool_call["known_findings"]

        assert any("Confusable tool names" in k for k in known)

    def test_its_severity_is_carried_so_a_disagreement_is_visible(self):
        known = self._capture().tool_call["known_findings"]

        assert any("HIGH" in k for k in known)

    def test_ai_findings_are_not_fed_back_in(self):
        result = _challenge5_result()
        result.add("llm_tool_analysis", "LOW", "[AI] something the model said")
        backend = _CapturingBackend()
        run_llm_analysis(
            _FakeSession(),
            result,
            probe_opts={"claude_max_tools": 0},
            console=_DummyConsole(),
            llm_backend=backend,
        )

        known = backend.tool_call["known_findings"]
        assert not any("[AI]" in k for k in known)


class TestThePromptUsesThem:
    def _system_prompt(self, monkeypatch, **kwargs) -> str:
        seen: dict = {}

        class _Messages:
            def create(self, **kw):
                seen["system"] = kw["system"]
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="[]")],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))
        llm.analyze_tools([{"name": "t", "description": "d"}], **kwargs)
        return seen["system"]

    def test_the_known_findings_appear_in_the_prompt(self, monkeypatch):
        system = self._system_prompt(
            monkeypatch, known_findings=["HIGH tool_shadowing: Confusable tool names"]
        )

        assert "Confusable tool names" in system

    def test_the_model_is_told_not_to_restate_them(self, monkeypatch):
        system = self._system_prompt(monkeypatch, known_findings=["HIGH x: y"])

        assert "restate" in system.lower() or "already" in system.lower()

    def test_disagreement_is_invited_rather_than_a_quiet_duplicate(self, monkeypatch):
        system = self._system_prompt(monkeypatch, known_findings=["HIGH x: y"])

        assert "disagree" in system.lower()

    def test_nothing_is_added_when_the_scanner_found_nothing(self, monkeypatch):
        system = self._system_prompt(monkeypatch, known_findings=[])

        assert "already reported" not in system.lower()

    def test_shadowing_is_named_as_a_threat_class(self, monkeypatch):
        """DVMCP challenge 5: unprompted, the model calls this redundancy."""
        system = self._system_prompt(monkeypatch)

        assert "confusable" in system.lower() or "shadow" in system.lower()


class TestBackwardCompatibility:
    def test_analyze_tools_still_works_without_known_findings(self, monkeypatch):
        class _Messages:
            def create(self, **kw):
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="[]")],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))

        assert llm.analyze_tools([{"name": "t", "description": "d"}]) == []

    def test_a_backend_without_the_parameter_still_runs(self):
        """An out-of-tree backend predating this change must not break."""

        class _OldBackend:
            def __init__(self):
                self.called = False

            def analyze_tools(self, tools, model, log) -> list:
                self.called = True
                return []

            def analyze_findings(self, tools, findings, model, log) -> list:
                return []

            def analyze_response(self, tool_name, tool_description, response_text, model, log) -> list:
                return []

        backend = _OldBackend()
        run_llm_analysis(
            _FakeSession(),
            _challenge5_result(),
            probe_opts={"claude_max_tools": 0},
            console=_DummyConsole(),
            llm_backend=backend,
        )

        assert backend.called
