"""The propose-execute-judge loop only runs when asked, and reports graded outcomes.

Replaying a chain calls tools on the target in sequence, so it is opt-in and
respects `--no-invoke`. A chain that completes with data moving between steps
(or with an out-of-band callback) becomes a CRITICAL finding; a chain that
runs end-to-end without proven composition is MEDIUM; a halted chain stays
silent.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcpnuke.checks.llm_analysis import _chain_finding, run_llm_analysis
from mcpnuke.core.chain_replay import ChainStep, ChainVerdict, ProposedChain
from mcpnuke.core.models import TargetResult


class _DummyConsole:
    def print(self, _msg: str) -> None:
        return


class _Session:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
        if method != "tools/call":
            return None
        name = params.get("name", "")
        self.calls.append(name)
        if name == "vault.read":
            return {"result": {"content": [{"type": "text", "text": "AKIA-secret"}]}}
        if name == "net.send":
            return {"result": {"content": [{"type": "text", "text": "queued"}]}}
        return {"result": {"isError": True, "content": [{"type": "text", "text": "no"}]}}


@dataclass
class _FakeFinding:
    severity: str
    title: str
    detail: str
    taxonomy_id: str = ""


class _Backend:
    def __init__(self, chains: list[ProposedChain] | None = None) -> None:
        self.chains = chains or []
        self.propose_calls = 0

    def analyze_tools(self, tools, model, log, known_findings=None) -> list:
        return []

    def analyze_findings(self, tools, findings, model, log) -> list:
        return []

    def analyze_response(self, tool_name, tool_description, response_text, model, log) -> list:
        return []

    def propose_chains(self, tools, findings, model, log) -> list[ProposedChain]:
        self.propose_calls += 1
        return self.chains


def _result() -> TargetResult:
    result = TargetResult(url="http://localhost:8080/mcp")
    result.tools = [
        {
            "name": "vault.read",
            "description": "Read a secret",
            "inputSchema": {"properties": {}},
        },
        {
            "name": "net.send",
            "description": "Send outbound",
            "inputSchema": {"properties": {"body": {"type": "string"}}},
        },
    ]
    result.add("token_theft", "HIGH", "Credential returned by tool 'vault.read'")
    return result


def _chain() -> ProposedChain:
    return ProposedChain(
        title="read then send",
        detail="Exfiltrate a secret",
        taxonomy_id="MCP-T12",
        steps=[
            ChainStep("vault.read", {}),
            ChainStep("net.send", {"body": "{{step0.output}}"}),
        ],
    )


class TestItIsOptIn:
    def test_off_by_default(self):
        backend = _Backend([_chain()])

        run_llm_analysis(
            _Session(),
            _result(),
            probe_opts={"claude_max_tools": 0},
            console=_DummyConsole(),
            llm_backend=backend,
        )

        assert backend.propose_calls == 0

    def test_enabled_by_flag(self):
        backend = _Backend([_chain()])

        run_llm_analysis(
            _Session(),
            _result(),
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=backend,
        )

        assert backend.propose_calls == 1

    def test_no_invoke_suppresses_it(self):
        backend = _Backend([_chain()])

        run_llm_analysis(
            _Session(),
            _result(),
            probe_opts={"claude_max_tools": 0, "chain_replay": True, "no_invoke": True},
            console=_DummyConsole(),
            llm_backend=backend,
        )

        assert backend.propose_calls == 0


class TestAReproducedChainIsReported:
    def test_a_successful_replay_is_critical(self):
        result = _result()

        run_llm_analysis(
            _Session(),
            result,
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=_Backend([_chain()]),
        )

        reproduced = [f for f in result.findings if f.check == "llm_chain_replay"]
        assert reproduced and all(f.severity == "CRITICAL" for f in reproduced)

    def test_the_title_names_the_chain(self):
        result = _result()

        run_llm_analysis(
            _Session(),
            result,
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=_Backend([_chain()]),
        )

        reproduced = [f for f in result.findings if f.check == "llm_chain_replay"]
        assert any("read then send" in f.title for f in reproduced)

    def test_the_transcript_is_evidence(self):
        result = _result()

        run_llm_analysis(
            _Session(),
            result,
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=_Backend([_chain()]),
        )

        reproduced = [f for f in result.findings if f.check == "llm_chain_replay"]
        assert any("AKIA-secret" in f.evidence for f in reproduced)

    def test_the_tools_were_actually_called(self):
        session = _Session()

        run_llm_analysis(
            session,
            _result(),
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=_Backend([_chain()]),
        )

        assert session.calls == ["vault.read", "net.send"]


class TestAFailedChainIsSilent:
    def test_a_halted_chain_produces_no_finding(self):
        result = _result()
        broken = ProposedChain(
            title="broken",
            steps=[ChainStep("vault.read", {}), ChainStep("does.not.exist", {})],
        )

        run_llm_analysis(
            _Session(),
            result,
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=_Backend([broken]),
        )

        assert not any(f.check == "llm_chain_replay" for f in result.findings)

    def test_a_backend_without_propose_chains_is_tolerated(self):
        class _Old:
            def analyze_tools(self, tools, model, log, known_findings=None) -> list:
                return []

            def analyze_findings(self, tools, findings, model, log) -> list:
                return []

            def analyze_response(self, *a, **k) -> list:
                return []

        run_llm_analysis(
            _Session(),
            _result(),
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=_Old(),
        )


def _grading_chain() -> ProposedChain:
    return ProposedChain(
        title="c",
        steps=[ChainStep("a"), ChainStep("b")],
        detail="d",
    )


def test_egress_confirmed_is_critical():
    sev, title = _chain_finding(
        _grading_chain(),
        ChainVerdict(True, True, "moved out", egress_confirmed=True),
    )
    assert sev == "CRITICAL"
    assert "exfiltrat" in title.lower()


def test_reproduced_inband_is_critical():
    sev, title = _chain_finding(_grading_chain(), ChainVerdict(True, True, "moved"))
    assert sev == "CRITICAL"
    assert "reproduced" in title.lower()


def test_callable_unproven_is_medium():
    sev, title = _chain_finding(
        _grading_chain(), ChainVerdict(False, True, "unproven")
    )
    assert sev == "MEDIUM"
    assert "callable" in title.lower()


def test_halted_returns_none():
    assert _chain_finding(_grading_chain(), ChainVerdict(False, False, "halted")) is None


def test_callable_unproven_chain_is_reported_as_medium():
    """A chain that runs end-to-end without data movement is no longer silent."""
    result = _result()
    unproven = ProposedChain(
        title="no data move",
        steps=[
            ChainStep("vault.read", {}),
            ChainStep("net.send", {"body": "static"}),
        ],
    )

    run_llm_analysis(
        _Session(),
        result,
        probe_opts={"claude_max_tools": 0, "chain_replay": True},
        console=_DummyConsole(),
        llm_backend=_Backend([unproven]),
    )

    findings = [f for f in result.findings if f.check == "llm_chain_replay"]
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "unproven" in findings[0].title.lower() or "callable" in findings[0].title.lower()


class _JudgingBackend(_Backend):
    def __init__(self, chains: list[ProposedChain], moved: bool = True) -> None:
        super().__init__(chains)
        self.judge_calls = 0
        self._moved = moved

    def judge_chain_run(self, title, transcript, model, log=None):
        self.judge_calls += 1
        return self._moved, "base64 of step0 in step1"


def _unproven_chain() -> ProposedChain:
    return ProposedChain(
        title="no data move",
        steps=[
            ChainStep("vault.read", {}),
            ChainStep("net.send", {"body": "static"}),
        ],
    )


class TestTheJudgeIsBackendDriven:
    def test_judge_runs_without_the_claude_flag(self):
        """Gating the judge on --claude silently disabled it for Ollama scans;
        any backend carrying the hook should be consulted."""
        result = _result()
        backend = _JudgingBackend([_unproven_chain()], moved=True)

        run_llm_analysis(
            _Session(),
            result,
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=backend,
        )

        assert backend.judge_calls == 1
        findings = [f for f in result.findings if f.check == "llm_chain_replay"]
        assert findings[0].severity == "HIGH"
        assert "AI-judged" in findings[0].title

    def test_judge_saying_no_movement_keeps_medium(self):
        result = _result()
        backend = _JudgingBackend([_unproven_chain()], moved=False)

        run_llm_analysis(
            _Session(),
            result,
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=backend,
        )

        assert backend.judge_calls == 1
        findings = [f for f in result.findings if f.check == "llm_chain_replay"]
        assert findings[0].severity == "MEDIUM"

    def test_backend_without_the_hook_still_works(self):
        result = _result()

        run_llm_analysis(
            _Session(),
            result,
            probe_opts={"claude_max_tools": 0, "chain_replay": True},
            console=_DummyConsole(),
            llm_backend=_Backend([_unproven_chain()]),
        )

        findings = [f for f in result.findings if f.check == "llm_chain_replay"]
        assert findings[0].severity == "MEDIUM"
