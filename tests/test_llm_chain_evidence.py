"""Chain reasoning has to be given enough to trace a data path.

Phase 3 asks the model for multi-step exploitation paths, then hands it
finding titles with no detail, no evidence and no tool attribution, plus a
tool list of names and 100 characters of description with no parameters. It
cannot say how data moves from one tool to another because it is never told
what any tool accepts or returns, so it answers in generalities.

The payload was also cut with a blunt character slice. On a 138-tool target
`json.dumps(...)[:3000]` left 24 tools visible and ended mid-string, so the
prompt carried malformed JSON describing 17% of the attack surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from mcpnuke.checks.llm_analysis import run_llm_analysis
from mcpnuke.core import llm
from mcpnuke.core.models import TargetResult


class _DummyConsole:
    def print(self, _msg: str) -> None:
        return


@dataclass
class _FakeFinding:
    severity: str
    title: str
    detail: str
    taxonomy_id: str = ""


class _CapturingBackend:
    """Records what Phase 3 was actually given."""

    def __init__(self) -> None:
        self.tools: list[dict] = []
        self.findings: list[dict] = []

    def analyze_tools(self, tools, model, log) -> list:
        return []

    def analyze_findings(self, tools, findings, model, log) -> list:
        self.tools = tools
        self.findings = findings
        return []

    def analyze_response(self, tool_name, tool_description, response_text, model, log) -> list:
        return []


def _result_with_finding() -> TargetResult:
    result = TargetResult(url="http://localhost:8080/mcp")
    result.tools = [
        {
            "name": "svc.read_secret",
            "description": "Read a stored secret",
            "inputSchema": {"properties": {"key": {"type": "string"}}},
        }
    ]
    result.add(
        "response_credentials",
        "HIGH",
        "Credential returned by tool 'svc.read_secret'",
        detail="The response body carried an AWS session token in plaintext.",
        evidence="ASIA...redacted in transcript",
    )
    return result


class TestFindingsCarryTheirEvidence:
    @pytest.fixture
    def sent(self) -> list[dict]:
        backend = _CapturingBackend()
        run_llm_analysis(
            _FakeSession(),
            _result_with_finding(),
            probe_opts={"claude_max_tools": 0},
            console=_DummyConsole(),
            llm_backend=backend,
        )
        assert backend.findings, "Phase 3 was never called"
        return backend.findings

    def test_the_detail_is_included(self, sent):
        assert "AWS session token" in sent[0]["detail"]

    def test_the_evidence_is_included(self, sent):
        assert "ASIA" in sent[0]["evidence"]

    def test_the_implicated_tool_is_named_as_a_field(self, sent):
        assert sent[0]["tool"] == "svc.read_secret"

    def test_the_taxonomy_id_is_carried(self, sent):
        assert "taxonomy_id" in sent[0]

    def test_the_original_fields_are_kept(self, sent):
        assert sent[0]["check"] == "response_credentials"
        assert sent[0]["severity"] == "HIGH"


class _FakeSession:
    def call(self, _method: str, _params: dict, timeout: float = 10.0) -> dict | None:
        return None


class TestToolsCarryTheirParameters:
    def test_the_digest_names_the_parameters(self):
        tool = {
            "name": "svc.fetch",
            "description": "Fetch a URL",
            "inputSchema": {
                "properties": {"url": {"type": "string"}, "depth": {"type": "integer"}}
            },
        }

        digest = llm._tool_digest(tool)

        assert digest["params"] == ["url:string", "depth:integer"]

    def test_a_tool_without_a_schema_is_still_described(self):
        digest = llm._tool_digest({"name": "svc.ping", "description": "Ping"})

        assert digest["name"] == "svc.ping"
        assert digest["params"] == []

    def test_the_description_is_kept_long_enough_to_be_useful(self):
        """100 characters cut most descriptions before the risky clause."""
        tool = {"name": "t", "description": "x" * 400, "inputSchema": {}}

        assert len(llm._tool_digest(tool)["description"]) > 100


class TestTheBudgetNeverEmitsBrokenJson:
    def _tools(self, n: int) -> list[dict]:
        return [
            {
                "name": f"camazotz.service.tool_{i}",
                "description": "Does a thing with data and returns results for the caller",
                "inputSchema": {"properties": {"payload": {"type": "string"}}},
            }
            for i in range(n)
        ]

    def test_an_over_budget_payload_is_still_valid_json(self):
        text = llm._budgeted_json([llm._tool_digest(t) for t in self._tools(138)], 3000)

        json.loads(text)

    def test_it_drops_whole_items_rather_than_cutting_one(self):
        items = [llm._tool_digest(t) for t in self._tools(138)]

        decoded = json.loads(llm._budgeted_json(items, 3000))

        assert 0 < len(decoded) < 138
        assert all(d in items for d in decoded)

    def test_everything_is_kept_when_it_fits(self):
        items = [llm._tool_digest(t) for t in self._tools(3)]

        assert json.loads(llm._budgeted_json(items, 100_000)) == items

    def test_the_budget_is_respected(self):
        items = [llm._tool_digest(t) for t in self._tools(138)]

        assert len(llm._budgeted_json(items, 3000)) <= 3000


class TestEveryVulnerabilityClassIsRepresented:
    """A prefix of the findings is not a sample of the target.

    Camazotz reports 903 findings across 47 checks, but 233 of them are one
    check. Taking findings in the order they were produced spends the budget on
    repeats of whatever ran first, so the 8 checks that fired exactly once —
    the rare, interesting ones — never reach the reasoner at all.
    """

    def _skewed(self) -> list[dict]:
        bulk = [
            {"check": "tool_response_injection", "severity": "HIGH", "title": f"bulk {i}"}
            for i in range(233)
        ]
        rare = [{"check": "webhook_persistence", "severity": "CRITICAL", "title": "rare"}]
        return bulk + rare

    def test_a_rare_check_is_not_crowded_out_by_a_noisy_one(self):
        ordered = llm._diverse_findings(self._skewed())

        # It must land before the noisy check's second instance, not merely
        # somewhere in a 234-long list.
        assert "webhook_persistence" in {f["check"] for f in ordered[:2]}

    def test_every_check_appears_before_any_check_repeats(self):
        findings = [
            {"check": c, "severity": "HIGH", "title": f"{c} {i}"}
            for c in ("a", "b", "c")
            for i in range(4)
        ]

        head = llm._diverse_findings(findings)[:3]

        assert {f["check"] for f in head} == {"a", "b", "c"}

    def test_the_worst_instance_represents_its_check(self):
        findings = [
            {"check": "x", "severity": "LOW", "title": "low"},
            {"check": "x", "severity": "CRITICAL", "title": "crit"},
            {"check": "x", "severity": "MEDIUM", "title": "med"},
        ]

        assert llm._diverse_findings(findings)[0]["title"] == "crit"

    def test_nothing_is_lost_only_reordered(self):
        findings = self._skewed()

        assert len(llm._diverse_findings(findings)) == len(findings)

    def test_a_severe_class_is_ordered_ahead_of_a_mild_one(self):
        findings = [
            {"check": "mild", "severity": "LOW", "title": "m"},
            {"check": "severe", "severity": "CRITICAL", "title": "s"},
        ]

        assert llm._diverse_findings(findings)[0]["check"] == "severe"


class TestTheBudgetFitsARealTarget:
    """Sized against Camazotz: 139 tools, 47 checks."""

    def test_the_tool_budget_holds_a_large_server(self):
        tools = [
            {
                "name": f"camazotz.service.tool_{i}",
                "description": "Does a thing with data and returns results for the caller",
                "inputSchema": {"properties": {"payload": {"type": "string"}}},
            }
            for i in range(139)
        ]
        digests = [llm._tool_digest(t) for t in tools]

        assert len(llm._fit(digests, llm._TOOLS_BUDGET_CHARS)) == 139

    def test_the_findings_budget_holds_one_of_every_class(self):
        findings = [
            {
                "check": f"check_{i}",
                "severity": "HIGH",
                "title": f"Something wrong in tool 'svc.tool_{i}'",
                "detail": "d" * 600,
                "evidence": "e" * 300,
                "tool": f"svc.tool_{i}",
                "taxonomy_id": "MCP-T05",
            }
            for i in range(47)
        ]

        assert len(llm._fit(findings, llm._FINDINGS_BUDGET_CHARS)) == 47


class TestTrimmingPrefersImplicatedTools:
    def test_a_tool_named_in_a_finding_survives_the_trim(self, monkeypatch):
        seen: dict = {}

        class _Messages:
            def create(self, **kwargs):
                seen["user"] = kwargs["messages"][0]["content"]
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="[]")],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))

        tools = [
            {"name": f"svc.filler_{i}", "description": "d" * 200, "inputSchema": {}}
            for i in range(200)
        ]
        tools.append({"name": "svc.the_sink", "description": "Send data out", "inputSchema": {}})

        llm.analyze_findings(
            tools,
            [{"check": "exfil_flow", "severity": "HIGH", "title": "x", "tool": "svc.the_sink"}],
        )

        # Look only at the tool list; the findings block names the tool too.
        tool_section = seen["user"].split("Existing findings:")[0]
        assert "svc.the_sink" in tool_section, "the implicated tool was trimmed away"

    def test_the_whole_surface_is_reported_when_trimmed(self, monkeypatch):
        """The model must know it is seeing a subset, not the entire server."""
        seen: dict = {}

        class _Messages:
            def create(self, **kwargs):
                seen["user"] = kwargs["messages"][0]["content"]
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="[]")],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))

        tools = [
            {"name": f"svc.t{i}", "description": "d" * 300, "inputSchema": {}} for i in range(400)
        ]

        llm.analyze_findings(tools, [{"check": "c", "severity": "HIGH", "title": "t"}])

        assert "400" in seen["user"], "the prompt does not say how many tools exist"
