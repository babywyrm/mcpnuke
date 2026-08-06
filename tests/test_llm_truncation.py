"""A truncated model response must not read as a clean target.

Both reasoning phases asked for at most 2000 output tokens and handed the text
to `_parse_findings`, which answers `[]` on `JSONDecodeError`. A response cut
mid-array is therefore indistinguishable from "nothing found".

The failure is inverted: output length tracks how much the model had to say, so
the targets that overflow the budget are the ones with the most findings. On a
live Camazotz scan phase 1 and phase 3 both reported zero while phase 2 — whose
per-response prompts stay small — reported four. Every finding in the two
phases that reason across the whole target was dropped, silently, after the API
work was billed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from mcpnuke.core import llm


def _obj(i: int, detail: str = "explanation of the risk") -> dict:
    return {
        "severity": "HIGH",
        "title": f"Finding {i}",
        "detail": detail,
        "taxonomy_id": "MCP-T05",
    }


def _truncate(objs: list[dict], chars: int) -> str:
    """Serialize an array and cut it, the way max_tokens cuts a response."""
    return json.dumps(objs, indent=2)[:chars]


class TestSalvagingTruncatedArrays:
    def test_the_complete_objects_before_the_cut_survive(self):
        text = _truncate([_obj(0), _obj(1), _obj(2)], 260)
        assert "Finding 1" in text and not text.rstrip().endswith("]")

        out = llm._parse_findings(text)

        assert [f.title for f in out] == ["Finding 0", "Finding 1"]

    def test_a_cut_inside_a_string_does_not_lose_the_earlier_object(self):
        # Object 0 closes; the cut lands inside object 1's title string.
        text = json.dumps([_obj(0)])[:-1] + ', {"severity": "HIGH", "title": "Fin'

        out = llm._parse_findings(text)

        assert [f.title for f in out] == ["Finding 0"]

    def test_the_salvaged_fields_are_carried_through(self):
        text = _truncate([_obj(0, detail="chain via svc.read then svc.send"), _obj(1)], 200)

        out = llm._parse_findings(text)

        assert out[0].severity == "HIGH"
        assert out[0].detail == "chain via svc.read then svc.send"
        assert out[0].taxonomy_id == "MCP-T05"

    def test_a_brace_inside_a_string_is_not_read_as_structure(self):
        objs = [_obj(0, detail='payload {"role": "system"} injected'), _obj(1)]
        text = _truncate(objs, 240)

        out = llm._parse_findings(text)

        assert [f.title for f in out] == ["Finding 0"]
        assert "role" in out[0].detail

    def test_a_truncated_fence_is_still_salvaged(self):
        text = "```json\n" + _truncate([_obj(0), _obj(1)], 240)

        out = llm._parse_findings(text)

        assert [f.title for f in out] == ["Finding 0"]


class TestSalvageStaysConservative:
    def test_well_formed_output_is_unaffected(self):
        out = llm._parse_findings(json.dumps([_obj(0), _obj(1)]))

        assert [f.title for f in out] == ["Finding 0", "Finding 1"]

    def test_prose_with_no_objects_yields_nothing(self):
        assert llm._parse_findings("I was unable to analyze this target.") == []

    def test_an_empty_array_yields_nothing(self):
        assert llm._parse_findings("[]") == []

    def test_a_partial_first_object_yields_nothing(self):
        assert llm._parse_findings('[{"severity": "HIGH", "title": "Fin') == []


class TestTheOutputBudget:
    """The salvage bounds the damage; the budget is what avoids the cut."""

    @pytest.fixture
    def captured(self, monkeypatch) -> dict:
        seen: dict = {}

        class _Messages:
            def create(self, **kwargs):
                seen.update(kwargs)
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="[]")],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))
        return seen

    def test_tool_analysis_asks_for_more_than_the_old_ceiling(self, captured):
        llm.analyze_tools([{"name": "t", "description": "d"}])

        assert captured["max_tokens"] == llm._ANALYSIS_MAX_TOKENS

    def test_chain_reasoning_asks_for_more_than_the_old_ceiling(self, captured):
        llm.analyze_findings(
            [{"name": "t", "description": "d"}],
            [{"check": "c", "severity": "HIGH", "title": "t"}],
        )

        assert captured["max_tokens"] == llm._ANALYSIS_MAX_TOKENS

    def test_the_budget_clears_a_realistic_finding_set(self):
        """Thirty findings at ~120 output tokens each is an ordinary rich target."""
        assert llm._ANALYSIS_MAX_TOKENS >= 4000


class TestTruncationIsReported:
    def test_hitting_the_ceiling_is_logged_as_a_warning(self, monkeypatch):
        class _Messages:
            def create(self, **kwargs):
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text='[{"title": "a"')],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=9),
                    stop_reason="max_tokens",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))

        lines: list[str] = []
        llm._call_claude("s", "u", model="m", max_tokens=10, log=lines.append)

        assert any("truncat" in line.lower() for line in lines)

    def test_a_normal_stop_is_not_reported_as_truncation(self, monkeypatch):
        class _Messages:
            def create(self, **kwargs):
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="[]")],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))

        lines: list[str] = []
        llm._call_claude("s", "u", model="m", max_tokens=10, log=lines.append)

        assert not any("truncat" in line.lower() for line in lines)
