"""AI prompts must constrain taxonomy_id to ids that actually exist.

Phase 1 named a range; Phase 3 said only "MCP threat taxonomy ID if
applicable" and the model duly invented `MCP-2024-AUTH-001`,
`MCP-2024-INJECT-002` and friends against a live DVMCP target. Findings
tagged with ids outside the taxonomy cannot be mapped to the threat model.
"""

from __future__ import annotations

import re

from mcpnuke.core.llm import taxonomy_id_clause
from mcpnuke.core.taxonomy import threat_ids


class TestTaxonomyClause:
    def test_the_clause_names_the_real_bounds(self) -> None:
        ids = sorted(threat_ids())
        clause = taxonomy_id_clause()
        assert ids[0] in clause
        assert ids[-1] in clause

    def test_the_clause_forbids_inventing_ids(self) -> None:
        clause = taxonomy_id_clause().lower()
        assert "only" in clause or "must" in clause
        assert "invent" in clause or "do not" in clause

    def test_the_clause_tracks_the_taxonomy(self) -> None:
        """Derived, not hardcoded — a taxonomy change must move the clause."""
        assert "MCP-T55" not in taxonomy_id_clause() or "MCP-T55" in threat_ids()


class TestBothPhasesCarryTheConstraint:
    def _system_prompt(self, monkeypatch, fn_name: str, *args) -> str:
        from mcpnuke.core import llm

        captured: dict[str, str] = {}

        def fake_call(system, user, model, max_tokens, log=None):
            captured["system"] = system
            return "[]"

        monkeypatch.setattr(llm, "_call_claude", fake_call)
        getattr(llm, fn_name)(*args)
        return captured["system"]

    def test_phase1_tool_analysis_constrains_ids(self, monkeypatch) -> None:
        system = self._system_prompt(
            monkeypatch, "analyze_tools", [{"name": "t", "description": "d"}]
        )
        assert taxonomy_id_clause() in system

    def test_phase3_chain_reasoning_constrains_ids(self, monkeypatch) -> None:
        system = self._system_prompt(
            monkeypatch,
            "analyze_findings",
            [{"name": "t", "description": "d"}],
            [{"check": "auth", "severity": "HIGH", "title": "x"}],
        )
        assert taxonomy_id_clause() in system

    def test_no_phase_names_a_stale_hardcoded_range(self, monkeypatch) -> None:
        """`MCP-T01 through MCP-T55` drifted from a 57-id taxonomy ending T58."""
        for fn, args in (
            ("analyze_tools", ([{"name": "t", "description": "d"}],)),
            (
                "analyze_findings",
                ([{"name": "t"}], [{"check": "a", "severity": "HIGH", "title": "x"}]),
            ),
        ):
            system = self._system_prompt(monkeypatch, fn, *args)
            assert "MCP-T55" not in system, f"{fn} names a hardcoded stale upper bound"


class TestParsingRejectsInventedIds:
    def test_ids_outside_the_taxonomy_are_dropped(self) -> None:
        from mcpnuke.core.llm import _parse_findings

        payload = (
            '[{"severity":"CRITICAL","title":"real","detail":"d",'
            '"taxonomy_id":"MCP-T05"},'
            '{"severity":"CRITICAL","title":"invented","detail":"d",'
            '"taxonomy_id":"MCP-2024-AUTH-001"}]'
        )
        out = _parse_findings(payload)
        ids = [f.taxonomy_id for f in out]
        assert "MCP-T05" in ids
        assert "MCP-2024-AUTH-001" not in ids, "invented id survived parsing"

    def test_the_finding_itself_is_kept(self) -> None:
        """Drop the bogus id, not the analysis."""
        from mcpnuke.core.llm import _parse_findings

        out = _parse_findings(
            '[{"severity":"HIGH","title":"keep me","detail":"d",'
            '"taxonomy_id":"MCP-2024-INJECT-002"}]'
        )
        assert len(out) == 1
        assert out[0].title == "keep me"
        assert not out[0].taxonomy_id

    def test_real_ids_survive(self) -> None:
        from mcpnuke.core.llm import _parse_findings

        for tid in sorted(threat_ids())[:5]:
            out = _parse_findings(
                f'[{{"severity":"LOW","title":"t","detail":"d","taxonomy_id":"{tid}"}}]'
            )
            assert out[0].taxonomy_id == tid

    def test_case_and_spacing_are_tolerated(self) -> None:
        from mcpnuke.core.llm import _parse_findings

        out = _parse_findings(
            '[{"severity":"LOW","title":"t","detail":"d","taxonomy_id":" mcp-t05 "}]'
        )
        assert out[0].taxonomy_id == "MCP-T05"

    def test_no_taxonomy_id_is_fine(self) -> None:
        from mcpnuke.core.llm import _parse_findings

        out = _parse_findings('[{"severity":"LOW","title":"t","detail":"d"}]')
        assert len(out) == 1
        assert not out[0].taxonomy_id


def test_clause_shape_is_a_single_line() -> None:
    """It is embedded in a bulleted prompt; a stray newline breaks the list."""
    assert not re.search(r"\n\n", taxonomy_id_clause())
