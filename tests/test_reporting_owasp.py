"""OWASP MCP Top 10 alignment reporting.

Maps findings to the canonical OWASP MCP Top 10 (2025) categories via their
agentic-sec taxonomy_id and renders a per-category alignment summary.

The vendored lanes.yaml carries an `owasp_mcp` field, but those values mirror
camazotz scenario numbering (MCP11..MCP32 appear; early entries are sequential
permutations), not the OWASP Top 10. The mapping here is curated against the
canonical list and owned by this repo.
"""

from __future__ import annotations

import yaml

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.reporting.owasp import OWASP_MCP_TOP10, TAXONOMY_TO_OWASP, build_owasp


def _finding(taxonomy_id: str = "", severity: str = "HIGH", check: str = "c") -> Finding:
    return Finding(
        target="http://t",
        check=check,
        severity=severity,
        title=f"title-{taxonomy_id or 'none'}",
        detail="d",
        taxonomy_id=taxonomy_id,
    )


def _results(*findings: Finding) -> list[TargetResult]:
    r = TargetResult(url="http://t")
    r.findings.extend(findings)
    return [r]


class TestMappingContract:
    def test_every_vendored_threat_id_is_mapped(self):
        with open("mcpnuke/data/taxonomy/lanes.yaml", encoding="utf-8") as fh:
            lanes = yaml.safe_load(fh)
        threat_ids = [t["threat_id"] for t in lanes["threats"]]
        missing = [t for t in threat_ids if t not in TAXONOMY_TO_OWASP]
        assert not missing, f"taxonomy IDs missing OWASP mapping: {missing}"

    def test_every_mapped_value_is_a_canonical_category(self):
        for tid, owasp_id in TAXONOMY_TO_OWASP.items():
            assert owasp_id in OWASP_MCP_TOP10, f"{tid} maps to unknown {owasp_id}"

    def test_all_ten_canonical_categories_exist(self):
        assert list(OWASP_MCP_TOP10) == [f"MCP{i:02d}" for i in range(1, 11)]


class TestBuildOwasp:
    def test_findings_bucket_by_taxonomy_id(self):
        report = build_owasp(_results(_finding("MCP-T21"), _finding("MCP-T21")))
        bucket = report["owasp_mcp"]["MCP01"]
        assert bucket["finding_count"] == 2
        assert bucket["severity_tally"] == {"HIGH": 2}

    def test_all_ten_categories_present_even_when_empty(self):
        report = build_owasp(_results(_finding("MCP-T13")))
        assert len(report["owasp_mcp"]) == 10
        assert report["owasp_mcp"]["MCP09"]["finding_count"] == 0
        assert report["owasp_mcp"]["MCP08"]["finding_count"] == 1

    def test_findings_without_taxonomy_land_in_unmapped(self):
        report = build_owasp(_results(_finding(""), _finding("MCP-T99")))
        assert report["unmapped"]["finding_count"] == 2

    def test_check_name_fallback_for_untagged_core_checks(self):
        report = build_owasp(_results(_finding("", check="code_execution")))
        assert report["owasp_mcp"]["MCP05"]["finding_count"] == 1
        assert "unmapped" not in report

    def test_taxonomy_id_wins_over_check_fallback(self):
        # code_execution falls back to MCP05, but an explicit taxonomy ID
        # (here: secrets in output) must take precedence.
        report = build_owasp(_results(_finding("MCP-T07", check="code_execution")))
        assert report["owasp_mcp"]["MCP01"]["finding_count"] == 1
        assert report["owasp_mcp"]["MCP05"]["finding_count"] == 0

    def test_ai_findings_without_taxonomy_stay_unmapped(self):
        report = build_owasp(_results(_finding("", check="llm_tool_analysis")))
        assert report["unmapped"]["finding_count"] == 1

    def test_total_counts_every_finding_once(self):
        report = build_owasp(
            _results(_finding("MCP-T21"), _finding(""), _finding("MCP-T53"))
        )
        assert report["total_findings"] == 3

    def test_severity_tally_in_canonical_order(self):
        report = build_owasp(
            _results(
                _finding("MCP-T21", severity="LOW"),
                _finding("MCP-T21", severity="CRITICAL"),
            )
        )
        tally = report["owasp_mcp"]["MCP01"]["severity_tally"]
        assert list(tally) == ["CRITICAL", "LOW"]


class TestPrintOwasp:
    def test_print_smoke(self, capsys):
        from mcpnuke.reporting.owasp import print_owasp

        print_owasp(_results(_finding("MCP-T21"), _finding("")))
        out = capsys.readouterr().out
        assert "MCP01" in out
        assert "Token Mismanagement" in out
        assert "Unmapped" in out


class TestJsonReport:
    def test_build_report_includes_owasp_alignment(self):
        from mcpnuke.reporting.json_out import build_report

        report = build_report(_results(_finding("MCP-T53")))
        assert report["owasp_mcp"]["owasp_mcp"]["MCP05"]["finding_count"] == 1
        assert report["owasp_mcp"]["total_findings"] == 1
