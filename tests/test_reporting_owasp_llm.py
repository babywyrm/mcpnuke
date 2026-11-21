"""OWASP Top 10 for LLM Applications (2025) alignment reporting.

A second view over the same findings as --owasp. Model-side categories
(poisoning, embeddings, misinformation) are out of scope for an MCP server
scan: nothing maps to them, and the report says so instead of calling them
gaps.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.reporting.owasp import (
    LLM_OUT_OF_SCOPE,
    OWASP_LLM_TOP10,
    OWASP_MCP_TO_LLM,
    OWASP_MCP_TOP10,
    build_owasp,
    build_owasp_llm,
    print_owasp_llm,
)


def _finding(taxonomy_id: str = "", check: str = "c", title: str = "t") -> Finding:
    return Finding(
        target="http://t",
        check=check,
        severity="HIGH",
        title=title,
        detail="d",
        taxonomy_id=taxonomy_id,
    )


def _results(*findings: Finding) -> list[TargetResult]:
    r = TargetResult(url="http://t")
    r.findings.extend(findings)
    return [r]


def _bucket_of(finding: Finding) -> str:
    report = build_owasp_llm(_results(finding))
    lit = [cat for cat, block in report["owasp_llm"].items() if block["finding_count"]]
    if "unmapped" in report:
        lit.append("unmapped")
    assert len(lit) == 1, lit
    return lit[0]


class TestMappingContract:
    def test_ten_canonical_categories_in_order(self) -> None:
        assert list(OWASP_LLM_TOP10) == [f"LLM{i:02d}" for i in range(1, 11)]

    def test_every_mcp_category_has_an_explicit_llm_answer(self) -> None:
        assert set(OWASP_MCP_TO_LLM) == set(OWASP_MCP_TOP10)

    def test_mapped_values_are_canonical_and_in_scope(self) -> None:
        for mcp, llm in OWASP_MCP_TO_LLM.items():
            if llm is not None:
                assert llm in OWASP_LLM_TOP10, mcp
                assert llm not in LLM_OUT_OF_SCOPE, mcp

    def test_out_of_scope_is_the_model_side(self) -> None:
        assert {"LLM04", "LLM08", "LLM09"} == LLM_OUT_OF_SCOPE


class TestBucketing:
    @pytest.mark.parametrize(
        ("finding", "expected"),
        [
            (_finding("MCP-T21"), "LLM02"),  # OAuth token theft: MCP01
            (_finding("MCP-T25"), "LLM06"),  # delegation abuse: MCP02
            (_finding("", check="tool_poisoning"), "LLM01"),  # MCP03
            (_finding("MCP-T08"), "LLM03"),  # supply chain: MCP04
            (_finding("", check="code_execution"), "LLM05"),  # MCP05
            (_finding("MCP-T02"), "LLM01"),  # indirect injection: MCP06
            (_finding("MCP-T20"), "LLM06"),  # RBAC bypass: MCP07
            (_finding("", check="shadow_mcp_server"), "LLM03"),  # MCP09
            (_finding("MCP-T11"), "LLM02"),  # cross-tenant leak: MCP10
        ],
    )
    def test_follows_the_mcp_category(self, finding: Finding, expected: str) -> None:
        assert _bucket_of(finding) == expected

    @pytest.mark.parametrize(
        ("finding", "expected"),
        [
            (_finding("MCP-T27"), "LLM10"),  # LLM cost exhaustion
            (_finding("MCP-T31"), "LLM10"),  # budget tuning
            (_finding("MCP-T51"), "LLM10"),  # anonymous rate-limit exhaustion
            (_finding("MCP-T54"), "LLM10"),  # open inference backend
            (_finding("MCP-T10"), "LLM06"),  # hallucination-driven destruction
            (_finding("MCP-T01", check="prompt_leakage"), "LLM07"),
        ],
    )
    def test_sharper_llm_fit_overrides(self, finding: Finding, expected: str) -> None:
        assert _bucket_of(finding) == expected

    def test_audit_findings_have_no_llm_counterpart(self) -> None:
        assert _bucket_of(_finding("MCP-T13")) == "unmapped"

    def test_untagged_findings_stay_unmapped(self) -> None:
        assert _bucket_of(_finding("", check="llm_tool_analysis")) == "unmapped"


class TestReport:
    def test_all_ten_present_with_scope(self) -> None:
        report = build_owasp_llm(_results(_finding("MCP-T21")))
        assert report["schema"] == "v1"
        assert list(report["owasp_llm"]) == list(OWASP_LLM_TOP10)
        for cat, block in report["owasp_llm"].items():
            assert block["name"] == OWASP_LLM_TOP10[cat]
            assert block["in_scope"] is (cat not in LLM_OUT_OF_SCOPE)

    def test_total_counts_every_finding_once(self) -> None:
        report = build_owasp_llm(
            _results(_finding("MCP-T21"), _finding("MCP-T13"), _finding(""))
        )
        assert report["total_findings"] == 3
        assert report["unmapped"]["finding_count"] == 2

    def test_mcp_report_is_unchanged(self) -> None:
        results = _results(_finding("MCP-T01", check="prompt_leakage"))
        report = build_owasp(results)
        assert report["owasp_mcp"]["MCP06"]["finding_count"] == 1
        assert "owasp_llm" not in report

    def test_json_report_carries_both_views(self) -> None:
        from mcpnuke.reporting.json_out import build_report

        report = build_report(_results(_finding("MCP-T54")))
        assert report["owasp_llm"]["owasp_llm"]["LLM10"]["finding_count"] == 1
        assert report["owasp_mcp"]["owasp_mcp"]["MCP07"]["finding_count"] == 1


class TestPrint:
    def test_plain_output_names_every_category_and_scope(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        print_owasp_llm(_results(_finding("MCP-T21"), _finding("MCP-T13")))
        out = capsys.readouterr().out
        assert "OWASP Top 10 for LLM Applications (2025)" in out
        for cat, name in OWASP_LLM_TOP10.items():
            assert f"{cat} — {name}" in out
        assert out.count("(model-side: out of scope for an MCP server scan)") == 3
        assert "Unmapped" in out

    def test_console_output_escapes_server_text(self) -> None:
        buf = io.StringIO()
        console = Console(file=buf, width=200, color_system=None)
        print_owasp_llm(
            _results(_finding("MCP-T21", title="[red]x[/red] \x1b]52;c;AAAA\x07")),
            console=console,
        )
        out = buf.getvalue()
        assert "[red]x[/red]" in out
        assert "\x1b" not in out
