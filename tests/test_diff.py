"""Tests for the scan diff engine."""

import json
import pytest
from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.reporting.diff import (
    ScanDiffResult,
    compare_scans,
    compare_json_files,
    format_diff_terminal,
)


def _finding(title: str, check: str = "auth", severity: str = "HIGH") -> Finding:
    return Finding(target="http://t", check=check, severity=severity, title=title)


def _result(findings: list[Finding], url: str = "http://localhost:8080/mcp") -> TargetResult:
    r = TargetResult(url=url)
    r.findings = findings
    return r


class TestCompareScansDiff:
    def test_empty_vs_empty_is_clean(self):
        diff = compare_scans(_result([]), _result([]))
        assert diff.new_findings == []
        assert diff.resolved_findings == []
        assert diff.unchanged_count == 0

    def test_new_finding_detected(self):
        before = _result([])
        after = _result([_finding("SQLi in param")])
        diff = compare_scans(before, after)
        assert len(diff.new_findings) == 1
        assert diff.new_findings[0].title == "SQLi in param"
        assert diff.resolved_findings == []

    def test_resolved_finding_detected(self):
        before = _result([_finding("SQLi in param")])
        after = _result([])
        diff = compare_scans(before, after)
        assert diff.new_findings == []
        assert len(diff.resolved_findings) == 1
        assert diff.resolved_findings[0].title == "SQLi in param"

    def test_unchanged_count_tracked(self):
        f = _finding("SSRF risk")
        before = _result([f, _finding("Other")])
        after = _result([f])
        diff = compare_scans(before, after)
        assert diff.unchanged_count == 1

    def test_matching_uses_check_and_title(self):
        f1 = _finding("A", check="auth")
        f2 = _finding("A", check="injection")
        before = _result([f1])
        after = _result([f2])
        diff = compare_scans(before, after)
        assert len(diff.new_findings) == 1
        assert len(diff.resolved_findings) == 1

    def test_severity_change_reported_as_changed(self):
        before = _result([_finding("Sec", severity="HIGH")])
        after = _result([_finding("Sec", severity="CRITICAL")])
        diff = compare_scans(before, after)
        assert len(diff.severity_changes) == 1
        change = diff.severity_changes[0]
        assert change["before"] == "HIGH"
        assert change["after"] == "CRITICAL"


class TestCompareJsonFiles:
    def _write_scan(self, tmp_path, findings: list[dict], fname: str = "scan.json") -> str:
        data = {
            "targets": [
                {
                    "url": "http://localhost:8080/mcp",
                    "transport": "http",
                    "risk_score": 10,
                    "auth_context": {},
                    "tools_total": 0,
                    "tools_scanned": 0,
                    "tools_scanned_names": [],
                    "tools_unscanned_count": 0,
                    "timings": {},
                    "findings": findings,
                    "attack_chains": [],
                }
            ]
        }
        path = tmp_path / fname
        path.write_text(json.dumps(data))
        return str(path)

    def test_compare_two_json_files(self, tmp_path):
        before_path = self._write_scan(tmp_path, [], "before.json")
        after_path = self._write_scan(tmp_path, [
            {"check": "auth", "severity": "HIGH", "title": "New finding",
             "detail": "", "evidence": "", "lane": None, "transport": None,
             "taxonomy_id": "", "mitre_id": ""}
        ], "after.json")
        diff = compare_json_files(before_path, after_path)
        assert len(diff.new_findings) == 1

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            compare_json_files("/nonexistent/a.json", "/nonexistent/b.json")


class TestFormatDiffTerminal:
    def test_format_no_changes(self):
        diff = ScanDiffResult(
            new_findings=[],
            resolved_findings=[],
            severity_changes=[],
            unchanged_count=5,
        )
        text = format_diff_terminal(diff)
        assert "5" in text
        assert "unchanged" in text.lower() or "no new" in text.lower()

    def test_format_new_findings_listed(self):
        diff = ScanDiffResult(
            new_findings=[_finding("SSRF via webhook", severity="CRITICAL")],
            resolved_findings=[],
            severity_changes=[],
            unchanged_count=0,
        )
        text = format_diff_terminal(diff)
        assert "SSRF via webhook" in text
        assert "CRITICAL" in text

    def test_format_resolved_findings_listed(self):
        diff = ScanDiffResult(
            new_findings=[],
            resolved_findings=[_finding("Old vuln")],
            severity_changes=[],
            unchanged_count=1,
        )
        text = format_diff_terminal(diff)
        assert "Old vuln" in text
