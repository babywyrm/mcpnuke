"""Tests for SARIF 2.1.0 export."""

import json
import pytest
from mcpnuke.core.models import TargetResult, Finding
from mcpnuke.reporting.sarif import build_sarif, write_sarif


def _make_result(url: str = "http://localhost:8080/mcp") -> TargetResult:
    result = TargetResult(url=url, transport="http")
    return result


def _add_finding(result: TargetResult, check: str, severity: str, title: str,
                 detail: str = "", evidence: str = "",
                 taxonomy_id: str = "", mitre_id: str = "") -> None:
    result.add(check, severity, title, detail, evidence,
               taxonomy_id=taxonomy_id, mitre_id=mitre_id)


class TestBuildSarif:
    def test_schema_and_version(self):
        sarif = build_sarif([])
        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_empty_results(self):
        sarif = build_sarif([])
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "mcpnuke"

    def test_critical_maps_to_error(self):
        result = _make_result()
        _add_finding(result, "tool_poisoning", "CRITICAL", "Tool Poisoning Detected")
        sarif = build_sarif([result])
        r = sarif["runs"][0]["results"][0]
        assert r["level"] == "error"
        assert r["ruleId"] == "tool_poisoning"

    def test_high_maps_to_error(self):
        result = _make_result()
        _add_finding(result, "exfil_flow", "HIGH", "Data Exfiltration Path")
        sarif = build_sarif([result])
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_medium_maps_to_warning(self):
        result = _make_result()
        _add_finding(result, "name_confusion", "MEDIUM", "Name Confusion")
        sarif = build_sarif([result])
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_low_maps_to_note(self):
        result = _make_result()
        _add_finding(result, "tls_hygiene", "LOW", "TLS Not Verified")
        sarif = build_sarif([result])
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_location_uses_target_url(self):
        result = _make_result("http://target:9090/mcp")
        _add_finding(result, "check_a", "HIGH", "Test")
        sarif = build_sarif([result])
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "http://target:9090/mcp"

    def test_rules_deduplicated(self):
        result = _make_result()
        _add_finding(result, "same_check", "HIGH", "First")
        _add_finding(result, "same_check", "HIGH", "Second")
        sarif = build_sarif([result])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len([r for r in rules if r["id"] == "same_check"]) == 1

    def test_multiple_findings(self):
        result = _make_result()
        _add_finding(result, "check_a", "CRITICAL", "A")
        _add_finding(result, "check_b", "MEDIUM", "B")
        sarif = build_sarif([result])
        assert len(sarif["runs"][0]["results"]) == 2

    def test_taxonomy_id_in_rule_tags(self):
        result = _make_result()
        _add_finding(result, "scope_pollution", "HIGH", "Scope Pollution",
                     taxonomy_id="MCP-T06", mitre_id="T1078")
        sarif = build_sarif([result])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "MCP-T06" in rule["properties"]["tags"]
        assert "T1078" in rule["properties"]["tags"]

    def test_security_severity_critical(self):
        result = _make_result()
        _add_finding(result, "check_crit", "CRITICAL", "Critical")
        sarif = build_sarif([result])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert float(rule["properties"]["security-severity"]) >= 9.0

    def test_evidence_in_message(self):
        result = _make_result()
        _add_finding(result, "check_e", "HIGH", "Test", evidence="tool_xyz leaked data")
        sarif = build_sarif([result])
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "tool_xyz leaked data" in msg

    def test_multiple_targets(self):
        r1 = _make_result("http://target1/mcp")
        r2 = _make_result("http://target2/mcp")
        _add_finding(r1, "check_a", "HIGH", "A")
        _add_finding(r2, "check_b", "MEDIUM", "B")
        sarif = build_sarif([r1, r2])
        assert len(sarif["runs"][0]["results"]) == 2
        urls = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in sarif["runs"][0]["results"]}
        assert "http://target1/mcp" in urls
        assert "http://target2/mcp" in urls


class TestWriteSarif:
    def test_writes_valid_json(self, tmp_path):
        result = _make_result()
        _add_finding(result, "check_a", "HIGH", "Test")
        out = tmp_path / "out.sarif"
        write_sarif([result], str(out))
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_console_message_printed(self, tmp_path, capsys):
        from rich.console import Console
        result = _make_result()
        out = tmp_path / "out.sarif"
        console = Console()
        write_sarif([result], str(out), console=console)
        # File should exist and be valid
        assert out.exists()
        assert json.loads(out.read_text())["version"] == "2.1.0"
