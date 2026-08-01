"""Tests for taxonomy_id extraction and JSON serialization."""

import json

from mcpnuke.core.llm import _parse_findings
from mcpnuke.core.models import TargetResult


class TestTaxonomyExtraction:
    def test_structured_field_mcp_id_used_when_present(self):
        raw = json.dumps([{
            "severity": "CRITICAL",
            "title": "[AI] [MCP-T06] Credential Exposure",
            "detail": "test",
            "taxonomy_id": "MCP-T06",
        }])
        findings = _parse_findings(raw)
        assert len(findings) == 1
        assert findings[0].taxonomy_id == "MCP-T06"

    def test_title_fallback_extracts_mcp_id(self):
        raw = json.dumps([{
            "severity": "HIGH",
            "title": "[AI] [MCP-T02] AI-Mediated Code Execution",
            "detail": "test",
        }])
        findings = _parse_findings(raw)
        assert len(findings) == 1
        assert findings[0].taxonomy_id == "MCP-T02"

    def test_title_fallback_extracts_mitre_id(self):
        raw = json.dumps([{
            "severity": "CRITICAL",
            "title": "[AI] [T1059] System Takeover",
            "detail": "test",
        }])
        findings = _parse_findings(raw)
        assert len(findings) == 1
        assert findings[0].mitre_id == "T1059"

    def test_none_string_treated_as_absent(self):
        raw = json.dumps([{
            "severity": "HIGH",
            "title": "[AI] [MCP-T05] Webhook",
            "detail": "test",
            "taxonomy_id": "None",
        }])
        findings = _parse_findings(raw)
        assert findings[0].taxonomy_id == "MCP-T05"

    def test_no_taxonomy_in_title_returns_empty(self):
        raw = json.dumps([{
            "severity": "MEDIUM",
            "title": "Some finding without taxonomy",
            "detail": "test",
        }])
        findings = _parse_findings(raw)
        assert findings[0].taxonomy_id == ""
        assert findings[0].mitre_id == ""

    def test_both_mcp_and_mitre_in_title(self):
        raw = json.dumps([{
            "severity": "CRITICAL",
            "title": "[MCP-T03] [T1195] Supply Chain",
            "detail": "test",
        }])
        findings = _parse_findings(raw)
        assert findings[0].taxonomy_id == "MCP-T03"
        assert findings[0].mitre_id == "T1195"


class TestJsonSerialization:
    def _make_result(self, taxonomy_id="", mitre_id=""):
        from mcpnuke.core.models import Finding
        result = TargetResult(url="http://localhost:8080/mcp")
        f = Finding(
            target="http://localhost:8080/mcp",
            check="test",
            severity="HIGH",
            title="[MCP-T06] Secret",
            taxonomy_id=taxonomy_id,
            mitre_id=mitre_id,
        )
        result.findings = [f]
        return result

    def test_taxonomy_id_present_in_json_output(self, tmp_path):
        from mcpnuke.reporting.json_out import write_json
        result = self._make_result(taxonomy_id="MCP-T06")
        out = tmp_path / "out.json"
        write_json([result], str(out))
        data = json.loads(out.read_text())
        finding = data["targets"][0]["findings"][0]
        assert "taxonomy_id" in finding
        assert finding["taxonomy_id"] == "MCP-T06"

    def test_mitre_id_present_in_json_output(self, tmp_path):
        from mcpnuke.reporting.json_out import write_json
        result = self._make_result(mitre_id="T1059")
        out = tmp_path / "out.json"
        write_json([result], str(out))
        data = json.loads(out.read_text())
        finding = data["targets"][0]["findings"][0]
        assert finding.get("mitre_id") == "T1059"

    def test_tools_total_and_scanned_in_json(self, tmp_path):
        from mcpnuke.reporting.json_out import write_json
        result = TargetResult(url="http://localhost:8080/mcp")
        result.tools = [{"name": "a"}, {"name": "b"}]
        result.tools_total = 10
        out = tmp_path / "out.json"
        write_json([result], str(out))
        data = json.loads(out.read_text())
        target = data["targets"][0]
        assert target["tools_total"] == 10
        assert target["tools_scanned"] == 2
        assert "tools_unscanned_count" in target
        assert target["tools_unscanned_count"] == 8

    def test_raw_token_redacted_from_json_output(self, tmp_path):
        from mcpnuke.reporting.json_out import write_json
        result = TargetResult(url="http://localhost:8080/mcp")
        result.auth_context = {
            "_raw_token": "supersecret.jwt.token",
            "jwt_claims_summary": {"sub": "user123"},
        }
        out = tmp_path / "out.json"
        write_json([result], str(out))
        data = json.loads(out.read_text())
        auth = data["targets"][0]["auth_context"]
        assert "_raw_token" not in auth
        assert auth.get("jwt_claims_summary") == {"sub": "user123"}

    def test_build_report_raw_token_redacted(self):
        from mcpnuke.reporting.json_out import build_report
        result = TargetResult(url="http://localhost:8080/mcp")
        result.auth_context = {"_raw_token": "tok", "other": "kept"}
        report = build_report([result], include_k8s=False)
        auth = report["targets"][0]["auth_context"]
        assert "_raw_token" not in auth
        assert auth.get("other") == "kept"
