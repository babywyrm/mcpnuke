"""Tests for --diff-baseline live scan wiring."""

import json

from mcpnuke.cli import parse_args


class TestDiffBaselineCLI:
    def test_diff_baseline_flag_parses(self, tmp_path):
        baseline = tmp_path / "baseline.json"
        baseline.write_text("{}")
        args = parse_args([
            "--targets", "http://localhost:8080/mcp",
            "--diff-baseline", str(baseline),
        ])
        assert args.diff_baseline == str(baseline)

    def test_diff_baseline_default_is_none(self):
        args = parse_args(["--targets", "http://localhost:8080/mcp"])
        assert getattr(args, "diff_baseline", None) is None


class TestDiffBaselineIntegration:
    """Verify scan_diff is attached to TargetResult when baseline is provided."""

    def _make_baseline_file(self, tmp_path, findings: list[dict]) -> str:
        data = {
            "targets": [{
                "url": "http://localhost:8080/mcp",
                "transport": "http",
                "risk_score": 0,
                "auth_context": {},
                "tools_total": 0,
                "tools_scanned": 0,
                "tools_scanned_names": [],
                "tools_unscanned_count": 0,
                "timings": {},
                "findings": findings,
                "attack_chains": [],
            }]
        }
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(data))
        return str(p)

    def test_scan_diff_attached_when_baseline_provided(self, tmp_path):
        from mcpnuke.core.models import Finding, TargetResult
        from mcpnuke.reporting.diff import ScanDiffResult, compare_json_files
        from mcpnuke.reporting.json_out import write_json

        # Build a "current" scan result
        result = TargetResult(url="http://localhost:8080/mcp")
        result.findings = [
            Finding(target=result.url, check="auth", severity="HIGH", title="New finding"),
        ]

        # Build baseline with no findings
        baseline_path = self._make_baseline_file(tmp_path, [])

        # Compute diff and attach to result
        current_json = tmp_path / "current.json"
        write_json([result], str(current_json))
        diff = compare_json_files(baseline_path, str(current_json))
        result.scan_diff = diff

        assert result.scan_diff is not None
        assert isinstance(result.scan_diff, ScanDiffResult)
        assert len(result.scan_diff.new_findings) == 1

    def test_scan_diff_written_to_json_output(self, tmp_path):
        from mcpnuke.core.models import Finding, TargetResult
        from mcpnuke.reporting.diff import ScanDiffResult
        from mcpnuke.reporting.json_out import write_json

        result = TargetResult(url="http://localhost:8080/mcp")
        result.findings = [
            Finding(target=result.url, check="auth", severity="HIGH", title="A finding"),
        ]
        result.scan_diff = ScanDiffResult(
            new_findings=result.findings[:],
            resolved_findings=[],
            severity_changes=[],
            unchanged_count=0,
        )
        out = tmp_path / "out.json"
        write_json([result], str(out))
        data = json.loads(out.read_text())
        target = data["targets"][0]
        assert "diff" in target
        diff = target["diff"]
        assert "new" in diff
        assert len(diff["new"]) == 1
        assert diff["new"][0]["title"] == "A finding"
        assert "resolved" in diff
        assert "unchanged_count" in diff
