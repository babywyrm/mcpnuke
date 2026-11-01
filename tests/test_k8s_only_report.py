"""Kubernetes findings reach every report and the --fail-on exit code."""

import json
import sys
from pathlib import Path

import pytest

from mcpnuke import __main__ as cli_main
from mcpnuke.__main__ import EXIT_CLEAN, EXIT_FINDINGS
from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS
from mcpnuke.reporting.sarif import build_sarif


@pytest.fixture(autouse=True)
def _clean_globals():
    GLOBAL_K8S_FINDINGS.clear()
    yield
    GLOBAL_K8S_FINDINGS.clear()


def _run(monkeypatch: pytest.MonkeyPatch, severity: str, *flags: str) -> int:
    def _fake_setup(args, urls, console) -> None:
        GLOBAL_K8S_FINDINGS.append(
            Finding(target="k8s", check="rbac", severity=severity, title="Wildcard RBAC",
                    detail="synthetic", evidence="verbs: ['*']")
        )

    monkeypatch.setattr(cli_main, "_k8s_setup", _fake_setup)
    monkeypatch.setattr(sys, "argv", ["mcpnuke", "--k8s-discover", *flags])
    with pytest.raises(SystemExit) as exc:
        cli_main._main_inner()
    return int(exc.value.code or 0)


def test_json_uses_the_standard_schema(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    _run(monkeypatch, "HIGH", "--json", str(out))
    report = json.loads(out.read_text())
    assert report["targets"] == []
    assert report["k8s_findings"][0]["evidence"] == "verbs: ['*']"


def test_sarif_is_written(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    out = tmp_path / "report.sarif"
    _run(monkeypatch, "HIGH", "--sarif", str(out))
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_fail_on_gates_on_k8s_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run(monkeypatch, "HIGH") == EXIT_FINDINGS
    GLOBAL_K8S_FINDINGS.clear()
    assert _run(monkeypatch, "LOW") == EXIT_CLEAN


def _run_url_scan(monkeypatch: pytest.MonkeyPatch, *flags: str) -> int:
    monkeypatch.setattr(cli_main, "scan_target", lambda url, *a, **k: TargetResult(url=url))
    monkeypatch.setattr(sys, "argv", ["mcpnuke", "--targets", "http://127.0.0.1:9/mcp", *flags])
    try:
        cli_main._main_inner()
    except SystemExit as exc:
        return int(exc.code or 0)
    return EXIT_CLEAN


def test_url_scan_fails_on_k8s_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_setup(args, urls, console) -> None:
        GLOBAL_K8S_FINDINGS.append(
            Finding(target="k8s", check="pod_security", severity="CRITICAL", title="Privileged pod")
        )

    monkeypatch.setattr(cli_main, "_k8s_setup", _fake_setup)
    assert _run_url_scan(monkeypatch) == EXIT_FINDINGS


def test_sarif_includes_k8s_findings() -> None:
    GLOBAL_K8S_FINDINGS.append(
        Finding(target="k8s://default/mcp", check="rbac", severity="HIGH", title="Wildcard RBAC",
                evidence="verbs: ['*']")
    )
    results = build_sarif([])["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["rbac"]
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "k8s://default/mcp"
    assert "verbs: ['*']" in results[0]["message"]["text"]


def test_sarif_can_leave_k8s_findings_out() -> None:
    GLOBAL_K8S_FINDINGS.append(Finding(target="k8s", check="rbac", severity="HIGH", title="t"))
    assert build_sarif([], include_k8s=False)["runs"][0]["results"] == []
