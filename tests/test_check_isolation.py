"""A check or target that crashes cannot hide the rest of the scan.

One check raising used to abort every check after it, and run_parallel
dropped a crashing target from the results, so --fail-on saw nothing and
exited 0. A server that trips a check on purpose hid itself from a CI gate.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

import mcpnuke.checks as checks
import mcpnuke.scanner as scanner
from mcpnuke.checks.base import time_check
from mcpnuke.cli_steps import _exit_code
from mcpnuke.core.enumerator import enumerate_server
from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.core.session import detect_transport
from mcpnuke.reporting.console import print_report
from mcpnuke.reporting.json_out import write_json
from mcpnuke.subcommands import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS
from tests.owasp_lab import start_owasp_lab


def _crash(result: TargetResult) -> None:
    with time_check("prompt_leakage", result):
        raise KeyError("unexpected schema shape")


def _scan_lab() -> TargetResult:
    server = start_owasp_lab()
    try:
        session = detect_transport(server.url)
        assert session is not None
        result = TargetResult(url=server.url)
        enumerate_server(session, result)
        checks.run_all_checks(session, result, [result], probe_opts={"no_invoke": True})
    finally:
        server.stop()
    return result


class TestCheckIsolation:
    def test_a_crashing_check_does_not_stop_the_rest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clean = _scan_lab()
        monkeypatch.setattr(checks, "check_prompt_leakage", _crash)
        crashed = _scan_lab()

        def survivors(r: TargetResult) -> list[tuple[str, str]]:
            return sorted((f.check, f.title) for f in r.findings if f.check != "prompt_leakage")

        assert survivors(crashed) == survivors(clean)
        assert set(crashed.timings) == set(clean.timings) - {"prompt_leakage"}
        assert crashed.check_errors == {"prompt_leakage": "KeyError: 'unexpected schema shape'"}
        assert clean.check_errors == {}

    def test_time_check_records_completed_checks_only(self) -> None:
        """A timing reads as "ran clean" to --taxonomy-coverage."""
        result = TargetResult(url="http://t")
        with time_check("ok", result):
            pass
        with pytest.raises(RuntimeError), time_check("boom", result):
            raise RuntimeError("x")
        assert set(result.timings) == {"ok"}

    def test_error_text_is_redacted_and_bounded(self) -> None:
        result = TargetResult(url="http://t")
        result.note_check_error("c", ValueError("key AKIAIOSFODNN7EXAMPLE " + "x" * 1000))
        message = result.check_errors["c"]
        assert "AKIAIOSFODNN7EXAMPLE" not in message
        assert message.startswith("ValueError: ")
        assert len(message) <= 320


class TestTargetIsolation:
    def test_a_crashing_target_stays_in_the_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def scan_target(url: str, *_args: object, **_kwargs: object) -> TargetResult:
            if url.endswith(":2/mcp"):
                raise ConnectionResetError("peer reset")
            return TargetResult(url=url)

        monkeypatch.setattr(scanner, "scan_target", scan_target)
        results = scanner.run_parallel(["http://h:1/mcp", "http://h:2/mcp"], workers=2)

        by_url = {r.url: r for r in results}
        assert set(by_url) == {"http://h:1/mcp", "http://h:2/mcp"}
        assert by_url["http://h:2/mcp"].check_errors == {"scan": "ConnectionResetError: peer reset"}
        assert by_url["http://h:1/mcp"].check_errors == {}


def _finding(severity: str) -> Finding:
    return Finding(target="t", check="c", severity=severity, title="t", detail="d")


class TestExitCode:
    def test_an_incomplete_scan_exits_2_even_with_findings(self) -> None:
        r = TargetResult(url="t")
        r.check_errors["c"] = "KeyError: x"
        assert _exit_code([r], [_finding("CRITICAL")], "high") == EXIT_ERROR

    def test_findings_at_threshold_exit_1(self) -> None:
        assert _exit_code([TargetResult(url="t")], [_finding("HIGH")], "high") == EXIT_FINDINGS

    def test_clean_scan_exits_0(self) -> None:
        assert _exit_code([TargetResult(url="t")], [_finding("LOW")], "high") == EXIT_CLEAN

    def test_routine_probe_errors_do_not_change_the_exit(self) -> None:
        r = TargetResult(url="t")
        r.note_error("dpop_no_header probe error: timeout")
        assert _exit_code([r], [], "high") == EXIT_CLEAN


def test_cli_exits_2_and_keeps_the_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from mcpnuke.__main__ import main

    monkeypatch.setattr(checks, "check_prompt_leakage", _crash)
    report = tmp_path / "r.json"
    server = start_owasp_lab()
    try:
        monkeypatch.setattr(
            "sys.argv",
            ["mcpnuke", "--targets", server.url, "--no-invoke", "--fail-on", "critical",
             "--json", str(report)],
        )
        with pytest.raises(SystemExit) as exit_info:
            main()
    finally:
        server.stop()

    assert exit_info.value.code == EXIT_ERROR
    target = json.loads(report.read_text())["targets"][0]
    assert target["check_errors"] == {"prompt_leakage": "KeyError: 'unexpected schema shape'"}
    assert target["findings"]
    assert "Incomplete scan" in capsys.readouterr().out


class TestReporting:
    def _crashed(self) -> TargetResult:
        r = TargetResult(url="http://t/mcp")
        r.check_errors["prompt_leakage"] = "KeyError: [red]x[/red]"
        return r

    def test_console_says_incomplete_not_clean(self) -> None:
        buf = io.StringIO()
        print_report([self._crashed()], console=Console(file=buf, width=200, color_system=None))
        out = buf.getvalue()
        assert "Incomplete scan" in out
        assert "prompt_leakage" in out
        assert "KeyError: [red]x[/red]" in out
        assert "No vulnerabilities found" not in out

    def test_json_carries_check_errors(self, tmp_path: Path) -> None:
        path = tmp_path / "r.json"
        write_json([self._crashed(), TargetResult(url="http://u/mcp")], str(path), console=None)
        targets = json.loads(path.read_text())["targets"]
        assert targets[0]["check_errors"] == {"prompt_leakage": "KeyError: [red]x[/red]"}
        assert targets[1]["check_errors"] == {}
