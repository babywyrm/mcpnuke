"""The mcpnuke CLI must actually scan the in-repo reference target.

pytest already drives enumerate_server + run_all_checks against that
server (test_false_positives). CI never ran `python -m mcpnuke`, so a
broken console entry, JSON writer, or --fail-on none would only show up
when an operator typed it. This is that path, hermetic.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.reference_target import start_reference_server
from tests.test_false_positives import _EXPECTED as _HTTP_EXPECTED
from tests.test_false_positives_stdio import _EXPECTED as _STDIO_EXPECTED
from tests.test_false_positives_stdio import STDIO_COMMAND

_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(args: list[str], json_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "mcpnuke",
            *args,
            "--fast",
            "--no-invoke",
            "--fail-on",
            "none",
            "--json",
            str(json_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=_ROOT,
    )


def _unexpected_high(findings: list[dict], expected: dict[tuple[str, str], str]) -> list[dict]:
    return [
        f
        for f in findings
        if f.get("severity") in {"CRITICAL", "HIGH"}
        and not any(
            f.get("check") == check and marker in (f.get("title") or "")
            for check, marker in expected
        )
    ]


def _missing_expected(findings: list[dict], expected: dict[tuple[str, str], str]) -> list[tuple[str, str]]:
    """Empty JSON findings would otherwise pass `_unexpected_high`."""
    return [
        key
        for key in expected
        if not any(
            f.get("check") == key[0] and key[1] in (f.get("title") or "")
            for f in findings
        )
    ]


def test_cli_scans_the_http_reference_target(tmp_path: Path) -> None:
    server = start_reference_server()
    report = tmp_path / "http.json"
    try:
        proc = _run_cli(
            ["--targets", server.url, "--auth-token", server.token],
            report,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(report.read_text())
        targets = data["targets"]
        assert len(targets) == 1
        tgt = targets[0]
        assert tgt["tools_total"] > 0
        offenders = _unexpected_high(tgt["findings"], _HTTP_EXPECTED)
        assert not offenders, offenders
        missing = _missing_expected(tgt["findings"], _HTTP_EXPECTED)
        assert not missing, missing
    finally:
        server.stop()


def test_cli_scans_the_stdio_reference_target(tmp_path: Path) -> None:
    report = tmp_path / "stdio.json"
    proc = _run_cli(["--stdio", STDIO_COMMAND], report)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(report.read_text())
    tgt = data["targets"][0]
    assert tgt["transport"] == "stdio"
    assert tgt["tools_total"] > 0
    offenders = _unexpected_high(tgt["findings"], _STDIO_EXPECTED)
    assert not offenders, offenders
    missing = _missing_expected(tgt["findings"], _STDIO_EXPECTED)
    assert not missing, missing
