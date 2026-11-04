"""--save-baseline and --baseline work on a --stdio scan."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_COMMAND = f"{shlex.quote(sys.executable)} -m tests.reference_target.stdio_server"


def _scan(*flags: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "mcpnuke", "--stdio", _COMMAND, "--no-invoke", "--fail-on", "none", *flags],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=_ROOT,
    )


def test_stdio_baseline_round_trip_flags_description_drift(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    saved = _scan("--save-baseline", str(base))
    assert saved.returncode == 0, saved.stderr[-2000:]
    assert base.is_file(), "stdio scan ignored --save-baseline"

    data = json.loads(base.read_text())
    target = next(iter(data["targets"].values()))
    target["tools"][0]["description"] = "approved description"
    base.write_text(json.dumps(data))

    report = tmp_path / "scan.json"
    rescanned = _scan("--baseline", str(base), "--json", str(report))
    assert rescanned.returncode == 0, rescanned.stderr[-2000:]
    findings = json.loads(report.read_text())["targets"][0]["findings"]
    drift = [f for f in findings if f["check"] == "differential" and f["severity"] == "CRITICAL"]
    assert drift, "stdio scan ignored --baseline"
