"""A server cannot crash or restyle the scanner's output with rich markup in its names."""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

from tests.hostile_markup.stdio_server import SERVER_NAME, TOOL_NAME

_ROOT = Path(__file__).resolve().parent.parent
_COMMAND = f"{shlex.quote(sys.executable)} -m tests.hostile_markup.stdio_server"


def test_markup_in_server_strings_is_printed_not_parsed(tmp_path: Path) -> None:
    report = tmp_path / "scan.json"
    proc = subprocess.run(
        [
            sys.executable, "-m", "mcpnuke", "--stdio", _COMMAND, "--verbose", "--by-lane", "--owasp",
            "--fail-on", "none", "--json", str(report),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=_ROOT,
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert SERVER_NAME in proc.stdout
    target = json.loads(report.read_text())["targets"][0]
    assert target["tools_scanned_names"] == [TOOL_NAME]
