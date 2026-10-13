"""The quickstart recipes are real commands, and the launch path runs.

A renamed flag or a doctor that no longer exits 0 would leave the
copy-paste blocks in QUICKSTART.md green while the first command an
operator types fails.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from mcpnuke.cli import parse_args
from tests.reference_target import start_reference_server

_ROOT = Path(__file__).resolve().parent.parent
_QUICKSTART = _ROOT / "QUICKSTART.md"

_PLACEHOLDERS = {
    "<mcp-host>": "127.0.0.1",
    "<other-host>": "127.0.0.1",
    "<ollama-host>": "127.0.0.1",
    "<cluster-node>": "127.0.0.1",
}


def _invocations() -> list[list[str]]:
    """argv after the mcpnuke / ./scan token, placeholders filled."""
    found: list[list[str]] = []
    blocks = re.findall(r"```bash\n(.*?)```", _QUICKSTART.read_text(), re.S)
    for block in blocks:
        env: dict[str, str] = {}
        buf = ""
        lines: list[str] = []
        for raw in block.splitlines():
            if raw.strip().startswith("#"):
                continue
            buf += raw
            if raw.rstrip().endswith("\\"):
                buf = buf[:-1] + " "
                continue
            lines.append(buf)
            buf = ""
        for line in lines:
            line = line.strip()
            if not line:
                continue
            for old, new in _PLACEHOLDERS.items():
                line = line.replace(old, new)
            assigned = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
            if assigned and " " not in assigned.group(1):
                env[assigned.group(1)] = assigned.group(2).strip("'\"")
                continue
            for key, value in env.items():
                line = line.replace(f'"${key}"', value).replace(f"${key}", value)
            line = re.sub(r"\$[A-Za-z_][A-Za-z0-9_]*", "dummy", line)
            if line.startswith("export "):
                continue
            argv = shlex.split(line)
            if argv[:3] == ["uv", "run", "mcpnuke"]:
                argv = argv[3:]
            elif argv and argv[0] in {"mcpnuke", "./scan"}:
                argv = argv[1:]
            else:
                continue
            found.append(argv)
    return found


def test_quickstart_matches_the_scanner() -> None:
    """Claims the proof run showed were wrong."""
    text = _QUICKSTART.read_text()
    assert "10.43." not in text
    assert "reports findings, `0` if clean" not in text
    assert "default `high`" in text
    assert "--diff-baseline" in text


def test_every_quickstart_command_parses() -> None:
    commands = _invocations()
    assert len(commands) >= 20
    for argv in commands:
        try:
            parse_args(argv)
        except SystemExit as exc:
            pytest.fail(f"{argv} -> {exc.code}")


def test_doctor_exits_zero() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "mcpnuke", "--doctor"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_quiet_recipe_scans_the_reference_target(tmp_path: Path) -> None:
    """The triage recipe: catalog only, JSON report, no tool calls."""
    server = start_reference_server()
    report = tmp_path / "triage.json"
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcpnuke",
                "--targets",
                server.url,
                f"--auth-token={server.token}",
                "--no-invoke",
                "--json",
                str(report),
                "--fail-on",
                "none",
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        target = json.loads(report.read_text())["targets"][0]
        assert target["tools_total"] > 0
        assert target["inventory"]["server"]["name"] == "reference-target"
    finally:
        server.stop()
