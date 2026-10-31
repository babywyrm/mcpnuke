"""The CLI --owasp report against the in-repo lab.

tests/test_owasp_lab.py drives the scanner in-process. CI's dogfood job
runs this file so a broken console entry or JSON writer fails on its
own, the same way the quiet reference target is scanned.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from mcpnuke.reporting.owasp import OWASP_MCP_TOP10
from tests.owasp_lab import start_owasp_lab
from tests.test_owasp_lab import _MARKER

_ROOT = Path(__file__).resolve().parent.parent


def _alignment_markdown(buckets: dict[str, Any]) -> str:
    """A short table for the Actions step summary."""
    lines = [
        "### OWASP lab alignment",
        "",
        "| Category | Findings | Marker |",
        "| --- | ---: | --- |",
    ]
    for code, name in OWASP_MCP_TOP10.items():
        block = buckets[code]
        lines.append(
            f"| {code} {name} | {block['finding_count']} | {_MARKER[code]} |"
        )
    lines.append("")
    return "\n".join(lines)


def _publish_alignment(text: str) -> None:
    print(text, flush=True)
    dest = os.environ.get("GITHUB_STEP_SUMMARY")
    if not dest:
        return
    with Path(dest).open("a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def test_alignment_markdown_names_every_marker(tmp_path: Path, monkeypatch) -> None:
    buckets = {
        code: {"finding_count": 1, "findings": [{"check": check}]}
        for code, check in _MARKER.items()
    }
    text = _alignment_markdown(buckets)
    dest = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(dest))
    _publish_alignment(text)
    written = dest.read_text(encoding="utf-8")
    for code, check in _MARKER.items():
        assert code in written
        assert check in written
        assert OWASP_MCP_TOP10[code] in written


def test_cli_owasp_report_lights_every_category(tmp_path: Path) -> None:
    server = start_owasp_lab()
    report_path = tmp_path / "owasp.json"
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcpnuke",
                "--targets",
                server.url,
                "--no-invoke",
                "--fail-on",
                "none",
                "--owasp",
                "--json",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=_ROOT,
            check=False,
        )
    finally:
        server.stop()

    assert proc.returncode == 0, proc.stdout + proc.stderr
    # Rich wraps the header on CI's narrow console and paints it with ANSI,
    # so the words are not one contiguous substring of the raw stream.
    plain = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout)
    plain = re.sub(r"\s+", " ", plain)
    assert "OWASP MCP Top 10 alignment" in plain
    assert "(no findings fired)" not in plain
    for code in OWASP_MCP_TOP10:
        assert f"{code} —" in plain

    report = json.loads(report_path.read_text())
    buckets = report["owasp_mcp"]["owasp_mcp"]
    missing = [
        f"{code} wanted {_MARKER[code]}"
        for code in OWASP_MCP_TOP10
        if _MARKER[code] not in {item["check"] for item in buckets[code]["findings"]}
    ]
    assert missing == []
    visible = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout)
    start = visible.find("OWASP MCP Top 10 alignment")
    print(visible[start:] if start != -1 else visible, flush=True)
    _publish_alignment(_alignment_markdown(buckets))
