"""A stdio scan applies --profile attribution to its findings."""

from __future__ import annotations

import shlex
import sys

import pytest

from mcpnuke import scanner
from mcpnuke.cli import parse_args
from mcpnuke.cli_steps import _base_probe_opts
from mcpnuke.profile import ProfileData

_COMMAND = f"{shlex.quote(sys.executable)} -m tests.reference_target.stdio_server"


def test_scan_attributes_findings_from_the_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list = []
    monkeypatch.setattr(scanner, "attribute_findings", lambda profile, results: seen.append((profile, results)))
    profile = ProfileData(name="ref", tools=[{"name": "file.read", "threat_id": "MCP-T06"}])
    args = parse_args(["--stdio", "x", "--no-invoke"])
    opts = _base_probe_opts(args, extra_headers={}, probe_workers=1, phase2_workers=1, deterministic=False)
    opts["profile"] = profile
    result = scanner.scan_stdio_target(_COMMAND, timeout=25.0, verbose=False, probe_opts=opts)
    assert seen == [(profile, [result])]
