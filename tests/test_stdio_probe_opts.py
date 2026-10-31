"""--stdio builds its probe options from the same base as a URL scan."""

import sys

import pytest

from mcpnuke import __main__ as cli_main
from mcpnuke.core.models import TargetResult


def _stdio_opts(monkeypatch: pytest.MonkeyPatch, *flags: str) -> dict:
    seen: dict = {}

    def _fake_scan(cmd: str, timeout: float, verbose: bool, probe_opts: dict) -> TargetResult:
        seen.update(probe_opts)
        return TargetResult(url="stdio://fake")

    monkeypatch.setattr(cli_main, "scan_stdio_target", _fake_scan)
    monkeypatch.setattr(cli_main, "_report", lambda *a, **k: None)
    monkeypatch.setattr(sys, "argv", ["mcpnuke", "--stdio", "fake-server", *flags])
    with pytest.raises(SystemExit):
        cli_main._main_inner()
    return seen


def test_stdio_honors_error_reflection(monkeypatch: pytest.MonkeyPatch) -> None:
    opts = _stdio_opts(monkeypatch, "--error-reflection", "keep")
    assert opts["error_reflection"] == "keep"


def test_stdio_opts_match_the_shared_base(monkeypatch: pytest.MonkeyPatch) -> None:
    opts = _stdio_opts(monkeypatch, "--fast", "--safe-mode")
    args = cli_main.parse_args(["--stdio", "fake-server", "--fast", "--safe-mode"])
    base = cli_main._base_probe_opts(
        args, extra_headers=opts["extra_headers"],
        probe_workers=opts["probe_workers"], phase2_workers=opts["claude_phase2_workers"],
        deterministic=opts["deterministic"],
    )
    assert opts == base
