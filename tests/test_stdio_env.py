"""A stdio server under test gets the SDK's default variables, not the scanner's secrets."""

import sys

import pytest

from mcpnuke import __main__ as cli_main
from mcpnuke import scanner
from mcpnuke.cli import parse_args
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports import stdio

_SECRET = "SYNTHETIC_SCANNER_API_KEY"


@pytest.fixture
def scanner_env(monkeypatch) -> None:
    monkeypatch.setenv(_SECRET, "synthetic-value")
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("HOME", "/home/lab")


def test_child_env_keeps_defaults_and_drops_secrets(scanner_env) -> None:
    env = stdio.child_env()
    assert env["PATH"] == "/usr/bin"
    assert _SECRET not in env


def test_named_variable_passes_through(scanner_env) -> None:
    assert stdio.child_env((_SECRET, "UNSET_SYNTHETIC_NAME")) == {
        **stdio.child_env(),
        _SECRET: "synthetic-value",
    }


def test_exported_shell_function_is_not_inherited(monkeypatch) -> None:
    monkeypatch.setenv("SHELL", "() { evil; }")
    assert "SHELL" not in stdio.child_env()


def test_session_launches_with_the_filtered_env(scanner_env, monkeypatch) -> None:
    seen: dict = {}

    class _Proc:
        stdout = iter(())

    def _popen(cmd, **kwargs):
        seen.update(kwargs)
        return _Proc()

    monkeypatch.setattr(stdio.subprocess, "Popen", _popen)
    stdio.StdioSession(["server"], env={"EXTRA": "1"}, inherit=("HOME",))
    assert _SECRET not in seen["env"]
    assert seen["env"]["EXTRA"] == "1"
    assert seen["env"]["HOME"] == "/home/lab"


def test_scan_stdio_target_forwards_pass_through_names(monkeypatch) -> None:
    seen: dict = {}

    def _session(cmd, **kwargs):
        seen.update(kwargs)
        raise OSError("not launched")

    monkeypatch.setattr(scanner, "StdioSession", _session)
    scanner.scan_stdio_target("server", inherit_env=("GITHUB_TOKEN",))
    assert seen["inherit"] == ("GITHUB_TOKEN",)


def test_cli_flag_reaches_the_scan(monkeypatch) -> None:
    assert parse_args(["--stdio", "s", "--stdio-env", "A", "--stdio-env", "B"]).stdio_env == ["A", "B"]
    seen: dict = {}

    def _fake_scan(cmd: str, **kwargs) -> TargetResult:
        seen.update(kwargs)
        return TargetResult(url="stdio://fake")

    monkeypatch.setattr(cli_main, "scan_stdio_target", _fake_scan)
    monkeypatch.setattr(cli_main, "_report", lambda *a, **k: None)
    monkeypatch.setattr(sys, "argv", ["mcpnuke", "--stdio", "s", "--stdio-env", "GITHUB_TOKEN"])
    with pytest.raises(SystemExit):
        cli_main._main_inner()
    assert seen["inherit_env"] == ("GITHUB_TOKEN",)
