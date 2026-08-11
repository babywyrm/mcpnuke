"""install.sh is the first code a new user runs, and it runs unreviewed.

These tests drive the script's `--dry-run` mode, which resolves a plan and
prints it without touching the machine. PATH is rewritten per-test so method
selection can be exercised without caring what the developer happens to have
installed.

The one test that really installs something is gated behind
MCPNUKE_INSTALL_LIVE=1, following DVMCP_LIVE and MCPNUKE_OSS_TARGETS: default
CI stays hermetic and offline.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_INSTALL_SH = _ROOT / "install.sh"


def _fake_tool(bin_dir: Path, name: str) -> None:
    """Put an executable of the given name on a throwaway PATH."""
    path = bin_dir / name
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


_BASH = shutil.which("bash") or "/bin/bash"


def _run(*args: str, tools: list[str] | None = None, tmp_path: Path | None = None):
    """Run install.sh with only `tools` available on PATH.

    PATH holds nothing but the stub directory. Leaving the real /usr/bin on
    it made "no installer available" untestable, because macOS ships a
    system pip3 that the script would find. Everything the script touches on
    the --dry-run path is a shell builtin, so nothing real is needed — and
    bash itself is invoked by absolute path for the same reason.
    """
    env = dict(os.environ)
    if tools is not None:
        assert tmp_path is not None
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(exist_ok=True)
        for tool in tools:
            _fake_tool(bin_dir, tool)
        env["PATH"] = str(bin_dir)
    return subprocess.run(
        [_BASH, str(_INSTALL_SH), *args],
        capture_output=True, text=True, timeout=120, env=env,
    )


def test_the_script_exists_and_is_executable():
    assert _INSTALL_SH.is_file()
    assert os.access(_INSTALL_SH, os.X_OK), "install.sh must be chmod +x to be piped to sh"


def test_help_exits_zero():
    result = _run("--help")
    assert result.returncode == 0, result.stderr
    assert "install.sh" in result.stdout


def test_prefers_uv_when_available(tmp_path):
    result = _run("--dry-run", tools=["uv", "pipx", "pip3"], tmp_path=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "uv tool install" in result.stdout


def test_falls_back_to_pipx_without_uv(tmp_path):
    result = _run("--dry-run", tools=["pipx", "pip3"], tmp_path=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "pipx install" in result.stdout
    assert "uv tool install" not in result.stdout


def test_falls_back_to_pip_user_without_uv_or_pipx(tmp_path):
    """Last resort, because it is the one that can disturb an existing
    environment. The script warns rather than staying silent about it."""
    result = _run("--dry-run", tools=["pip3"], tmp_path=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "pip3 install" in result.stdout
    assert "--user" in result.stdout


def test_fails_clearly_when_nothing_can_install(tmp_path):
    result = _run("--dry-run", tools=[], tmp_path=tmp_path)
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "uv" in combined and "pipx" in combined


def test_installs_the_plain_package_by_default(tmp_path):
    result = _run("--dry-run", tools=["uv"], tmp_path=tmp_path)
    assert "mcpnuke" in result.stdout
    assert "[" not in result.stdout.split("uv tool install")[1].split("\n")[0]


def test_extras_are_requested_as_a_pep508_spec(tmp_path):
    result = _run("--dry-run", "--extras", "all", tools=["uv"], tmp_path=tmp_path)
    assert "mcpnuke[all]" in result.stdout


def test_version_pin_is_passed_through(tmp_path):
    result = _run("--dry-run", "--version", "6.15.0", tools=["uv"], tmp_path=tmp_path)
    assert "mcpnuke==6.15.0" in result.stdout


def test_from_overrides_the_source_entirely(tmp_path):
    """Without this the script could not be tested until it was published,
    which is the sort of thing users end up testing."""
    wheel = "/tmp/mcpnuke-6.15.0-py3-none-any.whl"
    result = _run("--dry-run", "--from", wheel, tools=["uv"], tmp_path=tmp_path)
    assert wheel in result.stdout


def test_from_and_version_together_are_rejected(tmp_path):
    """A pin and an explicit source contradict each other, and silently
    honouring one would install something the user did not ask for."""
    result = _run(
        "--dry-run", "--from", "/tmp/x.whl", "--version", "6.15.0",
        tools=["uv"], tmp_path=tmp_path,
    )
    assert result.returncode != 0


def test_an_unknown_flag_is_an_error(tmp_path):
    result = _run("--dry-run", "--frobnicate", tools=["uv"], tmp_path=tmp_path)
    assert result.returncode != 0


def test_dry_run_changes_nothing(tmp_path):
    """The plan is printed, not executed. Asserted via the stub tools: a real
    install would need network, and the stubs exit 0 without doing anything,
    so the only honest signal is that the script says so."""
    result = _run("--dry-run", tools=["uv"], tmp_path=tmp_path)
    assert "dry run" in result.stdout.lower()


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_shellcheck_is_clean():
    result = subprocess.run(
        ["shellcheck", str(_INSTALL_SH)], capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout


@pytest.mark.skipif(
    os.getenv("MCPNUKE_INSTALL_LIVE") != "1",
    reason="set MCPNUKE_INSTALL_LIVE=1 to really install into a temp prefix",
)
def test_live_install_from_a_local_wheel(tmp_path):
    """The whole point of --from: exercise the real install path before the
    package exists on PyPI."""
    subprocess.run(
        ["uv", "build", "--out-dir", str(tmp_path / "dist")],
        cwd=_ROOT, check=True, capture_output=True, timeout=300,
    )
    wheel = next((tmp_path / "dist").glob("*.whl"))

    env = dict(os.environ, UV_TOOL_BIN_DIR=str(tmp_path / "bin"),
               UV_TOOL_DIR=str(tmp_path / "tools"))
    result = subprocess.run(
        ["bash", str(_INSTALL_SH), "--from", str(wheel)],
        capture_output=True, text=True, timeout=600, env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    installed = tmp_path / "bin" / "mcpnuke"
    assert installed.is_file(), sorted((tmp_path / "bin").glob("*"))
    version = subprocess.run(
        [str(installed), "--version"], capture_output=True, text=True, timeout=60,
    )
    assert "mcpnuke" in version.stdout
