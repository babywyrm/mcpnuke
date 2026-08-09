"""The version is declared twice and must not drift.

A wheel whose metadata disagrees with `mcpnuke --version` leaves a user unable
to tell which build they are running. That matters more here than in most
projects: the answer decides whether they have the release where a given check
stopped producing a false positive.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import mcpnuke

_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    with (_ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def test_package_version_matches_pyproject():
    assert mcpnuke.__version__ == _pyproject_version()


def test_cli_reports_the_version(capsys):
    """--version is the only way to ask a running install what it is."""
    import pytest

    from mcpnuke.cli import parse_args

    with pytest.raises(SystemExit) as exc:
        parse_args(["--version"])
    assert exc.value.code == 0
    assert mcpnuke.__version__ in capsys.readouterr().out


def test_changelog_documents_the_current_version():
    """A release that ships without a changelog entry cannot be diffed by the
    people it affects."""
    changelog = (_ROOT / "CHANGELOG.md").read_text()
    assert f"## [{mcpnuke.__version__}]" in changelog, (
        f"CHANGELOG.md has no section for {mcpnuke.__version__}. Close the "
        "Unreleased section before tagging."
    )
