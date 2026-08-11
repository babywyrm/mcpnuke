"""Invariants that only break once the package is installed from PyPI.

Every failure guarded here is invisible from a source checkout with all
extras present, which is where all the other tests run. The first person to
hit one would be someone who just ran `pip install mcpnuke`.
"""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"

# Distribution names supplied only by optional extras. A console script that
# needs one of these at import time is broken in a base install.
_OPTIONAL_MODULES: frozenset[str] = frozenset({
    "anthropic", "boto3", "botocore", "fastapi", "kubernetes", "pydantic", "uvicorn",
})


def _config() -> dict:
    with _PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


def _scripts() -> dict[str, str]:
    return _config()["project"].get("scripts", {})


def test_there_are_console_scripts_to_check():
    """Guards the tests below from passing on an empty mapping."""
    assert _scripts()


@pytest.mark.parametrize("name", sorted(_scripts()))
def test_every_console_script_target_imports_without_an_extra(name):
    """`pip install mcpnuke` installs every script in [project.scripts],
    including ones whose implementation lives behind an extra. Importing the
    target module must therefore work with only the base dependencies.

    mcpnuke-runner failed this: it pointed at mcpnuke.server.app, whose
    package __init__ imports pydantic, so it printed a traceback rather than
    telling the user to install mcpnuke[server].

    The check has teeth only because the dev environment does not install the
    ai/k8s/server extras — the same shape as a base install.
    """
    target = _scripts()[name]
    module_path, _, attr = target.partition(":")

    module = importlib.import_module(module_path)

    assert hasattr(module, attr), f"{target} does not exist"
    assert callable(getattr(module, attr)), f"{target} is not callable"


@pytest.mark.parametrize("name", sorted(_scripts()))
def test_no_console_script_target_lives_under_an_optional_module(name):
    """Catches the regression at its cause rather than its symptom.

    Re-pointing a script at something inside mcpnuke.server would pass the
    import test above on any machine that happens to have the extra
    installed, and fail only for users.
    """
    module_path = _scripts()[name].partition(":")[0]
    module = importlib.import_module(module_path)

    offenders = sorted(
        m for m in _OPTIONAL_MODULES
        if getattr(module, m, None) is not None
    )
    assert not offenders, f"{name} imports optional deps at module level: {offenders}"


def test_the_package_declares_the_data_files_it_reads_at_runtime():
    """Files outside the package directory are not carried into the wheel,
    so a runtime read of one works from a checkout and fails once installed."""
    pkg = _ROOT / "mcpnuke"
    for relative in ("data/tool_names.txt", "data/taxonomy/lanes.yaml", "py.typed"):
        assert (pkg / relative).is_file(), f"{relative} missing from the package dir"


def test_version_is_a_release_number_not_a_local_or_dev_marker():
    """PyPI rejects local version identifiers, and does so after the tag has
    already been pushed."""
    version = _config()["project"]["version"]
    assert "+" not in version, f"local version identifier: {version}"
    assert not version.endswith((".dev", "dev0")), version
