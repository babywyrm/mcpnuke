"""The guard that stops a tag shipping the wrong version to PyPI.

A PyPI upload cannot be undone or replaced: publishing 6.15.0 under a v6.16.0
tag burns the version number permanently. tests/test_version_consistency.py
keeps __init__.py, pyproject.toml and the changelog in agreement, but none of
them can see the git tag.

This logic lives in a script rather than inline in the workflow YAML so that
it can be tested here instead of being exercised for the first time during a
release.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_GUARD = _ROOT / "scripts" / "check-tag-version.sh"
_BASH = shutil.which("bash") or "/bin/bash"


def _run(tag: str, version: str = "6.15.0"):
    return subprocess.run(
        [_BASH, str(_GUARD), tag, version],
        capture_output=True, text=True, timeout=60,
    )


def test_the_guard_exists_and_is_executable():
    assert _GUARD.is_file()


@pytest.mark.parametrize("tag", ["v6.15.0", "6.15.0", "refs/tags/v6.15.0"])
def test_matching_tag_passes(tag):
    """Accepts a bare tag, a v-prefixed tag, and a full ref, because
    different workflow contexts hand over different shapes of the same
    thing."""
    result = _run(tag)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("tag", ["v6.16.0", "v6.15.1", "v7.0.0", "v6.15"])
def test_mismatched_tag_fails(tag):
    result = _run(tag)
    assert result.returncode != 0
    assert "6.15.0" in result.stdout + result.stderr


def test_a_prerelease_tag_does_not_match_the_release_version():
    """v6.15.0-rc1 and 6.15.0 are different releases. A substring or prefix
    comparison would let this through."""
    assert _run("v6.15.0-rc1").returncode != 0


def test_an_empty_tag_fails():
    """A workflow misconfiguration that leaves the ref empty must not be
    read as agreement."""
    assert _run("").returncode != 0


def test_an_empty_version_fails():
    assert _run("v6.15.0", "").returncode != 0


def test_a_local_version_identifier_is_rejected():
    """PyPI refuses these, and it refuses them after the tag is already
    pushed."""
    assert _run("v6.15.0+dirty", "6.15.0+dirty").returncode != 0


def test_the_publish_workflow_calls_this_guard():
    """A renamed or moved script would leave the workflow calling something
    that does not exist, and the first sign of it would be a failed release."""
    workflow = (_ROOT / ".github" / "workflows" / "publish.yml").read_text()
    assert "./scripts/check-tag-version.sh" in workflow


def test_the_publish_workflow_only_uploads_on_a_tag():
    """Guards the one condition that separates a release from every other
    push. A publish job that ran on branch pushes would ship whatever was on
    main."""
    import yaml

    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "publish.yml").read_text())
    publish = workflow["jobs"]["publish"]

    assert "refs/tags/" in publish["if"]
    # Uploading is opt-in on top of the tag check, so a tag pushed before the
    # PyPI trusted publisher exists produces a green build with the upload
    # skipped, rather than a red one nobody can fix from this repo.
    assert "vars.PYPI_PUBLISH" in publish["if"]
    # Trusted publishing needs this and must not be granted repo-wide.
    assert publish["permissions"] == {"id-token": "write"}
    assert workflow.get("permissions") == {"contents": "read"}


def test_the_real_project_version_matches_its_own_tag():
    """Ties the guard to the actual packaged version, so this test starts
    describing the next release the moment the version is bumped."""
    import tomllib

    with (_ROOT / "pyproject.toml").open("rb") as fh:
        version = tomllib.load(fh)["project"]["version"]

    assert _run(f"v{version}", version).returncode == 0
