"""The runner must work before it can measure anything.

Uses server-memory: the smallest and fastest of the pinned targets.
"""

from __future__ import annotations

import os
import shutil

import pytest

from tests.oss_targets.runner import launcher_available, scan_target
from tests.oss_targets.targets import TARGETS

pytestmark = pytest.mark.skipif(
    os.environ.get("MCPNUKE_OSS_TARGETS", "0") != "1",
    reason="MCPNUKE_OSS_TARGETS!=1 — set it to run against local open-source servers",
)


def test_pin_table_is_fully_pinned():
    """An unpinned target makes the measurement unreproducible."""
    for name, target in TARGETS.items():
        assert target.version, f"{name} has no version pin"
        assert target.version in target.command, (
            f"{name}: command {target.command!r} does not carry the pin "
            f"{target.version!r}"
        )


def test_launcher_availability_is_detectable():
    assert launcher_available("npx") == bool(shutil.which("npx"))


def test_memory_server_scans():
    target = TARGETS["server-memory"]
    if not launcher_available(target.launcher):
        pytest.skip(f"{target.launcher} not installed")

    findings = scan_target(target)
    assert isinstance(findings, list)
    # Every entry is normalized down to the three stable fields.
    for f in findings:
        assert set(f) == {"check", "severity", "title"}


def test_findings_are_sorted_for_a_stable_diff():
    target = TARGETS["server-memory"]
    if not launcher_available(target.launcher):
        pytest.skip(f"{target.launcher} not installed")

    findings = scan_target(target)
    keys = [(f["check"], f["severity"], f["title"]) for f in findings]
    assert keys == sorted(keys)
