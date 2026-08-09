"""What mcpnuke reports against MCP servers other people wrote.

The existing gate (tests/test_false_positives.py) measures a server we wrote
to be quiet. This one measures servers we did not write, pinned to exact
versions and launched locally, because our own SECURITY.md forbids scanning
hosted endpoints we do not control.

A snapshot diff proves the output *changed*. Whether it is *wrong* is decided
in docs/oss-target-baseline.md, which the diff sends you back to.

Run:     MCPNUKE_OSS_TARGETS=1 uv run pytest tests/test_oss_targets.py -v
Update:  MCPNUKE_OSS_TARGETS=1 MCPNUKE_OSS_UPDATE=1 uv run pytest tests/test_oss_targets.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.oss_targets.runner import launcher_available, scan_target
from tests.oss_targets.targets import TARGETS

pytestmark = pytest.mark.skipif(
    os.environ.get("MCPNUKE_OSS_TARGETS", "0") != "1",
    reason="MCPNUKE_OSS_TARGETS!=1 — set it to run against local open-source servers",
)

_SNAPSHOT_DIR = Path(__file__).parent / "oss_targets" / "snapshots"
_UPDATING = os.environ.get("MCPNUKE_OSS_UPDATE", "0") == "1"


def _snapshot_path(name: str) -> Path:
    return _SNAPSHOT_DIR / f"{name}.json"


def _describe(rows: list[dict]) -> str:
    return "\n".join(
        f"  {r['severity']:<8} {r['check']:<32} {r['title'][:70]}" for r in rows
    )


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_snapshot_matches(name):
    target = TARGETS[name]
    if not launcher_available(target.launcher):
        pytest.skip(f"{target.launcher} not installed")

    live = scan_target(target)
    path = _snapshot_path(name)

    if _UPDATING:
        _SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"version": target.version, "findings": live}, indent=2) + "\n"
        )
        pytest.skip(f"snapshot updated: {path.name}")

    assert path.exists(), (
        f"no snapshot for {name}. Capture one with MCPNUKE_OSS_UPDATE=1."
    )
    stored = json.loads(path.read_text())

    assert stored["version"] == target.version, (
        f"{name}: snapshot was captured against {stored['version']}, pin is "
        f"now {target.version}. Re-capture and re-triage."
    )

    added = [r for r in live if r not in stored["findings"]]
    removed = [r for r in stored["findings"] if r not in live]
    assert not added and not removed, (
        f"{name} snapshot drifted.\n"
        f"NEW ({len(added)}):\n{_describe(added)}\n"
        f"GONE ({len(removed)}):\n{_describe(removed)}\n\n"
        "Re-triage in docs/oss-target-baseline.md, then update with "
        "MCPNUKE_OSS_UPDATE=1."
    )
