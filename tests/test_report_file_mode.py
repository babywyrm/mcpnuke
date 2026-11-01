"""Scan output is written readable by its owner only."""

import os
import stat
from pathlib import Path

import pytest

from mcpnuke.core.models import TargetResult
from mcpnuke.diff import save_baseline
from mcpnuke.reporting.files import write_private
from mcpnuke.reporting.json_out import write_json
from mcpnuke.reporting.sarif import write_sarif

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_new_file_is_owner_only(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    write_private(out, "{}")
    assert _mode(out) == 0o600
    assert out.read_text() == "{}"


def test_existing_world_readable_file_is_tightened(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    out.write_text("old contents that are longer")
    out.chmod(0o644)
    write_private(out, "new")
    assert _mode(out) == 0o600
    assert out.read_text() == "new"


@pytest.mark.parametrize("writer", ["json", "sarif", "baseline"])
def test_report_writers_are_owner_only(tmp_path: Path, writer: str) -> None:
    out = tmp_path / "out"
    results = [TargetResult(url="http://t")]
    {
        "json": lambda: write_json(results, str(out)),
        "sarif": lambda: write_sarif(results, str(out)),
        "baseline": lambda: save_baseline(results, out),
    }[writer]()
    assert _mode(out) == 0o600
