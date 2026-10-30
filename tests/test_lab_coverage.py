"""A target profile says which labs exist. The check catalog says which fire."""

import json
from pathlib import Path

from mcpnuke.reporting.lab_coverage import build_lab_coverage
from mcpnuke.reporting.taxonomy_coverage import check_taxonomy_catalog

_ROOT = Path(__file__).resolve().parent.parent


def test_a_lab_with_no_check_is_a_gap() -> None:
    profile = {
        "name": "toy",
        "tools": [
            {"name": "alpha.read", "threat_id": "MCP-T01"},
            {"name": "alpha.write", "threat_id": "MCP-T01"},
            {"name": "beta.run", "threat_id": "MCP-T99"},
        ],
    }
    catalog = {"quiet_check": frozenset({"MCP-T01"})}
    report = build_lab_coverage(profile, catalog)
    by_lab = {row["lab"]: row for row in report["labs"]}
    assert by_lab["alpha"]["tools"] == 2
    assert by_lab["alpha"]["checks"] == ["quiet_check"]
    assert by_lab["alpha"]["gap"] is False
    assert by_lab["beta"]["checks"] == []
    assert by_lab["beta"]["gap"] is True
    assert report["summary"]["gaps"] == 1


def test_a_tool_with_no_threat_id_is_unmapped() -> None:
    profile = {"name": "toy", "tools": [{"name": "lone"}]}
    report = build_lab_coverage(profile, {})
    assert report["summary"]["unmapped"] == 1
    assert report["labs"] == []


def test_the_dvmcp_profile_meets_the_real_catalog() -> None:
    profile = json.loads((_ROOT / "profiles" / "dvmcp.json").read_text())
    report = build_lab_coverage(profile, check_taxonomy_catalog())
    assert report["name"] == "dvmcp"
    assert report["summary"]["labs"] == len(report["labs"])
    assert report["summary"]["labs"] > 0
