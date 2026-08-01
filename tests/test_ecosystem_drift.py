"""Cross-repo drift guards.

Three guarantees enforced by this module:

1. **Profile in sync** — every entry in ``profiles/camazotz.json`` must have
   a matching ``camazotz_modules/<lab>/scenario.yaml`` in the sibling camazotz
   repo, AND every camazotz lab must have profile entries.

2. **Profile threat IDs valid** — every ``threat_id`` referenced in the
   profile must exist in the vendored taxonomy.

3. **Profile lane/transport matches scenario** — for each tool entry, the
   profile's ``lane``/``transport`` must agree with the scenario file.

These tests are skipped when the camazotz repo is not present on disk
(e.g. CI runs that only install mcpnuke). When the repo IS present, drift
is a hard failure — preventing silent vocabulary divergence between
camazotz labs and mcpnuke's profile.

The matching test in camazotz is
``camazotz/tests/test_lane_taxonomy.py::test_agentic_sec_taxonomy_in_sync``
which guards drift between scenario files and the taxonomy itself.
Together the three repos (camazotz, mcpnuke, agentic-sec) cannot silently
drift on threat_id, lane, or transport.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import yaml

from mcpnuke.core.taxonomy import threat_ids

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PROFILE = _REPO_ROOT / "profiles" / "camazotz.json"
_CAMAZOTZ_REPO = _REPO_ROOT.parent / "camazotz"
_CAMAZOTZ_MODULES = _CAMAZOTZ_REPO / "camazotz_modules"


def _camazotz_available() -> bool:
    return _CAMAZOTZ_MODULES.exists() and _CAMAZOTZ_MODULES.is_dir()


def _load_profile() -> list[dict]:
    return json.loads(_PROFILE.read_text())["tools"]


def _all_scenario_files() -> dict[str, dict]:
    """Return {lab_name: parsed_scenario_dict} for every camazotz lab."""
    out: dict[str, dict] = {}
    for scenario_path in sorted(_CAMAZOTZ_MODULES.glob("*/scenario.yaml")):
        lab_name = scenario_path.parent.name
        try:
            data = yaml.safe_load(scenario_path.read_text())
        except yaml.YAMLError:
            continue
        if isinstance(data, dict):
            out[lab_name] = data
    return out


# ---------------------------------------------------------------------------
# Profile integrity
# ---------------------------------------------------------------------------


def test_profile_loads_as_json() -> None:
    """profiles/camazotz.json must be valid JSON with a tools array."""
    data = json.loads(_PROFILE.read_text())
    assert isinstance(data, dict)
    assert "tools" in data
    assert isinstance(data["tools"], list)
    assert len(data["tools"]) > 0


def test_profile_entries_have_required_fields() -> None:
    """Every profile entry must have name + lane + transport + threat_id."""
    missing = []
    for tool in _load_profile():
        if not all(k in tool for k in ("name", "lane", "transport", "threat_id")):
            missing.append(tool.get("name", "<unnamed>"))
    assert not missing, f"Profile entries missing required fields: {missing}"


def test_profile_threat_ids_are_in_taxonomy() -> None:
    """Every threat_id referenced in the profile must exist in lanes.yaml."""
    valid = threat_ids()
    unknown = []
    for tool in _load_profile():
        tid = tool.get("threat_id")
        if tid not in valid:
            unknown.append(f"{tool.get('name', '?')}: threat_id={tid!r}")
    assert not unknown, (
        "Profile references threat IDs not in the vendored taxonomy. "
        "Either add them to agentic-sec/docs/taxonomy/lanes.yaml (and refresh the "
        "vendored copy at mcpnuke/data/taxonomy/lanes.yaml), or fix the profile:\n"
        + "\n".join(unknown)
    )


# ---------------------------------------------------------------------------
# Cross-repo drift — profile vs scenario.yaml (skipped if camazotz absent)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _camazotz_available(), reason="camazotz repo not adjacent")
def test_profile_tools_reference_known_threats() -> None:
    """
    Every threat_id in the profile must correspond to at least one camazotz lab
    in the adjacent sibling repo. Catches profile entries that point at threats
    no lab actually implements.
    """
    scenarios = _all_scenario_files()
    scenario_threat_ids: set[str] = set()
    for data in scenarios.values():
        tid = (data.get("threat_id") or "").strip('"')
        if tid:
            scenario_threat_ids.add(tid)

    orphaned = []
    for tool in _load_profile():
        tid = tool.get("threat_id")
        if tid not in scenario_threat_ids:
            orphaned.append(f"{tool.get('name', '?')}: threat_id={tid!r}")
    assert not orphaned, (
        "Profile entries reference threat IDs with no matching camazotz lab:\n"
        + "\n".join(orphaned)
    )


@pytest.mark.skipif(not _camazotz_available(), reason="camazotz repo not adjacent")
def test_profile_lane_transport_match_scenarios() -> None:
    """
    For each profile entry, the lane and transport must match what the
    corresponding scenario.yaml declares for that threat_id.

    Profiles can have many tools per scenario (one scenario yields multiple
    MCP tool names), but they must all agree on lane/transport.
    """
    scenarios = _all_scenario_files()
    # Index scenario lane/transport by threat_id
    by_tid: dict[str, tuple[int, str, str]] = {}
    for lab_name, data in scenarios.items():
        tid = (data.get("threat_id") or "").strip('"')
        if not tid:
            continue
        agentic = data.get("agentic") or {}
        lane = agentic.get("primary_lane", data.get("lane"))
        transport = agentic.get("transport", data.get("transport"))
        by_tid[tid] = (lane, transport, lab_name)

    mismatches = []
    for tool in _load_profile():
        tid = tool.get("threat_id")
        if tid not in by_tid:
            continue  # caught by the orphan test above
        sc_lane, sc_transport, lab_name = by_tid[tid]
        if tool.get("lane") != sc_lane:
            mismatches.append(
                f"{tool['name']} ({tid} → {lab_name}): "
                f"profile.lane={tool.get('lane')!r} != scenario.lane={sc_lane!r}"
            )
        if tool.get("transport") != sc_transport:
            mismatches.append(
                f"{tool['name']} ({tid} → {lab_name}): "
                f"profile.transport={tool.get('transport')!r} != scenario.transport={sc_transport!r}"
            )
    assert not mismatches, (
        "Profile lane/transport drifted from camazotz scenario.yaml:\n"
        + "\n".join(mismatches)
    )


@pytest.mark.skipif(not _camazotz_available(), reason="camazotz repo not adjacent")
def test_every_camazotz_lab_appears_in_profile() -> None:
    """
    Every camazotz lab whose threat_id is in the taxonomy should have at
    least one profile entry. Catches the case where a new lab ships in
    camazotz but mcpnuke's profile doesn't get updated.

    Excludes labs whose threat_id is in the taxonomy but whose tool surface
    isn't reachable via tools/list (e.g. teardown helpers); none currently.
    """
    valid = threat_ids()
    scenarios = _all_scenario_files()
    profile_threat_ids = {t.get("threat_id") for t in _load_profile()}

    missing = []
    for lab_name, data in scenarios.items():
        tid = (data.get("threat_id") or "").strip('"')
        if not tid or tid not in valid:
            continue
        if tid not in profile_threat_ids:
            missing.append(f"{lab_name} ({tid})")
    assert not missing, (
        "camazotz labs with no entry in profiles/camazotz.json. "
        "Add their tools to the profile when shipping a new lab:\n"
        + "\n".join(missing)
    )


# ---------------------------------------------------------------------------
# Taxonomy parity — taxonomy entries must match camazotz scenarios
# (skipped if camazotz absent)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _camazotz_available(), reason="camazotz repo not adjacent")
def test_vendored_taxonomy_matches_camazotz_scenarios() -> None:
    """
    The vendored taxonomy and the sibling camazotz scenarios must agree on
    threat_id/lane/transport for every lab. Mirrors the equivalent guard in
    camazotz/tests/test_lane_taxonomy.py.
    """
    from mcpnuke.core.taxonomy import load_taxonomy

    tax = load_taxonomy()
    tax_by_lab = {t["camazotz_lab"]: t for t in tax.get("threats", []) if "camazotz_lab" in t}
    scenarios = _all_scenario_files()

    errors = []
    for lab_name, data in scenarios.items():
        tid = (data.get("threat_id") or "").strip('"')
        if not tid:
            continue
        if lab_name not in tax_by_lab:
            errors.append(
                f"{lab_name}: in camazotz but not in vendored taxonomy "
                "(refresh mcpnuke/data/taxonomy/lanes.yaml from agentic-sec)"
            )
            continue
        entry = tax_by_lab[lab_name]
        if entry["threat_id"] != tid:
            errors.append(
                f"{lab_name}: scenario.threat_id={tid!r} vs taxonomy={entry['threat_id']!r}"
            )
        agentic = data.get("agentic") or {}
        sc_lane = agentic.get("primary_lane", data.get("lane"))
        sc_transport = agentic.get("transport", data.get("transport"))
        if sc_lane != entry["lane"]:
            errors.append(
                f"{lab_name}: scenario.lane={sc_lane!r} vs taxonomy={entry['lane']!r}"
            )
        if sc_transport != entry["transport"]:
            errors.append(
                f"{lab_name}: scenario.transport={sc_transport!r} vs taxonomy={entry['transport']!r}"
            )

    assert not errors, (
        "Vendored taxonomy is out of sync with adjacent camazotz scenarios. "
        "Refresh mcpnuke/data/taxonomy/lanes.yaml from "
        "agentic-sec/docs/taxonomy/lanes.yaml:\n"
        + "\n".join(errors)
    )
