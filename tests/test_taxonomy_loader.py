"""Tests for the taxonomy loader (``mcpnuke.core.taxonomy``)."""

from __future__ import annotations

import pathlib

import pytest

from mcpnuke.core.taxonomy import (
    get_taxonomy,
    lab_to_threat_id,
    load_taxonomy,
    threat_id_to_lab,
    threat_ids,
    threat_metadata,
)

# ---------------------------------------------------------------------------
# Basic loader
# ---------------------------------------------------------------------------


def test_vendored_taxonomy_loads() -> None:
    tax = load_taxonomy()
    assert tax["schema_version"] == "1.0.0"
    assert len(tax["lanes"]) == 5
    assert len(tax["transports"]) == 5
    assert len(tax["threats"]) >= 51


def test_vendored_taxonomy_has_required_lanes() -> None:
    tax = load_taxonomy()
    lane_ids = {lane["id"] for lane in tax["lanes"]}
    assert lane_ids == {1, 2, 3, 4, 5}
    lane_slugs = {lane["slug"] for lane in tax["lanes"]}
    assert lane_slugs == {"human-direct", "delegated", "machine", "chain", "anonymous"}


def test_vendored_taxonomy_has_required_transports() -> None:
    tax = load_taxonomy()
    codes = {t["code"] for t in tax["transports"]}
    assert codes == {"A", "B", "C", "D", "E"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_threat_ids_is_a_set_of_canonical_strings() -> None:
    ids = threat_ids()
    assert all(tid.startswith("MCP-T") for tid in ids)
    assert "MCP-T01" in ids
    assert "MCP-T50" in ids
    assert "MCP-T52" in ids


def test_lab_to_threat_id_mapping_is_bijective() -> None:
    forward = lab_to_threat_id()
    reverse = threat_id_to_lab()
    assert len(forward) == len(reverse)
    for lab, tid in forward.items():
        assert reverse[tid] == lab


def test_threat_metadata_returns_full_entry() -> None:
    md = threat_metadata("MCP-T50")
    assert md is not None
    assert md["camazotz_lab"] == "anon_schema_harvest_lab"
    assert md["lane"] == 5
    assert md["transport"] == "A"


def test_threat_metadata_unknown_returns_none() -> None:
    assert threat_metadata("MCP-T999") is None


def test_get_taxonomy_is_cached() -> None:
    a = get_taxonomy()
    b = get_taxonomy()
    assert a is b  # same dict object — lru_cache hit


# ---------------------------------------------------------------------------
# Override sources
# ---------------------------------------------------------------------------


def test_load_taxonomy_from_explicit_path(tmp_path: pathlib.Path) -> None:
    minimal = tmp_path / "tiny.yaml"
    minimal.write_text(
        """
schema_version: "1.0.0"
lanes:
  - id: 1
    slug: "human-direct"
    name: "Human Direct"
transports:
  - code: "A"
    name: "MCP"
threats:
  - threat_id: "MCP-T01"
    title: "Test"
    category: "test"
    lane: 1
    transport: "A"
    owasp_mcp: "MCP01"
    camazotz_lab: "test_lab"
"""
    )
    tax = load_taxonomy(minimal)
    assert tax["threats"][0]["threat_id"] == "MCP-T01"


def test_load_taxonomy_missing_path_raises(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_taxonomy(tmp_path / "does-not-exist.yaml")


def test_load_taxonomy_malformed_top_level_raises(tmp_path: pathlib.Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("just a string, not a dict")
    with pytest.raises(RuntimeError, match="missing expected top-level keys"):
        load_taxonomy(bad)


def test_load_taxonomy_invalid_yaml_raises(tmp_path: pathlib.Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("{ unclosed: brace\n")
    with pytest.raises(RuntimeError, match="Failed to parse taxonomy"):
        load_taxonomy(bad)
