"""Threat taxonomy loader for the agentic-sec lanes.yaml contract.

The taxonomy is the cross-repo vocabulary contract between camazotz (labs),
nullfield (policies), mcpnuke (scanner), and the agentic-sec docs hub.
Canonical source: ``agentic-sec/docs/taxonomy/lanes.yaml`` (schema v1.0.0).

A copy is vendored at ``mcpnuke/data/taxonomy/lanes.yaml`` so mcpnuke can run
without requiring the sibling agentic-sec repo on disk. The vendored copy
should be refreshed when the canonical taxonomy ships a new version.

Usage:

    from mcpnuke.core.taxonomy import load_taxonomy, threat_ids

    # Default — load vendored copy
    tax = load_taxonomy()

    # Explicit path or URL (used by --taxonomy CLI flag)
    tax = load_taxonomy("/path/to/lanes.yaml")
    tax = load_taxonomy("https://raw.githubusercontent.com/.../lanes.yaml")

    # Helpers
    valid = threat_ids()                   # set of MCP-T01..T52
    by_id  = threat_id_to_lab()            # MCP-T50 -> "anon_schema_harvest_lab"
    by_lab = lab_to_threat_id()            # "anon_schema_harvest_lab" -> MCP-T50

Drift detection — both camazotz and mcpnuke have tests that fail when the
taxonomy diverges from scenario.yaml files or profile entries. See:

  - ``camazotz/tests/test_lane_taxonomy.py::test_agentic_sec_taxonomy_in_sync``
  - ``mcpnuke/tests/test_camazotz_profile_in_sync``
  - ``mcpnuke/tests/test_taxonomy_threat_ids_valid``
"""

from __future__ import annotations

import pathlib
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen

try:
    import yaml
except ImportError as exc:  # pragma: no cover - dep is in base requirements
    raise RuntimeError(
        "PyYAML is required for taxonomy support. "
        "Install with: uv pip install 'pyyaml>=6.0'"
    ) from exc


_VENDORED_PATH: pathlib.Path = (
    pathlib.Path(__file__).resolve().parent.parent / "data" / "taxonomy" / "lanes.yaml"
)


def load_taxonomy(source: str | pathlib.Path | None = None) -> dict[str, Any]:
    """Load the threat taxonomy.

    Args:
        source: Optional override. May be:
            * ``None`` — load the vendored copy (default).
            * A filesystem path (str or Path) — load that file.
            * An http/https URL — fetch and parse remotely.

    Returns:
        Parsed taxonomy dict with keys: ``schema_version``, ``lanes``,
        ``transports``, ``threats``.

    Raises:
        FileNotFoundError: If ``source`` is a path that doesn't exist.
        RuntimeError: If the fetched/loaded data fails to parse as YAML or
                      lacks the expected top-level shape.
    """
    if source is None:
        text = _VENDORED_PATH.read_text(encoding="utf-8")
        origin = str(_VENDORED_PATH)
    elif isinstance(source, str) and _looks_like_url(source):
        with urlopen(source, timeout=10) as resp:  # noqa: S310 - intentional URL fetch
            text = resp.read().decode("utf-8")
        origin = source
    else:
        path = pathlib.Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Taxonomy file not found: {source}")
        text = path.read_text(encoding="utf-8")
        origin = str(path)

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Failed to parse taxonomy at {origin}: {exc}") from exc

    if not isinstance(data, dict) or "threats" not in data or "lanes" not in data:
        raise RuntimeError(
            f"Taxonomy at {origin} missing expected top-level keys "
            f"(schema_version, lanes, transports, threats)"
        )

    return data


def _looks_like_url(s: str) -> bool:
    parsed = urlparse(s)
    return parsed.scheme in ("http", "https")


@lru_cache(maxsize=1)
def get_taxonomy() -> dict[str, Any]:
    """Cached load of the vendored taxonomy. Use ``load_taxonomy(source)`` to override."""
    return load_taxonomy()


def threat_ids(taxonomy: dict[str, Any] | None = None) -> set[str]:
    """Return the set of valid threat IDs (e.g. ``{"MCP-T01", "MCP-T02", ...}``)."""
    tax = taxonomy if taxonomy is not None else get_taxonomy()
    return {t["threat_id"] for t in tax.get("threats", [])}


def lab_to_threat_id(taxonomy: dict[str, Any] | None = None) -> dict[str, str]:
    """Map camazotz lab name (``camazotz_lab``) → threat ID."""
    tax = taxonomy if taxonomy is not None else get_taxonomy()
    return {t["camazotz_lab"]: t["threat_id"] for t in tax.get("threats", []) if "camazotz_lab" in t}


def threat_id_to_lab(taxonomy: dict[str, Any] | None = None) -> dict[str, str]:
    """Map threat ID → camazotz lab name."""
    tax = taxonomy if taxonomy is not None else get_taxonomy()
    return {t["threat_id"]: t["camazotz_lab"] for t in tax.get("threats", []) if "camazotz_lab" in t}


def threat_metadata(threat_id: str, taxonomy: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Return the full taxonomy entry for ``threat_id``, or ``None`` if unknown."""
    tax = taxonomy if taxonomy is not None else get_taxonomy()
    threats = tax.get("threats", [])
    if isinstance(threats, list):
        for t in threats:
            if isinstance(t, dict) and t.get("threat_id") == threat_id:
                return t
    return None
