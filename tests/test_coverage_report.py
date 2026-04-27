"""Tests for --coverage-report: schema validation + intersection logic."""

from __future__ import annotations

import pytest

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.reporting.coverage_report import (
    SchemaMismatchError,
    build_coverage_report,
    fetch_lane_taxonomy,
)


def _taxonomy_v1(
    lane_coverage: dict[str, dict] | None = None,
    labs: list[dict] | None = None,
) -> dict:
    """Minimal well-formed camazotz /api/lanes payload."""
    return {
        "schema": "v1",
        "lanes": [
            {"id": 1, "slug": "human-direct", "name": "Human Direct"},
            {"id": 2, "slug": "delegated", "name": "Human → Agent"},
            {"id": 3, "slug": "machine", "name": "Machine Identity"},
            {"id": 4, "slug": "chain", "name": "Agent → Agent"},
            {"id": 5, "slug": "anonymous", "name": "Anonymous"},
        ],
        "coverage": lane_coverage or {},
        "labs": labs or [],
    }


def _scan_with_findings(by_lane: dict[int, int]) -> list[TargetResult]:
    """Build a scan result with `n` HIGH findings on each requested lane."""
    r = TargetResult(url="http://camazotz.test")
    for lane_id, n in by_lane.items():
        for i in range(n):
            r.add("check_x", "HIGH", f"finding {i}", lane=lane_id, transport="A")
    return [r]


def test_fetch_rejects_wrong_schema(monkeypatch):
    import httpx
    from mcpnuke.reporting import coverage_report

    class _R:
        def raise_for_status(self): pass
        def json(self): return {"schema": "v2", "lanes": []}

    monkeypatch.setattr(coverage_report.httpx, "get", lambda *a, **kw: _R())
    with pytest.raises(SchemaMismatchError, match="v2"):
        fetch_lane_taxonomy("http://example")


def test_fetch_returns_v1_payload(monkeypatch):
    from mcpnuke.reporting import coverage_report

    payload = _taxonomy_v1()
    class _R:
        def raise_for_status(self): pass
        def json(self): return payload

    monkeypatch.setattr(coverage_report.httpx, "get", lambda *a, **kw: _R())
    out = fetch_lane_taxonomy("http://example")
    assert out["schema"] == "v1"


def test_report_aligned_when_camazotz_and_mcpnuke_both_cover_lane():
    taxonomy = _taxonomy_v1(lane_coverage={
        "3": {"primary_count": 4, "secondary_count": 0, "transports_present": ["A"], "gaps": []},
    })
    results = _scan_with_findings({3: 2})
    report = build_coverage_report(results, taxonomy)
    assert report["lanes"]["3"]["camazotz"]["primary_count"] == 4
    assert report["lanes"]["3"]["mcpnuke"]["checks_fired"] == 2
    assert "aligned" in report["lanes"]["3"]["alignment_note"]


def test_report_flags_widest_gap_when_camazotz_covers_but_mcpnuke_silent():
    taxonomy = _taxonomy_v1(lane_coverage={
        "2": {"primary_count": 12, "secondary_count": 0, "transports_present": ["A"], "gaps": []},
        "4": {"primary_count": 6, "secondary_count": 0, "transports_present": ["A"], "gaps": []},
    })
    results = _scan_with_findings({})  # empty scan
    report = build_coverage_report(results, taxonomy)
    # Widest gap = lane where camazotz declares the most labs and mcpnuke fired 0.
    assert report["summary"]["widest_gap"].startswith("Lane 2")
    assert "dormant" in report["lanes"]["2"]["alignment_note"]


def test_report_notes_scanner_ahead_when_finding_on_lane_without_labs():
    taxonomy = _taxonomy_v1(lane_coverage={
        "1": {"primary_count": 0, "secondary_count": 0, "transports_present": [], "gaps": []},
    })
    results = _scan_with_findings({1: 1})
    report = build_coverage_report(results, taxonomy)
    assert "scanner ahead" in report["lanes"]["1"]["alignment_note"]


def test_report_surfaces_camazotz_transport_gaps_verbatim():
    taxonomy = _taxonomy_v1(lane_coverage={
        "4": {
            "primary_count": 6, "secondary_count": 0,
            "transports_present": ["A"],
            "gaps": ["Transport B not covered", "Transport C not covered"],
        },
    })
    results = _scan_with_findings({4: 1})
    report = build_coverage_report(results, taxonomy)
    note = report["lanes"]["4"]["alignment_note"]
    assert "Transport B not covered" in note
    assert "Transport C not covered" in note


def test_summary_counts_lanes_covered_by_each_project():
    taxonomy = _taxonomy_v1(lane_coverage={
        "1": {"primary_count": 6, "secondary_count": 0, "transports_present": ["A", "B"], "gaps": []},
        "3": {"primary_count": 5, "secondary_count": 0, "transports_present": ["A", "C"], "gaps": []},
        "5": {"primary_count": 3, "secondary_count": 0, "transports_present": [], "gaps": []},
    })
    results = _scan_with_findings({1: 1, 3: 2})
    report = build_coverage_report(results, taxonomy)
    assert report["summary"]["lanes_covered_by_camazotz"] == 3
    assert report["summary"]["lanes_covered_by_mcpnuke"] == 2
    assert report["summary"]["lanes_both"] == 2
