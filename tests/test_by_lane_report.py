"""Tests for --by-lane grouping logic."""

from __future__ import annotations

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.reporting.by_lane import build_by_lane


def _r(url: str = "http://t1") -> TargetResult:
    return TargetResult(url=url)


def test_empty_scan_produces_all_five_lanes_with_zero_counts():
    out = build_by_lane([_r()])
    assert out["schema"] == "v1"
    assert out["total_findings"] == 0
    for lane_id in ("1", "2", "3", "4", "5"):
        assert out["by_lane"][lane_id]["finding_count"] == 0
        assert out["by_lane"][lane_id]["findings"] == []


def test_findings_group_into_correct_lanes():
    r = _r()
    r.add("chk_a", "HIGH", "lane-3 finding", lane=3, transport="A")
    r.add("chk_b", "CRITICAL", "lane-5 finding", lane=5)
    r.add("chk_c", "HIGH", "another lane-3", lane=3, transport="A")
    out = build_by_lane([r])
    assert out["total_findings"] == 3
    assert out["by_lane"]["3"]["finding_count"] == 2
    assert out["by_lane"]["3"]["transports_hit"] == ["A"]
    assert out["by_lane"]["5"]["finding_count"] == 1
    assert out["by_lane"]["1"]["finding_count"] == 0


def test_severity_tally_orders_canonically_and_hides_zeros():
    r = _r()
    r.add("c1", "CRITICAL", "x", lane=3, transport="A")
    r.add("c2", "CRITICAL", "y", lane=3, transport="A")
    r.add("c3", "HIGH",     "z", lane=3, transport="A")
    out = build_by_lane([r])
    tally = out["by_lane"]["3"]["severity_tally"]
    assert list(tally.keys()) == ["CRITICAL", "HIGH"]
    assert tally["CRITICAL"] == 2
    assert tally["HIGH"] == 1


def test_transports_hit_deduplicates_and_sorts():
    r = _r()
    r.add("c", "HIGH", "x", lane=3, transport="A")
    r.add("c", "HIGH", "y", lane=3, transport="C")
    r.add("c", "HIGH", "z", lane=3, transport="A")
    out = build_by_lane([r])
    assert out["by_lane"]["3"]["transports_hit"] == ["A", "C"]


def test_uncategorized_bucket_captures_lane_none():
    r = _r()
    r.add("tls", "LOW", "weak cipher")  # no lane / no transport
    r.add("lane3", "HIGH", "machine lab finding", lane=3, transport="A")
    out = build_by_lane([r])
    assert out["total_findings"] == 2
    assert "uncategorized" in out["by_lane"]
    assert out["by_lane"]["uncategorized"]["finding_count"] == 1
    assert out["by_lane"]["3"]["finding_count"] == 1


def test_invalid_lane_id_falls_into_uncategorized():
    r = _r()
    r.add("weird", "HIGH", "bogus lane", lane=99)  # not 1-5
    out = build_by_lane([r])
    assert "uncategorized" in out["by_lane"]
    assert out["by_lane"]["uncategorized"]["finding_count"] == 1


def test_multi_target_findings_merge_into_lane_buckets():
    a = _r("http://a")
    b = _r("http://b")
    a.add("c", "HIGH", "t1", lane=2, transport="A")
    b.add("c", "HIGH", "t2", lane=2, transport="A")
    out = build_by_lane([a, b])
    assert out["by_lane"]["2"]["finding_count"] == 2
    assert {f["target"] for f in out["by_lane"]["2"]["findings"]} == {"http://a", "http://b"}
