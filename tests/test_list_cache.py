"""SEP-2549 list-result cache hints: ttlMs and cacheScope.

Absence is not a finding. Most servers do not send the fields yet, and
flagging that would fire on every target including the FP harness.
"""

from __future__ import annotations

from mcpnuke.checks.list_cache import check_list_cache
from mcpnuke.core.models import TargetResult


def _result(pages: dict[str, list[dict]]) -> TargetResult:
    r = TargetResult(url="http://localhost:9001/sse")
    r.list_cache = pages
    return r


def test_silent_when_no_cache_fields():
    r = _result({"tools/list": [{}, {}]})
    check_list_cache(r)
    assert r.findings == []


def test_silent_when_fields_absent_entirely():
    r = TargetResult(url="http://localhost:9001/sse")
    check_list_cache(r)
    assert r.findings == []


def test_silent_when_valid_public_ttl():
    r = _result(
        {
            "tools/list": [
                {"ttlMs": 60_000, "cacheScope": "public"},
                {"ttlMs": 30_000, "cacheScope": "public"},
            ]
        }
    )
    check_list_cache(r)
    assert r.findings == []


def test_negative_ttl_is_reported():
    r = _result({"tools/list": [{"ttlMs": -1, "cacheScope": "public"}]})
    check_list_cache(r)
    hits = [f for f in r.findings if f.check == "list_cache"]
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert hits[0].taxonomy_id == "MCP-T16"
    assert "ttlMs" in hits[0].title or "ttl" in hits[0].title.lower()


def test_invalid_scope_is_reported():
    r = _result({"tools/list": [{"cacheScope": "shared"}]})
    check_list_cache(r)
    hits = [f for f in r.findings if f.check == "list_cache"]
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert "cacheScope" in hits[0].title or "scope" in hits[0].title.lower()


def test_private_then_omitted_scope_is_a_mismatch():
    """Spec: all pages of one list MUST share cacheScope. Omitted defaults to public."""
    r = _result(
        {
            "tools/list": [
                {"cacheScope": "private", "ttlMs": 1000},
                {"ttlMs": 1000},
            ]
        }
    )
    check_list_cache(r)
    hits = [f for f in r.findings if "mismatch" in f.title.lower() or "pages" in f.detail.lower()]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"


def test_timing_recorded():
    r = _result({})
    check_list_cache(r)
    assert "list_cache" in r.timings
