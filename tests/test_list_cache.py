"""SEP-2549 list-result cache hints: ttlMs and cacheScope.

Absence is not a finding. Most servers do not send the fields yet, and
flagging that would fire on every target including the FP harness.
"""

from __future__ import annotations

from mcpnuke.checks import run_all_checks
from mcpnuke.checks.list_cache import check_list_cache
from mcpnuke.core.cache_hints import cache_fields_from_result
from mcpnuke.core.models import TargetResult


def test_cache_fields_omits_absent_keys():
    assert cache_fields_from_result({"tools": []}) == {}


def test_cache_fields_keeps_only_hint_keys():
    assert cache_fields_from_result(
        {"ttlMs": 5000, "cacheScope": "private", "tools": [{"name": "t"}]}
    ) == {"ttlMs": 5000, "cacheScope": "private"}


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


def test_mixed_scope_on_resource_reads_is_not_a_page_mismatch():
    """Each URI is independently cacheable. Mixed public/private across reads
    is not the SEP-2549 page-scope rule, which applies to one list request.
    """
    r = _result(
        {
            "resources/read": [
                {"uri": "file://a", "cacheScope": "private"},
                {"uri": "file://b", "cacheScope": "public"},
            ]
        }
    )
    check_list_cache(r)
    assert not any("mismatch" in f.title.lower() for f in r.findings)


def test_invalid_ttl_on_resource_read_is_reported():
    r = _result({"resources/read": [{"uri": "file://a", "ttlMs": -5}]})
    check_list_cache(r)
    hits = [f for f in r.findings if f.check == "list_cache"]
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"


class _ReadSession:
    def __init__(self, by_uri: dict[str, object]):
        self.by_uri = by_uri
        self.calls: list[str] = []

    def call(self, method, params=None, timeout=15, retries=2):
        self.calls.append(method)
        if method != "resources/read":
            return None
        uri = (params or {}).get("uri")
        body = self.by_uri.get(uri)
        if body is None:
            return None
        return {"result": body}


def test_samples_resource_reads_when_session_given():
    r = TargetResult(url="http://localhost:9001/sse")
    r.resources = [{"uri": "file://doc"}]
    session = _ReadSession(
        {"file://doc": {"contents": [{"text": "ok"}], "ttlMs": -1, "cacheScope": "public"}}
    )
    check_list_cache(r, session=session)
    assert session.calls == ["resources/read"]
    hits = [f for f in r.findings if "ttlMs" in f.title]
    assert len(hits) == 1


def test_no_invoke_skips_resource_read_sample():
    r = TargetResult(url="http://localhost:9001/sse")
    r.resources = [{"uri": "file://doc"}]
    session = _ReadSession(
        {"file://doc": {"ttlMs": -1, "cacheScope": "public"}}
    )
    check_list_cache(r, session=session, probe_opts={"no_invoke": True})
    assert session.calls == []
    assert r.findings == []


def test_does_not_resample_when_reads_already_recorded():
    r = _result({"resources/read": [{"uri": "file://a", "ttlMs": 1000}]})
    r.resources = [{"uri": "file://doc"}]
    session = _ReadSession({"file://doc": {"ttlMs": -1}})
    check_list_cache(r, session=session)
    assert session.calls == []
    assert r.findings == []


def test_samples_at_most_five_resource_reads():
    r = TargetResult(url="http://localhost:9001/sse")
    r.resources = [{"uri": f"file://{i}"} for i in range(8)]
    session = _ReadSession(
        {f"file://{i}": {"ttlMs": 1000, "cacheScope": "public"} for i in range(8)}
    )
    check_list_cache(r, session=session)
    assert session.calls == ["resources/read"] * 5
    assert r.findings == []


def test_read_call_exception_does_not_crash():
    class _Boom:
        def call(self, method, params=None, timeout=15, retries=2):
            raise RuntimeError("transport down")

    r = TargetResult(url="http://localhost:9001/sse")
    r.resources = [{"uri": "file://doc"}]
    check_list_cache(r, session=_Boom())
    assert r.findings == []
    assert "list_cache" in r.timings


def test_skips_resources_without_uri():
    r = TargetResult(url="http://localhost:9001/sse")
    r.resources = [{"name": "no-uri"}, {"uri": "file://doc"}]
    session = _ReadSession({"file://doc": {"ttlMs": -1, "cacheScope": "public"}})
    check_list_cache(r, session=session)
    assert session.calls == ["resources/read"]
    hits = [f for f in r.findings if "ttlMs" in f.title]
    assert len(hits) == 1


def test_non_dict_read_result_is_skipped():
    r = TargetResult(url="http://localhost:9001/sse")
    r.resources = [{"uri": "file://doc"}]
    session = _ReadSession({"file://doc": "not-a-dict"})
    check_list_cache(r, session=session)
    assert r.findings == []
    assert session.calls == ["resources/read"]


def test_run_all_checks_forwards_session_and_no_invoke(monkeypatch):
    """Sampling is wired through the orchestrator, not only the unit tests."""
    captured: dict[str, object] = {}

    def _spy(result, session=None, probe_opts=None):
        captured["session"] = session
        captured["no_invoke"] = (probe_opts or {}).get("no_invoke")
        result.timings["list_cache"] = 0.0

    monkeypatch.setattr("mcpnuke.checks.check_list_cache", _spy)
    session = object()
    result = TargetResult(url="http://t/mcp")
    run_all_checks(session, result, [result], probe_opts={"no_invoke": True})
    assert captured["session"] is session
    assert captured["no_invoke"] is True
