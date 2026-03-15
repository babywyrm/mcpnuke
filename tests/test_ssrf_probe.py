"""Tests for ssrf_probe check."""

import pytest
from mcpredator.core.models import TargetResult
from mcpredator.checks.ssrf_probe import check_ssrf_probe, URL_PARAM_PATTERNS


class FakeSession:
    def __init__(self, responses=None):
        self._responses = responses or {}

    def call(self, method, params=None, timeout=None, retries=2):
        if method == "tools/call":
            name = (params or {}).get("name", "")
            args = (params or {}).get("arguments", {})
            for pname, pval in args.items():
                if pval in self._responses:
                    return {"result": {"content": [{"type": "text", "text": self._responses[pval]}]}}
            default = self._responses.get("_default", "OK")
            return {"result": {"content": [{"type": "text", "text": default}]}}
        return None


def _make(tools):
    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = tools
    return r


def test_url_param_detection():
    assert URL_PARAM_PATTERNS.search("url")
    assert URL_PARAM_PATTERNS.search("webhook")
    assert URL_PARAM_PATTERNS.search("endpoint")
    assert not URL_PARAM_PATTERNS.search("username")


def test_cloud_metadata_detected():
    tools = [{"name": "fetch", "description": "Fetch URL content", "inputSchema": {
        "properties": {"url": {"type": "string"}}, "required": ["url"],
    }}]
    r = _make(tools)
    session = FakeSession({
        "http://example.com/test": "Not found",
        "http://169.254.169.254/latest/meta-data/": "ami-0123456789 instance-id i-abc",
        "_default": "error",
    })
    check_ssrf_probe(session, r)
    assert any(f.check == "ssrf_probe" and f.severity == "CRITICAL" for f in r.findings)


def test_clean_tool_no_url_params():
    tools = [{"name": "calc", "description": "Calculate", "inputSchema": {
        "properties": {"expression": {"type": "string"}},
    }}]
    r = _make(tools)
    session = FakeSession({"_default": "42"})
    check_ssrf_probe(session, r)
    assert not any(f.check == "ssrf_probe" for f in r.findings)


def test_static_ssrf_surface_flag():
    tools = [{"name": "proxy", "description": "Fetch and proxy remote content", "inputSchema": {
        "properties": {"target": {"type": "string"}}, "required": ["target"],
    }}]
    r = _make(tools)
    session = FakeSession({"_default": "OK"})
    check_ssrf_probe(session, r)
    assert any(f.check == "ssrf_probe" for f in r.findings)


def test_timing_recorded():
    tools = [{"name": "x", "description": "y", "inputSchema": {"properties": {}}}]
    r = _make(tools)
    session = FakeSession({})
    check_ssrf_probe(session, r)
    assert "ssrf_probe" in r.timings
