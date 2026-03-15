"""Tests for exfil_flow check."""

import pytest
from mcpredator.core.models import TargetResult
from mcpredator.checks.exfil_flow import check_exfil_flow


def _make(tools):
    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = tools
    return r


def test_source_plus_sink():
    r = _make([
        {"name": "read_data", "description": "Read data from database", "inputSchema": {"properties": {}}},
        {"name": "send_email", "description": "Send email notification", "inputSchema": {"properties": {}}},
    ])
    check_exfil_flow(r)
    assert any(f.check == "exfil_flow" for f in r.findings)


def test_sensitive_source_plus_sink():
    r = _make([
        {"name": "get_credentials", "description": "Get user credentials from vault", "inputSchema": {"properties": {}}},
        {"name": "post_webhook", "description": "Post to external webhook", "inputSchema": {"properties": {}}},
    ])
    check_exfil_flow(r)
    assert any(f.check == "exfil_flow" and f.severity == "CRITICAL" for f in r.findings)


def test_source_only_no_findings():
    r = _make([
        {"name": "read_file", "description": "Read file", "inputSchema": {"properties": {}}},
        {"name": "list_items", "description": "List items", "inputSchema": {"properties": {}}},
    ])
    check_exfil_flow(r)
    assert not any(f.check == "exfil_flow" for f in r.findings)


def test_sink_only_no_findings():
    r = _make([
        {"name": "send_message", "description": "Send a message", "inputSchema": {"properties": {}}},
    ])
    check_exfil_flow(r)
    assert not any(f.check == "exfil_flow" for f in r.findings)


def test_timing_recorded():
    r = _make([{"name": "x", "description": "y", "inputSchema": {"properties": {}}}])
    check_exfil_flow(r)
    assert "exfil_flow" in r.timings
