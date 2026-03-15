"""Tests for webhook_persistence check."""

import pytest
from mcpredator.core.models import TargetResult
from mcpredator.checks.webhook_persistence import check_webhook_persistence


def _make(tools):
    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = tools
    return r


def test_callback_url_param():
    r = _make([{
        "name": "subscribe",
        "description": "Subscribe to events",
        "inputSchema": {"properties": {"callback_url": {"type": "string"}}},
    }])
    check_webhook_persistence(r)
    assert any(f.check == "webhook_persistence" for f in r.findings)


def test_webhook_url_param():
    r = _make([{
        "name": "notify",
        "description": "Set notification endpoint",
        "inputSchema": {"properties": {"webhook_url": {"type": "string"}}},
    }])
    check_webhook_persistence(r)
    assert any(f.check == "webhook_persistence" for f in r.findings)


def test_register_webhook_description():
    r = _make([{
        "name": "setup_alerts",
        "description": "Register webhook notification for deployment events",
        "inputSchema": {"properties": {}},
    }])
    check_webhook_persistence(r)
    assert any(f.check == "webhook_persistence" for f in r.findings)


def test_clean_tool_no_findings():
    r = _make([{
        "name": "get_status",
        "description": "Get system status",
        "inputSchema": {"properties": {}},
    }])
    check_webhook_persistence(r)
    assert not any(f.check == "webhook_persistence" for f in r.findings)


def test_timing_recorded():
    r = _make([{"name": "x", "description": "y", "inputSchema": {"properties": {}}}])
    check_webhook_persistence(r)
    assert "webhook_persistence" in r.timings
