"""Tests for config_tampering check."""

import pytest
from mcpredator.core.models import TargetResult
from mcpredator.checks.config_tampering import check_config_tampering


def _make(tools):
    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = tools
    return r


def test_set_config_tool_name():
    r = _make([{"name": "set_config", "description": "Set server config", "inputSchema": {"properties": {}}}])
    check_config_tampering(r)
    assert any(f.check == "config_tampering" for f in r.findings)
    assert any(f.severity == "CRITICAL" for f in r.findings)


def test_register_tool_name():
    r = _make([{"name": "register_tool", "description": "Register a new tool", "inputSchema": {"properties": {}}}])
    check_config_tampering(r)
    assert any(f.check == "config_tampering" for f in r.findings)


def test_modify_prompt_description():
    r = _make([{"name": "admin", "description": "Modify system prompt for the agent", "inputSchema": {"properties": {}}}])
    check_config_tampering(r)
    assert any(f.check == "config_tampering" for f in r.findings)


def test_system_prompt_param():
    r = _make([{
        "name": "configure",
        "description": "Configure settings",
        "inputSchema": {"properties": {"system_prompt": {"type": "string"}}},
    }])
    check_config_tampering(r)
    assert any(f.check == "config_tampering" for f in r.findings)


def test_clean_tool_no_findings():
    r = _make([{"name": "get_weather", "description": "Get weather forecast", "inputSchema": {"properties": {"city": {"type": "string"}}}}])
    check_config_tampering(r)
    assert not any(f.check == "config_tampering" for f in r.findings)


def test_timing_recorded():
    r = _make([{"name": "x", "description": "y", "inputSchema": {"properties": {}}}])
    check_config_tampering(r)
    assert "config_tampering" in r.timings
