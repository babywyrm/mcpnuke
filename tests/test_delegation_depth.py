"""Tests for check_delegation_depth (MCP-T32)."""

from __future__ import annotations

from mcpnuke.checks.taxonomy_coverage import check_delegation_depth
from mcpnuke.core.models import TargetResult


def _result(tools: list[dict]) -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.tools = tools
    return r


def _findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "delegation_depth"]


def test_flags_delegate_to_parameter() -> None:
    r = _result([{
        "name": "tasks.handoff",
        "description": "Hand a task to another worker",
        "inputSchema": {"properties": {"delegate_to": {"type": "string"}}},
    }])
    check_delegation_depth(r)
    found = _findings(r)
    assert len(found) == 1
    assert found[0].severity == "MEDIUM"
    assert found[0].taxonomy_id == "MCP-T32"
    assert found[0].lane == 4


def test_flags_camazotz_shaped_name() -> None:
    r = _result([{
        "name": "delegation_depth.inspect_chain",
        "description": "Inspect the chain",
        "inputSchema": {},
    }])
    check_delegation_depth(r)
    found = _findings(r)
    assert found
    assert found[0].taxonomy_id == "MCP-T32"


def test_flags_weak_hop_with_agent() -> None:
    r = _result([{
        "name": "hop_to_agent",
        "description": "Send work to another agent",
        "inputSchema": {},
    }])
    check_delegation_depth(r)
    found = _findings(r)
    assert len(found) == 1
    assert found[0].taxonomy_id == "MCP-T32"


def test_silent_on_list_allowed_directories() -> None:
    r = _result([{
        "name": "list_allowed_directories",
        "description": "Returns a list of directories that the server is allowed to access.",
        "inputSchema": {},
    }])
    check_delegation_depth(r)
    assert _findings(r) == []


def test_silent_on_nested_directory() -> None:
    """Filesystem 'create a nested directory' is not multi-agent hop depth."""
    r = _result([{
        "name": "create_directory",
        "description": "Create a new directory or nested directory structure",
        "inputSchema": {"properties": {"path": {"type": "string"}}},
    }])
    check_delegation_depth(r)
    assert _findings(r) == []


def test_silent_on_depth_parameter_alone() -> None:
    r = _result([{
        "name": "image.resize",
        "description": "Resize an image",
        "inputSchema": {"properties": {"depth": {"type": "integer"}}},
    }])
    check_delegation_depth(r)
    assert _findings(r) == []


def test_silent_on_clean_tools() -> None:
    r = _result([{"name": "echo", "description": "Echo a string", "inputSchema": {}}])
    check_delegation_depth(r)
    assert _findings(r) == []


def test_timing_recorded() -> None:
    r = _result([{"name": "x", "description": "y", "inputSchema": {}}])
    check_delegation_depth(r)
    assert "delegation_depth" in r.timings
