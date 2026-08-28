"""Tests for check_execution_context_forgery (MCP-T22)."""

from __future__ import annotations

from mcpnuke.checks.taxonomy_coverage import check_execution_context_forgery
from mcpnuke.core.models import TargetResult
from tests.reference_target.tools import TOOL_DEFINITIONS


def _result(tools: list[dict], *, transport: str = "http") -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.transport = transport
    r.tools = tools
    return r


def _findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "execution_context_forgery"]


def test_flags_on_behalf_of_parameter() -> None:
    r = _result([{
        "name": "tickets.comment",
        "description": "Comment on a ticket",
        "inputSchema": {"properties": {"on_behalf_of": {"type": "string"}}},
    }])
    check_execution_context_forgery(r)
    found = _findings(r)
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T22"
    assert found[0].lane == 4


def test_silent_on_bare_user_id() -> None:
    """user_id is identity presence (T35), not a forged execution principal."""
    r = _result([{
        "name": "users.get",
        "description": "Fetch a user record",
        "inputSchema": {"properties": {"user_id": {"type": "string"}}},
    }])
    check_execution_context_forgery(r)
    assert _findings(r) == []


def test_silent_on_clean_tools() -> None:
    r = _result([{"name": "echo", "description": "Echo a string", "inputSchema": {}}])
    check_execution_context_forgery(r)
    assert _findings(r) == []


def test_silent_on_the_reference_target() -> None:
    r = _result(list(TOOL_DEFINITIONS))
    check_execution_context_forgery(r)
    assert _findings(r) == []


def test_still_fires_on_stdio() -> None:
    r = _result(
        [{
            "name": "act",
            "inputSchema": {"properties": {"as_user": {"type": "string"}}},
        }],
        transport="stdio",
    )
    check_execution_context_forgery(r)
    found = _findings(r)
    assert found
    assert found[0].taxonomy_id == "MCP-T22"


def test_timing_recorded() -> None:
    r = _result([{"name": "x", "description": "y", "inputSchema": {}}])
    check_execution_context_forgery(r)
    assert "execution_context_forgery" in r.timings
