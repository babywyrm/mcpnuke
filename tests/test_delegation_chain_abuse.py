"""Tests for check_delegation_chain_abuse (MCP-T25).

T25 is the composition signal: a tool that *delegates* to other agents AND
carries caller credentials on the delegation. Delegation alone is T32
(delegation_depth); credentials alone are T03/T45. Both on one tool means
delegated calls inherit caller privilege with no attenuation — the chain-abuse
vector.
"""

from __future__ import annotations

from mcpnuke.checks.taxonomy_coverage import check_delegation_chain_abuse
from mcpnuke.core.models import TargetResult


def _result(tools: list[dict]) -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.tools = tools
    return r


def _findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "delegation_chain_abuse"]


def test_flags_delegation_with_credential_param() -> None:
    r = _result([{
        "name": "delegate_task",
        "description": "Delegate a task to another agent",
        "inputSchema": {"properties": {
            "task": {"type": "string"},
            "agent_id": {"type": "string"},
            "token": {"type": "string"},
        }},
    }])
    check_delegation_chain_abuse(r)
    found = _findings(r)
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T25"
    assert found[0].lane == 4


def test_flags_delegation_by_description_with_session_param() -> None:
    r = _result([{
        "name": "run_job",
        "description": "Spawns a sub-agent to run the job",
        "inputSchema": {"properties": {
            "job": {"type": "string"},
            "session": {"type": "string"},
        }},
    }])
    check_delegation_chain_abuse(r)
    assert len(_findings(r)) == 1


def test_silent_on_delegation_without_credentials() -> None:
    """Delegation alone is delegation_depth (T32), not chain abuse."""
    r = _result([{
        "name": "delegate_task",
        "description": "Delegate a task to another agent",
        "inputSchema": {"properties": {
            "task": {"type": "string"},
            "agent_id": {"type": "string"},
        }},
    }])
    check_delegation_chain_abuse(r)
    assert _findings(r) == []


def test_silent_on_credentials_without_delegation() -> None:
    """A token param on a plain API tool is T03/T45 territory, not T25."""
    r = _result([{
        "name": "fetch_url",
        "description": "Fetch a URL",
        "inputSchema": {"properties": {
            "url": {"type": "string"},
            "token": {"type": "string"},
        }},
    }])
    check_delegation_chain_abuse(r)
    assert _findings(r) == []


def test_silent_on_clean_tools() -> None:
    r = _result([{"name": "echo", "description": "Echo a string", "inputSchema": {}}])
    check_delegation_chain_abuse(r)
    assert _findings(r) == []


def test_timing_recorded() -> None:
    r = _result([{"name": "x", "description": "y", "inputSchema": {}}])
    check_delegation_chain_abuse(r)
    assert "delegation_chain_abuse" in r.timings
