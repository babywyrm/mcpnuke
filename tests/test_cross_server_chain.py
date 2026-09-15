"""Tests for check_cross_server_chain (MCP-T05, cross-server Phase A).

Per-target chains miss the documented failure mode: poisoned context on
server A steering the agent into server B's sinks. This check correlates
findings across all targets in a run — a peer with active injection vectors
plus local execution/credential sinks is a cross-server chain.
"""

from __future__ import annotations

from mcpnuke.checks.chaining import check_cross_server_chain
from mcpnuke.core.models import TargetResult


def _result(
    url: str,
    tools: tuple[dict, ...] = (),
    findings: tuple[tuple[str, str], ...] = (),
) -> TargetResult:
    r = TargetResult(url=url)
    r.tools = list(tools)
    for check, severity in findings:
        r.add(check, severity, f"{check} finding")
    return r


def _findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "cross_server_chain"]


def test_fires_when_peer_has_source_and_i_have_sink() -> None:
    me = _result("http://b/mcp", findings=(("code_execution", "CRITICAL"),))
    peer = _result("http://a/mcp", findings=(("indirect_injection", "HIGH"),))
    check_cross_server_chain([me, peer], me)
    found = _findings(me)
    assert len(found) == 1
    assert found[0].severity == "MEDIUM"
    assert found[0].taxonomy_id == "MCP-T05"
    assert found[0].lane == 4
    assert "http://a/mcp" in str(found[0].evidence)


def test_silent_when_peer_lacks_source() -> None:
    me = _result("http://b/mcp", findings=(("code_execution", "CRITICAL"),))
    peer = _result("http://a/mcp", findings=(("code_execution", "HIGH"),))
    check_cross_server_chain([me, peer], me)
    assert _findings(me) == []


def test_silent_when_i_lack_sink() -> None:
    me = _result("http://b/mcp", findings=(("prompt_injection", "HIGH"),))
    peer = _result("http://a/mcp", findings=(("indirect_injection", "HIGH"),))
    check_cross_server_chain([me, peer], me)
    assert _findings(me) == []


def test_silent_on_single_target_run() -> None:
    me = _result("http://b/mcp", findings=(("code_execution", "CRITICAL"),))
    check_cross_server_chain([me], me)
    assert _findings(me) == []


def test_low_severity_peer_vectors_do_not_count() -> None:
    me = _result("http://b/mcp", findings=(("code_execution", "CRITICAL"),))
    peer = _result("http://a/mcp", findings=(("indirect_injection", "LOW"),))
    check_cross_server_chain([me, peer], me)
    assert _findings(me) == []


def test_name_collision_with_peer_upgrades_to_high() -> None:
    shared = {"name": "read_file", "description": "d", "inputSchema": {}}
    me = _result(
        "http://b/mcp",
        tools=(shared,),
        findings=(("token_theft", "HIGH"),),
    )
    peer = _result(
        "http://a/mcp",
        tools=(shared,),
        findings=(("tool_response_injection", "HIGH"),),
    )
    check_cross_server_chain([me, peer], me)
    found = _findings(me)
    assert len(found) == 1
    assert found[0].severity == "HIGH"


def test_one_finding_per_source_peer() -> None:
    me = _result("http://b/mcp", findings=(("code_execution", "CRITICAL"),))
    p1 = _result("http://a/mcp", findings=(("indirect_injection", "HIGH"),))
    p2 = _result("http://c/mcp", findings=(("prompt_injection", "CRITICAL"),))
    check_cross_server_chain([me, p1, p2], me)
    assert len(_findings(me)) == 2


def test_timing_recorded() -> None:
    me = _result("http://b/mcp")
    check_cross_server_chain([me], me)
    assert "cross_server_chain" in me.timings
