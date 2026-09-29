"""Servers in one run are not one agent unless a trust set says so.

With no --trust-set, the run stays one set (today's scans keep their
findings). With sets, cross-server chains, name collisions, and replay
peers stay inside a set. A target in no set is not chained.
"""

from __future__ import annotations

import pytest

from mcpnuke.checks import run_cross_target_checks
from mcpnuke.cli import parse_args
from mcpnuke.core.models import TargetResult
from mcpnuke.core.trust import parse_trust_sets, trusted_with


def test_flag_is_repeatable() -> None:
    args = parse_args(
        [
            "--targets",
            "http://a/mcp,http://b/mcp,http://c/mcp",
            "--trust-set",
            "http://a/mcp,http://b/mcp",
            "--trust-set",
            "http://c/mcp,http://d/mcp",
        ]
    )
    assert args.trust_set == [
        "http://a/mcp,http://b/mcp",
        "http://c/mcp,http://d/mcp",
    ]


def test_absent_sets_leave_the_run_as_one_agent() -> None:
    assert parse_trust_sets(None, targets=["http://a/mcp"]) == []
    results = [_result("http://a/mcp"), _result("http://b/mcp")]
    peers = trusted_with("http://a/mcp", results, [])
    assert [item.url for item in peers] == ["http://b/mcp"]


def test_a_url_in_two_sets_is_rejected() -> None:
    with pytest.raises(ValueError, match="more than one trust set"):
        parse_trust_sets(
            ["http://a/mcp,http://b/mcp", "http://b/mcp,http://c/mcp"],
            targets=["http://a/mcp", "http://b/mcp", "http://c/mcp"],
        )


def test_a_set_must_name_scan_targets() -> None:
    with pytest.raises(ValueError, match="not a target"):
        parse_trust_sets(
            ["http://a/mcp,http://missing/mcp"],
            targets=["http://a/mcp", "http://b/mcp"],
        )


def test_a_one_url_set_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least two"):
        parse_trust_sets(["http://a/mcp"], targets=["http://a/mcp"])


def test_trusted_with_drops_other_sets_and_isolates_the_unnamed() -> None:
    results = [
        _result("http://a/mcp"),
        _result("http://b/mcp"),
        _result("http://c/mcp"),
    ]
    sets = parse_trust_sets(
        ["http://a/mcp,http://b/mcp"],
        targets=["http://a/mcp", "http://b/mcp", "http://c/mcp"],
    )
    assert [item.url for item in trusted_with("http://a/mcp", results, sets)] == [
        "http://b/mcp"
    ]
    assert trusted_with("http://c/mcp", results, sets) == []


def test_cross_server_chain_stays_inside_the_set() -> None:
    sink = _armed("http://b/mcp", "code_execution")
    trusted = _armed("http://a/mcp", "indirect_injection")
    outsider = _armed("http://c/mcp", "indirect_injection")
    shared = {"name": "read_file", "description": "d", "inputSchema": {}}
    sink.tools = [shared]
    outsider.tools = [shared]

    run_cross_target_checks(
        [sink, trusted, outsider],
        trust_sets=[frozenset({"http://a/mcp", "http://b/mcp"})],
    )

    chains = [f for f in sink.findings if f.check == "cross_server_chain"]
    assert len(chains) == 1
    assert chains[0].evidence["peer"] == "http://a/mcp"
    assert not any(f.check == "cross_server_chain" for f in outsider.findings)
    collisions = [
        f.title
        for f in sink.findings
        if f.check == "tool_shadowing" and "Name collision" in f.title
    ]
    assert collisions == []


def _result(url: str) -> TargetResult:
    return TargetResult(url=url)


def _armed(url: str, check: str) -> TargetResult:
    result = TargetResult(url=url)
    result.add(check, "HIGH", f"{check} finding")
    return result
