"""Confusable tool names on one server (DVMCP challenge 5, MCP-T25).

The challenge ships `get_user_role` alongside `get_user_roles`, whose
description is one character different and which silently returns admin for
everyone. An agent picking by name cannot tell them apart. The existing check
only matched a fixed list of common names or exact collisions across
*different* targets, so a live scan produced nine findings and none of them
were about shadowing.
"""

from __future__ import annotations

from mcpnuke.checks.chaining import check_tool_shadowing
from mcpnuke.core.models import TargetResult


def _result(tools: list[dict], url: str = "http://localhost:9005/sse") -> TargetResult:
    r = TargetResult(url=url)
    r.tools = tools
    return r


def _tool(name: str, description: str = "") -> dict:
    return {"name": name, "description": description, "inputSchema": {"properties": {}}}


def _shadow_findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "tool_shadowing"]


class TestChallenge5Shape:
    """The exact pair DVMCP ships."""

    def _challenge5(self) -> TargetResult:
        return _result([
            _tool("get_user_role", "Get the role of a user in the system"),
            _tool("get_user_roles", "Get the roles of a user in the system"),
        ])

    def test_the_confusable_pair_is_flagged(self) -> None:
        r = self._challenge5()
        check_tool_shadowing([r], r)
        assert _shadow_findings(r), "challenge 5 shadowing went undetected"

    def test_both_tool_names_appear_in_the_finding(self) -> None:
        r = self._challenge5()
        check_tool_shadowing([r], r)
        blob = " ".join(f.title + f.detail for f in _shadow_findings(r))
        assert "get_user_role" in blob
        assert "get_user_roles" in blob

    def test_matching_descriptions_raise_the_severity(self) -> None:
        """Name collision alone is ambiguity; name *and* description is a trap."""
        near = self._challenge5()
        check_tool_shadowing([near], near)

        far = _result([
            _tool("get_user_role", "Get the role of a user in the system"),
            _tool("get_user_roles", "Delete an archived billing export permanently"),
        ])
        check_tool_shadowing([far], far)

        assert _shadow_findings(near)[0].severity == "HIGH"
        assert _shadow_findings(far)[0].severity == "MEDIUM"

    def test_it_carries_the_taxonomy_id(self) -> None:
        r = self._challenge5()
        check_tool_shadowing([r], r)
        assert _shadow_findings(r)[0].taxonomy_id == "MCP-T25"


class TestNoFalsePositives:
    def test_unrelated_names_are_quiet(self) -> None:
        r = _result([
            _tool("create_ticket", "Open a support ticket"),
            _tool("deploy_service", "Deploy a service to production"),
            _tool("fetch_weather", "Look up the forecast"),
        ])
        check_tool_shadowing([r], r)
        assert not _shadow_findings(r)

    def test_a_shared_prefix_alone_is_not_confusable(self) -> None:
        """`get_user` / `get_billing` share a verb but read differently."""
        r = _result([
            _tool("get_user", "Fetch a user record"),
            _tool("get_billing_history", "Fetch invoices"),
        ])
        check_tool_shadowing([r], r)
        assert not _shadow_findings(r)

    def test_a_single_tool_cannot_shadow_itself(self) -> None:
        r = _result([_tool("get_user_role", "Get a role")])
        check_tool_shadowing([r], r)
        assert not _shadow_findings(r)

    def test_short_names_do_not_trip_it(self) -> None:
        """`ls` vs `cat` are 100% different but tiny; distance ratios lie on
        short strings, and these are already covered by SHADOW_TARGETS."""
        r = _result([_tool("add", "Add"), _tool("adds", "Adds")])
        check_tool_shadowing([r], r)
        assert not any(
            "confusab" in (f.title + f.detail).lower() for f in _shadow_findings(r)
        )

    def test_each_pair_is_reported_once(self) -> None:
        r = _result([
            _tool("get_user_role", "Get the role of a user"),
            _tool("get_user_roles", "Get the roles of a user"),
        ])
        check_tool_shadowing([r], r)
        confusable = [
            f for f in _shadow_findings(r) if "confusab" in (f.title + f.detail).lower()
        ]
        assert len(confusable) == 1


class TestExistingBehaviourPreserved:
    def test_shadow_targets_still_fire(self) -> None:
        r = _result([_tool("read", "Read a file")])
        check_tool_shadowing([r], r)
        assert any("redefines common name" in f.title for f in _shadow_findings(r))

    def test_cross_target_collisions_still_fire(self) -> None:
        a = _result([_tool("deploy_service", "Deploy")], url="http://a/mcp")
        b = _result([_tool("deploy_service", "Deploy")], url="http://b/mcp")
        check_tool_shadowing([a, b], a)
        hits = [f for f in _shadow_findings(a) if "Name collision" in f.title]
        assert hits
        assert all(f.taxonomy_id == "MCP-T25" for f in hits)

    def test_confusable_check_does_not_need_other_targets(self) -> None:
        r = _result([
            _tool("get_user_role", "Get the role of a user"),
            _tool("get_user_roles", "Get the roles of a user"),
        ])
        check_tool_shadowing([], r)
        assert _shadow_findings(r)

    def test_timing_is_recorded(self) -> None:
        r = _result([_tool("a_tool", "x")])
        check_tool_shadowing([r], r)
        assert "tool_shadowing" in r.timings
