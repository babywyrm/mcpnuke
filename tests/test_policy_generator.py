"""Tests for policy rule generation internals and YAML serialization edges.

Complements tests/test_policy_generation.py with: tool-name extraction
formats, arrow-path parsing, proof gating, merge/dedup/sort semantics,
parsed-YAML structure assertions, and FINDING_TO_ACTION map integrity.
"""

from __future__ import annotations

import pytest
import yaml

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.policy.generator import (
    _extract_tool_name,
    _extract_tool_path,
    _merge_identical_rules,
    _proof_kind,
    generate_policy,
)
from mcpnuke.policy.nullfield import serialize_policy
from mcpnuke.policy.rules import ACTION_PRIORITY, FINDING_TO_ACTION, PolicyRule


def _result_with_findings(
    findings: list[tuple[str, str, str] | tuple[str, str, str, str]],
) -> TargetResult:
    """Create a TargetResult with findings: (check, severity, title[, detail])."""
    r = TargetResult(url="http://test:8080/mcp")
    for item in findings:
        check, severity, title = item[0], item[1], item[2]
        detail = item[3] if len(item) > 3 else ""
        r.findings.append(Finding(
            target=r.url,
            check=check,
            severity=severity,
            title=title,
            detail=detail,
        ))
    return r


def _tool_actions(rules: list[PolicyRule]) -> dict[str, str]:
    """Map tool name → action for non-default rules."""
    out: dict[str, str] = {}
    for rule in rules:
        for name in rule.tool_names:
            if name == "*":
                continue
            out[name] = rule.action
    return out


class TestToolNameExtraction:
    def _finding(self, title: str = "", detail: str = "",
                 evidence: str = "") -> Finding:
        return Finding(target="t", check="webhook_persistence",
                       severity="HIGH", title=title, detail=detail,
                       evidence=evidence)

    def test_tool_prefix(self):
        f = self._finding(title="Tool 'mod.tool_name' does a thing")
        assert _extract_tool_name(f) == "mod.tool_name"

    def test_lowercase_tool_prefix(self):
        f = self._finding(title="tool 'mod.other' matched")
        assert _extract_tool_name(f) == "mod.other"

    def test_plain_quoted_dotted(self):
        f = self._finding(title="Leaked via 'relay.execute_with_context' param")
        assert _extract_tool_name(f) == "relay.execute_with_context"

    def test_bracketed_name(self):
        f = self._finding(title="Remote access [shell_exec]: enabled")
        assert _extract_tool_name(f) == "shell_exec"

    def test_double_quoted_dotted(self):
        f = self._finding(title='Schema issue on "pkg.tool" here')
        assert _extract_tool_name(f) == "pkg.tool"

    def test_falls_through_to_detail(self):
        f = self._finding(title="no name here",
                          detail="Tool 'detail.tool' in body")
        assert _extract_tool_name(f) == "detail.tool"

    def test_falls_through_to_evidence(self):
        f = self._finding(title="nothing", detail="still nothing",
                          evidence="Tool 'evidence.tool' seen")
        assert _extract_tool_name(f) == "evidence.tool"

    def test_no_name_returns_empty(self):
        f = self._finding(title="Webhook vector found", detail="generic")
        assert _extract_tool_name(f) == ""

    def test_first_quoted_match_wins(self):
        f = self._finding(title="'first.tool' then 'second.tool'")
        assert _extract_tool_name(f) == "first.tool"


class TestProofKind:
    def _finding(self, check: str, title: str) -> Finding:
        return Finding(target="t", check=check, severity="CRITICAL",
                       title=title)

    def test_oob_confirmed(self):
        f = self._finding("llm_chain_replay",
                          "Chain exfiltrated data (out-of-band confirmed): x")
        assert _proof_kind(f) == "out-of-band"

    def test_reproduced(self):
        f = self._finding("llm_chain_replay", "Chain reproduced: compose")
        assert _proof_kind(f) == "reproduced"

    def test_unproven_chain_replay(self):
        f = self._finding("llm_chain_replay",
                          "Chain callable end-to-end (composition unproven)")
        assert _proof_kind(f) is None

    def test_live_exfil(self):
        f = self._finding("exfil_flow", "Live exfil confirmed: 'a.b' → 'c.d'")
        assert _proof_kind(f) == "live-exfil"

    def test_unproven_exfil_flow(self):
        f = self._finding("exfil_flow", "Potential exfil path detected")
        assert _proof_kind(f) is None

    def test_other_check(self):
        f = self._finding("webhook_persistence", "out-of-band confirmed x")
        assert _proof_kind(f) is None

    def test_title_matching_is_case_insensitive(self):
        f = self._finding("llm_chain_replay", "CHAIN REPRODUCED: loud")
        assert _proof_kind(f) == "reproduced"


class TestArrowPathExtraction:
    def _finding(self, title: str = "", detail: str = "",
                 evidence: str = "") -> Finding:
        return Finding(target="t", check="llm_chain_replay",
                       severity="CRITICAL", title=title, detail=detail,
                       evidence=evidence)

    def test_parenthetical_path_in_detail(self):
        f = self._finding(
            detail="Chain moved data (vault.read → net.send) out.")
        assert _extract_tool_path(f) == ["vault.read", "net.send"]

    def test_ascii_arrows(self):
        f = self._finding(detail="Path: vault.read -> net.send confirmed")
        assert _extract_tool_path(f) == ["vault.read", "net.send"]

    def test_quoted_path(self):
        f = self._finding(detail="Saw 'a.read → b.send' in output")
        assert _extract_tool_path(f) == ["a.read", "b.send"]

    def test_three_hop_path(self):
        f = self._finding(detail="(one.read → two.mid → three.send)")
        assert _extract_tool_path(f) == ["one.read", "two.mid", "three.send"]

    def test_detail_preferred_over_title(self):
        f = self._finding(title="(title.a → title.b)",
                          detail="(detail.a → detail.b)")
        assert _extract_tool_path(f) == ["detail.a", "detail.b"]

    def test_undotted_names_cannot_form_path(self):
        """Single-word tool names fail the dotted-token pattern; the path
        parse yields nothing and extraction falls back to a single name."""
        f = self._finding(detail="read → send with no dots")
        assert _extract_tool_path(f) == []

    def test_no_arrows_falls_back_to_single_tool(self):
        f = self._finding(title="Tool 'lonely.sink' reproduced")
        assert _extract_tool_path(f) == ["lonely.sink"]

    def test_nothing_extractable(self):
        f = self._finding(title="vague", detail="vaguer")
        assert _extract_tool_path(f) == []


class TestGenerationSemantics:
    def test_unknown_check_produces_no_rule(self):
        result = _result_with_findings([
            ("tls_hygiene", "LOW", "Tool 'a.b' has weak TLS"),
        ])
        rules = generate_policy([result])
        assert len(rules) == 1
        assert rules[0].tool_names == ["*"]

    def test_mapped_check_without_tool_name_produces_no_rule(self):
        result = _result_with_findings([
            ("webhook_persistence", "HIGH", "Webhook vector, no tool named"),
        ])
        rules = generate_policy([result])
        assert len(rules) == 1
        assert rules[0].tool_names == ["*"]

    def test_weaker_after_stronger_appends_reason(self):
        result = _result_with_findings([
            ("webhook_persistence", "HIGH", "Tool 'x.y' webhook vector"),
            ("prompt_leakage", "MEDIUM", "Tool 'x.y' leaks prompt"),
        ])
        rules = generate_policy([result])
        tool_rules = [r for r in rules if "x.y" in r.tool_names]
        assert len(tool_rules) == 1
        assert tool_rules[0].action == "DENY"
        assert "webhook persistence vector" in tool_rules[0].reason
        assert "system prompt leakage" in tool_rules[0].reason

    def test_stronger_after_weaker_replaces(self):
        result = _result_with_findings([
            ("rate_limit", "MEDIUM", "Tool 'x.y' no rate limit"),
            ("remote_access", "HIGH", "Tool 'x.y' remote access"),
        ])
        rules = generate_policy([result])
        tool_rules = [r for r in rules if "x.y" in r.tool_names]
        assert len(tool_rules) == 1
        assert tool_rules[0].action == "DENY"
        assert tool_rules[0].budget is None

    def test_same_priority_keeps_first_appends_reason(self):
        result = _result_with_findings([
            ("webhook_persistence", "HIGH", "Tool 'x.y' webhook"),
            ("supply_chain", "HIGH", "Tool 'x.y' supply chain"),
        ])
        rules = generate_policy([result])
        tool_rules = [r for r in rules if "x.y" in r.tool_names]
        assert len(tool_rules) == 1
        assert tool_rules[0].action == "DENY"
        assert "webhook persistence vector" in tool_rules[0].reason
        assert "supply chain risk" in tool_rules[0].reason

    def test_identical_rules_merge_tool_lists(self):
        result = _result_with_findings([
            ("webhook_persistence", "HIGH", "Tool 'a.one' webhook"),
            ("webhook_persistence", "HIGH", "Tool 'b.two' webhook"),
        ])
        rules = generate_policy([result])
        deny_rules = [r for r in rules
                      if r.action == "DENY" and "*" not in r.tool_names]
        assert len(deny_rules) == 1
        assert sorted(deny_rules[0].tool_names) == ["a.one", "b.two"]

    def test_same_action_different_reason_not_merged(self):
        result = _result_with_findings([
            ("webhook_persistence", "HIGH", "Tool 'a.one' webhook"),
            ("remote_access", "HIGH", "Tool 'b.two' remote access"),
        ])
        rules = generate_policy([result])
        deny_rules = [r for r in rules
                      if r.action == "DENY" and "*" not in r.tool_names]
        assert len(deny_rules) == 2

    def test_rules_sorted_by_action_priority_desc(self):
        result = _result_with_findings([
            ("rate_limit", "MEDIUM", "Tool 'budget.tool' no limit"),
            ("prompt_leakage", "MEDIUM", "Tool 'scope.tool' leaks"),
            ("code_execution", "CRITICAL", "Tool 'hold.tool' execs"),
            ("webhook_persistence", "HIGH", "Tool 'deny.tool' webhook"),
        ])
        rules = generate_policy([result])
        # Generated rules sort strictest-first; the default deny is
        # appended after the sort so it always lands last.
        priorities = [ACTION_PRIORITY.get(r.action, 0) for r in rules[:-1]]
        assert priorities == sorted(priorities, reverse=True)
        assert rules[-1].tool_names == ["*"]
        assert rules[-1].action == "DENY"

    def test_findings_combined_across_results(self):
        r1 = _result_with_findings([
            ("webhook_persistence", "HIGH", "Tool 'a.one' webhook")])
        r2 = _result_with_findings([
            ("code_execution", "CRITICAL", "Tool 'b.two' execs")])
        actions = _tool_actions(generate_policy([r1, r2]))
        assert actions == {"a.one": "DENY", "b.two": "HOLD"}

    def test_three_hop_proved_chain_holds_all_sources(self):
        result = _result_with_findings([
            (
                "llm_chain_replay",
                "CRITICAL",
                "Chain exfiltrated data (out-of-band confirmed): 3 hops",
                "Proved (one.read → two.mid → three.send) via canary.",
            ),
        ])
        rules = generate_policy([result])
        actions = _tool_actions(rules)
        assert actions["three.send"] == "DENY"
        assert actions["one.read"] == "HOLD"
        assert actions["two.mid"] == "HOLD"
        hold_rules = [r for r in rules if r.action == "HOLD"]
        for r in hold_rules:
            assert r.hold == {"timeout": "5m", "onTimeout": "DENY"}

    def test_proved_exfil_source_not_denied_by_generic_map(self):
        """exfil_flow maps to DENY in FINDING_TO_ACTION, but a proved
        multi-hop finding must HOLD the source, not DENY it."""
        result = _result_with_findings([
            (
                "exfil_flow",
                "CRITICAL",
                "Live exfil confirmed: 'docs.read' → 'webhook.push'",
                "Canary moved docs.read → webhook.push",
            ),
        ])
        actions = _tool_actions(generate_policy([result]))
        assert actions["docs.read"] == "HOLD"
        assert actions["webhook.push"] == "DENY"

    def test_proved_finding_without_path_emits_nothing(self):
        """llm_chain_replay is not in FINDING_TO_ACTION, so a proved
        finding with no extractable tools yields only the default deny."""
        result = _result_with_findings([
            (
                "llm_chain_replay",
                "CRITICAL",
                "Chain exfiltrated data (out-of-band confirmed): vague",
                "Out-of-band confirmed but no tool names anywhere.",
            ),
        ])
        rules = generate_policy([result])
        assert len(rules) == 1
        assert rules[0].tool_names == ["*"]

    @pytest.mark.parametrize("check", sorted(FINDING_TO_ACTION))
    def test_every_mapped_check_produces_mapped_action(self, check: str):
        mapping = FINDING_TO_ACTION[check]
        result = _result_with_findings([
            (check, "HIGH", f"Tool 'target.tool' triggered {check}"),
        ])
        actions = _tool_actions(generate_policy([result]))
        assert actions.get("target.tool") == mapping["action"]


class TestMergeIdenticalRules:
    def test_hold_config_preserved_when_merging(self):
        rules = [
            PolicyRule(action="HOLD", tool_names=["a.b"], reason="r",
                       hold={"timeout": "5m", "onTimeout": "DENY"}),
            PolicyRule(action="HOLD", tool_names=["c.d"], reason="r",
                       hold={"timeout": "5m", "onTimeout": "DENY"}),
        ]
        merged = _merge_identical_rules(rules)
        assert len(merged) == 1
        assert merged[0].tool_names == ["a.b", "c.d"]
        assert merged[0].hold == {"timeout": "5m", "onTimeout": "DENY"}

    def test_input_rules_not_mutated(self):
        original = PolicyRule(action="DENY", tool_names=["a.b"], reason="r")
        _merge_identical_rules([original,
                                PolicyRule(action="DENY",
                                           tool_names=["c.d"], reason="r")])
        assert original.tool_names == ["a.b"]


class TestSerializationStructure:
    def test_budget_block_round_trips(self):
        rules = [
            PolicyRule(action="ALLOW", tool_names=["noisy.tool"],
                       reason="no rate limiting detected",
                       budget={
                           "perIdentity": {"maxCallsPerHour": 100},
                           "perSession": {"maxCallsPerHour": 30},
                           "onExhausted": "DENY",
                       }),
            PolicyRule(action="DENY", tool_names=["*"], reason="default"),
        ]
        loaded = yaml.safe_load(serialize_policy(rules))
        budget = loaded["spec"]["rules"][0]["budget"]
        assert budget["perIdentity"]["maxCallsPerHour"] == 100
        assert budget["perSession"]["maxCallsPerHour"] == 30
        assert budget["onExhausted"] == "DENY"

    def test_empty_rules_list_is_valid_yaml(self):
        # ponytail: serializer emits a bare "rules:" key, which YAML loads
        # as None rather than []; both decode as "no rules" for a CRD.
        loaded = yaml.safe_load(serialize_policy([]))
        assert loaded["kind"] == "NullfieldPolicy"
        assert not loaded["spec"]["rules"]

    def test_namespace_omitted_when_empty(self):
        loaded = yaml.safe_load(serialize_policy(
            [PolicyRule(action="DENY", tool_names=["*"], reason="d")]))
        assert "namespace" not in loaded["metadata"]

    def test_every_rule_declares_tools_call_method(self):
        result = _result_with_findings([
            ("webhook_persistence", "HIGH", "Tool 'a.b' webhook"),
            ("code_execution", "CRITICAL", "Tool 'c.d' execs"),
            ("rate_limit", "MEDIUM", "Tool 'e.f' unlimited"),
        ])
        loaded = yaml.safe_load(serialize_policy(generate_policy([result])))
        assert len(loaded["spec"]["rules"]) == 4  # 3 tools + default deny
        for entry in loaded["spec"]["rules"]:
            assert entry["mcpMethod"] == "tools/call"
            assert isinstance(entry["toolNames"], list)
            assert entry["reason"]

    def test_selector_scoping_in_parsed_yaml(self):
        loaded = yaml.safe_load(serialize_policy(
            [PolicyRule(action="DENY", tool_names=["*"], reason="d")],
            selector_labels={"app": "brain-gateway"},
        ))
        assert loaded["spec"]["selector"]["matchLabels"] == {
            "app": "brain-gateway"}

    def test_generated_policy_for_all_mapped_checks_parses(self):
        """End-to-end: one finding per mapped check → valid YAML whose
        non-default rules carry the mapped actions."""
        findings = [
            (check, "HIGH", f"Tool 'tool.{i}' triggered {check}")
            for i, check in enumerate(sorted(FINDING_TO_ACTION))
        ]
        loaded = yaml.safe_load(serialize_policy(
            generate_policy([_result_with_findings(findings)])))
        rules = loaded["spec"]["rules"]
        assert rules[-1]["toolNames"] == ["*"]
        by_tool = {}
        for entry in rules[:-1]:
            for name in entry["toolNames"]:
                by_tool[name] = entry["action"]
        for i, check in enumerate(sorted(FINDING_TO_ACTION)):
            assert by_tool[f"tool.{i}"] == FINDING_TO_ACTION[check]["action"]


class TestRulesMapIntegrity:
    def test_all_actions_have_priority(self):
        for check, mapping in FINDING_TO_ACTION.items():
            assert mapping["action"] in ACTION_PRIORITY, check

    def test_hold_entries_carry_hold_config(self):
        for check, mapping in FINDING_TO_ACTION.items():
            if mapping["action"] == "HOLD":
                assert mapping["hold"]["onTimeout"] == "DENY", check
                assert "timeout" in mapping["hold"], check

    def test_scope_entries_carry_scope_config(self):
        for check, mapping in FINDING_TO_ACTION.items():
            if mapping["action"] == "SCOPE":
                assert "response" in mapping["scope"], check

    def test_budget_entries_are_allow_with_budget(self):
        for check, mapping in FINDING_TO_ACTION.items():
            if "budget" in mapping:
                assert mapping["action"] == "ALLOW", check
                assert mapping["budget"]["onExhausted"] == "DENY", check

    def test_policy_rule_defaults(self):
        rule = PolicyRule(action="DENY", tool_names=["a.b"], reason="r")
        assert rule.hold is None
        assert rule.scope is None
        assert rule.budget is None
