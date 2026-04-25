"""Tests for nullfield policy generation from scan findings."""

from __future__ import annotations

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.policy.generator import generate_policy
from mcpnuke.policy.nullfield import serialize_policy
from mcpnuke.policy.rules import PolicyRule, ACTION_PRIORITY


def _result_with_findings(findings: list[tuple[str, str, str]]) -> TargetResult:
    """Create a TargetResult with findings: [(check, severity, title)]."""
    r = TargetResult(url="http://test:8080/mcp")
    for check, severity, title in findings:
        r.findings.append(Finding(
            target=r.url,
            check=check,
            severity=severity,
            title=title,
        ))
    return r


class TestPolicyGeneration:
    def test_deny_from_webhook_finding(self):
        result = _result_with_findings([
            ("webhook_persistence", "HIGH", "Webhook/callback tool 'shadow.register_webhook' accepts URL"),
        ])
        rules = generate_policy([result])
        deny_rules = [r for r in rules if r.action == "DENY" and "*" not in r.tool_names]
        assert len(deny_rules) >= 1
        assert any("webhook" in r.reason for r in deny_rules)

    def test_hold_from_code_execution(self):
        result = _result_with_findings([
            ("code_execution", "CRITICAL", "Tool 'hallucination.execute_plan' has execution-like param"),
        ])
        rules = generate_policy([result])
        hold_rules = [r for r in rules if r.action == "HOLD"]
        assert len(hold_rules) >= 1
        assert hold_rules[0].hold is not None
        assert hold_rules[0].hold["onTimeout"] == "DENY"

    def test_scope_from_credential_finding(self):
        result = _result_with_findings([
            ("response_credentials", "HIGH", "Tool 'relay.execute_with_context' leaks credentials"),
        ])
        rules = generate_policy([result])
        scope_rules = [r for r in rules if r.action == "SCOPE"]
        assert len(scope_rules) >= 1
        assert scope_rules[0].scope is not None
        assert "response" in scope_rules[0].scope

    def test_budget_from_rate_limit(self):
        result = _result_with_findings([
            ("rate_limit", "MEDIUM", "No rate limiting on 'cost.check_usage'"),
        ])
        rules = generate_policy([result])
        budget_rules = [r for r in rules if r.action == "BUDGET"]
        assert len(budget_rules) >= 1
        assert budget_rules[0].budget is not None

    def test_default_deny_always_last(self):
        result = _result_with_findings([
            ("code_execution", "CRITICAL", "Tool 'test.exec' has execution"),
        ])
        rules = generate_policy([result])
        assert rules[-1].action == "DENY"
        assert rules[-1].tool_names == ["*"]

    def test_strictest_action_wins(self):
        result = _result_with_findings([
            ("rate_limit", "MEDIUM", "Tool 'test.tool' no rate limit"),
            ("webhook_persistence", "HIGH", "Tool 'test.tool' webhook vector"),
        ])
        rules = generate_policy([result])
        tool_rules = [r for r in rules if "test.tool" in str(r.tool_names)]
        if tool_rules:
            assert tool_rules[0].action == "DENY"

    def test_empty_findings(self):
        result = TargetResult(url="http://test:8080/mcp")
        rules = generate_policy([result])
        assert len(rules) == 1
        assert rules[0].action == "DENY"
        assert rules[0].tool_names == ["*"]

    def test_teleport_lab_findings(self):
        result = _result_with_findings([
            ("teleport_lab_bot_theft", "CRITICAL", "Tool 'bot_identity_theft.read_tbot_secret' — tbot secret readable"),
            ("teleport_lab_role_escalation", "CRITICAL", "Tool 'teleport_role_escalation.request_role' — role escalation succeeded"),
        ])
        rules = generate_policy([result])
        deny_rules = [r for r in rules if r.action == "DENY" and "*" not in r.tool_names]
        hold_rules = [r for r in rules if r.action == "HOLD"]
        assert len(deny_rules) + len(hold_rules) >= 1


class TestPolicySerialization:
    def test_produces_valid_yaml(self):
        rules = [
            PolicyRule(action="DENY", tool_names=["bad.tool"], reason="test"),
            PolicyRule(action="DENY", tool_names=["*"], reason="default deny"),
        ]
        yaml_str = serialize_policy(rules)
        assert "apiVersion: nullfield.io/v1alpha1" in yaml_str
        assert "kind: NullfieldPolicy" in yaml_str
        assert "bad.tool" in yaml_str
        assert "action: DENY" in yaml_str

    def test_includes_hold_config(self):
        rules = [
            PolicyRule(
                action="HOLD",
                tool_names=["dangerous.tool"],
                reason="test",
                hold={"timeout": "5m", "onTimeout": "DENY"},
            ),
            PolicyRule(action="DENY", tool_names=["*"], reason="default"),
        ]
        yaml_str = serialize_policy(rules)
        assert "hold:" in yaml_str
        assert "timeout:" in yaml_str or "timeout" in yaml_str

    def test_includes_scope_config(self):
        rules = [
            PolicyRule(
                action="SCOPE",
                tool_names=["leaky.tool"],
                reason="test",
                scope={"response": {"redactPatterns": ["password"]}},
            ),
            PolicyRule(action="DENY", tool_names=["*"], reason="default"),
        ]
        yaml_str = serialize_policy(rules)
        assert "scope:" in yaml_str
        assert "redactPatterns" in yaml_str or "redact" in yaml_str

    def test_custom_name_and_namespace(self):
        rules = [PolicyRule(action="DENY", tool_names=["*"], reason="default")]
        yaml_str = serialize_policy(rules, name="my-policy", namespace="prod")
        assert "my-policy" in yaml_str
        assert "prod" in yaml_str

    def test_multiple_tools_in_rule(self):
        rules = [
            PolicyRule(action="DENY", tool_names=["a.tool", "b.tool"], reason="both bad"),
            PolicyRule(action="DENY", tool_names=["*"], reason="default"),
        ]
        yaml_str = serialize_policy(rules)
        assert "a.tool" in yaml_str
        assert "b.tool" in yaml_str


class TestActionPriority:
    def test_deny_highest(self):
        assert ACTION_PRIORITY["DENY"] > ACTION_PRIORITY["HOLD"]
        assert ACTION_PRIORITY["HOLD"] > ACTION_PRIORITY["SCOPE"]
        assert ACTION_PRIORITY["SCOPE"] > ACTION_PRIORITY["BUDGET"]
        assert ACTION_PRIORITY["BUDGET"] > ACTION_PRIORITY["ALLOW"]
