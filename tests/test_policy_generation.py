"""Tests for nullfield policy generation from scan findings."""

from __future__ import annotations

import ast
from pathlib import Path

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.policy.generator import generate_policy
from mcpnuke.policy.nullfield import serialize_policy
from mcpnuke.policy.rules import ACTION_PRIORITY, PolicyRule

_POLICY_DIR = Path(__file__).resolve().parents[1] / "mcpnuke" / "policy"
_LAB_BANNED = ("camazotz", "dvmcp", "localhost:9001", "challenge-")


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
        budget_rules = [r for r in rules if r.action == "ALLOW" and r.budget is not None]
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
            (
                "teleport_lab_role_escalation",
                "CRITICAL",
                "Tool 'teleport_role_escalation.request_role' — role escalation succeeded",
            ),
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

    def test_default_selector_is_empty_match_labels(self):
        """Without selector_labels, output preserves the legacy empty selector."""
        rules = [PolicyRule(action="DENY", tool_names=["*"], reason="default")]
        yaml_str = serialize_policy(rules)
        assert "matchLabels: {}" in yaml_str

    def test_selector_labels_render_under_match_labels(self):
        rules = [PolicyRule(action="DENY", tool_names=["*"], reason="default")]
        yaml_str = serialize_policy(
            rules,
            selector_labels={"app": "brain-gateway", "tier": "data"},
        )
        assert "matchLabels: {}" not in yaml_str
        assert "matchLabels:" in yaml_str
        assert '"app": "brain-gateway"' in yaml_str
        assert '"tier": "data"' in yaml_str

    def test_metadata_labels_render_under_metadata(self):
        rules = [PolicyRule(action="DENY", tool_names=["*"], reason="default")]
        yaml_str = serialize_policy(
            rules,
            metadata_labels={"nullfield.io/lane": "machine"},
        )
        assert "  labels:" in yaml_str
        assert '"nullfield.io/lane": "machine"' in yaml_str

    def test_full_round_trip_yaml_parses(self):
        """The fallback emitter must produce YAML that real parsers can load."""
        import yaml

        rules = [
            PolicyRule(
                action="HOLD",
                tool_names=["risky.tool"],
                reason="test",
                hold={"timeout": "5m", "onTimeout": "DENY"},
            ),
            PolicyRule(
                action="SCOPE",
                tool_names=["leaky.tool"],
                reason="test",
                scope={"response": {"redactPatterns": ["password"]}},
            ),
            PolicyRule(action="DENY", tool_names=["*"], reason="default"),
        ]
        yaml_str = serialize_policy(
            rules,
            name="round-trip",
            namespace="camazotz",
            selector_labels={"app": "brain-gateway"},
            metadata_labels={"nullfield.io/lane": "machine"},
        )
        loaded = yaml.safe_load(yaml_str)
        assert loaded["apiVersion"] == "nullfield.io/v1alpha1"
        assert loaded["kind"] == "NullfieldPolicy"
        assert loaded["metadata"]["name"] == "round-trip"
        assert loaded["metadata"]["namespace"] == "camazotz"
        assert loaded["metadata"]["labels"] == {"nullfield.io/lane": "machine"}
        assert loaded["spec"]["selector"]["matchLabels"] == {
            "app": "brain-gateway"
        }
        actions = [r["action"] for r in loaded["spec"]["rules"]]
        assert actions == ["HOLD", "SCOPE", "DENY"]
        assert loaded["spec"]["rules"][0]["hold"] == {
            "timeout": "5m",
            "onTimeout": "DENY",
        }


class TestActionPriority:
    def test_deny_highest(self):
        assert ACTION_PRIORITY["DENY"] > ACTION_PRIORITY["HOLD"]
        assert ACTION_PRIORITY["HOLD"] > ACTION_PRIORITY["SCOPE"]
        assert ACTION_PRIORITY["SCOPE"] > ACTION_PRIORITY["ALLOW"]


class TestProvedChainPolicy:
    """Slice B: DENY sink + HOLD source from proved multi-hop findings."""

    def test_oob_chain_denies_sink_holds_source(self):
        result = _result_with_findings([
            (
                "llm_chain_replay",
                "CRITICAL",
                "Chain exfiltrated data (out-of-band confirmed): read then send",
                "Chain exfiltrated data out-of-band (vault.read → net.send). "
                "The target reached the canary URL.",
            ),
        ])
        actions = _tool_actions(generate_policy([result]))
        assert actions.get("net.send") == "DENY"
        assert actions.get("vault.read") == "HOLD"
        yaml_str = serialize_policy(generate_policy([result]))
        assert "proved chain sink (out-of-band)" in yaml_str
        assert "proved chain source (out-of-band)" in yaml_str

    def test_reproduced_chain_denies_sink_holds_source(self):
        result = _result_with_findings([
            (
                "llm_chain_replay",
                "CRITICAL",
                "Chain reproduced: compose secrets",
                "Chain reproduced end to end (secrets.get → http.post). "
                "Output of step 0 appeared in the request to step 1.",
            ),
        ])
        actions = _tool_actions(generate_policy([result]))
        assert actions.get("http.post") == "DENY"
        assert actions.get("secrets.get") == "HOLD"
        reasons = " ".join(r.reason for r in generate_policy([result]))
        assert "proved chain sink (reproduced)" in reasons
        assert "proved chain source (reproduced)" in reasons

    def test_live_exfil_confirmed_hop_aware(self):
        result = _result_with_findings([
            (
                "exfil_flow",
                "CRITICAL",
                "Live exfil confirmed: 'docs.read' → 'webhook.push'",
                "Canary transferred docs.read → webhook.push",
            ),
        ])
        actions = _tool_actions(generate_policy([result]))
        assert actions.get("webhook.push") == "DENY"
        assert actions.get("docs.read") == "HOLD"
        reasons = " ".join(r.reason for r in generate_policy([result]))
        assert "proved live exfil sink" in reasons
        assert "proved live exfil source" in reasons

    def test_unproven_callable_chain_emits_no_hop_rules(self):
        result = _result_with_findings([
            (
                "llm_chain_replay",
                "MEDIUM",
                "Chain callable end-to-end (composition unproven): maybe later",
                "Every step completed (a.read → b.send) without proven movement.",
            ),
        ])
        actions = _tool_actions(generate_policy([result]))
        assert actions == {}

    def test_single_tool_proved_finding_denies_only(self):
        result = _result_with_findings([
            (
                "llm_chain_replay",
                "CRITICAL",
                "Chain reproduced: lonely hop",
                "Chain reproduced end to end but only Tool 'lonely.sink' named.",
            ),
        ])
        rules = generate_policy([result])
        actions = _tool_actions(rules)
        assert actions.get("lonely.sink") == "DENY"
        assert not any(r.action == "HOLD" and "lonely.sink" in r.tool_names for r in rules)
        assert any("single-tool proved finding" in r.reason for r in rules)

    def test_webhook_deny_on_sink_stays_deny_with_proved_chain(self):
        result = _result_with_findings([
            (
                "webhook_persistence",
                "HIGH",
                "Webhook/callback tool 'net.send' accepts URL",
            ),
            (
                "llm_chain_replay",
                "CRITICAL",
                "Chain exfiltrated data (out-of-band confirmed): path",
                "Chain exfiltrated data out-of-band (vault.read → net.send).",
            ),
        ])
        actions = _tool_actions(generate_policy([result]))
        assert actions.get("net.send") == "DENY"
        assert actions.get("vault.read") == "HOLD"

    def test_policy_package_has_no_lab_host_special_cases(self):
        for path in _POLICY_DIR.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    low = node.value.lower()
                    for banned in _LAB_BANNED:
                        assert banned not in low, f"{path}: banned {banned!r}"
