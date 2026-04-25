"""Generate nullfield policy rules from mcpnuke scan findings."""

from __future__ import annotations

from collections import defaultdict

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.policy.rules import ACTION_PRIORITY, FINDING_TO_ACTION, PolicyRule


def generate_policy(
    results: list[TargetResult],
    policy_name: str = "mcpnuke-recommended",
    namespace: str = "",
) -> list[PolicyRule]:
    """Convert scan findings into a deduplicated list of nullfield policy rules.

    When multiple findings affect the same tool, the strictest action wins.
    Tools with no findings are not included (default deny covers them).
    """
    tool_rules: dict[str, PolicyRule] = {}
    global_rules: list[PolicyRule] = []

    for result in results:
        for finding in result.findings:
            mapping = FINDING_TO_ACTION.get(finding.check)
            if mapping is None:
                continue

            action = mapping["action"]
            reason = f"mcpnuke: {mapping['reason']}"

            tool_name = _extract_tool_name(finding)
            if not tool_name:
                continue

            existing = tool_rules.get(tool_name)
            if existing and ACTION_PRIORITY.get(existing.action, 0) >= ACTION_PRIORITY.get(action, 0):
                existing.reason += f"; {mapping['reason']}"
                continue

            rule = PolicyRule(
                action=action,
                tool_names=[tool_name],
                reason=reason,
                hold=mapping.get("hold"),
                scope=mapping.get("scope"),
                budget=mapping.get("budget"),
            )
            tool_rules[tool_name] = rule

    rules = _merge_identical_rules(list(tool_rules.values()))
    rules.sort(key=lambda r: -ACTION_PRIORITY.get(r.action, 0))

    rules.append(PolicyRule(
        action="DENY",
        tool_names=["*"],
        reason="mcpnuke: default deny",
    ))

    return rules


def _extract_tool_name(finding: Finding) -> str:
    """Extract the tool name from a finding's title or detail."""
    import re
    for field in (finding.title, finding.detail, finding.evidence):
        matches = re.findall(r"'([a-zA-Z_][a-zA-Z0-9_.]*\.[a-zA-Z_][a-zA-Z0-9_]*)'", field)
        if matches:
            return matches[0]
        matches = re.findall(r"Tool '([^']+)'", field)
        if matches:
            return matches[0]
        matches = re.findall(r"tool '([^']+)'", field)
        if matches:
            return matches[0]
        matches = re.findall(r"\"([a-zA-Z_][a-zA-Z0-9_.]+\.[a-zA-Z_][a-zA-Z0-9_]+)\"", field)
        if matches:
            return matches[0]
    return ""


def _merge_identical_rules(rules: list[PolicyRule]) -> list[PolicyRule]:
    """Merge rules with the same action + config into multi-tool rules."""
    groups: dict[str, PolicyRule] = {}
    for rule in rules:
        key = f"{rule.action}:{rule.reason}"
        if key in groups:
            groups[key].tool_names.extend(rule.tool_names)
        else:
            groups[key] = PolicyRule(
                action=rule.action,
                tool_names=list(rule.tool_names),
                reason=rule.reason,
                hold=rule.hold,
                scope=rule.scope,
                budget=rule.budget,
            )
    return list(groups.values())
