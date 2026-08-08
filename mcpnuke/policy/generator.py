"""Generate nullfield policy rules from mcpnuke scan findings."""

from __future__ import annotations

import re

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.policy.rules import ACTION_PRIORITY, FINDING_TO_ACTION, PolicyRule

_HOLD_ON_TIMEOUT: dict[str, str] = {"timeout": "5m", "onTimeout": "DENY"}

_TOOL_TOKEN: re.Pattern[str] = re.compile(
    r"[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+"
)
_ARROW_SPLIT: re.Pattern[str] = re.compile(r"\s*(?:→|->)\s*")


def generate_policy(
    results: list[TargetResult],
    policy_name: str = "mcpnuke-recommended",
    namespace: str = "",
) -> list[PolicyRule]:
    """Convert scan findings into a deduplicated list of nullfield policy rules.

    When multiple findings affect the same tool, the strictest action wins.
    Tools with no findings are not included (default deny covers them).
    Proved multi-hop findings emit DENY on the sink and HOLD on sources;
    those findings skip the generic FINDING_TO_ACTION single-tool map so
    sources are not accidentally DENY'd by the same finding.
    """
    tool_rules: dict[str, PolicyRule] = {}

    for result in results:
        for finding in result.findings:
            hop_rules = _proved_hop_rules(finding)
            if hop_rules:
                for hop in hop_rules:
                    for tool_name in hop.tool_names:
                        _apply_candidate(
                            tool_rules,
                            tool_name,
                            action=hop.action,
                            reason=hop.reason,
                            hold=hop.hold,
                            scope=hop.scope,
                            budget=hop.budget,
                            append_reason=hop.reason.removeprefix("mcpnuke: "),
                        )
                continue

            mapping = FINDING_TO_ACTION.get(finding.check)
            if mapping is None:
                continue

            tool_name = _extract_tool_name(finding)
            if not tool_name:
                continue

            _apply_candidate(
                tool_rules,
                tool_name,
                action=mapping["action"],
                reason=f"mcpnuke: {mapping['reason']}",
                hold=mapping.get("hold"),
                scope=mapping.get("scope"),
                budget=mapping.get("budget"),
                append_reason=mapping["reason"],
            )

    rules = _merge_identical_rules(list(tool_rules.values()))
    rules.sort(key=lambda r: -ACTION_PRIORITY.get(r.action, 0))

    rules.append(PolicyRule(
        action="DENY",
        tool_names=["*"],
        reason="mcpnuke: default deny",
    ))

    return rules


def _apply_candidate(
    tool_rules: dict[str, PolicyRule],
    tool_name: str,
    *,
    action: str,
    reason: str,
    hold: dict | None,
    scope: dict | None,
    budget: dict | None,
    append_reason: str,
) -> None:
    existing = tool_rules.get(tool_name)
    if existing and ACTION_PRIORITY.get(existing.action, 0) >= ACTION_PRIORITY.get(action, 0):
        if append_reason and append_reason not in existing.reason:
            existing.reason += f"; {append_reason}"
        return

    tool_rules[tool_name] = PolicyRule(
        action=action,
        tool_names=[tool_name],
        reason=reason,
        hold=hold,
        scope=scope,
        budget=budget,
    )


def _proof_kind(finding: Finding) -> str | None:
    """Return a stable proof tag, or None if the finding is not proved for policy."""
    title_l = finding.title.lower()
    if finding.check == "llm_chain_replay":
        if "out-of-band confirmed" in title_l:
            return "out-of-band"
        if "chain reproduced" in title_l:
            return "reproduced"
        return None
    if finding.check == "exfil_flow" and "live exfil confirmed" in title_l:
        return "live-exfil"
    return None


def _tokens_from_arrow_field(field: str) -> list[str]:
    """Return the longest arrow-separated tool path found in *field*, or []."""
    if "→" not in field and "->" not in field:
        return []
    best: list[str] = []
    # Scan overlapping windows: any substring that contains arrows.
    for match in re.finditer(r"[^\n]+", field):
        line = match.group(0)
        if "→" not in line and "->" not in line:
            continue
        # Strip wrapping prose by taking the parenthetical path when present.
        candidates = [line]
        for paren in re.findall(r"\(([^)]*(?:→|->)[^)]*)\)", line):
            candidates.append(paren)
        for quoted in re.findall(r"'([^']*(?:→|->)[^']*)'", line):
            candidates.append(quoted)
        for cand in candidates:
            parts = [p.strip(" '\".,;:") for p in _ARROW_SPLIT.split(cand)]
            tokens: list[str] = []
            for part in parts:
                m = _TOOL_TOKEN.fullmatch(part)
                if not m:
                    m = _TOOL_TOKEN.search(part)
                if not m:
                    tokens = []
                    break
                tokens.append(m.group(0))
            if len(tokens) >= 2 and len(tokens) > len(best):
                best = tokens
    return best


def _extract_tool_path(finding: Finding) -> list[str]:
    """Prefer arrow-separated multi-hop paths; else a single extracted tool name."""
    for field in (finding.detail, finding.title, finding.evidence):
        if not isinstance(field, str) or not field:
            continue
        path = _tokens_from_arrow_field(field)
        if path:
            return path
    single = _extract_tool_name(finding)
    return [single] if single else []


def _proved_hop_rules(finding: Finding) -> list[PolicyRule]:
    """DENY sink + HOLD sources for proved multi-hop findings."""
    kind = _proof_kind(finding)
    if kind is None:
        return []

    path = _extract_tool_path(finding)
    if not path:
        return []

    if len(path) == 1:
        return [
            PolicyRule(
                action="DENY",
                tool_names=[path[0]],
                reason="mcpnuke: single-tool proved finding",
            )
        ]

    sink = path[-1]
    sources = path[:-1]
    if kind == "out-of-band":
        sink_reason = "mcpnuke: proved chain sink (out-of-band)"
        source_reason = "mcpnuke: proved chain source (out-of-band)"
    elif kind == "reproduced":
        sink_reason = "mcpnuke: proved chain sink (reproduced)"
        source_reason = "mcpnuke: proved chain source (reproduced)"
    else:
        sink_reason = "mcpnuke: proved live exfil sink"
        source_reason = "mcpnuke: proved live exfil source"

    rules = [
        PolicyRule(action="DENY", tool_names=[sink], reason=sink_reason),
    ]
    for source in sources:
        rules.append(
            PolicyRule(
                action="HOLD",
                tool_names=[source],
                reason=source_reason,
                hold=dict(_HOLD_ON_TIMEOUT),
            )
        )
    return rules


def _extract_tool_name(finding: Finding) -> str:
    """Extract the tool name from a finding's title or detail.

    Handles formats like:
      Tool 'module.tool_name': ...
      Remote access [shell_exec]: 'remote_access'
      "module.tool_name"
    """
    for field in (finding.title, finding.detail, finding.evidence):
        if not isinstance(field, str) or not field:
            continue
        matches = re.findall(r"'([a-zA-Z_][a-zA-Z0-9_.]*\.[a-zA-Z_][a-zA-Z0-9_]*)'", field)
        if matches:
            return str(matches[0])
        matches = re.findall(r"Tool '([^']+)'", field)
        if matches:
            return str(matches[0])
        matches = re.findall(r"tool '([^']+)'", field)
        if matches:
            return str(matches[0])
        matches = re.findall(r"\[([a-zA-Z_][a-zA-Z0-9_.]*)\]", field)
        if matches:
            return str(matches[0])
        matches = re.findall(r"\"([a-zA-Z_][a-zA-Z0-9_.]+\.[a-zA-Z_][a-zA-Z0-9_]+)\"", field)
        if matches:
            return str(matches[0])
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
