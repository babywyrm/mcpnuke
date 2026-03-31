"""Tool shadowing, multi-vector, attack chain checks."""

import re

from mcpnuke.core.models import TargetResult, AttackChain
from mcpnuke.core.constants import SHADOW_TARGETS, ATTACK_CHAIN_PATTERNS
from mcpnuke.checks.base import time_check

_TOOL_NAME_RE = re.compile(r"'([^']+)'|tool\s+'?(\w+)'?", re.IGNORECASE)


def check_tool_shadowing(
    all_results: list[TargetResult], result: TargetResult
):
    with time_check("tool_shadowing", result):
        my_names = {t["name"].lower() for t in result.tools}

        shadows = my_names & SHADOW_TARGETS
        if shadows:
            result.add(
                "tool_shadowing",
                "HIGH",
                f"Tool shadowing: redefines common name(s): {sorted(shadows)}",
            )

        for other in all_results:
            if other.url == result.url:
                continue
            dupes = my_names & {t["name"].lower() for t in other.tools}
            if dupes:
                result.add(
                    "tool_shadowing",
                    "MEDIUM",
                    f"Name collision with {other.url}: {sorted(dupes)}",
                )


def check_multi_vector(result: TargetResult):
    with time_check("multi_vector", result):
        checks_hit = {f.check for f in result.findings}
        dangerous = {
            "prompt_injection",
            "tool_poisoning",
            "token_theft",
            "code_execution",
            "remote_access",
            "indirect_injection",
        }
        hit = checks_hit & dangerous
        if len(hit) >= 2:
            result.add(
                "multi_vector",
                "CRITICAL",
                f"Multi-vector attack: {len(hit)} categories active",
                f"Vectors: {sorted(hit)}",
            )
        if (
            {"prompt_injection", "indirect_injection", "tool_poisoning"}
            & checks_hit
            and {"token_theft", "remote_access"} & checks_hit
        ):
            result.add(
                "multi_vector",
                "CRITICAL",
                "Attack chain: injection + exfiltration vector present",
            )


def _extract_tool_names(findings: list, check_type: str) -> list[str]:
    """Extract tool names mentioned in findings for a given check type."""
    names: list[str] = []
    for f in findings:
        if f.check != check_type:
            continue
        for m in _TOOL_NAME_RE.finditer(f.title):
            name = m.group(1) or m.group(2)
            if name and name.lower() not in ("tool", "param"):
                names.append(name)
                break
    return names


def check_attack_chains(result: TargetResult):
    with time_check("attack_chains", result):
        checks = {f.check for f in result.findings}
        for a, b in ATTACK_CHAIN_PATTERNS:
            if a in checks and b in checks:
                tools_a = _extract_tool_names(result.findings, a)
                tools_b = _extract_tool_names(result.findings, b)
                evidence_tools = sorted(set(tools_a + tools_b))

                result.attack_chains.append(
                    AttackChain(source=a, target=b, evidence_tools=evidence_tools)
                )

                if evidence_tools:
                    detail = f"{a} → {b} ({', '.join(evidence_tools[:5])})"
                else:
                    detail = f"{a} → {b}"
                result.add(
                    "attack_chain",
                    "CRITICAL",
                    f"Attack chain: {detail}",
                    f"Two linked vulnerability classes detected in sequence",
                )
