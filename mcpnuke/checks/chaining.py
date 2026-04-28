"""Tool shadowing, multi-vector, attack chain checks."""

import re

from mcpnuke.core.models import TargetResult, AttackChain
from mcpnuke.core.constants import SHADOW_TARGETS, ATTACK_CHAIN_PATTERNS
from mcpnuke.checks.base import time_check

from mcpnuke.checks._lane_helpers import lane_tagged

# All findings in this module are scoped to Lane 4 / Transport "A"
# (2026-04-26 by-lane reporting spec).
_add = lane_tagged(lane=4, transport="A")

_TOOL_NAME_RE = re.compile(r"'([\w.]+)'|tool\s+'?([\w.]+)'?", re.IGNORECASE)


def check_tool_shadowing(
    all_results: list[TargetResult], result: TargetResult
):
    with time_check("tool_shadowing", result):
        my_names = {t["name"].lower() for t in result.tools}

        shadows = my_names & SHADOW_TARGETS
        if shadows:
            _add(result, 
                "tool_shadowing",
                "HIGH",
                f"Tool shadowing: redefines common name(s): {sorted(shadows)}",
            )

        for other in all_results:
            if other.url == result.url:
                continue
            dupes = my_names & {t["name"].lower() for t in other.tools}
            if dupes:
                _add(result, 
                    "tool_shadowing",
                    "MEDIUM",
                    f"Name collision with {other.url}: {sorted(dupes)}",
                )


def check_multi_vector(result: TargetResult):
    with time_check("multi_vector", result):
        checks_hit = {f.check for f in result.findings}
        dangerous = {
            "prompt_injection",
            "active_prompt_injection",
            "tool_poisoning",
            "tool_response_injection",
            "token_theft",
            "code_execution",
            "remote_access",
            "indirect_injection",
            "ssrf_probe",
            "config_tampering",
            "exfil_flow",
            "response_credentials",
        }
        hit = checks_hit & dangerous
        if len(hit) >= 2:
            _add(result, 
                "multi_vector",
                "CRITICAL",
                f"Multi-vector attack: {len(hit)} categories active",
                f"Vectors: {sorted(hit)}",
            )
        if (
            {"prompt_injection", "active_prompt_injection",
             "indirect_injection", "tool_poisoning", "tool_response_injection"}
            & checks_hit
            and {"token_theft", "remote_access", "exfil_flow",
                 "response_credentials"} & checks_hit
        ):
            _add(result, 
                "multi_vector",
                "CRITICAL",
                "Attack chain: injection + exfiltration vector present",
            )


def _extract_tool_names(
    findings: list, check_type: str, valid_names: set[str] | None = None
) -> list[str]:
    """Extract tool names mentioned in findings for a given check type.

    When *valid_names* is provided, only names (or their dotted-prefix) that
    appear in the set are kept — prevents descriptive text fragments from
    leaking into evidence_tools.
    """
    names: list[str] = []
    for f in findings:
        if f.check != check_type:
            continue
        for m in _TOOL_NAME_RE.finditer(f.title):
            raw = m.group(1) or m.group(2)
            if not raw or raw.lower() in ("tool", "param"):
                continue
            if valid_names is not None:
                prefix = raw.split(".")[0]
                if raw not in valid_names and prefix not in valid_names:
                    continue
            names.append(raw)
            break
    return names


def check_attack_chains(result: TargetResult):
    with time_check("attack_chains", result):
        checks = {f.check for f in result.findings}
        tool_names = {t["name"] for t in result.tools}
        tool_prefixes = {n.split(".")[0] for n in tool_names}
        valid = tool_names | tool_prefixes
        for a, b in ATTACK_CHAIN_PATTERNS:
            if a in checks and b in checks:
                tools_a = _extract_tool_names(result.findings, a, valid)
                tools_b = _extract_tool_names(result.findings, b, valid)
                evidence_tools = sorted(set(tools_a + tools_b))

                result.attack_chains.append(
                    AttackChain(source=a, target=b, evidence_tools=evidence_tools)
                )

                if evidence_tools:
                    detail = f"{a} → {b} ({', '.join(evidence_tools[:5])})"
                else:
                    detail = f"{a} → {b}"
                _add(result, 
                    "attack_chain",
                    "CRITICAL",
                    f"Attack chain: {detail}",
                    f"Two linked vulnerability classes detected in sequence",
                )
