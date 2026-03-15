"""Tool shadowing, multi-vector, attack chain checks."""

from collections import defaultdict

from mcprowler.core.models import TargetResult
from mcprowler.core.constants import SHADOW_TARGETS, ATTACK_CHAIN_PATTERNS
from mcprowler.checks.base import time_check


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


def check_attack_chains(result: TargetResult):
    with time_check("attack_chains", result):
        checks = {f.check for f in result.findings}
        for a, b in ATTACK_CHAIN_PATTERNS:
            if a in checks and b in checks:
                result.add(
                    "attack_chain",
                    "CRITICAL",
                    f"Attack chain: {a} → {b}",
                    "Two linked vulnerability classes detected in sequence",
                )
