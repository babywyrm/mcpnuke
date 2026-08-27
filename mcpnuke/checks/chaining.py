"""Tool shadowing, multi-vector, attack chain checks."""

import re
from difflib import SequenceMatcher
from itertools import combinations

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.constants import ATTACK_CHAIN_PATTERNS, SHADOW_TARGETS
from mcpnuke.core.models import AttackChain, TargetResult

# All findings in this module are scoped to Lane 4 / Transport "A"
# (2026-04-26 by-lane reporting spec).
_add = lane_tagged(lane=4, transport="A")

_TOOL_NAME_RE = re.compile(r"'([\w.]+)'|tool\s+'?([\w.]+)'?", re.IGNORECASE)

# What counts as an active attack vector. LOW is excluded on its own merits:
# a chain is a claim about things an attacker can actually use, and a finding
# we graded LOW is one we are saying is probably not that.
_VECTOR_SEVERITY_FLOOR: frozenset[str] = frozenset({"CRITICAL", "HIGH", "MEDIUM"})

# Two tools on one server whose names differ by a plural or a character are
# indistinguishable to an agent selecting by name. Calibrated against real
# tool vocabularies: legitimate neighbours peak around 0.71
# (read_file/write_file), while a shadow pair like
# get_user_role/get_user_roles scores 0.96.
_CONFUSABLE_RATIO: float = 0.86
# Ratios are unstable on short strings; those names are covered by
# SHADOW_TARGETS instead.
_MIN_CONFUSABLE_LEN: int = 6
# A near-identical description turns name ambiguity into a deliberate decoy.
_DESCRIPTION_ECHO_RATIO: float = 0.80
_MAX_CONFUSABLE_PAIRS: int = 8


def _normalize_tool_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _similar(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _confusable_pairs(tools: list[dict]) -> list[tuple[dict, dict, float]]:
    """Same-server tool pairs whose names are near-duplicates."""
    pairs: list[tuple[dict, dict, float]] = []
    for first, second in combinations(tools, 2):
        left = _normalize_tool_name(str(first.get("name", "")))
        right = _normalize_tool_name(str(second.get("name", "")))
        if not left or not right or left == right:
            continue
        if min(len(left), len(right)) < _MIN_CONFUSABLE_LEN:
            continue
        ratio = _similar(left, right)
        if ratio >= _CONFUSABLE_RATIO:
            pairs.append((first, second, ratio))
    return sorted(pairs, key=lambda p: p[2], reverse=True)


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
                taxonomy_id="MCP-T25",
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
                    taxonomy_id="MCP-T25",
                )

        _flag_confusable_names(result)


def _flag_confusable_names(result: TargetResult) -> None:
    """Report near-duplicate tool names served side by side (MCP-T25).

    An agent routes by name, so a decoy that differs by one character can be
    selected in place of the tool the user asked for.
    """
    for first, second, ratio in _confusable_pairs(result.tools)[:_MAX_CONFUSABLE_PAIRS]:
        left, right = str(first.get("name", "")), str(second.get("name", ""))
        desc_ratio = _similar(
            str(first.get("description", "") or "").lower(),
            str(second.get("description", "") or "").lower(),
        )
        echoed = desc_ratio >= _DESCRIPTION_ECHO_RATIO
        detail = (
            f"'{left}' and '{right}' differ by too little to distinguish "
            f"(name similarity {ratio:.0%}). An agent selecting a tool by name "
            "may invoke either one."
        )
        if echoed:
            detail += (
                f" Their descriptions are also near-identical "
                f"({desc_ratio:.0%}), so the pair reads as a deliberate decoy "
                "rather than two distinct operations."
            )
        _add(result,
            "tool_shadowing",
            "HIGH" if echoed else "MEDIUM",
            f"Confusable tool names: '{left}' vs '{right}'",
            detail,
            evidence={
                "tools": [left, right],
                "name_similarity": round(ratio, 3),
                "description_similarity": round(desc_ratio, 3),
            },
            taxonomy_id="MCP-T25",
        )


def _active_vectors(result: TargetResult) -> set[str]:
    """Checks with at least one finding we graded MEDIUM or above.

    Both chaining checks used to build this from finding names alone, with no
    severity filter, so a finding demoted to LOW still counted as a fully
    active attack vector. That let a CRITICAL "multi-vector attack" rest
    entirely on evidence we ourselves graded weak.

    Per check, not per finding: one weak finding must not disqualify a check
    that also produced a strong one.
    """
    return {f.check for f in result.findings if f.severity in _VECTOR_SEVERITY_FLOOR}


def check_multi_vector(result: TargetResult):
    with time_check("multi_vector", result):
        checks_hit = _active_vectors(result)
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


def _grade_linkage(
    tools_a: list[str], tools_b: list[str], shared: list[str]
) -> tuple[str, str, str]:
    """Return (severity, linkage, basis) for a matched check pair.

    The pair table says two vulnerability classes compose; it says nothing
    about whether these two instances can reach each other. Only a shared tool
    shows they meet. Disjoint tool sets are positive evidence that they do not,
    and are graded down. A finding that names no tool is target-scoped (auth,
    transport) and could reach anything, so silence is not evidence and the
    severity stands.
    """
    if shared:
        return (
            "CRITICAL",
            "shared-tool",
            f"Both classes implicate the same tool ({', '.join(shared[:5])}), "
            "so one exposure is reachable from the other.",
        )
    if tools_a and tools_b:
        return (
            "HIGH",
            "disjoint-tools",
            "Both classes are tool-scoped with no shared tool, so the link is "
            "unproven: an operator must confirm data can flow between them.",
        )
    return (
        "CRITICAL",
        "co-occurrence",
        "Reported on co-occurrence: at least one class is target-scoped and "
        "names no tool, so it is not attributable to a single entry point.",
    )


def check_attack_chains(result: TargetResult):
    with time_check("attack_chains", result):
        checks = _active_vectors(result)
        tool_names = {t["name"] for t in result.tools}
        tool_prefixes = {n.split(".")[0] for n in tool_names}
        valid = tool_names | tool_prefixes
        for a, b in ATTACK_CHAIN_PATTERNS:
            if a in checks and b in checks:
                tools_a = _extract_tool_names(result.findings, a, valid)
                tools_b = _extract_tool_names(result.findings, b, valid)
                evidence_tools = sorted(set(tools_a + tools_b))
                shared = sorted(set(tools_a) & set(tools_b))

                severity, linkage, basis = _grade_linkage(tools_a, tools_b, shared)

                result.attack_chains.append(
                    AttackChain(
                        source=a,
                        target=b,
                        evidence_tools=evidence_tools,
                        shared_tools=shared,
                        linkage=linkage,
                    )
                )

                detail = f"{a} → {b} ({', '.join(evidence_tools[:5])})" if evidence_tools else f"{a} → {b}"
                _add(result,
                    "attack_chain",
                    severity,
                    f"Attack chain: {detail}",
                    basis,
                )
