"""OWASP MCP Top 10 and LLM Top 10 alignment reporting.

Maps findings to the canonical OWASP MCP Top 10 (2025) categories via their
agentic-sec taxonomy_id and renders a per-category alignment summary. The
OWASP Top 10 for LLM Applications (2025) view is derived from the MCP
category, with overrides where the LLM list has a sharper fit.

The vendored lanes.yaml carries an `owasp_mcp` field, but those values mirror
camazotz scenario numbering (MCP11..MCP32 appear; early entries are sequential
permutations), not the OWASP Top 10. The mapping here is curated against the
canonical list and owned by this repo.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from rich.console import Console

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.core.terminal import escape

# Canonical OWASP MCP Top 10 (2025), in order.
OWASP_MCP_TOP10: dict[str, str] = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

# Canonical OWASP Top 10 for LLM Applications (2025), in order.
OWASP_LLM_TOP10: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# Properties of the model and its training or retrieval data. A server scan
# cannot observe them, so nothing maps here; model resistance is graded by
# stoneburner.
LLM_OUT_OF_SCOPE: frozenset[str] = frozenset({"LLM04", "LLM08", "LLM09"})

# MCP category -> LLM category. MCP05 is LLM05: model output reaching a
# shell unvalidated is that entry's definition. MCP08 (audit) has no
# counterpart.
OWASP_MCP_TO_LLM: dict[str, str | None] = {
    "MCP01": "LLM02",
    "MCP02": "LLM06",
    "MCP03": "LLM01",
    "MCP04": "LLM03",
    "MCP05": "LLM05",
    "MCP06": "LLM01",
    "MCP07": "LLM06",
    "MCP08": None,
    "MCP09": "LLM03",
    "MCP10": "LLM02",
}

# Where the LLM list names the risk more precisely than the MCP category.
TAXONOMY_TO_OWASP_LLM: dict[str, str] = {
    "MCP-T10": "LLM06",  # Hallucination-Driven Destruction
    "MCP-T27": "LLM10",  # LLM Cost Exhaustion & Misattribution
    "MCP-T31": "LLM10",  # Budget Tuning
    "MCP-T51": "LLM10",  # Anonymous Rate-Limit Exhaustion
    "MCP-T54": "LLM10",  # Unauthenticated Inference Backend Exposure
}

# Checked first: prompt_leakage is tagged MCP-T01 (injection), but what it
# finds is LLM07 by name.
CHECK_TO_OWASP_LLM: dict[str, str] = {
    "prompt_leakage": "LLM07",
}

# agentic-sec taxonomy_id -> OWASP MCP category. Curated per threat title.
# MCP09 (Shadow MCP Servers) has no taxonomy ID: a scan cannot know which
# hosts an operator approved. check_shadow_mcp_server is the visible half
# (a manifest recruiting some other MCP endpoint) and maps by check name.
TAXONOMY_TO_OWASP: dict[str, str] = {
    "MCP-T01": "MCP06",  # Direct Prompt Injection
    "MCP-T02": "MCP06",  # Indirect Prompt Injection
    "MCP-T03": "MCP03",  # Tool Behavior Mutation (Rug Pull)
    "MCP-T04": "MCP01",  # Confused Deputy / Token Theft
    "MCP-T05": "MCP10",  # Cross-Tool Context Poisoning
    "MCP-T06": "MCP05",  # SSRF via Tool
    "MCP-T07": "MCP01",  # Secrets in Tool Output
    "MCP-T08": "MCP04",  # Supply Chain via Content
    "MCP-T09": "MCP03",  # Agent Config Tampering
    "MCP-T10": "MCP06",  # Hallucination-Driven Destruction
    "MCP-T11": "MCP10",  # Cross-Tenant Memory Leak
    "MCP-T12": "MCP10",  # Exfiltration via Chaining
    "MCP-T13": "MCP08",  # Audit Log Evasion
    "MCP-T14": "MCP03",  # Persistence via Webhook
    "MCP-T15": "MCP01",  # Error Information Disclosure
    "MCP-T16": "MCP06",  # Temporal Consistency Drift
    "MCP-T17": "MCP06",  # Notification / Sampling Abuse
    "MCP-T18": "MCP01",  # Bot Identity Theft via tbot Credential Exposure
    "MCP-T19": "MCP07",  # Short-Lived Certificate Replay Attack
    "MCP-T20": "MCP07",  # RBAC & Isolation Boundary Bypass
    "MCP-T21": "MCP01",  # OAuth Token Theft & Replay
    "MCP-T22": "MCP07",  # Execution Context Forgery
    "MCP-T23": "MCP01",  # Credential Isolation & Sidecar Tampering
    "MCP-T24": "MCP07",  # Authentication Pattern Downgrade
    "MCP-T25": "MCP02",  # Agent Delegation Chain Abuse
    "MCP-T26": "MCP01",  # Token Lifecycle & Revocation Gaps
    "MCP-T27": "MCP02",  # LLM Cost Exhaustion & Misattribution
    "MCP-T28": "MCP02",  # Teleport Role Escalation via MCP Tool
    "MCP-T29": "MCP06",  # Policy Authoring (defends chain attacks)
    "MCP-T30": "MCP01",  # Response Inspection (defends secret leaks)
    "MCP-T31": "MCP02",  # Budget Tuning (defends abuse of scope)
    "MCP-T32": "MCP07",  # Delegation Depth — Multi-Agent Identity Dilution
    "MCP-T33": "MCP01",  # SDK Token Cache Poisoning
    "MCP-T34": "MCP01",  # Subprocess Credential Inheritance
    "MCP-T35": "MCP07",  # Native Function-Calling Identity Erasure
    "MCP-T36": "MCP03",  # LangChain Tool Description Injection
    "MCP-T37": "MCP07",  # Agent HTTP Bypass — Direct Transport B Access
    "MCP-T38": "MCP05",  # Code Review Agent — Subprocess Injection via PR Content
    "MCP-T39": "MCP06",  # RAG Pipeline Injection
    "MCP-T41": "MCP07",  # AI Governance Gate Bypass via Trusted Redirect
    "MCP-T42": "MCP02",  # Shared IdP Cross-Pollution (User → Agent escalation)
    "MCP-T43": "MCP01",  # DPoP Key Exposure and JWT Forgery
    "MCP-T44": "MCP05",  # Blocklist Bypass via Incomplete Input Filter
    "MCP-T45": "MCP01",  # Agent-to-Agent Credential Forwarding
    "MCP-T46": "MCP01",  # In-Process SDK Credential Cache Exposure
    "MCP-T47": "MCP07",  # Agent Chain In-Process SDK Identity Dilution
    "MCP-T48": "MCP01",  # Agent Chain Subprocess Credential Injection
    "MCP-T49": "MCP10",  # Agent Chain LLM Function-Calling Context Leak
    "MCP-T50": "MCP07",  # Anonymous Tool Schema Over-Disclosure
    "MCP-T51": "MCP07",  # Anonymous Rate-Limit Exhaustion
    "MCP-T52": "MCP06",  # Pre-Authentication Injection
    "MCP-T53": "MCP05",  # Shell Command Wrapping Injection
    "MCP-T54": "MCP07",  # Unauthenticated Inference Backend Exposure
    "MCP-T55": "MCP04",  # Inference Model Integrity Drift
    "MCP-T56": "MCP06",  # AI Guardrail Bypass via Social Engineering
    "MCP-T57": "MCP01",  # Cached Session Token Exposure
    "MCP-T58": "MCP07",  # hostNetwork Loopback Bridge
}

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Fallback for core checks that predate taxonomy tagging. Composites
# (attack_chain, multi_vector) span categories by definition; they are
# bucketed by their primary — initial-access — vector, which is injection.
CHECK_TO_OWASP: dict[str, str] = {
    "code_execution": "MCP05",
    "auth": "MCP07",
    "indirect_injection": "MCP06",
    "attack_chain": "MCP06",
    "multi_vector": "MCP06",
    # Legacy checks observed unmapped on the DVMCP baseline (2026-09-14).
    "schema_risk": "MCP05",  # unbounded params are the injection enabler
    "input_sanitization": "MCP05",  # unsanitized reflection
    "sse_security": "MCP07",  # unauthenticated stream / cross-origin POST
    "actuator_probe": "MCP07",  # exposed management/discovery endpoints
    "tool_response_injection": "MCP06",  # indirect injection via tool output
    "active_prompt_injection": "MCP06",  # server follows injected instructions
    "resource_poisoning": "MCP06",  # poisoned resource content hijacks intent
    "differential": "MCP03",  # --baseline inventory drift is tool-surface mutation
    # Exposed Teleport /webapi/ping. Not MCP-T28 (that is role escalation
    # through an MCP tool). Same OWASP bucket as actuator_probe: an
    # unauthenticated discovery endpoint.
    "teleport_proxy_discovery": "MCP07",
    "shadow_mcp_server": "MCP09",
    "tool_poisoning": "MCP03",
}


def _category_for(f: Finding) -> str | None:
    return TAXONOMY_TO_OWASP.get(f.taxonomy_id) or CHECK_TO_OWASP.get(f.check)


def _llm_category_for(f: Finding) -> str | None:
    mcp = _category_for(f)
    return (
        CHECK_TO_OWASP_LLM.get(f.check)
        or TAXONOMY_TO_OWASP_LLM.get(f.taxonomy_id)
        or (OWASP_MCP_TO_LLM[mcp] if mcp else None)
    )


def _tally(findings: Iterable[Finding]) -> dict[str, int]:
    c: Counter[str] = Counter(f.severity for f in findings)
    return {s: c[s] for s in _SEV_ORDER if c.get(s, 0) > 0}


def _block(findings: list[Finding]) -> dict[str, Any]:
    return {
        "finding_count": len(findings),
        "severity_tally": _tally(findings),
        "findings": [
            {
                "target": f.target,
                "check": f.check,
                "severity": f.severity,
                "title": f.title,
                "taxonomy_id": f.taxonomy_id,
            }
            for f in findings
        ],
    }


def _build(
    results: list[TargetResult],
    key: str,
    categories: dict[str, str],
    category_for: Callable[[Finding], str | None],
    extra: Callable[[str], dict[str, Any]] = lambda _cat: {},
) -> dict[str, Any]:
    by_cat: dict[str, list[Finding]] = defaultdict(list)
    unmapped: list[Finding] = []

    for r in results:
        for f in r.findings:
            cat = category_for(f)
            if cat:
                by_cat[cat].append(f)
            else:
                unmapped.append(f)

    out: dict[str, Any] = {"schema": "v1", key: {}}
    total = 0
    for cat_id, name in categories.items():
        findings = by_cat.get(cat_id, [])
        total += len(findings)
        out[key][cat_id] = {"name": name, **extra(cat_id), **_block(findings)}
    if unmapped:
        out["unmapped"] = _block(unmapped)
        total += len(unmapped)
    out["total_findings"] = total
    return out


def build_owasp(results: list[TargetResult]) -> dict[str, Any]:
    """Group findings from all targets by OWASP MCP Top 10 category.

    Returns a versioned dict with every canonical category present (empty
    buckets included — an alignment report exists to show coverage gaps),
    plus an "unmapped" bucket for findings with no recognized taxonomy_id.
    """
    return _build(results, "owasp_mcp", OWASP_MCP_TOP10, _category_for)


def build_owasp_llm(results: list[TargetResult]) -> dict[str, Any]:
    """Group findings by OWASP Top 10 for LLM Applications (2025) category.

    Same shape as build_owasp, keyed "owasp_llm". Each category carries
    in_scope; out-of-scope ones are model-side and never receive findings.
    """
    return _build(
        results,
        "owasp_llm",
        OWASP_LLM_TOP10,
        _llm_category_for,
        lambda cat: {"in_scope": cat not in LLM_OUT_OF_SCOPE},
    )


def print_owasp(results: list[TargetResult], console: Console | None = None) -> None:
    """Render the OWASP MCP Top 10 alignment report."""
    _render(
        build_owasp(results),
        "owasp_mcp",
        OWASP_MCP_TOP10,
        "OWASP MCP Top 10 alignment",
        "no taxonomy mapping",
        console,
    )


def print_owasp_llm(results: list[TargetResult], console: Console | None = None) -> None:
    """Render the OWASP Top 10 for LLM Applications alignment report."""
    _render(
        build_owasp_llm(results),
        "owasp_llm",
        OWASP_LLM_TOP10,
        "OWASP Top 10 for LLM Applications (2025) alignment",
        "no LLM Top 10 counterpart",
        console,
    )


def _render(
    report: dict[str, Any],
    key: str,
    categories: dict[str, str],
    title: str,
    unmapped_reason: str,
    console: Console | None,
) -> None:
    from mcpnuke.core.constants import SEV_COLOR

    total = report["total_findings"]

    def _write(line: str = "") -> None:
        if console is not None:
            console.print(line)
        else:
            print(line)

    header = f"── {title} ({total} finding(s)) ──"
    _write()
    _write(f"[bold]{header}[/bold]" if console else header)

    for cat_id, name in categories.items():
        block = report[key][cat_id]
        count = block["finding_count"]
        if console is not None:
            _write(f"\n[bold cyan]{cat_id} — {name}[/]")
        else:
            _write(f"\n{cat_id} — {name}")
        if not block.get("in_scope", True):
            _write("  (model-side: out of scope for an MCP server scan)")
            continue
        if count == 0:
            _write("  (no findings fired)")
            continue
        tally_s = ", ".join(f"{s}={n}" for s, n in block["severity_tally"].items())
        _write(f"  {count} finding(s): {tally_s}")
        for f in block["findings"][:10]:
            sev = f["severity"]
            if console is not None:
                color = SEV_COLOR.get(sev, "dim")
                _write(f"    [{color}]{sev:8s}[/] {f['check']:25s} {escape(f['title'])}")
            else:
                _write(f"    {sev:8s} {f['check']:25s} {f['title']}")
        if count > 10:
            _write(f"    ... and {count - 10} more")

    unmapped = report.get("unmapped")
    if unmapped:
        _write()
        line = f"Unmapped ({unmapped_reason} — {unmapped['finding_count']} finding(s))"
        _write(f"[bold]{line}[/bold]" if console else line)
        for f in unmapped["findings"][:10]:
            title = escape(f['title']) if console is not None else f['title']
            _write(f"    {f['severity']:8s} {f['check']:25s} {title}")
