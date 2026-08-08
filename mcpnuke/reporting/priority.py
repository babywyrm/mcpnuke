"""Proof-ranked priority actions for scan reports.

Ranks mcpnuke finding *shapes* (check, title markers, severity) so operators
see what to fix first. Target-agnostic: no lab hostnames or challenge IDs.
Does not mutate findings or risk_score.

Slice C adds deterministic impact / fix / verify guidance on each action so
red and blue teams leave with an actionable next step, not only a severity.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from mcpnuke.core.constants import SEVERITY_WEIGHTS
from mcpnuke.core.models import Finding

_ALWAYS_COLLAPSE: frozenset[str] = frozenset({"excessive_permissions"})
_COLLAPSE_WHEN_GE_5: frozenset[str] = frozenset(
    {"remote_access", "code_execution", "token_theft"}
)
_HIGH_SIGNAL_BEHAVIORAL: frozenset[str] = frozenset(
    {
        "tool_response_injection",
        "ssrf_probe",
        "sdk_cache_tamper",
        "deep_rug_pull",
    }
)

_DEFAULT_LIMIT: int = 10

# check → (impact, fix, verify). Keep language target-agnostic.
_CHECK_GUIDANCE: dict[str, tuple[str, str, str]] = {
    "llm_chain_replay": (
        "An executable multi-step attack path was demonstrated against this server.",
        "Break the chain: require auth on each hop, remove or gate the sink tool, "
        "and stop untrusted data from flowing into privileged tools.",
        "Re-run with --claude --chain-replay (and --oast if egress was involved) "
        "and confirm this path no longer appears under Priority actions.",
    ),
    "exfil_flow": (
        "Sensitive source tools can feed communication or network sinks.",
        "Separate read and send privileges, require approval on sinks, and "
        "block planting of attacker-controlled callback URLs.",
        "Re-run the scan with the same flags; live exfil findings should clear "
        "or drop out of Priority actions.",
    ),
    "attack_chain": (
        "Two or more finding classes combine into a plausible attack narrative.",
        "Remediate the earliest link in the chain (usually injection or auth) "
        "so later stages cannot be reached.",
        "Re-scan and confirm the linked attack_chain finding is gone.",
    ),
    "excessive_permissions": (
        "Many tools advertise dangerous capabilities (exec, write, send, etc.).",
        "Remove unused dangerous tools, require strong auth, and default-deny "
        "high-risk tool names at the gateway or policy layer.",
        "Re-scan; the collapsed capability count under Priority actions should fall.",
    ),
    "remote_access": (
        "Tools expose remote access or network control surfaces.",
        "Disable or tightly scope remote-access tools; require MFA/auth and network allowlists.",
        "Re-scan and confirm remote_access findings are reduced or cleared.",
    ),
    "code_execution": (
        "Tools can evaluate or execute attacker-influenced code.",
        "Remove eval/exec surfaces or sandbox them; never pass untrusted strings to interpreters.",
        "Re-scan and attempt the same tool with a benign canary; execution findings should clear.",
    ),
    "token_theft": (
        "Tools accept or expose credential material that can be stolen or replayed.",
        "Stop returning raw tokens, shorten TTL, bind tokens to audience/DPoP, and redact outputs.",
        "Re-scan; token_theft findings should clear from Priority actions.",
    ),
    "ssrf_probe": (
        "Tools fetch caller-controlled URLs (SSRF / egress risk).",
        "Enforce URL allowlists, block link-local and metadata ranges, and disable open fetch tools.",
        "Re-scan with --oast when possible; SSRF/exfil priority items should disappear.",
    ),
    "sdk_cache_tamper": (
        "A writable identity/token cache can be poisoned then consumed.",
        "Make the cache immutable to callers, sign entries, or remove write tools entirely.",
        "Re-scan; sdk_cache_tamper / cache-poison chains should leave Priority actions.",
    ),
    "tool_response_injection": (
        "Tool output can inject instructions into a downstream agent.",
        "Sanitize/encode tool responses before they enter LLM context; strip instruction markers.",
        "Re-scan behavioral probes; tool_response_injection should clear.",
    ),
    "deep_rug_pull": (
        "Tool behavior changes across calls (rug pull / bait-and-switch).",
        "Pin tool versions, monitor schema drift, and refuse tools that mutate after first use.",
        "Re-scan deep rug-pull probes across repeated calls.",
    ),
    "input_sanitization": (
        "Untrusted input reaches dangerous sinks without adequate validation.",
        "Validate and encode all string parameters; reject shell/URL metacharacters where inappropriate.",
        "Re-run input_sanitization probes; CRITICAL/HIGH hits should clear.",
    ),
    "webhook_persistence": (
        "Webhook/callback registration enables persistent attacker-controlled callbacks.",
        "Allowlist callback domains, require auth to register, and expire webhooks.",
        "Re-scan; webhook_persistence should leave Priority actions.",
    ),
    "prompt_injection": (
        "Tool parameters or content can override agent instructions.",
        "Treat tool inputs as untrusted data; use structured outputs and instruction hierarchy.",
        "Re-scan prompt-injection checks; related Priority actions should clear.",
    ),
    "schema_risk": (
        "Tool schemas disclose sensitive structure or unsafe parameters.",
        "Minimize pre-auth schema detail; remove credential-shaped examples from descriptions.",
        "Re-scan static schema checks.",
    ),
}

_PROOF_GUIDANCE: dict[str, tuple[str, str, str]] = {
    "out-of-band egress confirmed": (
        "Data left the target to an attacker-controlled callback (observed, not inferred).",
        "Disable or tightly allowlist the egress/fetch/webhook sink; block outbound "
        "callbacks to untrusted hosts; require auth on the source tool.",
        "Re-scan with --claude --chain-replay --oast and confirm no "
        "'out-of-band confirmed' Priority action remains.",
    ),
    "live exfil confirmed out-of-band": (
        "A live source→sink transfer produced a confirmed outbound callback.",
        "Split source and sink permissions; deny open URL/webhook parameters; monitor egress.",
        "Re-scan with --oast; 'Live exfil confirmed' should not reappear.",
    ),
    "chain reproduced end-to-end": (
        "A multi-step exploit was executed successfully with data moving between steps.",
        "Fix the first hop that enables composition (usually a read or inject tool) "
        "and gate the sink that accepts prior output.",
        "Re-scan with --chain-replay; 'Chain reproduced' for this path should disappear.",
    ),
    "AI-judged transformed data movement": (
        "The model judged that data moved between steps despite transformation "
        "(encoding, field extract).",
        "Treat the composition as real: break the source→sink link and redact sensitive fields.",
        "Re-scan with --claude --chain-replay; AI-judged movement for this path should clear.",
    ),
    "live exfil path (egress unconfirmed)": (
        "A source→sink path accepted a canary end-to-end, but egress was not observed.",
        "Still treat as high risk: remove the sink or require strong auth; do not rely on "
        "the sink's 'accepted' reply as proof of safety.",
        "Re-scan with --oast to see if egress confirms; either way, clear the live path finding.",
    ),
    "linked attack chain": (
        "Deterministic findings combine into a multi-stage attack narrative.",
        "Remediate the enabling finding first (often injection or missing auth).",
        "Re-scan and confirm the attack_chain entry is gone.",
    ),
}

_FALLBACK: tuple[str, str, str] = (
    "This finding increases attacker options against the MCP server.",
    "Harden the implicated tool: require authentication, least privilege, "
    "and input validation; remove the tool if unused.",
    "Re-run mcpnuke against the same target and confirm this item leaves Priority actions.",
)

_COLLAPSED_CAPABILITY: tuple[str, str, str] = (
    "A large dangerous-capability surface gives attackers many equivalent tools to abuse.",
    "Inventory and remove unused dangerous tools; enforce default-deny policy for "
    "exec/send/write/webhook/egress names; require auth on what remains.",
    "Re-scan; the collapsed capability Priority action count should drop sharply.",
)


@dataclass(frozen=True)
class ActionGuidance:
    """Operator-facing remediation for one priority action."""

    impact: str
    fix: str
    verify: str


@dataclass(frozen=True)
class PriorityAction:
    """One fix-first item derived from scan findings."""

    rank: int
    score: int
    reason: str
    title: str
    check: str
    severity: str
    target: str
    taxonomy_id: str
    finding_index: int
    collapsed_count: int
    impact: str
    fix: str
    verify: str


@dataclass(frozen=True)
class _Candidate:
    score: int
    reason: str
    title: str
    check: str
    severity: str
    target: str
    taxonomy_id: str
    finding_index: int
    collapsed_count: int
    sev_weight: int


def guidance_for(
    check: str,
    reason: str,
    *,
    taxonomy_id: str = "",
    collapsed: bool = False,
) -> ActionGuidance:
    """Return deterministic impact/fix/verify for a finding shape.

    Prefers proof-tier guidance when *reason* is a known proof string, then
    check-specific templates, then a safe fallback. *taxonomy_id* is reserved
    for future specialization and must not encode lab-specific names.
    """
    _ = taxonomy_id  # reserved; keeps the public signature stable for Slice C+
    if collapsed and check in _ALWAYS_COLLAPSE | _COLLAPSE_WHEN_GE_5:
        impact, fix, verify = _COLLAPSED_CAPABILITY
        return ActionGuidance(impact=impact, fix=fix, verify=verify)
    if reason in _PROOF_GUIDANCE:
        impact, fix, verify = _PROOF_GUIDANCE[reason]
        return ActionGuidance(impact=impact, fix=fix, verify=verify)
    if check in _CHECK_GUIDANCE:
        impact, fix, verify = _CHECK_GUIDANCE[check]
        return ActionGuidance(impact=impact, fix=fix, verify=verify)
    impact, fix, verify = _FALLBACK
    return ActionGuidance(impact=impact, fix=fix, verify=verify)


def _tier(finding: Finding) -> tuple[int, str]:
    """Return (score, reason) for the first matching proof tier."""
    title_l = finding.title.lower()
    check = finding.check
    sev = finding.severity

    if check == "llm_chain_replay" and "out-of-band confirmed" in title_l:
        return 1000, "out-of-band egress confirmed"
    if check == "exfil_flow" and "live exfil confirmed" in title_l:
        return 1000, "live exfil confirmed out-of-band"
    if check == "llm_chain_replay" and "chain reproduced" in title_l:
        return 800, "chain reproduced end-to-end"
    if check == "attack_chain":
        return 700, "linked attack chain"
    if check == "llm_chain_replay" and "ai-judged" in title_l:
        return 600, "AI-judged transformed data movement"
    if check == "exfil_flow" and "live exfil path" in title_l:
        return 500, "live exfil path (egress unconfirmed)"
    if check in _HIGH_SIGNAL_BEHAVIORAL and sev in ("CRITICAL", "HIGH"):
        return 400, "high-signal behavioral finding"
    if sev == "CRITICAL":
        return 200, "critical finding"
    if sev == "HIGH":
        return 100, "high finding"
    if sev == "MEDIUM":
        return 40, "medium finding"
    if sev == "LOW":
        return 10, "low finding"
    return 5, "informational finding"


def _should_collapse(check: str, count: int) -> bool:
    if check in _ALWAYS_COLLAPSE:
        return True
    return check in _COLLAPSE_WHEN_GE_5 and count >= 5


def rank_priority_actions(
    findings: list[Finding],
    *,
    limit: int = _DEFAULT_LIMIT,
) -> list[PriorityAction]:
    """Return up to *limit* proof-ranked actions for *findings*."""
    if not findings or limit <= 0:
        return []

    by_key: dict[tuple[str, str], list[tuple[int, Finding]]] = defaultdict(list)
    for index, finding in enumerate(findings):
        by_key[(finding.target, finding.check)].append((index, finding))

    candidates: list[_Candidate] = []
    for (target, check), group in by_key.items():
        if _should_collapse(check, len(group)):
            first_index, first = group[0]
            max_sev = max(
                group, key=lambda item: SEVERITY_WEIGHTS.get(item[1].severity, 0)
            )[1]
            base_score, _ = _tier(max_sev)
            score = max(0, base_score - 50)
            n = len(group)
            candidates.append(
                _Candidate(
                    score=score,
                    reason=f"collapsed capability noise ({n} findings)",
                    title=(
                        f"{check}: {n} findings — review dangerous capability surface"
                    ),
                    check=check,
                    severity=max_sev.severity,
                    target=target,
                    taxonomy_id=first.taxonomy_id,
                    finding_index=first_index,
                    collapsed_count=n,
                    sev_weight=SEVERITY_WEIGHTS.get(max_sev.severity, 0),
                )
            )
            continue

        for index, finding in group:
            score, reason = _tier(finding)
            candidates.append(
                _Candidate(
                    score=score,
                    reason=reason,
                    title=finding.title,
                    check=finding.check,
                    severity=finding.severity,
                    target=finding.target,
                    taxonomy_id=finding.taxonomy_id,
                    finding_index=index,
                    collapsed_count=1,
                    sev_weight=SEVERITY_WEIGHTS.get(finding.severity, 0),
                )
            )

    candidates.sort(
        key=lambda c: (-c.score, -c.sev_weight, c.check, c.title, c.finding_index)
    )

    actions: list[PriorityAction] = []
    for rank, cand in enumerate(candidates[:limit], start=1):
        guide = guidance_for(
            cand.check,
            cand.reason,
            taxonomy_id=cand.taxonomy_id,
            collapsed=cand.collapsed_count > 1,
        )
        actions.append(
            PriorityAction(
                rank=rank,
                score=cand.score,
                reason=cand.reason,
                title=cand.title,
                check=cand.check,
                severity=cand.severity,
                target=cand.target,
                taxonomy_id=cand.taxonomy_id,
                finding_index=cand.finding_index,
                collapsed_count=cand.collapsed_count,
                impact=guide.impact,
                fix=guide.fix,
                verify=guide.verify,
            )
        )
    return actions


def priority_actions_as_dicts(
    findings: list[Finding],
    *,
    limit: int = _DEFAULT_LIMIT,
) -> list[dict]:
    """JSON-serializable priority actions for a finding list."""
    return [
        {
            "rank": a.rank,
            "score": a.score,
            "reason": a.reason,
            "title": a.title,
            "check": a.check,
            "severity": a.severity,
            "taxonomy_id": a.taxonomy_id,
            "finding_index": a.finding_index,
            "collapsed_count": a.collapsed_count,
            "impact": a.impact,
            "fix": a.fix,
            "verify": a.verify,
        }
        for a in rank_priority_actions(findings, limit=limit)
    ]
