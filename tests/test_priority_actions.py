"""Priority Actions: proof-ranked fix-first list (target-agnostic)."""

from __future__ import annotations

import ast
from io import StringIO
from pathlib import Path

from rich.console import Console

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.reporting.console import print_report
from mcpnuke.reporting.json_out import build_report
from mcpnuke.reporting.priority import guidance_for, rank_priority_actions


def _f(
    check: str,
    severity: str,
    title: str,
    *,
    target: str = "http://example.test/mcp",
    taxonomy_id: str = "",
) -> Finding:
    return Finding(
        target=target,
        check=check,
        severity=severity,
        title=title,
        taxonomy_id=taxonomy_id,
    )


def test_empty_findings_yield_no_actions():
    assert rank_priority_actions([]) == []


def test_oob_beats_excessive_permissions_spam():
    findings = [
        _f("excessive_permissions", "CRITICAL", f"Dangerous capability [{i}]")
        for i in range(50)
    ]
    findings.append(
        _f(
            "llm_chain_replay",
            "CRITICAL",
            "[AI] [MCP-T51] Chain exfiltrated data (out-of-band confirmed): SSRF",
            taxonomy_id="MCP-T51",
        )
    )
    actions = rank_priority_actions(findings, limit=10)
    assert actions[0].check == "llm_chain_replay"
    assert "out-of-band" in actions[0].reason.lower()
    collapsed = [a for a in actions if a.check == "excessive_permissions"]
    assert len(collapsed) == 1
    assert collapsed[0].collapsed_count == 50
    assert actions[0].score > collapsed[0].score


def test_collapse_excessive_permissions():
    findings = [
        _f("excessive_permissions", "CRITICAL", f"Dangerous capability [{i}]")
        for i in range(10)
    ]
    actions = rank_priority_actions(findings)
    assert len(actions) == 1
    assert actions[0].collapsed_count == 10
    assert "10 findings" in actions[0].title


def test_reproduced_ranks_above_ai_judged():
    findings = [
        _f(
            "llm_chain_replay",
            "HIGH",
            "[AI] [AI-judged] Chain moved data (transformed): cache poison",
        ),
        _f(
            "llm_chain_replay",
            "CRITICAL",
            "[AI] Chain reproduced: credential forwarding",
        ),
    ]
    actions = rank_priority_actions(findings)
    assert "reproduced" in actions[0].title.lower()
    assert "ai-judged" in actions[1].title.lower()


def test_live_exfil_confirmed_above_unconfirmed_path():
    findings = [
        _f(
            "exfil_flow",
            "CRITICAL",
            "Live exfil path: 'read_secret' → 'post_webhook'",
        ),
        _f(
            "exfil_flow",
            "CRITICAL",
            "Live exfil confirmed: 'read_secret' → 'post_webhook'",
        ),
    ]
    actions = rank_priority_actions(findings)
    assert "confirmed" in actions[0].title.lower()
    assert "path" in actions[1].title.lower()


def test_limit_and_stable_ranks():
    findings = [
        _f("schema_risk", "MEDIUM", f"issue {i}") for i in range(20)
    ]
    actions = rank_priority_actions(findings, limit=5)
    assert len(actions) == 5
    assert [a.rank for a in actions] == [1, 2, 3, 4, 5]


def test_collapse_high_volume_token_theft():
    findings = [
        _f("token_theft", "HIGH", f"Token param [{i}]") for i in range(5)
    ]
    actions = rank_priority_actions(findings)
    assert len(actions) == 1
    assert actions[0].collapsed_count == 5


def test_json_report_includes_priority_actions():
    r = TargetResult(url="http://example.test/mcp")
    r.add(
        "llm_chain_replay",
        "CRITICAL",
        "Chain exfiltrated data (out-of-band confirmed): x",
    )
    for i in range(3):
        r.add("excessive_permissions", "CRITICAL", f"Dangerous [{i}]")
    report = build_report([r], include_k8s=False)
    actions = report["targets"][0]["priority_actions"]
    assert actions[0]["check"] == "llm_chain_replay"
    assert set(actions[0]) >= {
        "rank",
        "score",
        "reason",
        "title",
        "check",
        "severity",
        "taxonomy_id",
        "finding_index",
        "collapsed_count",
        "impact",
        "fix",
        "verify",
    }
    assert actions[0]["impact"]
    assert actions[0]["fix"]
    assert actions[0]["verify"]


def test_console_prints_priority_actions_section():
    r = TargetResult(url="http://example.test/mcp")
    r.add(
        "llm_chain_replay",
        "CRITICAL",
        "Chain exfiltrated data (out-of-band confirmed): x",
    )
    buf = StringIO()
    print_report([r], console=Console(file=buf, force_terminal=False, width=120))
    text = buf.getvalue()
    assert "Priority actions" in text
    assert "out-of-band" in text.lower()
    assert "Impact:" in text
    assert "Fix:" in text
    assert "Verify:" in text


def test_console_omits_priority_when_no_findings():
    r = TargetResult(url="http://example.test/mcp")
    buf = StringIO()
    print_report([r], console=Console(file=buf, force_terminal=False, width=120))
    assert "Priority actions" not in buf.getvalue()


def test_actions_include_nonempty_guidance_fields():
    findings = [
        _f(
            "llm_chain_replay",
            "CRITICAL",
            "Chain exfiltrated data (out-of-band confirmed): leak",
        ),
        _f("ssrf_probe", "HIGH", "Tool accepts URL param"),
    ]
    for action in rank_priority_actions(findings):
        assert action.impact.strip()
        assert action.fix.strip()
        assert action.verify.strip()


def test_oob_guidance_mentions_egress_and_rescan():
    g = guidance_for(
        "llm_chain_replay",
        "out-of-band egress confirmed",
        taxonomy_id="MCP-T12",
    )
    blob = f"{g.impact} {g.fix} {g.verify}".lower()
    assert "egress" in blob or "exfil" in blob or "out-of-band" in blob
    assert "scan" in blob or "re-scan" in blob or "rescan" in blob


def test_collapsed_capability_guidance_is_inventory_focused():
    g = guidance_for(
        "excessive_permissions",
        "collapsed capability noise (12 findings)",
        collapsed=True,
    )
    blob = f"{g.impact} {g.fix}".lower()
    assert "capability" in blob or "dangerous" in blob or "tool" in blob
    assert "deny" in blob or "auth" in blob or "remove" in blob


def test_unknown_check_still_gets_fallback_guidance():
    g = guidance_for("brand_new_future_check", "critical finding")
    assert g.impact.strip() and g.fix.strip() and g.verify.strip()


def test_priority_module_has_no_lab_host_special_cases():
    """Red/blue usefulness: ranker must not hardcode lab targets."""
    src = Path("mcpnuke/reporting/priority.py").read_text()
    tree = ast.parse(src)
    banned = ("camazotz", "dvmcp", "localhost:900", "host.docker.internal")
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            for needle in banned:
                assert needle not in low, f"lab-specific string in priority.py: {node.value!r}"


def test_attack_chain_outranks_generic_critical():
    findings = [
        _f("schema_risk", "CRITICAL", "Generic schema issue"),
        _f("attack_chain", "HIGH", "prompt_injection → code_execution"),
    ]
    actions = rank_priority_actions(findings)
    assert actions[0].check == "attack_chain"


def test_collapse_counts_are_independent_per_url():
    findings = [
        _f("excessive_permissions", "CRITICAL", "A1", target="http://a/mcp"),
        _f("excessive_permissions", "CRITICAL", "A2", target="http://a/mcp"),
        _f("excessive_permissions", "CRITICAL", "B1", target="http://b/mcp"),
    ]
    actions = rank_priority_actions(findings, limit=10)
    by_target = {a.target: a for a in actions if a.check == "excessive_permissions"}
    assert by_target["http://a/mcp"].collapsed_count == 2
    assert by_target["http://b/mcp"].collapsed_count == 1
