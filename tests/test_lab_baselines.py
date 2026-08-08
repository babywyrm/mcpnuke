"""Slice D: offline golden fixtures for Priority Actions + proved-chain policy.

Fixtures are Camazotz/DVMCP-shaped finding sets used as oracles only.
Production ranking/policy code stays target-agnostic.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mcpnuke.core.models import Finding, TargetResult
from mcpnuke.policy.generator import generate_policy
from mcpnuke.reporting.priority import rank_priority_actions

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "scans"
_FIXTURE_TARGET = "http://fixture.example/mcp"


def _load_fixture(name: str) -> dict:
    path = _FIXTURES / name
    assert path.is_file(), f"missing Slice D fixture: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def _findings_from_fixture(data: dict) -> list[Finding]:
    out: list[Finding] = []
    for raw in data["findings"]:
        out.append(
            Finding(
                target=_FIXTURE_TARGET,
                check=raw["check"],
                severity=raw["severity"],
                title=raw["title"],
                detail=raw.get("detail") or "",
                taxonomy_id=raw.get("taxonomy_id") or "",
            )
        )
    return out


def test_fixture_files_are_secret_free():
    """Committed goldens must not carry evidence blobs or obvious secret markers."""
    for path in sorted(_FIXTURES.glob("*.json")):
        text = path.read_text(encoding="utf-8").lower()
        assert '"evidence"' not in text, path
        for banned in ("akia", "begin private key", "xoxb-", "ghp_"):
            assert banned not in text, f"{path} looks like it contains {banned!r}"


def test_proved_outranks_capability_spam_fixture():
    data = _load_fixture("proved_outranks_capability_spam.json")
    findings = _findings_from_fixture(data)
    assert any(f.check == "excessive_permissions" for f in findings)
    assert any(
        f.check == "llm_chain_replay" and "out-of-band" in f.title.lower()
        for f in findings
    )

    actions = rank_priority_actions(findings, limit=10)
    assert actions, "expected priority actions from fixture"
    top = actions[0]
    assert top.score >= 800
    assert "out-of-band" in top.reason or "reproduced" in top.reason
    assert top.check != "excessive_permissions"
    assert top.impact.strip() and top.fix.strip() and top.verify.strip()


def test_proved_multihop_policy_fixture():
    data = _load_fixture("proved_multihop_policy.json")
    findings = _findings_from_fixture(data)
    result = TargetResult(url=_FIXTURE_TARGET)
    result.findings.extend(findings)

    rules = generate_policy([result])
    by_tool: dict[str, str] = {}
    for rule in rules:
        for name in rule.tool_names:
            if name != "*":
                by_tool[name] = rule.action

    # Path from fixture: chain.get_service_manifest → egress.fetch_url
    assert by_tool.get("egress.fetch_url") == "DENY"
    assert by_tool.get("chain.get_service_manifest") == "HOLD"
    reasons = " ".join(r.reason for r in rules)
    assert "proved chain sink (out-of-band)" in reasons
    assert "proved chain source (out-of-band)" in reasons


def test_dvmcp_challenge_shapes_still_get_guidance():
    data = _load_fixture("dvmcp_challenge_shapes.json")
    findings = _findings_from_fixture(data)
    assert findings

    actions = rank_priority_actions(findings, limit=10)
    # May be empty only if fixture somehow has zero findings — already asserted
    for action in actions:
        assert action.impact.strip()
        assert action.fix.strip()
        assert action.verify.strip()

    # Unproven composition must not invent hop DENYs from this fixture alone
    result = TargetResult(url=_FIXTURE_TARGET)
    result.findings.extend(findings)
    rules = generate_policy([result])
    proved_reasons = [r.reason for r in rules if "proved chain" in r.reason or "proved live" in r.reason]
    assert proved_reasons == []


@pytest.mark.skipif(
    os.environ.get("CAMAZOTZ_LIVE") != "1",
    reason="Set CAMAZOTZ_LIVE=1 when Camazotz is reachable",
)
def test_live_camazotz_priority_soft_oracle():
    """If live scan emits OOB/reproduced, it must appear among top priority actions."""
    from mcpnuke.scanner import scan_target

    url = os.environ.get("CAMAZOTZ_URL", "http://localhost:8080/mcp")
    result = scan_target(
        url,
        [],
        timeout=20,
        probe_opts={"no_invoke": True, "fast": True},
    )
    if result.transport == "none":
        pytest.skip(f"Camazotz unreachable at {url}")

    actions = rank_priority_actions(result.findings, limit=10)
    proved = [
        f
        for f in result.findings
        if f.check == "llm_chain_replay"
        and (
            "out-of-band confirmed" in f.title.lower()
            or "chain reproduced" in f.title.lower()
        )
    ]
    if not proved:
        pytest.skip("live scan had no OOB/reproduced chain findings")

    action_checks = {a.check for a in actions}
    assert "llm_chain_replay" in action_checks
    assert actions[0].score >= 800 or any(
        "out-of-band" in a.reason or "reproduced" in a.reason for a in actions[:5]
    )
