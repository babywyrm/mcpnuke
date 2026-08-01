"""Tests for the anon_budget_exhaust behavioral probe (MCP-T51)."""

from __future__ import annotations

from typing import Any

from mcpnuke.checks.anon_budget_exhaust import ANON_BURST_COUNT, check_anon_budget_exhaust
from mcpnuke.core.models import TargetResult

# ---------------------------------------------------------------------------
# Fake session that returns canned responses
# ---------------------------------------------------------------------------


class FakeSession:
    """Pretends to be an MCPSession.call_tool target.

    The check uses ``_call_tool(session, name, args, timeout)`` which in real
    code dispatches into the MCPSession. We monkeypatch the helper in tests
    instead of trying to mimic the full HTTP/stdio surface.
    """

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.call_count = 0

    def __call__(self) -> Any:
        if not self._responses:
            return {"result": {"content": [{"type": "text", "text": "ok"}]}}
        self.call_count += 1
        return self._responses.pop(0)


def _result(tools: list[dict]) -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.tools = tools
    return r


def _patch_call_tool(monkeypatch, responses: list[str]) -> dict[str, int]:
    """Patch _call_tool to return canned text responses in sequence.

    Returns a counters dict the caller can inspect after the run.
    """
    counters = {"calls": 0}
    iter_responses = iter(responses)

    def fake_call(session, name, args, timeout=5):  # noqa: ARG001
        counters["calls"] += 1
        try:
            text = next(iter_responses)
        except StopIteration:
            text = "ok"
        return {"result": {"content": [{"type": "text", "text": text}]}}

    monkeypatch.setattr(
        "mcpnuke.checks.anon_budget_exhaust._call_tool", fake_call
    )
    return counters


# ---------------------------------------------------------------------------
# Anonymous skip behavior
# ---------------------------------------------------------------------------


def test_skipped_when_session_has_jwt(monkeypatch) -> None:
    r = _result([{"name": "tool.list_items"}])
    r.auth_context = {"jwt_claims_summary": {"sub": "alice"}}
    counters = _patch_call_tool(monkeypatch, ["ok"] * ANON_BURST_COUNT)
    check_anon_budget_exhaust(FakeSession([]), r)
    assert counters["calls"] == 0
    assert not [f for f in r.findings if f.check == "anon_budget_exhaust"]


def test_skipped_when_session_has_raw_token(monkeypatch) -> None:
    r = _result([{"name": "tool.list_items"}])
    r.auth_context = {"_raw_token": "ghp_xxx"}
    counters = _patch_call_tool(monkeypatch, ["ok"] * ANON_BURST_COUNT)
    check_anon_budget_exhaust(FakeSession([]), r)
    assert counters["calls"] == 0


def test_skipped_when_no_safe_tool_available(monkeypatch) -> None:
    """All tools are destructive — nothing to burst."""
    r = _result([
        {"name": "files.delete_everything"},
        {"name": "deploy.kill_workload"},
    ])
    counters = _patch_call_tool(monkeypatch, ["ok"] * ANON_BURST_COUNT)
    check_anon_budget_exhaust(FakeSession([]), r)
    assert counters["calls"] == 0


# ---------------------------------------------------------------------------
# Throttle / rate-limit detection (no finding)
# ---------------------------------------------------------------------------


def test_no_finding_when_throttle_text_in_response(monkeypatch) -> None:
    r = _result([{"name": "tool.list_items", "description": "lists items"}])
    # Burst returns "ok" once, then a throttle message
    counters = _patch_call_tool(monkeypatch, ["ok", "ok", "429 too many requests"])
    check_anon_budget_exhaust(FakeSession([]), r)
    findings = [f for f in r.findings if f.check == "anon_budget_exhaust"]
    assert not findings
    # Burst short-circuited; should NOT have done all 25 calls
    assert counters["calls"] < ANON_BURST_COUNT


def test_no_finding_when_quota_exceeded_response(monkeypatch) -> None:
    r = _result([{"name": "status.health"}])
    counters = _patch_call_tool(monkeypatch, ["ok"] * 5 + ["quota exceeded"])
    check_anon_budget_exhaust(FakeSession([]), r)
    assert not [f for f in r.findings if f.check == "anon_budget_exhaust"]
    assert counters["calls"] == 6


# ---------------------------------------------------------------------------
# Finding fires when burst is clean and no per-caller signal exists
# ---------------------------------------------------------------------------


def test_high_finding_when_burst_clean_and_no_per_caller_signal(monkeypatch) -> None:
    r = _result([{"name": "tool.list_items", "description": "Lists items."}])
    counters = _patch_call_tool(monkeypatch, ["ok"] * ANON_BURST_COUNT)
    check_anon_budget_exhaust(FakeSession([]), r)
    findings = [f for f in r.findings if f.check == "anon_budget_exhaust"]
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].taxonomy_id == "MCP-T51"
    assert findings[0].lane == 5
    assert findings[0].transport == "A"
    assert counters["calls"] == ANON_BURST_COUNT


def test_medium_finding_when_per_caller_advertised_elsewhere(monkeypatch) -> None:
    r = _result([
        {"name": "tool.list_items", "description": "Lists items."},
        # Another tool advertises per-caller accounting
        {"name": "billing.quota", "description": "Per-caller bucket usage."},
    ])
    counters = _patch_call_tool(monkeypatch, ["ok"] * ANON_BURST_COUNT)
    check_anon_budget_exhaust(FakeSession([]), r)
    findings = [f for f in r.findings if f.check == "anon_budget_exhaust"]
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].taxonomy_id == "MCP-T51"
    assert counters["calls"] == ANON_BURST_COUNT


# ---------------------------------------------------------------------------
# Preferred tool selection
# ---------------------------------------------------------------------------


def test_prefers_read_only_verb_tools(monkeypatch) -> None:
    r = _result([
        {"name": "tool.do_something"},
        {"name": "tool.list_items"},  # should be picked first
        {"name": "tool.update_thing"},  # destructive verb 'update' not in skip list
    ])
    selected: list[str] = []

    def fake_call(session, name, args, timeout=5):  # noqa: ARG001
        selected.append(name)
        return {"result": {"content": [{"type": "text", "text": "ok"}]}}

    monkeypatch.setattr("mcpnuke.checks.anon_budget_exhaust._call_tool", fake_call)
    check_anon_budget_exhaust(FakeSession([]), r)
    assert selected[0] == "tool.list_items"


def test_evidence_includes_burst_count_and_tool_name(monkeypatch) -> None:
    r = _result([{"name": "status.health"}])
    _patch_call_tool(monkeypatch, ["ok"] * ANON_BURST_COUNT)
    check_anon_budget_exhaust(FakeSession([]), r)
    findings = [f for f in r.findings if f.check == "anon_budget_exhaust"]
    assert findings
    assert f"burst={ANON_BURST_COUNT}" in findings[0].evidence
    assert "tool=status.health" in findings[0].evidence


# ---------------------------------------------------------------------------
# OIDC active also counts as authenticated
# ---------------------------------------------------------------------------


def test_skipped_when_oidc_url_configured(monkeypatch) -> None:
    r = _result([{"name": "status.health"}])
    r.auth_context = {"oidc_url": "https://keycloak.example/realms/x"}
    counters = _patch_call_tool(monkeypatch, ["ok"] * ANON_BURST_COUNT)
    check_anon_budget_exhaust(FakeSession([]), r)
    assert counters["calls"] == 0
