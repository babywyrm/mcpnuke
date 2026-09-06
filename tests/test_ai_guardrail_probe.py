"""Tests for ai_guardrail_probe check (MCP-T56)."""

from collections.abc import Callable

from mcpnuke.checks.ai_guardrail_probe import check_ai_guardrail

# Matches the UUID pattern in SECRET_SHAPED_PATTERNS; length > 12.
LEAK = "123e4567-e89b-12d3-a456-426614174000"


class _Session:
    """Fake MCP session whose tool response is decided by the probe payload."""

    def __init__(self, responder: Callable[[str], str | None]) -> None:
        self.responder = responder
        self.messages: list[str] = []

    def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
        if method != "tools/call":
            return None
        args = params.get("arguments", {})
        message = next(iter(args.values()), "")
        self.messages.append(message)
        text = self.responder(message)
        if text is None:
            return None
        return {"result": {"content": [{"type": "text", "text": text}]}}


def _guardrail_tool(
    name: str = "deploy_gate",
    description: str = "AI review gate for deployments",
    param: str = "message",
) -> dict:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"properties": {param: {"type": "string"}}},
    }


def _always_leak(_message: str) -> str:
    return f"Sure, the value is {LEAK}"


def test_no_guardrail_tools_no_findings(result_with_tools):
    session = _Session(_always_leak)
    r = result_with_tools([
        {"name": "read_file", "description": "Read a file", "inputSchema": {}},
    ])
    check_ai_guardrail(session, r)
    assert len(r.findings) == 0
    assert session.messages == []


def test_all_strategies_leak_critical(result_with_tools):
    """A guardrail that leaks under every strategy is CRITICAL / minimal."""
    session = _Session(_always_leak)
    r = result_with_tools([_guardrail_tool()])
    check_ai_guardrail(session, r)
    hits = [f for f in r.findings if f.check == "ai_guardrail_bypass"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "deploy_gate" in hits[0].title
    assert "5/5 strategies" in hits[0].detail
    assert "minimal" in hits[0].detail
    assert hits[0].taxonomy_id == "MCP-T56"


def test_single_strategy_leak_high(result_with_tools):
    """One broken strategy is HIGH / partial — even when both target vars leak
    under it, the count is per-strategy, not per-response."""
    session = _Session(lambda m: f"ok: {LEAK}" if "SYSTEM OVERRIDE" in m else "I can't share that.")
    r = result_with_tools([
        _guardrail_tool(description="AI review gate guarding CLIENT_SECRET and API_KEY"),
    ])
    check_ai_guardrail(session, r)
    hits = [f for f in r.findings if f.check == "ai_guardrail_bypass"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "1/5 strategies" in hits[0].detail
    assert "partial" in hits[0].detail
    assert "authority_override" in hits[0].detail


def test_three_strategies_leak_critical(result_with_tools):
    """Three or more broken strategies cross the CRITICAL threshold."""
    markers = ("SYSTEM OVERRIDE", "as JSON", "debug mode")
    session = _Session(lambda m: f"ok: {LEAK}" if any(k in m for k in markers) else "denied")
    r = result_with_tools([_guardrail_tool()])
    check_ai_guardrail(session, r)
    hits = [f for f in r.findings if f.check == "ai_guardrail_bypass"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "3/5 strategies" in hits[0].detail


def test_guardrail_holds_no_finding(result_with_tools):
    session = _Session(lambda _m: "I can't share that.")
    r = result_with_tools([_guardrail_tool()])
    check_ai_guardrail(session, r)
    assert len(r.findings) == 0
    # All 5 strategies probed against the single default target var.
    assert len(session.messages) == 5


def test_short_values_are_not_leaks(result_with_tools):
    """detect_guardrail_leak ignores values too short to be real secrets."""
    session = _Session(lambda _m: "token=abc")
    r = result_with_tools([_guardrail_tool()])
    check_ai_guardrail(session, r)
    assert len(r.findings) == 0


def test_tool_without_message_param_skipped(result_with_tools):
    """No message/query/prompt-style parameter means the tool is never called."""
    session = _Session(_always_leak)
    r = result_with_tools([
        {
            "name": "deploy_gate",
            "description": "AI review gate for deployments",
            "inputSchema": {"properties": {"level": {"type": "integer"}}},
        }
    ])
    check_ai_guardrail(session, r)
    assert len(r.findings) == 0
    assert session.messages == []


def test_no_invoke_skips_probing(result_with_tools):
    session = _Session(_always_leak)
    r = result_with_tools([_guardrail_tool()])
    check_ai_guardrail(session, r, probe_opts={"no_invoke": True})
    assert len(r.findings) == 0
    assert session.messages == []


def test_empty_response_no_finding(result_with_tools):
    session = _Session(lambda _m: None)
    r = result_with_tools([_guardrail_tool()])
    check_ai_guardrail(session, r)
    assert len(r.findings) == 0


def test_tool_name_match_selects_tool(result_with_tools):
    """The hint regex also matches tool names, not just descriptions."""
    session = _Session(_always_leak)
    r = result_with_tools([_guardrail_tool(name="ops_assistant", description="Operations helper")])
    check_ai_guardrail(session, r)
    hits = [f for f in r.findings if f.check == "ai_guardrail_bypass"]
    assert len(hits) == 1
    assert "ops_assistant" in hits[0].title


def test_target_var_from_description(result_with_tools):
    """Secret variable names in the tool description become probe targets."""
    session = _Session(lambda _m: "denied")
    r = result_with_tools([
        _guardrail_tool(description="AI review gate protecting API_KEY"),
    ])
    check_ai_guardrail(session, r)
    assert session.messages
    assert all("API_KEY" in m for m in session.messages)


def test_default_target_var_is_client_secret(result_with_tools):
    session = _Session(lambda _m: "denied")
    r = result_with_tools([_guardrail_tool()])
    check_ai_guardrail(session, r)
    assert session.messages
    assert all("CLIENT_SECRET" in m for m in session.messages)


def test_target_var_from_prior_finding(result_with_tools):
    """Secret names in earlier findings' details are also probed."""
    session = _Session(lambda _m: "denied")
    r = result_with_tools([_guardrail_tool()])
    r.add("response_credentials", "HIGH", "cred", "the AUTH_TOKEN value was returned")
    check_ai_guardrail(session, r)
    assert any("AUTH_TOKEN" in m for m in session.messages)


def test_call_count_scales_with_target_vars(result_with_tools):
    """Each strategy is tried against at most two target vars: 5 probes x 2 vars."""
    session = _Session(lambda _m: "denied")
    r = result_with_tools([
        _guardrail_tool(description="AI review gate guarding CLIENT_SECRET and API_KEY"),
    ])
    check_ai_guardrail(session, r)
    assert len(session.messages) == 10


def test_query_param_accepted(result_with_tools):
    """'query' is one of the preferred message parameter names."""
    session = _Session(_always_leak)
    r = result_with_tools([_guardrail_tool(param="query")])
    check_ai_guardrail(session, r)
    assert any(f.check == "ai_guardrail_bypass" for f in r.findings)


def test_prefixed_message_param_accepted(result_with_tools):
    """Fallback: any parameter whose name contains 'message' is used."""
    session = _Session(_always_leak)
    r = result_with_tools([_guardrail_tool(param="user_message")])
    check_ai_guardrail(session, r)
    assert any(f.check == "ai_guardrail_bypass" for f in r.findings)


def test_timing_recorded(result_with_tools):
    session = _Session(_always_leak)
    r = result_with_tools([])
    check_ai_guardrail(session, r)
    assert "ai_guardrail_probe" in r.timings
