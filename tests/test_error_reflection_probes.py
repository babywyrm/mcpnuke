"""A server that refuses bad input and names it is not a vulnerability.

Each test here has a matching true-positive case. The pair is the point: the
fix is only correct if the refusal goes quiet *and* the compliance does not.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from mcpnuke.checks.tool_probes import (
    check_input_sanitization,
    check_tool_response_injection,
)
from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.probes import CANARY, REFLECTION_PAYLOAD


def _tool(name="run_thing", param="cmd"):
    return {
        "name": name,
        "description": "A tool",
        "inputSchema": {"type": "object", "properties": {param: {"type": "string"}}},
    }


def _session(text: str, *, is_error: bool):
    """A server that answers every call with the same canned text."""
    session = MagicMock()
    session.call.return_value = {
        "result": {"content": [{"text": text}], "isError": is_error}
    }
    return session


def _echoing_session(template: str, *, is_error: bool):
    """A server that quotes back whatever arguments it was sent.

    The canned-text mock above cannot express the false positive being fixed
    here: it returns one payload's echo to every probe, so later probes see a
    canary that has nothing to do with what they sent. A real server quotes
    the input *it* received, which is what makes the echo subtractable.
    """

    def _call(method, params=None, **_kwargs):
        args = (params or {}).get("arguments") or {}
        sent = " ".join(str(v) for v in args.values())
        return {
            "result": {
                "content": [{"text": template.format(payload=sent)}],
                "isError": is_error,
            }
        }

    session = MagicMock()
    session.call.side_effect = _call
    return session


def _result(tool):
    r = TargetResult(url="http://fixture.example/mcp")
    r.tools = [tool]
    return r


def _sev(result, check):
    return [f.severity for f in result.findings if f.check == check]


class TestInputSanitization:
    def test_canary_quoted_in_a_rejection_is_downgraded(self):
        """The server refuses and quotes the offending input verbatim."""
        r = _result(_tool())
        session = _echoing_session("Invalid command: {payload}", is_error=True)
        check_input_sanitization(session, r, {"error_reflection": "downgrade"})
        assert _sev(r, "input_sanitization"), "expected a finding, downgraded not gone"
        assert all(s == "LOW" for s in _sev(r, "input_sanitization")), r.findings

    def test_canary_in_successful_output_stays_high(self):
        """Execution. The canary came back on its own, not inside our probe."""
        r = _result(_tool())
        session = _session(CANARY, is_error=False)
        check_input_sanitization(session, r, {"error_reflection": "downgrade"})
        assert "HIGH" in _sev(r, "input_sanitization"), r.findings

    def test_keep_policy_reproduces_old_behaviour(self):
        r = _result(_tool())
        session = _echoing_session("Invalid command: {payload}", is_error=True)
        check_input_sanitization(session, r, {"error_reflection": "keep"})
        assert "HIGH" in _sev(r, "input_sanitization"), r.findings

    def test_suppress_policy_emits_nothing(self):
        r = _result(_tool())
        session = _echoing_session("Invalid command: {payload}", is_error=True)
        check_input_sanitization(session, r, {"error_reflection": "suppress"})
        assert _sev(r, "input_sanitization") == []

    def test_an_echo_in_a_successful_response_is_untouched(self):
        """Out of scope. A successful echo is a different question, and
        `tool_response_injection` is the check that asks it."""
        r = _result(_tool())
        session = _echoing_session("You sent: {payload}", is_error=False)
        check_input_sanitization(session, r, {"error_reflection": "downgrade"})
        assert "HIGH" in _sev(r, "input_sanitization"), r.findings


class TestToolResponseInjection:
    def test_reflection_in_an_error_is_downgraded(self):
        r = _result(_tool(param="path"))
        session = _session(f"No such path: {REFLECTION_PAYLOAD}", is_error=True)
        check_tool_response_injection(session, r, {"error_reflection": "downgrade"})
        assert _sev(r, "tool_response_injection"), "expected a finding"
        assert all(s == "LOW" for s in _sev(r, "tool_response_injection")), r.findings

    def test_reflection_in_successful_output_stays_high(self):
        """A genuine injection conduit into the LLM context."""
        r = _result(_tool(param="path"))
        session = _session(f"Here you go: {REFLECTION_PAYLOAD}", is_error=False)
        check_tool_response_injection(session, r, {"error_reflection": "downgrade"})
        assert "HIGH" in _sev(r, "tool_response_injection"), r.findings
