"""Tests for Teleport lab exploit chain checks."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.teleport_labs import (
    check_teleport_lab_bot_theft,
    check_teleport_lab_role_escalation,
    check_teleport_lab_cert_replay,
)


def _make_result_with_tools(tool_names: list[str]) -> TargetResult:
    result = TargetResult(url="http://test:8080/mcp")
    result.tools = [{"name": n, "inputSchema": {"type": "object", "properties": {}}} for n in tool_names]
    return result


def _mock_session(responses: dict[str, dict]):
    """Create a mock session that returns predefined tool call responses."""
    session = MagicMock()

    def call(method: str, params: dict, **kwargs):
        if method != "tools/call":
            return None
        tool_name = params.get("name", "")
        resp_data = responses.get(tool_name, {})
        return {
            "result": {
                "content": [{"type": "text", "text": json.dumps(resp_data)}]
            }
        }

    session.call = call
    return session


class TestBotTheftSkips:
    def test_skips_no_invoke(self):
        result = _make_result_with_tools(["bot_identity_theft.read_tbot_secret"])
        check_teleport_lab_bot_theft(None, result, {"no_invoke": True})
        assert len(result.findings) == 0

    def test_skips_no_tools(self):
        result = _make_result_with_tools(["auth.issue_token"])
        session = _mock_session({})
        check_teleport_lab_bot_theft(session, result)
        assert len(result.findings) == 0


class TestBotTheftChain:
    def test_full_chain_easy(self):
        result = _make_result_with_tools([
            "bot_identity_theft.read_tbot_secret",
            "bot_identity_theft.replay_identity",
            "bot_identity_theft.check_session_binding",
        ])
        session = _mock_session({
            "bot_identity_theft.read_tbot_secret": {
                "accessible": True,
                "cert_serial": "abc123",
                "identity": "bot-agent-bot",
                "roles": ["agent-readonly"],
            },
            "bot_identity_theft.replay_identity": {
                "valid": True,
                "flag": "CZTZ{test}",
            },
            "bot_identity_theft.check_session_binding": {
                "session_binding_check": "MISMATCH",
                "nullfield_action": "DENY (-32001)",
            },
        })
        check_teleport_lab_bot_theft(session, result)
        assert len(result.findings) == 3
        severities = [f.severity for f in result.findings]
        assert "HIGH" in severities
        assert "CRITICAL" in severities
        assert "INFO" in severities

    def test_secret_not_accessible(self):
        result = _make_result_with_tools(["bot_identity_theft.read_tbot_secret"])
        session = _mock_session({
            "bot_identity_theft.read_tbot_secret": {
                "accessible": False,
                "error": "forbidden",
            },
        })
        check_teleport_lab_bot_theft(session, result)
        assert len(result.findings) == 1
        assert result.findings[0].severity == "INFO"
        assert "not accessible" in result.findings[0].title


class TestRoleEscalationSkips:
    def test_skips_no_invoke(self):
        result = _make_result_with_tools(["teleport_role_escalation.get_current_roles"])
        check_teleport_lab_role_escalation(None, result, {"no_invoke": True})
        assert len(result.findings) == 0

    def test_skips_no_tools(self):
        result = _make_result_with_tools(["auth.issue_token"])
        session = _mock_session({})
        check_teleport_lab_role_escalation(session, result)
        assert len(result.findings) == 0


class TestRoleEscalationChain:
    def test_escalation_succeeds(self):
        result = _make_result_with_tools([
            "teleport_role_escalation.get_current_roles",
            "teleport_role_escalation.request_role",
            "teleport_role_escalation.privileged_operation",
        ])
        session = _mock_session({
            "teleport_role_escalation.get_current_roles": {
                "roles": ["agent-readonly"],
            },
            "teleport_role_escalation.request_role": {
                "approved": True,
                "new_roles": ["agent-readonly", "agent-ops"],
                "flag": "CZTZ{esc}",
            },
            "teleport_role_escalation.privileged_operation": {
                "status": "executed",
                "operation": "restart",
                "target": "brain-gateway",
                "flag": "CZTZ{priv}",
            },
        })
        check_teleport_lab_role_escalation(session, result)
        assert len(result.findings) == 2
        assert all(f.severity == "CRITICAL" for f in result.findings)

    def test_escalation_held(self):
        result = _make_result_with_tools([
            "teleport_role_escalation.get_current_roles",
            "teleport_role_escalation.request_role",
        ])
        session = _mock_session({
            "teleport_role_escalation.get_current_roles": {
                "roles": ["agent-readonly"],
            },
            "teleport_role_escalation.request_role": {
                "approved": False,
                "_held": True,
                "_nullfield_action": "HOLD",
            },
        })
        check_teleport_lab_role_escalation(session, result)
        assert len(result.findings) == 1
        assert result.findings[0].severity == "INFO"
        assert "HOLD" in result.findings[0].title


class TestCertReplaySkips:
    def test_skips_no_invoke(self):
        result = _make_result_with_tools(["cert_replay.get_expired_cert"])
        check_teleport_lab_cert_replay(None, result, {"no_invoke": True})
        assert len(result.findings) == 0

    def test_skips_no_tools(self):
        result = _make_result_with_tools(["auth.issue_token"])
        session = _mock_session({})
        check_teleport_lab_cert_replay(session, result)
        assert len(result.findings) == 0


class TestCertReplayChain:
    def test_replay_succeeds(self):
        result = _make_result_with_tools([
            "cert_replay.get_expired_cert",
            "cert_replay.replay_cert",
            "cert_replay.check_replay_detection",
        ])
        session = _mock_session({
            "cert_replay.get_expired_cert": {
                "cert_id": "abc-123",
                "not_after": 1000,
                "expired_seconds_ago": 10,
            },
            "cert_replay.replay_cert": {
                "access": "granted",
                "flag": "CZTZ{replay}",
            },
            "cert_replay.check_replay_detection": {
                "previously_seen": True,
                "replay_detection": "BLOCKED",
            },
        })
        check_teleport_lab_cert_replay(session, result)
        assert len(result.findings) == 2
        assert result.findings[0].severity == "CRITICAL"
        assert result.findings[1].severity == "INFO"

    def test_replay_denied(self):
        result = _make_result_with_tools([
            "cert_replay.get_expired_cert",
            "cert_replay.replay_cert",
            "cert_replay.check_replay_detection",
        ])
        session = _mock_session({
            "cert_replay.get_expired_cert": {
                "cert_id": "abc-123",
                "not_after": 1000,
            },
            "cert_replay.replay_cert": {
                "access": "denied",
                "reason": "cert expired",
            },
            "cert_replay.check_replay_detection": {
                "previously_seen": True,
                "replay_detection": "BLOCKED",
            },
        })
        check_teleport_lab_cert_replay(session, result)
        assert len(result.findings) == 2
        assert result.findings[0].severity == "INFO"
        assert "rejected" in result.findings[0].title
