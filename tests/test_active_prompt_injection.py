"""Tests for active prompt injection check."""

import re
from unittest.mock import MagicMock

from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.probes import (
    ACTIVE_INJECTION_PAYLOADS,
    SYSTEM_PROMPT_INDICATORS,
    CANARY,
)


def test_payloads_have_required_fields():
    for p in ACTIVE_INJECTION_PAYLOADS:
        assert "payload" in p
        assert "category" in p
        assert isinstance(p["payload"], str)


def test_system_prompt_indicators_compile():
    for pat in SYSTEM_PROMPT_INDICATORS:
        re.compile(pat, re.IGNORECASE)


class TestActivePromptInjection:
    def _make_session(self, response_text: str):
        session = MagicMock()
        session.call.return_value = {
            "result": {"content": [{"text": response_text}]}
        }
        return session

    def _make_tool(self, name="test_tool"):
        return {
            "name": name,
            "description": "A test tool",
            "inputSchema": {
                "type": "object",
                "properties": {"input": {"type": "string"}},
                "required": ["input"],
            },
        }

    def test_detects_instruction_following(self):
        from mcpnuke.checks.injection import check_active_prompt_injection

        result = TargetResult(url="http://test")
        result.tools = [self._make_tool()]
        session = self._make_session(f"Sure! INJECTED_{CANARY}")
        check_active_prompt_injection(session, result)
        findings = [f for f in result.findings if f.check == "active_prompt_injection"]
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"

    def test_detects_system_prompt_leak(self):
        from mcpnuke.checks.injection import check_active_prompt_injection

        result = TargetResult(url="http://test")
        result.tools = [self._make_tool()]
        session = self._make_session(
            "You are an AI assistant designed to help users."
        )
        check_active_prompt_injection(session, result)
        findings = [f for f in result.findings if f.check == "active_prompt_injection"]
        assert len(findings) >= 1

    def test_clean_server_no_findings(self):
        from mcpnuke.checks.injection import check_active_prompt_injection

        result = TargetResult(url="http://test")
        result.tools = [self._make_tool()]
        session = self._make_session("I processed your request normally.")
        check_active_prompt_injection(session, result)
        findings = [f for f in result.findings if f.check == "active_prompt_injection"]
        assert len(findings) == 0

    def test_skips_tools_without_string_params(self):
        from mcpnuke.checks.injection import check_active_prompt_injection

        result = TargetResult(url="http://test")
        result.tools = [{
            "name": "numeric_tool",
            "inputSchema": {
                "type": "object",
                "properties": {"count": {"type": "integer"}},
                "required": ["count"],
            },
        }]
        session = MagicMock()
        check_active_prompt_injection(session, result)
        session.call.assert_not_called()

    def test_respects_no_invoke(self):
        from mcpnuke.checks.injection import check_active_prompt_injection

        result = TargetResult(url="http://test")
        result.tools = [self._make_tool()]
        session = MagicMock()
        check_active_prompt_injection(session, result, probe_opts={"no_invoke": True})
        session.call.assert_not_called()
