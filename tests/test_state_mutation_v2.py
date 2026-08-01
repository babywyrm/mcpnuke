"""Tests for enhanced state mutation detection with write-then-read probes."""

from unittest.mock import MagicMock

from mcpnuke.checks.behavioral import (
    _STATE_CANARY,
    _classify_tool,
    check_state_mutation,
)
from mcpnuke.core.models import TargetResult


class TestClassifyTool:
    def test_write_tools(self):
        assert _classify_tool({"name": "relay.store_context"}) == "write"
        assert _classify_tool({"name": "tenant.store_memory"}) == "write"
        assert _classify_tool({"name": "shadow.register_webhook"}) == "write"
        assert _classify_tool({"name": "config.update_system_prompt"}) == "write"

    def test_read_tools(self):
        assert _classify_tool({"name": "tenant.recall_memory"}) == "read"
        assert _classify_tool({"name": "audit.list_actions"}) == "read"
        assert _classify_tool({"name": "comms.list_sent"}) == "read"
        assert _classify_tool({"name": "shadow.list_webhooks"}) == "read"

    def test_unclassified(self):
        assert _classify_tool({"name": "tool.hidden_exec"}) is None
        assert _classify_tool({"name": "hallucination.execute_plan"}) is None

    def test_description_fallback(self):
        t = {"name": "foo.bar", "description": "Store user preferences"}
        assert _classify_tool(t) == "write"


class TestWriteThenReadProbe:
    def _make_tools(self):
        return [
            {"name": "relay.store_context", "inputSchema": {
                "properties": {"data": {"type": "string"}},
            }},
            {"name": "comms.list_sent", "inputSchema": {
                "properties": {},
            }},
        ]

    def test_detects_canary_leak(self):
        session = MagicMock()
        tools = self._make_tools()

        def call_handler(method, params=None, timeout=None):
            if method == "tools/call":
                name = params.get("name", "")
                if name == "comms.list_sent":
                    return {"result": {"content": [
                        {"type": "text", "text": f"messages: [{_STATE_CANARY}]"}
                    ]}}
                return {"result": {"content": [{"type": "text", "text": "ok"}]}}
            return None

        session.call.side_effect = call_handler

        r = TargetResult(url="http://test")
        r.tools = tools
        check_state_mutation(session, r)

        findings = [f for f in r.findings if f.check == "state_mutation"]
        assert len(findings) >= 1
        assert "relay.store_context" in findings[0].title
        assert "comms.list_sent" in findings[0].title

    def test_no_finding_when_canary_absent(self):
        session = MagicMock()
        tools = self._make_tools()
        session.call.return_value = {
            "result": {"content": [{"type": "text", "text": "nothing here"}]}
        }

        r = TargetResult(url="http://test")
        r.tools = tools
        check_state_mutation(session, r)

        findings = [f for f in r.findings if f.check == "state_mutation"]
        assert len(findings) == 0

    def test_skips_when_no_readers(self):
        session = MagicMock()
        r = TargetResult(url="http://test")
        r.tools = [
            {"name": "relay.store_context", "inputSchema": {"properties": {"data": {"type": "string"}}}},
            {"name": "tool.hidden_exec", "inputSchema": {"properties": {}}},
        ]
        check_state_mutation(session, r)
        findings = [f for f in r.findings if f.check == "state_mutation"]
        assert len(findings) == 0

    def test_skips_when_no_writers(self):
        session = MagicMock()
        r = TargetResult(url="http://test")
        r.tools = [
            {"name": "comms.list_sent", "inputSchema": {"properties": {}}},
            {"name": "audit.list_actions", "inputSchema": {"properties": {}}},
        ]
        check_state_mutation(session, r)
        findings = [f for f in r.findings if f.check == "state_mutation"]
        assert len(findings) == 0
