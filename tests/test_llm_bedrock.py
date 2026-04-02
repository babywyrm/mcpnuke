"""Tests for Bedrock Claude backend wiring in core.llm."""

from __future__ import annotations

from unittest.mock import patch


def test_configure_bedrock_toggle() -> None:
    from mcpnuke.core.llm import configure_bedrock, is_bedrock_enabled

    configure_bedrock(enabled=True, region="us-east-1", profile="default", model="model-id")
    assert is_bedrock_enabled() is True

    configure_bedrock(enabled=False)
    assert is_bedrock_enabled() is False


def test_call_claude_routes_to_bedrock_when_enabled() -> None:
    from mcpnuke.core.llm import _call_claude, configure_bedrock

    configure_bedrock(enabled=True, model="anthropic.claude-3-5-sonnet-20241022-v2:0")
    with patch("mcpnuke.core.llm._call_bedrock_claude", return_value="bedrock-ok") as mock_bedrock:
        text = _call_claude("sys", "user", "claude-sonnet-4-20250514", 100)
    assert text == "bedrock-ok"
    mock_bedrock.assert_called_once()
    configure_bedrock(enabled=False)


def test_call_claude_uses_direct_client_when_bedrock_disabled() -> None:
    from mcpnuke.core.llm import _call_claude, configure_bedrock

    class _Resp:
        class _Usage:
            input_tokens = 1
            output_tokens = 1

        content = [type("Text", (), {"text": "direct-ok"})()]
        usage = _Usage()
        stop_reason = "end_turn"

    configure_bedrock(enabled=False)
    with patch("mcpnuke.core.llm._get_client") as mock_client:
        mock_client.return_value.messages.create.return_value = _Resp()
        text = _call_claude("sys", "user", "claude-sonnet-4-20250514", 100)
    assert text == "direct-ok"
