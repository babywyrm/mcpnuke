"""Tests for LLM-augmented probe classification (classify_probe_response)."""

from unittest.mock import patch, MagicMock

from mcpnuke.core.models import TargetResult


def test_classify_probe_response_importable():
    from mcpnuke.core.llm import classify_probe_response
    assert callable(classify_probe_response)


def test_classify_returns_none_for_short_text():
    from mcpnuke.core.llm import classify_probe_response
    result = classify_probe_response("test_tool", "probe", "hi")
    assert result is None


def test_classify_returns_none_for_empty():
    from mcpnuke.core.llm import classify_probe_response
    result = classify_probe_response("test_tool", "probe", "")
    assert result is None


class TestClassifyProbeResponse:
    def test_returns_malicious(self):
        from mcpnuke.core.llm import classify_probe_response

        mock_resp = MagicMock()
        mock_resp.content = [MagicMock(text="malicious")]
        mock_resp.usage = MagicMock(input_tokens=50, output_tokens=1)
        mock_resp.stop_reason = "end_turn"

        with patch("mcpnuke.core.llm._get_client") as mock_client:
            mock_client.return_value.messages.create.return_value = mock_resp
            result = classify_probe_response(
                "evil_tool", "tool_response",
                "This is some suspicious content that needs classification " * 3,
            )
        assert result == "malicious"

    def test_returns_benign(self):
        from mcpnuke.core.llm import classify_probe_response

        mock_resp = MagicMock()
        mock_resp.content = [MagicMock(text="benign")]
        mock_resp.usage = MagicMock(input_tokens=50, output_tokens=1)
        mock_resp.stop_reason = "end_turn"

        with patch("mcpnuke.core.llm._get_client") as mock_client:
            mock_client.return_value.messages.create.return_value = mock_resp
            result = classify_probe_response(
                "safe_tool", "tool_response",
                "Normal output: weather is sunny and 72 degrees in New York" * 2,
            )
        assert result == "benign"

    def test_returns_none_for_unexpected(self):
        from mcpnuke.core.llm import classify_probe_response

        mock_resp = MagicMock()
        mock_resp.content = [MagicMock(text="I'm not sure about this one")]
        mock_resp.usage = MagicMock(input_tokens=50, output_tokens=10)
        mock_resp.stop_reason = "end_turn"

        with patch("mcpnuke.core.llm._get_client") as mock_client:
            mock_client.return_value.messages.create.return_value = mock_resp
            result = classify_probe_response(
                "tool", "probe",
                "ambiguous content that could go either way " * 3,
            )
        assert result is None

    def test_returns_none_on_api_error(self):
        from mcpnuke.core.llm import classify_probe_response

        with patch("mcpnuke.core.llm._get_client") as mock_client:
            mock_client.return_value.messages.create.side_effect = Exception("API error")
            result = classify_probe_response(
                "tool", "probe",
                "some text that would fail classification " * 3,
            )
        assert result is None


class TestLLMAugmentedResponseInjection:
    """Test that tool_response_injection uses classify_probe_response when --claude is active."""

    def test_llm_classification_wired_in(self):
        from mcpnuke.checks.tool_probes import check_tool_response_injection

        session = MagicMock()
        session.call.return_value = {
            "result": {"content": [{"text": "Subtle manipulation that regex would miss " * 5}]}
        }

        result = TargetResult(url="http://test")
        result.tools = [{
            "name": "test_tool",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {"input": {"type": "string"}},
                "required": ["input"],
            },
        }]

        mock_classify = MagicMock(return_value="malicious")
        opts = {"claude": True, "claude_model": "claude-sonnet-4-20250514"}

        with patch("mcpnuke.core.llm.classify_probe_response", mock_classify):
            check_tool_response_injection(session, result, probe_opts=opts)

        ai_findings = [f for f in result.findings if "[AI]" in f.title]
        assert len(ai_findings) >= 1
        assert ai_findings[0].severity == "HIGH"

    def test_no_llm_without_claude_flag(self):
        from mcpnuke.checks.tool_probes import check_tool_response_injection

        session = MagicMock()
        session.call.return_value = {
            "result": {"content": [{"text": "Clean benign response without threats " * 5}]}
        }

        result = TargetResult(url="http://test")
        result.tools = [{
            "name": "test_tool",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {"input": {"type": "string"}},
                "required": ["input"],
            },
        }]

        with patch("mcpnuke.core.llm.classify_probe_response") as mock_classify:
            check_tool_response_injection(session, result, probe_opts={})
            mock_classify.assert_not_called()
