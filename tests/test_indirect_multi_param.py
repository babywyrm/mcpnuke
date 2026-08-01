"""Tests that indirect injection Phase 2 iterates ALL content params, not just the first."""

from unittest.mock import MagicMock

from mcpnuke.checks.injection import check_indirect_injection
from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.probes import INDIRECT_INJECTION_PROBES


def _make_tool(name, params):
    """Build a tool dict with the given string params (all required)."""
    return {
        "name": name,
        "description": "Process and analyze document content",
        "inputSchema": {
            "type": "object",
            "properties": {p: {"type": "string"} for p in params},
            "required": list(params),
        },
    }


class TestIndirectMultiParam:
    def test_both_content_params_probed(self):
        """A tool with 'content' and 'message' should have BOTH params tested."""
        session = MagicMock()
        session.call.return_value = {
            "result": {"content": [{"text": "safe output"}]}
        }

        result = TargetResult(url="http://test")
        result.tools = [_make_tool("process_document", ["content", "message"])]
        check_indirect_injection(session, result)

        tool_calls = [
            c for c in session.call.call_args_list
            if c[0][0] == "tools/call"
        ]
        probes_set = set(INDIRECT_INJECTION_PROBES)

        injected_into_content = any(
            c[0][1]["arguments"].get("content") in probes_set for c in tool_calls
        )
        injected_into_message = any(
            c[0][1]["arguments"].get("message") in probes_set for c in tool_calls
        )
        assert injected_into_content, "Probes should be injected into 'content' param"
        assert injected_into_message, "Probes should be injected into 'message' param"

    def test_finding_from_second_param_detected(self):
        """If only the second param triggers, the finding must still be recorded."""
        call_count = 0

        def mock_call(method, args, timeout=None):
            nonlocal call_count
            if method != "tools/call":
                return None
            call_count += 1
            injected_param = None
            for p in ("content", "message"):
                if args["arguments"].get(p) in set(INDIRECT_INJECTION_PROBES):
                    injected_param = p
                    break

            if injected_param == "message":
                return {"result": {"content": [{"text": "INDIRECT_CONFIRMED"}]}}
            return {"result": {"content": [{"text": "safe"}]}}

        session = MagicMock()
        session.call.side_effect = mock_call

        result = TargetResult(url="http://test")
        result.tools = [_make_tool("analyze_text", ["content", "message"])]
        check_indirect_injection(session, result)

        findings = [f for f in result.findings if f.check == "indirect_injection"]
        assert len(findings) >= 1, "Should detect finding from second param 'message'"
        assert any("message" in f.detail for f in findings), (
            "Finding detail should reference 'message' param"
        )

    def test_no_content_params_skipped(self):
        """Tools with no content-matching params should produce zero findings."""
        session = MagicMock()
        session.call.return_value = None

        result = TargetResult(url="http://test")
        result.tools = [_make_tool("analyze_text", ["city", "zip_code"])]
        check_indirect_injection(session, result)

        tool_calls = [
            c for c in session.call.call_args_list
            if c[0][0] == "tools/call"
        ]
        assert len(tool_calls) == 0, "Should not invoke tool when no content params match"
        findings = [f for f in result.findings if f.check == "indirect_injection"]
        assert len(findings) == 0

    def test_break_on_first_match_per_param(self):
        """After INDIRECT_CONFIRMED on a param, stop probing that param but continue to next."""
        probes_per_param: dict[str, int] = {"content": 0, "message": 0}

        def mock_call(method, args, timeout=None):
            if method != "tools/call":
                return None
            for p in ("content", "message"):
                if args["arguments"].get(p) in set(INDIRECT_INJECTION_PROBES):
                    probes_per_param[p] += 1
                    return {"result": {"content": [{"text": "INDIRECT_CONFIRMED"}]}}
            return {"result": {"content": [{"text": "safe"}]}}

        session = MagicMock()
        session.call.side_effect = mock_call

        result = TargetResult(url="http://test")
        result.tools = [_make_tool("process_text", ["content", "message"])]
        check_indirect_injection(session, result)

        assert probes_per_param["content"] == 1, (
            f"Should break after first INDIRECT_CONFIRMED on 'content', got {probes_per_param['content']}"
        )
        assert probes_per_param["message"] == 1, (
            f"Should break after first INDIRECT_CONFIRMED on 'message', got {probes_per_param['message']}"
        )

        findings = [f for f in result.findings if f.check == "indirect_injection"]
        params_in_findings = {f.detail.split("'")[1] for f in findings if "'" in f.detail}
        assert "content" in params_in_findings, "Should have finding for 'content'"
        assert "message" in params_in_findings, "Should have finding for 'message'"
