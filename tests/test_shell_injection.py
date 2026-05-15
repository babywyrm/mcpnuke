"""Tests for Transport D shell injection probes."""

from unittest.mock import MagicMock

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.shell_injection import (
    check_shell_injection,
    _is_shell_tool,
    _find_injectable_params,
    _INJECTION_PAYLOADS,
)


def _make_session(response_text: str):
    session = MagicMock()
    session.call.return_value = {
        "result": {"content": [{"text": response_text}]}
    }
    return session


def _shell_tool(name="shellwrap.exec", params=None):
    if params is None:
        params = {
            "base_cmd": {"type": "string", "description": "Command"},
            "args": {"type": "string", "description": "Arguments"},
        }
    return {
        "name": name,
        "description": "Execute a shell command via subprocess wrapper",
        "inputSchema": {
            "type": "object",
            "required": ["base_cmd"],
            "properties": params,
        },
    }


def _safe_tool():
    return {
        "name": "weather.get",
        "description": "Get the weather forecast",
        "inputSchema": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    }


class TestShellToolDetection:
    def test_identifies_shell_tool(self):
        assert _is_shell_tool(_shell_tool()) is True

    def test_rejects_safe_tool(self):
        assert _is_shell_tool(_safe_tool()) is False

    def test_identifies_subprocess_tool(self):
        tool = _shell_tool(name="subprocess.invoke_worker")
        assert _is_shell_tool(tool) is True

    def test_identifies_exec_in_description(self):
        tool = {"name": "do_thing", "description": "Execute a shell command"}
        assert _is_shell_tool(tool) is True


class TestInjectableParams:
    def test_finds_args_and_base_cmd(self):
        params = _find_injectable_params(_shell_tool())
        assert "base_cmd" in params
        assert "args" in params

    def test_no_injectable_in_safe_tool(self):
        params = _find_injectable_params(_safe_tool())
        assert len(params) == 0

    def test_finds_command_param(self):
        tool = _shell_tool(params={
            "command": {"type": "string"},
            "verbose": {"type": "boolean"},
        })
        params = _find_injectable_params(tool)
        assert "command" in params
        assert "verbose" not in params


class TestShellInjectionCheck:
    def test_detects_semicolon_injection(self):
        result = TargetResult(url="http://test")
        result.tools = [_shell_tool()]
        session = _make_session("output\nMCPNUKE_SHELL_INJECTED\n")
        check_shell_injection(session, result)
        findings = [f for f in result.findings if f.check == "shell_injection"]
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"
        assert findings[0].lane == 3
        assert findings[0].transport == "D"

    def test_detects_subshell_injection(self):
        result = TargetResult(url="http://test")
        result.tools = [_shell_tool()]
        response = "echo MCPNUKE_SUBSHELL_INJECTED"
        session = _make_session(response)
        check_shell_injection(session, result)
        findings = [f for f in result.findings if f.check == "shell_injection"]
        assert len(findings) >= 1

    def test_clean_response_no_findings(self):
        result = TargetResult(url="http://test")
        result.tools = [_shell_tool()]
        session = _make_session("hello world")
        check_shell_injection(session, result)
        findings = [f for f in result.findings if f.check == "shell_injection"]
        assert len(findings) == 0

    def test_safe_tool_skipped(self):
        result = TargetResult(url="http://test")
        result.tools = [_safe_tool()]
        session = _make_session("MCPNUKE_SHELL_INJECTED")
        check_shell_injection(session, result)
        findings = [f for f in result.findings if f.check == "shell_injection"]
        assert len(findings) == 0

    def test_detects_dangerous_base_command(self):
        result = TargetResult(url="http://test")
        result.tools = [_shell_tool()]
        session = _make_session("MCPNUKE_SH_EXEC\nuid=501(user) gid=20(staff)")
        check_shell_injection(session, result)
        findings = [f for f in result.findings if f.check == "shell_injection"]
        assert any("Dangerous base command" in f.title for f in findings)

    def test_dangerous_base_not_flagged_if_denied(self):
        result = TargetResult(url="http://test")
        result.tools = [_shell_tool()]
        session = _make_session('{"status": "denied", "reason": "not in allowlist"}')
        check_shell_injection(session, result)
        findings = [
            f for f in result.findings
            if f.check == "shell_injection" and "Dangerous base" in f.title
        ]
        assert len(findings) == 0

    def test_timing_recorded(self):
        result = TargetResult(url="http://test")
        result.tools = [_shell_tool()]
        session = _make_session("ok")
        check_shell_injection(session, result)
        assert "shell_injection" in result.timings

    def test_no_invoke_skips_check(self):
        result = TargetResult(url="http://test")
        result.tools = [_shell_tool()]
        session = _make_session("MCPNUKE_SHELL_INJECTED")
        check_shell_injection(session, result, probe_opts={"no_invoke": True})
        findings = [f for f in result.findings if f.check == "shell_injection"]
        assert len(findings) == 0

    def test_multiple_tools_tested(self):
        result = TargetResult(url="http://test")
        result.tools = [
            _shell_tool(name="shellwrap.exec"),
            _shell_tool(name="subprocess.run_cmd"),
        ]
        session = _make_session("MCPNUKE_SHELL_INJECTED")
        check_shell_injection(session, result)
        findings = [f for f in result.findings if f.check == "shell_injection"]
        assert len(findings) >= 2


class TestPayloadStructure:
    def test_all_payloads_have_required_fields(self):
        for p in _INJECTION_PAYLOADS:
            assert "payload" in p
            assert "indicator" in p
            assert "category" in p

    def test_payloads_contain_metacharacters(self):
        metachar_found = 0
        for p in _INJECTION_PAYLOADS:
            if any(c in p["payload"] for c in ";|&$`()"):
                metachar_found += 1
        assert metachar_found == len(_INJECTION_PAYLOADS)
