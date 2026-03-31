"""Tests for risk-aware --fast mode that retains input_sanitization for dangerous params."""

from mcpnuke.checks import _has_dangerous_params, FAST_SKIP_CHECKS, _FAST_RETAIN_PARAM_NAMES


def test_dangerous_param_names_exist():
    assert "command" in _FAST_RETAIN_PARAM_NAMES
    assert "exec" in _FAST_RETAIN_PARAM_NAMES
    assert "sql" in _FAST_RETAIN_PARAM_NAMES
    assert "url" in _FAST_RETAIN_PARAM_NAMES


def test_has_dangerous_params_true():
    tools = [{
        "name": "run_cmd",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
        },
    }]
    assert _has_dangerous_params(tools) is True


def test_has_dangerous_params_false():
    tools = [{
        "name": "get_weather",
        "inputSchema": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
        },
    }]
    assert _has_dangerous_params(tools) is False


def test_has_dangerous_params_empty():
    assert _has_dangerous_params([]) is False


def test_has_dangerous_params_no_schema():
    tools = [{"name": "simple_tool"}]
    assert _has_dangerous_params(tools) is False


def test_input_sanitization_in_default_skip():
    assert "input_sanitization" in FAST_SKIP_CHECKS


def test_dangerous_params_multiple_tools():
    tools = [
        {
            "name": "safe_tool",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
            },
        },
        {
            "name": "db_tool",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
            },
        },
    ]
    assert _has_dangerous_params(tools) is True
