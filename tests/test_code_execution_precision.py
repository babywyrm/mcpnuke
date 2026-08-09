"""Parameter-name heuristics for code_execution must not fire on ordinary params.

A `query` on a search tool and a `country_code` on an address tool are the two
commonest parameter names in the wild that the old substring match called
"execution-like". Both are HIGH findings on servers that do nothing of the sort.
"""

from __future__ import annotations

from mcpnuke.checks.execution import check_code_execution
from mcpnuke.core.models import TargetResult


def _result(tools: list[dict]) -> TargetResult:
    r = TargetResult(url="http://fixture.example/mcp")
    r.tools = tools
    return r


def _param_findings(result: TargetResult) -> list:
    return [f for f in result.findings if "execution-like param" in f.title]


def _tool(name: str, description: str, params: list[str]) -> dict:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"properties": {p: {"type": "string"} for p in params}},
    }


class TestUnambiguousParamsStillFire:
    """The true positives this heuristic exists for."""

    def test_command_param(self):
        r = _result([_tool("run_command", "Execute a shell command", ["command"])])
        check_code_execution(r)
        assert _param_findings(r)

    def test_expression_param(self):
        r = _result([_tool("evaluate", "Evaluate a Python expression", ["expression"])])
        check_code_execution(r)
        assert _param_findings(r)

    def test_script_param_with_underscores(self):
        r = _result([_tool("runner", "Run a job", ["shell_script"])])
        check_code_execution(r)
        assert _param_findings(r)


class TestOrdinaryParamsStayQuiet:
    def test_query_on_a_search_tool(self):
        r = _result([
            _tool("docs.search", "Search the documentation and return matches", ["query"])
        ])
        check_code_execution(r)
        assert _param_findings(r) == []

    def test_country_code_on_an_address_tool(self):
        r = _result([_tool("address.format", "Format a postal address", ["country_code"])])
        check_code_execution(r)
        assert _param_findings(r) == []

    def test_zipcode_is_not_code(self):
        r = _result([_tool("address.lookup", "Look up an address", ["zipcode"])])
        check_code_execution(r)
        assert _param_findings(r) == []

    def test_status_code_on_a_webhook_tool(self):
        r = _result([_tool("webhook.log", "Record a delivery result", ["status_code"])])
        check_code_execution(r)
        assert _param_findings(r) == []


class TestContextGatedParams:
    """Ambiguous names fire only when the tool says it executes something."""

    def test_query_fires_on_a_sql_tool(self):
        r = _result([_tool("db.run", "Run a SQL query against the database", ["query"])])
        check_code_execution(r)
        assert _param_findings(r)

    def test_code_fires_on_an_interpreter_tool(self):
        r = _result([_tool("sandbox", "Execute Python code in a sandbox", ["code"])])
        check_code_execution(r)
        assert _param_findings(r)


def test_timing_recorded():
    r = _result([_tool("t", "d", ["query"])])
    check_code_execution(r)
    assert "code_execution" in r.timings
