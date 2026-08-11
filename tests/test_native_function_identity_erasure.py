"""Tests for check_native_function_identity_erasure (MCP-T35).

Written when the check was made transport-aware. It had none before, so the
first four characterise the behaviour being preserved.
"""

from __future__ import annotations

from mcpnuke.checks.taxonomy_coverage import check_native_function_identity_erasure
from mcpnuke.core.models import TargetResult

_TOOLS = [{"name": "read_file", "description": "Read a file"}]


def _result(transport: str, *, token: str | None = None, tools=None) -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.transport = transport
    r.tools = list(_TOOLS if tools is None else tools)
    if token:
        r.auth_context["_raw_token"] = token
    return r


def _findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "native_function_identity_erasure"]


def test_reports_erased_identity_over_http():
    """The real finding: a networked server whose tool calls carry no
    attribution to any caller."""
    r = _result("http")
    check_native_function_identity_erasure(r)
    findings = _findings(r)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_silent_when_a_credential_is_present():
    r = _result("http", token="secret-value")
    check_native_function_identity_erasure(r)
    assert _findings(r) == []


def test_silent_when_a_tool_takes_an_identity_parameter():
    r = _result("http", tools=[{
        "name": "read_file",
        "inputSchema": {"properties": {"caller_id": {"type": "string"}}},
    }])
    check_native_function_identity_erasure(r)
    assert _findings(r) == []


def test_silent_on_stdio():
    """stdio has exactly one caller, and it is the process that spawned the
    server.

    The server runs as the user who launched it and inherits their
    privileges, so there is no ambiguity about who a tool call belongs to.
    A caller_id parameter would be self-asserted by that same client, which
    is worthless as attribution — the finding's premise and its remedy are
    both empty here. It fired on all five pinned open-source servers.
    """
    r = _result("stdio")
    check_native_function_identity_erasure(r)
    assert _findings(r) == []


def test_timing_recorded():
    r = _result("http")
    check_native_function_identity_erasure(r)
    assert "native_function_identity_erasure" in r.timings
