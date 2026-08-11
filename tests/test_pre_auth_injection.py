"""Tests for check_pre_auth_injection (MCP-T52).

Written when the check was made transport-aware. It had none before that, so
the four tests below characterise the behaviour being preserved as much as
they cover the behaviour being added — modifying an untested check is the
actual hazard in that work.
"""

from __future__ import annotations

from mcpnuke.checks.taxonomy_coverage import check_pre_auth_injection
from mcpnuke.core.models import TargetResult

_TOOLS = [{"name": "read_file", "description": "Read a file"}]


def _result(transport: str, *, token: str | None = None) -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.transport = transport
    r.tools = list(_TOOLS)
    if token:
        r.auth_context["_raw_token"] = token
    return r


def _findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "pre_auth_injection"]


def test_reports_pre_auth_tool_access_over_http():
    """The real finding: a networked server listed its tools with no credential."""
    r = _result("http")
    check_pre_auth_injection(r)
    findings = _findings(r)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "1 tools" in findings[0].title


def test_silent_when_a_credential_was_supplied():
    r = _result("http", token="secret-value")
    check_pre_auth_injection(r)
    assert _findings(r) == []


def test_silent_when_there_are_no_tools():
    """Nothing is reachable pre-auth if nothing is reachable at all."""
    r = _result("http")
    r.tools = []
    check_pre_auth_injection(r)
    assert _findings(r) == []


def test_silent_on_stdio():
    """stdio has no auth boundary for anything to be 'pre'.

    Every stdio server lists its tools without a credential, because the
    transport is a pipe with nowhere to put one. The finding described the
    transport rather than the server, and fired on all five pinned
    open-source targets.
    """
    r = _result("stdio")
    check_pre_auth_injection(r)
    assert _findings(r) == []


def test_timing_recorded():
    r = _result("http")
    check_pre_auth_injection(r)
    assert "pre_auth_injection" in r.timings
