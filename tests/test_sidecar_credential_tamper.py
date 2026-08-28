"""Tests for check_sidecar_credential_tamper (MCP-T23)."""

from __future__ import annotations

from mcpnuke.checks.taxonomy_coverage import check_sidecar_credential_tamper
from mcpnuke.core.models import TargetResult
from tests.reference_target.tools import TOOL_DEFINITIONS


def _result(tools: list[dict]) -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.tools = tools
    return r


def _findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "sidecar_credential_tamper"]


def test_flags_sidecar_secret_write() -> None:
    r = _result([{
        "name": "sidecar.secret_write",
        "description": "Replace the credential broker sidecar's mounted token",
        "inputSchema": {"properties": {"token": {"type": "string"}}},
    }])
    check_sidecar_credential_tamper(r)
    found = _findings(r)
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T23"
    assert found[0].lane == 2


def test_flags_secret_volume_parameter() -> None:
    r = _result([{
        "name": "config.apply",
        "description": "Apply runtime config",
        "inputSchema": {"properties": {"secret_mount": {"type": "string"}}},
    }])
    check_sidecar_credential_tamper(r)
    found = _findings(r)
    assert found
    assert found[0].taxonomy_id == "MCP-T23"


def test_silent_on_hardcoded_schema_secret_without_sidecar() -> None:
    """credential_in_schema (T07) is not T23."""
    r = _result([{
        "name": "db.query",
        "description": "Run a read-only query",
        "inputSchema": {
            "properties": {
                "sql": {"type": "string", "default": "sk-live-example-key"},
            },
        },
    }])
    check_sidecar_credential_tamper(r)
    assert _findings(r) == []


def test_silent_on_clean_tools() -> None:
    r = _result([{"name": "echo", "description": "Echo a string", "inputSchema": {}}])
    check_sidecar_credential_tamper(r)
    assert _findings(r) == []


def test_silent_on_the_reference_target() -> None:
    r = _result(list(TOOL_DEFINITIONS))
    check_sidecar_credential_tamper(r)
    assert _findings(r) == []


def test_timing_recorded() -> None:
    r = _result([{"name": "x", "description": "y", "inputSchema": {}}])
    check_sidecar_credential_tamper(r)
    assert "sidecar_credential_tamper" in r.timings
