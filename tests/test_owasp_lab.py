"""A static scan of the in-repo lab lights every OWASP MCP Top 10 bucket.

The marker is the check that proves the planted signal, not whichever
other finding happened to land in the same bucket.
"""

from __future__ import annotations

import pytest

from mcpnuke.checks import run_all_checks
from mcpnuke.core.enumerator import enumerate_server
from mcpnuke.core.models import TargetResult
from mcpnuke.core.session import detect_transport
from mcpnuke.reporting.owasp import OWASP_MCP_TOP10, build_owasp, print_owasp
from tests.owasp_lab import start_owasp_lab

# Planted signal, one per category. Side findings may share a bucket.
_MARKER: dict[str, str] = {
    "MCP01": "credential_in_schema",
    "MCP02": "delegation_chain_abuse",
    "MCP03": "tool_description_injection",
    "MCP04": "remote_package_execution",
    "MCP05": "code_execution",
    "MCP06": "prompt_injection",
    "MCP07": "auth",
    "MCP08": "insecure_agent_comms",
    "MCP09": "shadow_mcp_server",
    "MCP10": "cross_tenant_memory_leak",
}


@pytest.fixture(scope="module")
def scanned() -> TargetResult:
    server = start_owasp_lab()
    try:
        session = detect_transport(server.url)
        assert session is not None
        result = TargetResult(url=server.url)
        enumerate_server(session, result)
        run_all_checks(session, result, [result], probe_opts={"no_invoke": True})
    finally:
        server.stop()
    return result


def test_each_category_has_its_planted_marker(scanned: TargetResult) -> None:
    assert set(_MARKER) == set(OWASP_MCP_TOP10)
    report = build_owasp([scanned])
    missing: list[str] = []
    for code, check in _MARKER.items():
        names = {item["check"] for item in report["owasp_mcp"][code]["findings"]}
        if check not in names:
            missing.append(f"{code} wanted {check}, saw {sorted(names)}")
    assert missing == []


def test_the_planted_secret_is_the_documented_example(scanned: TargetResult) -> None:
    hits = [
        finding
        for finding in scanned.findings
        if finding.check == "credential_in_schema" and "aws_access_key" in finding.title
    ]
    assert len(hits) == 1
    assert "AKIAIOSFODNN7EXAMPLE" in hits[0].evidence


def test_shadow_evidence_is_the_other_endpoint(scanned: TargetResult) -> None:
    hits = [finding for finding in scanned.findings if finding.check == "shadow_mcp_server"]
    assert len(hits) == 1
    assert hits[0].evidence == "http://127.0.0.1:9/mcp"
    assert scanned.url not in hits[0].evidence


def test_owasp_report_prints_every_category(scanned: TargetResult, capsys: pytest.CaptureFixture[str]) -> None:
    print_owasp([scanned])
    printed = capsys.readouterr().out
    assert "(no findings fired)" not in printed
    for code, name in OWASP_MCP_TOP10.items():
        assert f"{code} — {name}" in printed
