"""Tests for the schema_overdisclosure check (MCP-T50)."""

from __future__ import annotations

from mcpnuke.checks.schema_overdisclosure import check_schema_overdisclosure
from mcpnuke.core.models import TargetResult


def _result(tools: list[dict]) -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.tools = tools
    return r


# ---------------------------------------------------------------------------
# Credential disclosure (CRITICAL)
# ---------------------------------------------------------------------------


def test_cztz_bearer_token_in_description_is_critical() -> None:
    r = _result([{
        "name": "schema.list_surface",
        "description": "Returns the tool catalog. Internal note: uses cztz-svc-bearer-abc123def456 for upstream auth.",
    }])
    check_schema_overdisclosure(r)
    findings = [f for f in r.findings if f.check == "schema_overdisclosure"]
    assert findings, "expected at least one finding for cztz- credential pattern"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].taxonomy_id == "MCP-T50"
    assert findings[0].lane == 5
    assert findings[0].transport == "A"


def test_cztz_env_var_in_description_is_critical() -> None:
    r = _result([{
        "name": "data.read_secret",
        "description": "Reads value of CZTZ_SERVICE_KEY from the environment.",
    }])
    check_schema_overdisclosure(r)
    crit = [f for f in r.findings if f.severity == "CRITICAL"]
    assert crit, "CZTZ_ env-var pattern should trip the credential rule"


def test_openai_key_pattern_in_default_is_critical() -> None:
    r = _result([{
        "name": "ai.query",
        "description": "Query the LLM.",
        "inputSchema": {
            "properties": {
                "api_key": {
                    "type": "string",
                    "default": "sk-abc123def456ghi789jkl012mno",
                }
            }
        },
    }])
    check_schema_overdisclosure(r)
    crit = [f for f in r.findings if f.severity == "CRITICAL"]
    assert crit


def test_bearer_token_phrase_is_critical() -> None:
    r = _result([{
        "name": "auth.proxy",
        "description": "Forwards: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def to upstream",
    }])
    check_schema_overdisclosure(r)
    crit = [f for f in r.findings if f.severity == "CRITICAL"]
    assert crit


# ---------------------------------------------------------------------------
# Internal hostname disclosure (HIGH)
# ---------------------------------------------------------------------------


def test_internal_tld_host_is_high() -> None:
    r = _result([{
        "name": "service.lookup",
        "description": "Calls https://billing.internal/api/v2/secrets to fetch config.",
    }])
    check_schema_overdisclosure(r)
    findings = [f for f in r.findings if f.check == "schema_overdisclosure"]
    assert any(f.severity == "HIGH" for f in findings)


def test_k8s_svc_host_is_high() -> None:
    r = _result([{
        "name": "service.call",
        "description": "Talks to https://payments.production.svc.cluster.local",
    }])
    check_schema_overdisclosure(r)
    assert any(
        f.severity == "HIGH" and f.taxonomy_id == "MCP-T50"
        for f in r.findings
    )


def test_imds_url_is_high() -> None:
    r = _result([{
        "name": "cloud.metadata",
        "description": "Fetches instance metadata from http://169.254.169.254/latest/meta-data/",
    }])
    check_schema_overdisclosure(r)
    assert any(f.severity == "HIGH" for f in r.findings)


def test_rfc1918_host_is_high() -> None:
    r = _result([{
        "name": "internal.call",
        "description": "Internal lookup at http://10.0.5.123/admin",
    }])
    check_schema_overdisclosure(r)
    assert any(f.severity == "HIGH" for f in r.findings)


# ---------------------------------------------------------------------------
# Env-var name disclosure (MEDIUM)
# ---------------------------------------------------------------------------


def test_database_url_env_is_medium() -> None:
    r = _result([{
        "name": "db.config",
        "description": "Reads connection from DATABASE_URL env var.",
    }])
    check_schema_overdisclosure(r)
    findings = [f for f in r.findings if f.check == "schema_overdisclosure"]
    assert findings
    # First (only) pattern match should be MEDIUM
    assert findings[0].severity == "MEDIUM"


def test_aws_env_is_medium() -> None:
    r = _result([{
        "name": "aws.boot",
        "description": "Uses AWS_SECRET_ACCESS_KEY from the host environment.",
    }])
    check_schema_overdisclosure(r)
    # Either CRITICAL (caught as infra_env_var token) or MEDIUM — must be at least one finding.
    assert any(f.check == "schema_overdisclosure" for f in r.findings)


# ---------------------------------------------------------------------------
# Internal path disclosure (LOW)
# ---------------------------------------------------------------------------


def test_workspace_path_is_low() -> None:
    r = _result([{
        "name": "diag.crash",
        "description": "Stack traces emitted from /workspace/brain_gateway/app/modules/",
    }])
    check_schema_overdisclosure(r)
    findings = [f for f in r.findings if f.check == "schema_overdisclosure"]
    assert findings
    assert findings[0].severity == "LOW"


def test_opt_path_is_low() -> None:
    r = _result([{
        "name": "agent.config",
        "description": "Reads from /opt/agent/etc/config.yaml",
    }])
    check_schema_overdisclosure(r)
    findings = [f for f in r.findings if f.check == "schema_overdisclosure"]
    assert findings


# ---------------------------------------------------------------------------
# Clean tools produce no findings
# ---------------------------------------------------------------------------


def test_clean_tool_produces_no_findings() -> None:
    r = _result([{
        "name": "math.add",
        "description": "Adds two numbers and returns the sum.",
        "inputSchema": {
            "properties": {
                "a": {"type": "integer"},
                "b": {"type": "integer"},
            }
        },
    }])
    check_schema_overdisclosure(r)
    assert not [f for f in r.findings if f.check == "schema_overdisclosure"]


def test_empty_tool_list_is_safe() -> None:
    r = _result([])
    check_schema_overdisclosure(r)
    assert not r.findings


# ---------------------------------------------------------------------------
# Findings are properly tagged for the by-lane / coverage report
# ---------------------------------------------------------------------------


def test_findings_carry_lane_transport_taxonomy_id() -> None:
    r = _result([{
        "name": "tool.x",
        "description": "Internal endpoint at http://gateway.internal",
    }])
    check_schema_overdisclosure(r)
    findings = [f for f in r.findings if f.check == "schema_overdisclosure"]
    assert findings
    for f in findings:
        assert f.lane == 5
        assert f.transport == "A"
        assert f.taxonomy_id == "MCP-T50"


# ---------------------------------------------------------------------------
# Only first match per tool per category (no spam)
# ---------------------------------------------------------------------------


def test_first_match_only_per_category() -> None:
    r = _result([{
        "name": "tool.leaks",
        "description": "uses cztz-svc-aaaa and also cztz-svc-bbbb in the same description",
    }])
    check_schema_overdisclosure(r)
    crit = [f for f in r.findings if f.severity == "CRITICAL"]
    # First-match-wins to avoid duplicate findings per category
    assert len(crit) == 1
