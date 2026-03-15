"""Tests for credential_in_schema check."""

import pytest
from mcpredator.core.models import TargetResult
from mcpredator.checks.credential_in_schema import check_credential_in_schema


def _make(tools):
    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = tools
    return r


def test_openai_key_in_default():
    r = _make([{
        "name": "ai_query",
        "description": "Query AI",
        "inputSchema": {"properties": {"api_key": {"type": "string", "default": "sk-abc123def456ghi789jkl012mno345pqr678"}}},
    }])
    check_credential_in_schema(r)
    assert any(f.check == "credential_in_schema" for f in r.findings)
    assert any(f.severity == "CRITICAL" for f in r.findings)


def test_aws_key_in_description():
    r = _make([{
        "name": "s3_upload",
        "description": "Upload to S3 with AKIAIOSFODNN7EXAMPLE",
        "inputSchema": {"properties": {}},
    }])
    check_credential_in_schema(r)
    assert any(f.check == "credential_in_schema" for f in r.findings)


def test_jwt_in_enum():
    r = _make([{
        "name": "auth",
        "description": "Auth",
        "inputSchema": {"properties": {"token": {"type": "string", "enum": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"]}}},
    }])
    check_credential_in_schema(r)
    assert any(f.check == "credential_in_schema" for f in r.findings)


def test_connection_string_in_schema():
    r = _make([{
        "name": "db",
        "description": "Connect to postgres://admin:secret@db:5432/app",
        "inputSchema": {"properties": {}},
    }])
    check_credential_in_schema(r)
    assert any(f.check == "credential_in_schema" for f in r.findings)


def test_clean_schema_no_findings():
    r = _make([{
        "name": "calculate",
        "description": "Perform math",
        "inputSchema": {"properties": {"expression": {"type": "string"}}},
    }])
    check_credential_in_schema(r)
    assert not any(f.check == "credential_in_schema" for f in r.findings)


def test_timing_recorded():
    r = _make([{"name": "x", "description": "y", "inputSchema": {"properties": {}}}])
    check_credential_in_schema(r)
    assert "credential_in_schema" in r.timings
