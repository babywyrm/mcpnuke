"""Tests for the MCP-T04 JWT identity boundary checks."""

from __future__ import annotations

import base64
import json

from mcpnuke.checks.jwt_boundary import (
    check_jwt_audience_target_match,
    check_jwt_cross_role_replay,
)
from mcpnuke.core.models import TargetResult


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _make_unsigned_token(claims: dict) -> str:
    """Build an alg:none token. Signature path is irrelevant for these checks."""
    h = _b64url({"alg": "none", "typ": "JWT"})
    p = _b64url(claims)
    return f"{h}.{p}."


def _result_with_token(url: str, claims: dict) -> TargetResult:
    r = TargetResult(url=url)
    r.auth_context["_raw_token"] = _make_unsigned_token(claims)
    return r


# ── audience target match ─────────────────────────────────────────────────


def test_audience_match_with_url_substring_passes():
    r = _result_with_token(
        "http://<cluster-node>:30080/mcp",
        {"aud": "http://<cluster-node>:30080/mcp", "sub": "u1"},
    )
    check_jwt_audience_target_match(r)
    assert not r.findings, "URL-equality audience must not flag"


def test_audience_match_with_host_only_passes():
    r = _result_with_token(
        "http://<cluster-node>:30080/mcp",
        {"aud": "<cluster-node>", "sub": "u1"},
    )
    check_jwt_audience_target_match(r)
    assert not r.findings


def test_audience_match_with_array_form_passes():
    r = _result_with_token(
        "http://<cluster-node>:30080/mcp",
        {"aud": ["other-svc", "<cluster-node>:30080"], "sub": "u1"},
    )
    check_jwt_audience_target_match(r)
    assert not r.findings


def test_audience_mismatch_fires_high_finding():
    r = _result_with_token(
        "http://<cluster-node>:30080/mcp",
        {"aud": "api://billing-service", "sub": "u1"},
    )
    check_jwt_audience_target_match(r)
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.check == "jwt_audience_target_match"
    assert f.severity == "HIGH"
    assert f.lane == 1
    assert f.transport == "A"
    assert "MCP-T04" in f.detail


def test_audience_missing_does_not_double_report():
    """check_jwt_audience already covers the missing-aud case."""
    r = _result_with_token(
        "http://<cluster-node>:30080/mcp",
        {"sub": "u1"},
    )
    check_jwt_audience_target_match(r)
    assert not r.findings


def test_audience_match_no_token_skips_silently():
    r = TargetResult(url="http://<cluster-node>:30080/mcp")
    check_jwt_audience_target_match(r)
    assert not r.findings


def test_uses_summary_claims_when_raw_token_absent():
    r = TargetResult(url="http://<cluster-node>:30080/mcp")
    r.auth_context["jwt_claims_summary"] = {"aud": "wrong-aud", "sub": "u1"}
    check_jwt_audience_target_match(r)
    assert len(r.findings) == 1
    assert r.findings[0].check == "jwt_audience_target_match"


# ── cross-role replay ─────────────────────────────────────────────────────


def test_read_only_scope_with_write_tools_fires():
    r = _result_with_token(
        "http://example/mcp",
        {"sub": "u1", "scope": "read"},
    )
    r.tools = [
        {"name": "list_users", "description": "List users"},
        {"name": "delete_user", "description": "Delete a user"},
    ]
    check_jwt_cross_role_replay(r)
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.check == "jwt_cross_role_replay"
    assert f.severity == "HIGH"
    assert f.lane == 1
    assert "delete_user" in f.evidence


def test_read_only_with_only_safe_tools_does_not_fire():
    r = _result_with_token(
        "http://example/mcp",
        {"sub": "u1", "scope": "read"},
    )
    r.tools = [
        {"name": "list_users", "description": "List users"},
        {"name": "search_logs", "description": "Search audit logs"},
    ]
    check_jwt_cross_role_replay(r)
    assert not r.findings


def test_admin_scope_does_not_fire():
    r = _result_with_token(
        "http://example/mcp",
        {"sub": "u1", "scope": "read write admin"},
    )
    r.tools = [{"name": "delete_user"}]
    check_jwt_cross_role_replay(r)
    assert not r.findings


def test_role_string_viewer_with_write_tools_fires():
    r = _result_with_token(
        "http://example/mcp",
        {"sub": "u1", "role": "viewer"},
    )
    r.tools = [{"name": "create_widget"}, {"name": "list_widgets"}]
    check_jwt_cross_role_replay(r)
    assert len(r.findings) == 1


def test_roles_array_all_read_with_write_tools_fires():
    r = _result_with_token(
        "http://example/mcp",
        {"sub": "u1", "roles": ["read", "viewer"]},
    )
    r.tools = [{"name": "exec_command"}]
    check_jwt_cross_role_replay(r)
    assert len(r.findings) == 1


def test_roles_array_with_admin_does_not_fire():
    r = _result_with_token(
        "http://example/mcp",
        {"sub": "u1", "roles": ["read", "admin"]},
    )
    r.tools = [{"name": "delete_widget"}]
    check_jwt_cross_role_replay(r)
    assert not r.findings


def test_cross_role_replay_no_token_skips_silently():
    r = TargetResult(url="http://example/mcp")
    r.tools = [{"name": "delete_widget"}]
    check_jwt_cross_role_replay(r)
    assert not r.findings


def test_no_tools_skips_silently():
    r = _result_with_token("http://example/mcp", {"sub": "u1", "scope": "read"})
    check_jwt_cross_role_replay(r)
    assert not r.findings


def test_evidence_truncates_after_five_tools():
    r = _result_with_token("http://example/mcp", {"sub": "u1", "scope": "read"})
    r.tools = [{"name": f"delete_{i}"} for i in range(8)]
    check_jwt_cross_role_replay(r)
    assert len(r.findings) == 1
    assert "+3 more" in r.findings[0].evidence
