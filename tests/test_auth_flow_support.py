"""Auth flow utility tests for headers/JWT/scope support."""

from __future__ import annotations

import base64
import json

import pytest

from mcpnuke.core.auth import decode_jwt_claims, parse_header_kv_pairs, summarize_jwt_claims
from mcpnuke.core.auth import summarize_introspection, summarize_jwks
from mcpnuke.core.session import _auth_headers, _mcp_headers


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def test_parse_header_kv_pairs() -> None:
    headers = parse_header_kv_pairs(["X-Tenant: blue", "X-Request-ID: abc123"])
    assert headers == {"X-Tenant": "blue", "X-Request-ID": "abc123"}


def test_parse_header_kv_pairs_rejects_bad_format() -> None:
    with pytest.raises(ValueError, match="expected KEY:VALUE"):
        parse_header_kv_pairs(["X-Bad-Header"])


def test_decode_jwt_claims_and_summary() -> None:
    token = ".".join(
        [
            _b64url({"alg": "none", "typ": "JWT"}),
            _b64url(
                {
                    "iss": "https://issuer.example",
                    "sub": "agent-client",
                    "aud": "mcp-api",
                    "scope": "mcp.read mcp.invoke",
                    "exp": 2000000000,
                    "custom": "ignore-me",
                }
            ),
            "",
        ]
    )
    claims = decode_jwt_claims(token)
    assert claims is not None
    summary = summarize_jwt_claims(claims)
    assert summary["iss"] == "https://issuer.example"
    assert summary["aud"] == "mcp-api"
    assert summary["scope"] == "mcp.read mcp.invoke"
    assert "custom" not in summary


def test_decode_jwt_claims_invalid_token_returns_none() -> None:
    assert decode_jwt_claims("not-a-jwt") is None


def test_headers_merge_with_custom_values() -> None:
    extra = {"X-Tenant": "blue"}
    h1 = _auth_headers("tok123", extra)
    h2 = _mcp_headers("tok123", extra)
    assert h1["Authorization"] == "Bearer tok123"
    assert h2["Authorization"] == "Bearer tok123"
    assert h1["X-Tenant"] == "blue"
    assert h2["X-Tenant"] == "blue"


def test_summarize_introspection_keeps_core_fields() -> None:
    summary = summarize_introspection(
        {
            "active": True,
            "scope": "mcp.read mcp.invoke",
            "client_id": "scanner",
            "sub": "agent",
            "custom": "drop-me",
        }
    )
    assert summary["active"] is True
    assert summary["scope"] == "mcp.read mcp.invoke"
    assert summary["client_id"] == "scanner"
    assert "custom" not in summary


def test_summarize_jwks_counts_keys_and_metadata() -> None:
    summary = summarize_jwks(
        {
            "keys": [
                {"kid": "k1", "kty": "RSA", "alg": "RS256"},
                {"kid": "k2", "kty": "EC", "alg": "ES256"},
            ]
        }
    )
    assert summary["key_count"] == 2
    assert summary["kids"] == ["k1", "k2"]
    assert summary["kty"] == ["EC", "RSA"]
