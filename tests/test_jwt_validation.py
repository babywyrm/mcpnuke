"""Tests for JWT hardening checks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from mcpnuke.core.models import TargetResult
from mcpnuke.core.auth import decode_jwt_header
from mcpnuke.checks.jwt_validation import (
    check_jwt_algorithm,
    check_jwt_audience,
    check_jwt_issuer,
    check_jwt_token_id,
    check_jwt_ttl,
    check_jwt_weak_key,
)


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _make_token(header: dict, claims: dict, key: str = "") -> str:
    h = _b64url(header)
    p = _b64url(claims)
    if header.get("alg", "none") == "none":
        return f"{h}.{p}."
    signing_input = f"{h}.{p}".encode("utf-8")
    alg_map = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
    hash_name = alg_map.get(header["alg"], "sha256")
    sig = hmac.new(key.encode("utf-8"), signing_input, hash_name).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    return f"{h}.{p}.{sig_b64}"


def _result_with_token(token: str, claims_summary: dict | None = None) -> TargetResult:
    r = TargetResult(url="http://test:9090")
    r.auth_context["_raw_token"] = token
    if claims_summary:
        r.auth_context["jwt_claims_summary"] = claims_summary
    return r


# --- decode_jwt_header ---

class TestDecodeJwtHeader:
    def test_decodes_valid_header(self):
        token = _make_token({"alg": "RS256", "typ": "JWT"}, {"sub": "test"})
        header = decode_jwt_header(token)
        assert header is not None
        assert header["alg"] == "RS256"

    def test_returns_none_for_invalid(self):
        assert decode_jwt_header("not-a-jwt") is None

    def test_returns_none_for_non_dict(self):
        raw = base64.urlsafe_b64encode(b'"just a string"').decode().rstrip("=")
        assert decode_jwt_header(f"{raw}.payload.sig") is None


# --- check_jwt_algorithm ---

class TestJwtAlgorithm:
    def test_flags_alg_none_as_critical(self):
        token = _make_token({"alg": "none", "typ": "JWT"}, {"sub": "x"})
        r = _result_with_token(token)
        check_jwt_algorithm(r)
        findings = [f for f in r.findings if f.check == "jwt_algorithm"]
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_flags_hs256_as_high(self):
        token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "x"}, key="secret")
        r = _result_with_token(token)
        check_jwt_algorithm(r)
        findings = [f for f in r.findings if f.check == "jwt_algorithm"]
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"

    def test_clean_rs256_no_finding(self):
        token = _make_token({"alg": "RS256", "typ": "JWT"}, {"sub": "x"})
        r = _result_with_token(token)
        check_jwt_algorithm(r)
        assert not any(f.check == "jwt_algorithm" for f in r.findings)

    def test_no_token_no_finding(self):
        r = TargetResult(url="http://test:9090")
        check_jwt_algorithm(r)
        assert not r.findings

    def test_timing_recorded(self):
        token = _make_token({"alg": "RS256"}, {"sub": "x"})
        r = _result_with_token(token)
        check_jwt_algorithm(r)
        assert "jwt_algorithm" in r.timings


# --- check_jwt_issuer ---

class TestJwtIssuer:
    def test_flags_missing_iss(self):
        token = _make_token({"alg": "none"}, {"sub": "x"})
        r = _result_with_token(token, {"sub": "x"})
        check_jwt_issuer(r)
        findings = [f for f in r.findings if f.check == "jwt_issuer"]
        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"

    def test_clean_with_iss(self):
        r = _result_with_token("dummy", {"iss": "https://auth.example.com", "sub": "x"})
        check_jwt_issuer(r)
        assert not any(f.check == "jwt_issuer" for f in r.findings)

    def test_timing_recorded(self):
        r = _result_with_token("dummy", {"sub": "x"})
        check_jwt_issuer(r)
        assert "jwt_issuer" in r.timings


# --- check_jwt_audience ---

class TestJwtAudience:
    def test_flags_missing_aud(self):
        r = _result_with_token("dummy", {"iss": "x", "sub": "y"})
        check_jwt_audience(r)
        findings = [f for f in r.findings if f.check == "jwt_audience"]
        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"

    def test_clean_with_aud(self):
        r = _result_with_token("dummy", {"iss": "x", "aud": "mcp-api"})
        check_jwt_audience(r)
        assert not any(f.check == "jwt_audience" for f in r.findings)

    def test_timing_recorded(self):
        r = _result_with_token("dummy", {"sub": "x"})
        check_jwt_audience(r)
        assert "jwt_audience" in r.timings


# --- check_jwt_token_id ---

class TestJwtTokenId:
    def test_flags_missing_jti(self):
        r = _result_with_token("dummy", {"sub": "x"})
        check_jwt_token_id(r)
        findings = [f for f in r.findings if f.check == "jwt_token_id"]
        assert len(findings) == 1
        assert findings[0].severity == "LOW"

    def test_clean_with_jti(self):
        r = _result_with_token("dummy", {"jti": "abc-123"})
        check_jwt_token_id(r)
        assert not any(f.check == "jwt_token_id" for f in r.findings)

    def test_timing_recorded(self):
        r = _result_with_token("dummy", {"sub": "x"})
        check_jwt_token_id(r)
        assert "jwt_token_id" in r.timings


# --- check_jwt_ttl ---

class TestJwtTtl:
    def test_flags_excessive_ttl(self):
        now = int(time.time())
        r = _result_with_token("dummy", {"iat": now, "exp": now + 86400})
        check_jwt_ttl(r, probe_opts={"jwt_max_ttl": 14400})
        findings = [f for f in r.findings if f.check == "jwt_ttl"]
        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"

    def test_acceptable_ttl_no_finding(self):
        now = int(time.time())
        r = _result_with_token("dummy", {"iat": now, "exp": now + 3600})
        check_jwt_ttl(r, probe_opts={"jwt_max_ttl": 14400})
        assert not any(f.check == "jwt_ttl" for f in r.findings)

    def test_missing_exp_flagged_high(self):
        r = _result_with_token("dummy", {"iat": int(time.time())})
        check_jwt_ttl(r)
        findings = [f for f in r.findings if f.check == "jwt_ttl"]
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"

    def test_custom_threshold(self):
        now = int(time.time())
        r = _result_with_token("dummy", {"iat": now, "exp": now + 7200})
        check_jwt_ttl(r, probe_opts={"jwt_max_ttl": 3600})
        assert any(f.check == "jwt_ttl" for f in r.findings)

    def test_timing_recorded(self):
        r = _result_with_token("dummy", {"exp": int(time.time()) + 3600})
        check_jwt_ttl(r)
        assert "jwt_ttl" in r.timings


# --- check_jwt_weak_key ---

class TestJwtWeakKey:
    def test_detects_secret_key(self):
        token = _make_token({"alg": "HS256"}, {"sub": "x"}, key="secret")
        r = _result_with_token(token)
        check_jwt_weak_key(r)
        findings = [f for f in r.findings if f.check == "jwt_weak_key"]
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"
        assert "secret" in findings[0].evidence

    def test_detects_empty_key(self):
        token = _make_token({"alg": "HS256"}, {"sub": "x"}, key="")
        r = _result_with_token(token)
        check_jwt_weak_key(r)
        findings = [f for f in r.findings if f.check == "jwt_weak_key"]
        assert len(findings) == 1

    def test_strong_key_no_finding(self):
        token = _make_token({"alg": "HS256"}, {"sub": "x"}, key="v3ry-$tr0ng-r4nd0m-k3y-99!")
        r = _result_with_token(token)
        check_jwt_weak_key(r)
        assert not any(f.check == "jwt_weak_key" for f in r.findings)

    def test_rs256_skipped(self):
        token = _make_token({"alg": "RS256"}, {"sub": "x"})
        r = _result_with_token(token)
        check_jwt_weak_key(r)
        assert not any(f.check == "jwt_weak_key" for f in r.findings)

    def test_no_token_no_finding(self):
        r = TargetResult(url="http://test:9090")
        check_jwt_weak_key(r)
        assert not r.findings

    def test_timing_recorded(self):
        token = _make_token({"alg": "HS256"}, {"sub": "x"}, key="strong-key-xyz")
        r = _result_with_token(token)
        check_jwt_weak_key(r)
        assert "jwt_weak_key" in r.timings
