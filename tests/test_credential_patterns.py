"""Golden corpus for credential detection.

Credential regexes were defined four times with conflicting patterns, so the
same secret was caught on one code path and missed on another — an Anthropic
key hardcoded in a tool schema was invisible to credential_in_schema, the check
whose entire job is that. This corpus is the anti-drift mechanism: every
consumer of the structural tier must detect exactly the same set.

Two tiers exist because they carry different false-positive risk:

- structural patterns match a secret's shape (``AKIA…``, ``-----BEGIN…``) and
  are safe against any text, including tool schemas
- keyword patterns match ``password: <value>`` and fire on parameter
  *declarations* such as ``"api_key": {"type": "string"}``, so they are only
  applied to response and config bodies
"""

from __future__ import annotations

import json
import re

import pytest

from mcpnuke.patterns.credentials import (
    KEYWORD_CREDENTIALS,
    STRUCTURAL_CREDENTIALS,
    VENDOR_CREDENTIALS,
    compile_patterns,
    find_credential,
)

# ── The corpus ────────────────────────────────────────────────────────
#
# Every entry is a realistic secret with a synthetic value. Keyed by the
# credential type each must be reported as.

STRUCTURAL_POSITIVES: dict[str, str] = {
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "anthropic_api_key": "sk-ant-api03-" + "x" * 24,
    "openai_key": "sk-" + "a" * 32,
    "github_pat": "ghp_" + "b" * 36,
    "github_pat_short": "ghp_" + "b" * 24,
    "github_oauth_token": "gho_" + "c" * 36,
    "github_fine_grained": "github_pat_" + "d" * 22 + "_" + "e" * 20,
    "gitlab_pat": "glpat-" + "f" * 20,
    "gcp_api_key": "AIza" + "g" * 35,
    "slack_token": "xoxb-" + "1" * 12 + "-abcdef",
    "slack_token_o": "xoxo-" + "2" * 12 + "-abcdef",
    "private_key_rsa": "-----BEGIN RSA PRIVATE KEY-----",
    "private_key_ec": "-----BEGIN EC PRIVATE KEY-----",
    "private_key_openssh": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "private_key_plain": "-----BEGIN PRIVATE KEY-----",
    "jwt_two_segment": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9",
    "jwt_three_segment": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2ln",
    "conn_postgres": "postgres://user:hunter2@db:5432/app",
    "conn_postgres_symbols": "postgres://user:p@ss!w0rd@db:5432/app",
    "conn_mongodb": "mongodb://admin:secret123@mongo:27017",
    "conn_amqp": "amqp://guest:guest123@rabbit:5672",
    "bearer_header": "Authorization: bearer " + "z" * 24,
    # Canonical capitalization. Two of the four previous definitions were
    # case-sensitive and lowercase-only, so they missed the common form.
    "bearer_header_capitalized": "Authorization: Bearer " + "z" * 24,
    "bearer_in_prose": "Forwards: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def upstream",
}

# Text that must NOT be reported by the structural tier. Parameter
# declarations and placeholders are the realistic false positives — Camazotz
# alone has three tools whose schemas would trip a keyword pattern.
STRUCTURAL_NEGATIVES: dict[str, str] = {
    "api_key_param_decl": '{"api_key": {"type": "string"}}',
    "password_param_decl": '{"password": {"type": "string", "description": "user password"}}',
    "secret_param_decl": '{"secret": {"type": "string"}}',
    "credential_param_decl": '{"credential": {"type": "string"}}',
    "prose_about_tokens": "Pass your bearer token in the Authorization header.",
    "env_var_name_only": "Set ANTHROPIC_API_KEY before running.",
    "placeholder_openai": "sk-xxxxxxxxxxxx",
    "placeholder_aws": "AKIAEXAMPLE",
    "short_sk_word": "sk-1",
    "plain_url": "postgres://db:5432/app",
    "public_key": "-----BEGIN PUBLIC KEY-----",
    "certificate": "-----BEGIN CERTIFICATE-----",
    "base64_blob": "eyJhbGciOiJIUzI1NiJ9",
    "ghp_prefix_only": "ghp_",
    "word_containing_akia": "MAKIAVELLIAN",
}

KEYWORD_POSITIVES: dict[str, str] = {
    "password_assign": 'password: "hunter2seven"',
    "password_equals": "PASSWORD=s3cr3t-value",
    "api_key_assign": '"api_key": "abc123def456"',
    "rcon_password": 'RCON_PASSWORD="minecraft123"',
    "admin_api_key": 'ADMIN_API_KEY = "adminsecret1"',
}


def _detect(text: str, patterns) -> str | None:
    """Return the credential type detected in *text*, or None."""
    for pat, name in compile_patterns(patterns):
        if pat.search(text):
            return name
    return None


# ── Tier behaviour ────────────────────────────────────────────────────


class TestStructuralTier:
    @pytest.mark.parametrize(
        ("label", "text"), sorted(STRUCTURAL_POSITIVES.items())
    )
    def test_positive_is_detected(self, label: str, text: str):
        assert _detect(text, STRUCTURAL_CREDENTIALS) is not None, (
            f"{label} not detected: {text!r}"
        )

    @pytest.mark.parametrize(
        ("label", "text"), sorted(STRUCTURAL_NEGATIVES.items())
    )
    def test_negative_is_not_detected(self, label: str, text: str):
        hit = _detect(text, STRUCTURAL_CREDENTIALS)
        assert hit is None, f"{label} false-positived as {hit}: {text!r}"

    def test_embedded_in_surrounding_json(self):
        """Secrets are found inside serialized tool definitions, not bare."""
        for label, secret in STRUCTURAL_POSITIVES.items():
            blob = json.dumps({"description": f"use {secret} to authenticate"})
            assert _detect(blob, STRUCTURAL_CREDENTIALS) is not None, label


class TestKeywordTier:
    @pytest.mark.parametrize(("label", "text"), sorted(KEYWORD_POSITIVES.items()))
    def test_positive_is_detected(self, label: str, text: str):
        combined = STRUCTURAL_CREDENTIALS + KEYWORD_CREDENTIALS
        assert _detect(text, combined) is not None, f"{label} not detected"

    def test_keyword_tier_is_kept_out_of_the_structural_tier(self):
        """Parameter declarations are why these two tiers are separate."""
        decl = '{"api_key": {"type": "string"}}'
        assert _detect(decl, STRUCTURAL_CREDENTIALS) is None
        assert _detect(decl, KEYWORD_CREDENTIALS) is not None


class TestVendorTier:
    def test_camazotz_tokens_detected(self):
        assert _detect("cztz-abc123def", VENDOR_CREDENTIALS) is not None
        assert _detect("CZTZ_ADMIN_TOKEN", VENDOR_CREDENTIALS) is not None

    def test_vendor_tokens_are_not_in_the_structural_tier(self):
        """Lab-specific tokens must not leak into generic detection."""
        assert _detect("cztz-abc123def", STRUCTURAL_CREDENTIALS) is None


# ── Every consumer agrees ─────────────────────────────────────────────
#
# This is the test that stops the drift from coming back.


def _consumers():
    """(name, detect_fn) for every check that scans text for credentials."""
    from mcpnuke.checks.credential_in_schema import SCHEMA_CREDENTIAL_PATTERNS
    from mcpnuke.checks.schema_overdisclosure import _CREDENTIAL_PATTERNS
    from mcpnuke.patterns.probes import CREDENTIAL_CONTENT_PATTERNS

    return [
        ("credential_in_schema", SCHEMA_CREDENTIAL_PATTERNS),
        ("schema_overdisclosure", _CREDENTIAL_PATTERNS),
        ("probes.CREDENTIAL_CONTENT", CREDENTIAL_CONTENT_PATTERNS),
    ]


class TestConsumersAgree:
    @pytest.mark.parametrize(
        ("label", "text"), sorted(STRUCTURAL_POSITIVES.items())
    )
    def test_every_consumer_detects_every_structural_positive(
        self, label: str, text: str
    ):
        missed = [
            name for name, pats in _consumers() if _detect(text, pats) is None
        ]
        assert not missed, f"{label} missed by {missed}"

    @pytest.mark.parametrize(
        ("label", "text"), sorted(STRUCTURAL_NEGATIVES.items())
    )
    def test_no_consumer_false_positives_on_a_schema_negative(
        self, label: str, text: str
    ):
        """Only checks that scan tool schemas; body scanners may be looser."""
        schema_scanners = [
            (n, p) for n, p in _consumers() if n != "probes.CREDENTIAL_CONTENT"
        ]
        hits = {
            name: _detect(text, pats)
            for name, pats in schema_scanners
            if _detect(text, pats) is not None
        }
        assert not hits, f"{label} false-positived: {hits}"


# ── Helper contract ───────────────────────────────────────────────────


class TestHelpers:
    def test_compile_patterns_accepts_strings_and_compiled(self):
        out = compile_patterns([(r"abc", "x")])
        assert isinstance(out[0][0], re.Pattern)
        assert out[0][1] == "x"

        pre = re.compile(r"abc")
        assert compile_patterns([(pre, "x")])[0][0] is pre

    def test_compile_patterns_is_cached(self):
        assert compile_patterns(STRUCTURAL_CREDENTIALS) is compile_patterns(
            STRUCTURAL_CREDENTIALS
        )

    def test_find_credential_returns_type_and_match(self):
        hit = find_credential("key AKIAIOSFODNN7EXAMPLE here", STRUCTURAL_CREDENTIALS)
        assert hit is not None
        cred_type, matched = hit
        assert cred_type == "aws_access_key"
        assert matched == "AKIAIOSFODNN7EXAMPLE"

    def test_find_credential_returns_none_when_clean(self):
        assert find_credential("nothing here", STRUCTURAL_CREDENTIALS) is None

    def test_no_duplicate_credential_type_names(self):
        for tier in (STRUCTURAL_CREDENTIALS, KEYWORD_CREDENTIALS, VENDOR_CREDENTIALS):
            names = [n for _, n in tier]
            assert len(names) == len(set(names)), f"duplicates: {names}"

    def test_every_pattern_compiles(self):
        for tier in (STRUCTURAL_CREDENTIALS, KEYWORD_CREDENTIALS, VENDOR_CREDENTIALS):
            compile_patterns(tier)
