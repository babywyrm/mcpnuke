"""Single source of truth for credential detection patterns.

These regexes were previously defined four times — in ``patterns/probes.py``,
``checks/credential_in_schema.py``, ``checks/schema_overdisclosure.py``, and
``checks/actuator_probe.py`` — with patterns that genuinely disagreed. The same
secret was caught on one code path and missed on another: a GitHub PAT shorter
than 36 characters was seen by exactly one of the three, and an Anthropic key
hardcoded in a tool schema was invisible to ``credential_in_schema``, the check
whose entire purpose is finding credentials in tool schemas. A scanner that is
inconsistently strict is worse than one that is uniformly strict, because the
gaps are invisible.

The patterns are split into tiers because they carry different false-positive
risk, not for tidiness:

``STRUCTURAL_CREDENTIALS``
    Match the *shape* of a secret — a distinctive prefix and a length floor, or
    a PEM banner. Safe against arbitrary text, including serialized tool
    definitions, so every consumer uses these.

``KEYWORD_CREDENTIALS``
    Match ``password: <value>`` style assignments. These cannot distinguish a
    real secret from a JSON Schema property declaration: ``{"api_key": {"type":
    "string"}}`` matches, because ``{"type":`` satisfies the value clause. Only
    for response and config bodies, never for tool schemas.

``VENDOR_CREDENTIALS``
    Lab-specific token formats (Camazotz). Deliberately outside the generic
    tier so they do not leak into findings against real servers.

``REFERENCE_PATTERNS``
    Paths and identifiers that point *at* a secret rather than containing one
    (a service-account token path). Disclosure-relevant, not a leaked value.

Where the four definitions disagreed, the resolution is the wider one: for a
scanner, a false negative on a distinctively-prefixed token costs more than a
false positive a human dismisses in seconds.
"""

from __future__ import annotations

import re
from typing import Union

# A pattern entry is (regex, credential_type). The regex may be a string or
# an already-compiled pattern; compile_patterns() normalizes either.
PatternSpec = tuple[Union[str, "re.Pattern[str]"], str]


# ── Structural: shape-based, safe on any text ─────────────────────────

STRUCTURAL_CREDENTIALS: tuple[PatternSpec, ...] = (
    # Private keys — a PEM banner is unmistakable. PUBLIC KEY and CERTIFICATE
    # are excluded by requiring the PRIVATE keyword.
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
     "private_key"),

    # Cloud provider keys.
    # AKIA is word-bounded so MAKIAVELLIAN does not match; AWS key IDs are
    # exactly 20 chars (AKIA + 16).
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
    (r"\bASIA[0-9A-Z]{16}\b", "aws_temp_key"),
    (r"\bAIza[a-zA-Z0-9_\-]{35}\b", "gcp_api_key"),

    # Vendor API keys. sk-ant- must precede the generic sk- so an Anthropic key
    # is reported as such rather than as an OpenAI key.
    (r"\bsk-ant-[a-zA-Z0-9_\-]{20,}", "anthropic_api_key"),
    (r"\bsk-[a-zA-Z0-9_\-]{20,}", "openai_key"),

    # Source forges. github_pat_ (fine-grained) must precede ghp_ so the more
    # specific prefix wins. The {20,} floor is the widest of the four previous
    # definitions: classic PATs are ghp_ + 36, but truncated and legacy forms
    # were caught by only one consumer before.
    (r"\bgithub_pat_[a-zA-Z0-9_]{22,}", "github_fine_grained_pat"),
    (r"\bghp_[a-zA-Z0-9]{20,}", "github_pat"),
    (r"\bgho_[a-zA-Z0-9]{20,}", "github_oauth_token"),
    (r"\bghs_[a-zA-Z0-9]{20,}", "github_server_token"),
    (r"\bglpat-[a-zA-Z0-9_\-]{20,}", "gitlab_pat"),

    # Slack. The character class covers bot/user/workspace/refresh/app/legacy
    # variants; two previous definitions omitted 'o'.
    (r"\bxox[bposar]-[a-zA-Z0-9\-]{10,}", "slack_token"),

    # Connection strings carrying inline credentials. \S+ for the password,
    # since real passwords contain symbols that \w+ misses.
    (r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql|ftp)://"
     r"[^\s:/@]+:[^\s@]+@", "connection_string"),

    # JWTs. Two segments is enough — a base64 header followed by a base64
    # payload is not a coincidence — and the previous 3-segment form missed
    # unsigned tokens.
    (r"\beyJ[a-zA-Z0-9_\-]{8,}\.eyJ[a-zA-Z0-9_\-]{8,}", "jwt_token"),

    # Bearer credentials presented in a header or config line. Case-insensitive
    # with a 16-char floor: the four previous definitions split on both, and
    # the case-sensitive ones missed the canonical capitalized "Bearer ".
    (r"(?i)\b(?:bearer|token)\s+[a-zA-Z0-9._\-]{16,}", "bearer_token"),
)


# ── Keyword: assignment-shaped, body text only ────────────────────────
#
# These match a keyword followed by any value, so they also match a JSON
# Schema property declaration. Never apply them to tool definitions.

# (?i) throughout: the previous definitions were lowercase-only, so an
# uppercase PASSWORD= in an env dump — the common case — went unmatched.
KEYWORD_CREDENTIALS: tuple[PatternSpec, ...] = (
    (r"(?i)[\"']?rcon[_-]?password[\"']?\s*[:=]\s*[\"']?\S{6,}", "rcon_password"),
    (r"(?i)[\"']?admin[_-]?(?:api[_-]?)?key[\"']?\s*[:=]\s*[\"']?\S{6,}",
     "admin_api_key"),
    # Covers both "ADMIN_PASSWORD=" and the prose "root password: " form.
    (r"(?i)[\"']?(?:admin|root)[\s_-]*(?:password|pwd|pass)[\"']?\s*[:=]\s*[\"']?\S{4,}",
     "admin_password"),
    (r"(?i)[\"']?(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?\S{6,}", "password"),
    (r"(?i)[\"']?(?:api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']?\S{6,}", "api_key"),
    (r"(?i)[\"']?(?:secret|token|credential)[\"']?\s*[:=]\s*[\"']?\S{6,}", "secret"),
    # Named secret env vars, which the bare keyword patterns above miss because
    # the keyword is a prefix of a longer name (SECRET_KEY=, AWS_SECRET=).
    (r"(?i)\b(?:DATABASE_URL|SECRET_KEY|AWS_SECRET(?:_ACCESS_KEY)?|PRIVATE_KEY"
     r"|ACCESS_TOKEN|AUTH_TOKEN|SESSION_SECRET)\s*[:=]\s*[\"']?\S{4,}",
     "secret_env_assignment"),
)


# ── Vendor: lab-specific formats ──────────────────────────────────────

VENDOR_CREDENTIALS: tuple[PatternSpec, ...] = (
    (r"cztz-[a-zA-Z0-9_\-]{6,}", "cztz_token"),
    (r"CZTZ_[A-Z][A-Z0-9_]{2,}", "cztz_env_var"),
)


# ── References: point at a secret rather than containing one ──────────
#
# Also prose forms that only make sense in response and config bodies. Like
# the keyword tier, these are too loose for tool schemas.

REFERENCE_PATTERNS: tuple[PatternSpec, ...] = (
    (r"(?:database|db)\s+(?:connection|conn)\s*[:=]?\s*\S+://", "db_connection"),
    (r"\[file:[^\]]*(?:key|secret|credential|cert|pem)[^\]]*\]",
     "secret_file_reference"),
    (r"(?:KEY|key|cert|pem|secret)\s*[:=]\s*[\"']?/(?:etc|var|run|opt|home)/\S+",
     "secret_path_reference"),
    (r"/var/run/secrets/kubernetes\.io/serviceaccount/token", "k8s_sa_token_path"),
    (r"(?:KUBERNETES_SERVICE_HOST|SERVICE_HOST)\s*[:=]\s*\S+",
     "k8s_service_endpoint"),
)


# Everything that is safe to run against response and config bodies.
CONTENT_CREDENTIALS: tuple[PatternSpec, ...] = (
    STRUCTURAL_CREDENTIALS + KEYWORD_CREDENTIALS + REFERENCE_PATTERNS
)

# What a check scanning tool definitions should use: shape-based only.
SCHEMA_CREDENTIALS: tuple[PatternSpec, ...] = STRUCTURAL_CREDENTIALS

# Anonymous-recon surface, which also cares about lab tokens.
RECON_CREDENTIALS: tuple[PatternSpec, ...] = (
    VENDOR_CREDENTIALS + STRUCTURAL_CREDENTIALS
)


_COMPILED_CACHE: dict[int, tuple[tuple[re.Pattern[str], str], ...]] = {}


def compile_patterns(
    patterns: "tuple[PatternSpec, ...] | list[PatternSpec]",
) -> tuple[tuple[re.Pattern[str], str], ...]:
    """Compile a pattern tier once and reuse it.

    Accepts already-compiled patterns so callers migrating from local
    precompiled lists do not have to change shape. Results are cached by
    identity, since the tiers are module-level constants scanned per tool.
    """
    key = id(patterns)
    cached = _COMPILED_CACHE.get(key)
    if cached is not None:
        return cached

    out = tuple(
        (p if isinstance(p, re.Pattern) else re.compile(p), name)
        for p, name in patterns
    )
    _COMPILED_CACHE[key] = out
    return out


def find_credential(
    text: str,
    patterns: "tuple[PatternSpec, ...] | list[PatternSpec]" = STRUCTURAL_CREDENTIALS,
) -> tuple[str, str] | None:
    """Return ``(credential_type, matched_text)`` for the first hit, else None.

    Order matters: the tiers list specific prefixes before generic ones so a
    ``sk-ant-`` key is reported as Anthropic rather than OpenAI.
    """
    for pat, name in compile_patterns(patterns):
        m = pat.search(text)
        if m:
            return name, m.group()
    return None
