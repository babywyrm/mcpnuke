"""JWT token hardening checks (MCP-T07).

Inspects the auth token attached to the scan for weak algorithm choices,
missing standard claims, excessive TTL, and known weak signing keys.
"""

import hashlib
import hmac
import time

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.core.auth import decode_jwt_header, decode_jwt_claims

DEFAULT_MAX_TTL: int = 14400  # 4 hours in seconds

_SYMMETRIC_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})

_WEAK_KEYS: list[str] = [
    "", "secret", "changeme", "test", "password", "key",
    "supersecret", "jwt_secret", "my_secret",
]

_HMAC_HASH_MAP: dict[str, str] = {
    "HS256": "sha256",
    "HS384": "sha384",
    "HS512": "sha512",
}


def _get_auth_token(result: TargetResult) -> str | None:
    return result.auth_context.get("_raw_token")


def _get_jwt_claims(result: TargetResult) -> dict | None:
    summary = result.auth_context.get("jwt_claims_summary")
    if summary:
        return summary
    token = _get_auth_token(result)
    if token:
        return decode_jwt_claims(token)
    return None


def _get_jwt_header(result: TargetResult) -> dict | None:
    token = _get_auth_token(result)
    if token:
        return decode_jwt_header(token)
    return result.auth_context.get("jwt_header")


def check_jwt_algorithm(result: TargetResult) -> None:
    """Flag dangerous JWT signing algorithms."""
    with time_check("jwt_algorithm", result):
        header = _get_jwt_header(result)
        if not header:
            return

        alg = header.get("alg", "")
        alg_upper = alg.upper() if isinstance(alg, str) else ""

        if alg_upper == "NONE" or alg == "none":
            result.add(
                "jwt_algorithm",
                "CRITICAL",
                "JWT uses alg:none — signature bypass",
                "Tokens signed with 'none' can be forged by any party",
                evidence=f"alg={alg}",
            )
        elif alg_upper in _SYMMETRIC_ALGORITHMS:
            result.add(
                "jwt_algorithm",
                "HIGH",
                f"JWT uses symmetric algorithm {alg}",
                "Symmetric HMAC algorithms require a shared secret; prefer "
                "asymmetric RS256/ES256 for server-to-server auth",
                evidence=f"alg={alg}",
            )


def check_jwt_issuer(result: TargetResult) -> None:
    """Flag missing iss claim."""
    with time_check("jwt_issuer", result):
        claims = _get_jwt_claims(result)
        if not claims:
            return

        if "iss" not in claims:
            result.add(
                "jwt_issuer",
                "MEDIUM",
                "JWT missing iss (issuer) claim",
                "Without an issuer claim, tokens cannot be scoped to a trusted authority",
            )


def check_jwt_audience(result: TargetResult) -> None:
    """Flag missing aud claim."""
    with time_check("jwt_audience", result):
        claims = _get_jwt_claims(result)
        if not claims:
            return

        if "aud" not in claims:
            result.add(
                "jwt_audience",
                "MEDIUM",
                "JWT missing aud (audience) claim",
                "Without an audience claim, tokens can be replayed against any "
                "service that trusts the same issuer",
            )


def check_jwt_token_id(result: TargetResult) -> None:
    """Flag missing jti claim."""
    with time_check("jwt_token_id", result):
        claims = _get_jwt_claims(result)
        if not claims:
            return

        if "jti" not in claims:
            result.add(
                "jwt_token_id",
                "LOW",
                "JWT missing jti (token ID) claim",
                "Without a unique token ID, replay detection is not possible",
            )


def check_jwt_ttl(result: TargetResult, probe_opts: dict | None = None) -> None:
    """Flag tokens with excessive time-to-live."""
    opts = probe_opts or {}
    max_ttl: int = opts.get("jwt_max_ttl", DEFAULT_MAX_TTL)

    with time_check("jwt_ttl", result):
        claims = _get_jwt_claims(result)
        if not claims:
            return

        exp = claims.get("exp")
        if exp is None:
            result.add(
                "jwt_ttl",
                "HIGH",
                "JWT has no exp (expiration) claim",
                "Tokens without expiration never become invalid",
            )
            return

        if not isinstance(exp, (int, float)):
            return

        iat = claims.get("iat")
        if isinstance(iat, (int, float)):
            ttl = int(exp - iat)
        else:
            ttl = int(exp - time.time())
            if ttl < 0:
                return

        if ttl > max_ttl:
            hours = ttl / 3600
            threshold_hours = max_ttl / 3600
            result.add(
                "jwt_ttl",
                "MEDIUM",
                f"JWT TTL is {hours:.1f}h (threshold: {threshold_hours:.0f}h)",
                f"Long-lived tokens increase the window for theft and replay; "
                f"measured TTL={ttl}s vs max={max_ttl}s",
                evidence=f"exp={exp}, iat={iat}, ttl={ttl}s",
            )


def check_jwt_weak_key(result: TargetResult) -> None:
    """Attempt to verify JWT signature with known weak/default keys."""
    with time_check("jwt_weak_key", result):
        token = _get_auth_token(result)
        if not token:
            return

        header = decode_jwt_header(token)
        if not header:
            return

        alg = header.get("alg", "")
        if alg not in _HMAC_HASH_MAP:
            return

        parts = token.split(".")
        if len(parts) != 3:
            return

        import base64
        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        sig_padding = "=" * ((4 - len(parts[2]) % 4) % 4)
        try:
            expected_sig = base64.urlsafe_b64decode(parts[2] + sig_padding)
        except Exception:
            return

        hash_name = _HMAC_HASH_MAP[alg]
        for weak_key in _WEAK_KEYS:
            computed = hmac.new(
                weak_key.encode("utf-8"),
                signing_input,
                hash_name,
            ).digest()
            if hmac.compare_digest(computed, expected_sig):
                display_key = repr(weak_key) if weak_key else '""(empty)'
                result.add(
                    "jwt_weak_key",
                    "CRITICAL",
                    f"JWT signed with weak key: {display_key}",
                    f"Token signature verified with a well-known default key "
                    f"using {alg} — any attacker can forge valid tokens",
                    evidence=f"alg={alg}, key={display_key}",
                )
                return
