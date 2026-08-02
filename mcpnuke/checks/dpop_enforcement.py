"""DPoP enforcement check (MCP-T43, Lane 3 / Machine Identity).

DPoP (Demonstrating Proof of Possession, RFC 9449) binds an access token
to a cryptographic key by requiring a fresh signed proof on every request.
When DPoP is NOT enforced, a stolen bearer token can be replayed without
the corresponding private key — the "proof of possession" guarantee is
absent.

This check probes for three indicators:

1. **DPoP header absent but request accepted** — sends a request without
   a ``DPoP`` header. If the server returns 200, DPoP is not enforced.

2. **Malformed DPoP accepted** — sends a ``DPoP: garbage`` header. RFC
   9449 §7.1 requires the server to return 401 with
   ``WWW-Authenticate: DPoP error="invalid_dpop_proof"`` for malformed
   proofs. Acceptance indicates the header is decorative.

3. **Missing htm/htu claims not rejected** — sends a minimal JWT lacking
   ``htm``/``htu`` claims. A compliant server MUST return 401. Acceptance
   indicates proof-of-possession binding is not checked.

Lane 3 (Machine Identity) — DPoP failures matter most when bots/agents
authenticate with short-lived certificates and the system relies on
proof-of-possession to prevent credential theft and replay.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol

_add = lane_tagged(lane=3, transport="A")

_PROBE_TOOL = "tools/list"  # lightweight probe, available on any MCP server


def _minimal_jwt(*, include_htm: bool = True, include_htu: bool = True) -> str:
    """Build a syntactically valid but semantically incomplete DPoP proof JWT.

    Not signed with a real key — the goal is to test whether the server
    validates the *structure* and *required claims*, not the signature.
    """
    header = {"alg": "RS256", "typ": "dpop+jwt", "jwk": {"kty": "RSA", "n": "x", "e": "AQAB"}}
    payload: dict[str, Any] = {"jti": "probe-000", "iat": 9_999_999_999}
    if include_htm:
        payload["htm"] = "POST"
    if include_htu:
        payload["htu"] = "http://probe.invalid/mcp"

    def _b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(payload)}.fakesignature"


def _probe_payload(req_id: int) -> dict[str, Any]:
    """A minimal, side-effect-free JSON-RPC request to authorize."""
    return {"jsonrpc": "2.0", "id": req_id, "method": _PROBE_TOOL, "params": {}}


def dpop_probeable(session: MCPSessionProtocol | None) -> bool:
    """True when the transport can carry a DPoP proof and its endpoint is resolved.

    A proof travels in an HTTP header, so ``post_raw`` is the discriminator:
    stdio sets a truthy ``stdio://`` ``post_url`` but has no header layer, and
    is excluded by the first conjunct alone. The second excludes SSE before its
    handshake resolves an endpoint, where ``post_url`` is still empty.

    The orchestrator's progress gate and ``run_dpop_enforcement_checks`` both
    read this, so the denominator cannot disagree with what runs.
    """
    return bool(getattr(session, "post_raw", None) and getattr(session, "post_url", ""))


def run_dpop_enforcement_checks(result: TargetResult, session: Any) -> None:
    """Run all DPoP enforcement probes against *session*'s MCP endpoint.

    Three targeted probes that need only ``tools/list`` — safe to run always,
    and they never call a lab tool, so ``--no-invoke`` does not suppress them.

    Skips transports with no HTTP header layer for a proof to live in (stdio),
    and sessions whose endpoint is not yet resolved (SSE before handshake).

    Not the path a scan takes: ``run_all_checks`` drives the three probes
    individually through its ``_run`` helper so each one appears in the
    progress count. This remains the entry point for callers outside the
    orchestrator — do not add a second call to it from there.

    A fourth probe must be added in both places. Nothing in production reads
    this function, but every DPoP test enters through it, so a probe added
    only here is fully tested and never runs;
    tests/test_check_progress.py::TestDpopRunnerStaysInSync fails when the
    chain below stops matching ``_DPOP_CHECK_NAMES``. The real fix is to delete
    this function and have the orchestrator and the tests iterate one shared
    table, leaving a single list to add to.
    """
    if not dpop_probeable(session):
        return

    _probe_no_dpop_header(result, session)
    _probe_malformed_dpop(result, session)
    _probe_missing_htm_htu(result, session)


def _probe_no_dpop_header(result: TargetResult, session: Any) -> None:
    """Check 1: plain bearer request accepted → DPoP not enforced."""
    with time_check("dpop_no_header", result):
        try:
            resp = session.post_raw(_probe_payload(1), timeout=10)
        except Exception as exc:
            result.note_error(f"dpop_no_header probe error: {exc}")
            return

    # A DPoP-enforcing server MUST return 401 for requests without DPoP proof.
    # HTTP 200 means the server accepts token-less or DPoP-less bearer tokens.
    if resp.status_code == 200:
        _add(
            result,
            "dpop_not_enforced",
            "HIGH",
            (
                "Server accepted an MCP request without a DPoP proof header. "
                "RFC 9449 §7 requires a fresh proof on every request. "
                "A stolen bearer token can be replayed without the paired private key."
            ),
            evidence={
                "probe": "no_dpop_header",
                "http_status": resp.status_code,
                "recommendation": (
                    "Enforce DPoP at the gateway/proxy layer. "
                    "Reject requests that lack a valid DPoP proof with "
                    "401 WWW-Authenticate: DPoP."
                ),
                "rfc": "RFC 9449 §7.1",
                "threat_id": "MCP-T43",
            },
        )


def _probe_malformed_dpop(result: TargetResult, session: Any) -> None:
    """Check 2: malformed DPoP header accepted → header is decorative."""
    with time_check("dpop_malformed", result):
        try:
            resp = session.post_raw(
                _probe_payload(2),
                extra_headers={"DPoP": "not.a.valid.jwt"},
                timeout=10,
            )
        except Exception as exc:
            result.note_error(f"dpop_malformed probe error: {exc}")
            return

    # RFC 9449 §7.1: malformed DPoP proof → 401 with error=invalid_dpop_proof
    if resp.status_code == 200:
        _add(
            result,
            "dpop_header_not_validated",
            "HIGH",
            (
                "Server accepted a request with a malformed DPoP header "
                "(not.a.valid.jwt). The DPoP header appears to be decorative — "
                "it is present but not validated. "
                "RFC 9449 §7.1 requires rejection with error=invalid_dpop_proof."
            ),
            evidence={
                "probe": "malformed_dpop",
                "dpop_sent": "not.a.valid.jwt",
                "http_status": resp.status_code,
                "recommendation": (
                    "Parse and cryptographically verify the DPoP proof JWT "
                    "on every request. Reject with 401 if parsing fails."
                ),
                "rfc": "RFC 9449 §7.1",
                "threat_id": "MCP-T43",
            },
        )


def _probe_missing_htm_htu(result: TargetResult, session: Any) -> None:
    """Check 3: JWT missing htm/htu accepted → binding not checked."""
    proof = _minimal_jwt(include_htm=False, include_htu=False)
    with time_check("dpop_missing_binding", result):
        try:
            resp = session.post_raw(
                _probe_payload(3),
                extra_headers={"DPoP": proof},
                timeout=10,
            )
        except Exception as exc:
            result.note_error(f"dpop_missing_binding probe error: {exc}")
            return

    # RFC 9449 §4.2: htm and htu are REQUIRED in every DPoP proof.
    # Acceptance → binding is absent; stolen proofs can be replayed anywhere.
    if resp.status_code == 200:
        _add(
            result,
            "dpop_binding_not_enforced",
            "HIGH",
            (
                "Server accepted a DPoP proof JWT that lacked both htm and htu "
                "claims. RFC 9449 §4.2 requires these claims to bind the proof "
                "to the specific HTTP method and URI. Without them, a stolen "
                "DPoP proof can be replayed against any endpoint."
            ),
            evidence={
                "probe": "missing_htm_htu",
                "htm_present": False,
                "htu_present": False,
                "http_status": resp.status_code,
                "recommendation": (
                    "Enforce htm (HTTP method) and htu (target URI) binding. "
                    "Reject proofs that do not match the current request."
                ),
                "rfc": "RFC 9449 §4.2, §7.1",
                "threat_id": "MCP-T43",
            },
        )
