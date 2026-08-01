"""Shared IdP scope pollution checks (MCP-T42, Lane 2 / Transport A).

When multiple agents/services share one IdP realm, a low-privilege caller can
sometimes ask a token-minting tool for a token containing another service's
scope. The token is validly signed by the IdP, but the requested scope is
outside the caller's service boundary.

This check is intentionally static/safe:

* It inspects the caller JWT claims (``scope``, ``scp``, ``role``, ``roles``).
* It inspects the exposed tool catalog for token-minting tools
  (``mint_token``, ``exchange_token``, ``issue_token``).
* It flags tools whose schemas allow caller-controlled requested scopes but do
  not advertise narrowing/allowlisting constraints.
* It separately flags service-config tools whose schema/description discloses
  shared IdP topology.

Pairs with camazotz ``shared_idp_pollution_lab`` (MCP-T42).
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.auth import decode_jwt_claims
from mcpnuke.core.models import TargetResult

_add = lane_tagged(lane=2, transport="A")

_TOKEN_MINT_TOOL = re.compile(
    r"(?:mint|issue|exchange|refresh|create).*(?:token|credential)|"
    r"(?:token|credential).*(?:mint|issue|exchange|refresh|create)",
    re.IGNORECASE,
)
_REQUESTED_SCOPE_PARAM = re.compile(
    r"(?:requested_)?scope|scopes|audience|role|roles|permission|permissions",
    re.IGNORECASE,
)
_NARROWING_LANGUAGE = re.compile(
    r"(?:allowlist|whitelist|narrow|narrower|downscope|least[-_\s]?privilege|"
    r"service[-_\s]?bound|audience[-_\s]?bound|scope[-_\s]?limit)",
    re.IGNORECASE,
)
_SHARED_IDP_DISCLOSURE = re.compile(
    r"(?:shared[-_\s]?idp|same[-_\s]?(?:issuer|realm|tenant)|"
    r"cross[-_\s]?service|other[-_\s]?services|client_credentials|"
    r"service[-_\s]?account.*(?:same|shared))",
    re.IGNORECASE,
)
_PRIVILEGED_SCOPE_TERMS = frozenset({
    "admin",
    "write",
    "delete",
    "deploy",
    "manage",
    "root",
    "sudo",
    "security",
})


def _claims(result: TargetResult) -> dict[str, Any]:
    claims = result.auth_context.get("jwt_claims_summary")
    if isinstance(claims, dict) and claims:
        return claims
    token = result.auth_context.get("_raw_token")
    if token:
        decoded = decode_jwt_claims(token)
        return decoded if isinstance(decoded, dict) else {}
    return {}


def _scope_tokens(claims: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for key in ("scope", "scp", "role", "roles"):
        val = claims.get(key)
        if isinstance(val, str):
            out.update(s.lower() for s in re.split(r"[\s,]+", val) if s)
        elif isinstance(val, list):
            out.update(str(s).lower() for s in val if s)
    return out


def _schema_text(tool: dict) -> str:
    return " ".join((
        str(tool.get("name", "")),
        str(tool.get("description", "")),
        json.dumps(tool.get("inputSchema", {}), default=str),
    ))


def _schema_has_requested_scope_param(tool: dict) -> bool:
    props = tool.get("inputSchema", {}).get("properties", {}) or {}
    for pname, pdef in props.items():
        if _REQUESTED_SCOPE_PARAM.search(str(pname)):
            return True
        if isinstance(pdef, dict) and _REQUESTED_SCOPE_PARAM.search(str(pdef.get("description", ""))):
            return True
    return False


def _schema_advertises_privileged_scope(tool: dict) -> bool:
    text = _schema_text(tool).lower()
    return any(term in text for term in _PRIVILEGED_SCOPE_TERMS)


def _schema_has_narrowing(tool: dict) -> bool:
    return bool(_NARROWING_LANGUAGE.search(_schema_text(tool)))


def _looks_like_token_minter(tool: dict) -> bool:
    return bool(_TOKEN_MINT_TOOL.search(_schema_text(tool)))


def check_scope_pollution(result: TargetResult) -> None:
    """Static shared-IdP scope-pollution detector (MCP-T42)."""
    with time_check("scope_pollution", result):
        caller_claims = _claims(result)
        caller_scopes = _scope_tokens(caller_claims)
        caller_is_low_priv = bool(caller_scopes) and not (
            caller_scopes & _PRIVILEGED_SCOPE_TERMS
        )

        for tool in result.tools:
            name = tool.get("name", "")
            text = _schema_text(tool)

            if _SHARED_IDP_DISCLOSURE.search(text):
                _add(
                    result,
                    "scope_pollution",
                    "MEDIUM",
                    f"Shared IdP topology disclosed by tool '{name}'",
                    "Tool schema/description exposes shared IdP or cross-service "
                    "token topology. This is reconnaissance for MCP-T42 scope "
                    "pollution attacks.",
                    evidence=text[:300],
                    taxonomy_id="MCP-T42",
                )

            if not _looks_like_token_minter(tool):
                continue

            has_requested_scope = _schema_has_requested_scope_param(tool)
            has_priv_scope = _schema_advertises_privileged_scope(tool)
            has_narrowing = _schema_has_narrowing(tool)

            if has_requested_scope and not has_narrowing:
                severity = "CRITICAL" if caller_is_low_priv and has_priv_scope else "HIGH"
                detail = (
                    "Token-minting tool accepts caller-controlled scope/audience/role "
                    "parameters but does not advertise scope narrowing or service-bound "
                    "allowlist enforcement. In a shared IdP this can let a delegated "
                    "agent mint out-of-bound tokens for another service (MCP-T42)."
                )
                if caller_scopes:
                    detail += f" Caller claims appear to have scopes: {sorted(caller_scopes)!r}."
                _add(
                    result,
                    "scope_pollution",
                    severity,
                    f"Token-minting tool may allow scope pollution: '{name}'",
                    detail,
                    evidence=text[:300],
                    taxonomy_id="MCP-T42",
                )
