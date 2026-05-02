"""JWT identity boundary checks (MCP-T04, Lane 1 / Human Direct).

Targets the gaps documented in the mcpnuke CHANGELOG under MCP-T04:

* **JWT audience validation** — decode the supplied bearer token, compare its
  ``aud`` claim to the target MCP endpoint, and detect cross-tool token
  replay where a token issued for service A is silently accepted by
  service B.
* **Cross-role token replay** — when a token's claims indicate a limited
  role (``role: viewer``, ``scope: read``), enumerate the tools the
  server exposes and flag write/admin/delete tools that the token can
  still call. Indicates same-realm role isolation gaps.

Both checks are static-analysis-only when no auth token is attached;
behavioural verification (actually calling out-of-scope tools) happens
only when a token is present and ``--no-invoke`` is not set.

Lane: 1 (Human Direct) — these failures matter most when a single
human-facing realm issues tokens that cross trust boundaries between
services or roles.
"""

from __future__ import annotations

from urllib.parse import urlparse

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.auth import decode_jwt_claims
from mcpnuke.core.models import TargetResult

_add = lane_tagged(lane=1, transport="A")


_READ_SCOPE_TOKENS: frozenset[str] = frozenset({
    "read", "readonly", "read-only", "viewer", "view",
    "list", "get", "ro",
})

_WRITE_TOOL_KEYWORDS: frozenset[str] = frozenset({
    "delete", "destroy", "drop", "purge", "remove",
    "create", "write", "update", "modify", "edit",
    "deploy", "execute", "exec", "run", "spawn",
    "admin", "sudo", "manage", "install", "uninstall",
    "subscribe", "register", "unregister", "publish",
})


def _normalize_audiences(aud_claim) -> list[str]:
    """RFC 9068: aud may be string or array of strings. Normalize to list."""
    if isinstance(aud_claim, str):
        return [aud_claim]
    if isinstance(aud_claim, list):
        return [str(a) for a in aud_claim if isinstance(a, str)]
    return []


def _expected_audiences(target_url: str) -> set[str]:
    """Derive the set of audience strings a token *should* carry for this target.

    Matches conservatively — any of these forms is accepted as a valid
    audience for the target:

    * the full URL                                 (e.g. http://host:port/mcp)
    * the URL without path                         (e.g. http://host:port)
    * the bare host                                (e.g. host)
    * the host:port                                (e.g. host:port)

    A token whose ``aud`` does not intersect any of these forms is flagged
    as cross-tool replay candidate.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port
    netloc = parsed.netloc or host
    candidates = {target_url}
    if parsed.scheme and netloc:
        candidates.add(f"{parsed.scheme}://{netloc}")
    if host:
        candidates.add(host)
    if host and port:
        candidates.add(f"{host}:{port}")
    return {c for c in candidates if c}


def check_jwt_audience_target_match(result: TargetResult) -> None:
    """MCP-T04: token ``aud`` claim must match the MCP endpoint it is sent to.

    A token issued for ``api://billing`` that is accepted by an MCP server
    serving ``api://identity`` indicates the server skipped audience
    validation (PyJWT ``options={"verify_aud": False}``) or has overlap in
    its trusted audience list. Both let a stolen token authenticate against
    services it was never authorized for.
    """
    with time_check("jwt_audience_target_match", result):
        claims = result.auth_context.get("jwt_claims_summary")
        if claims is None:
            token = result.auth_context.get("_raw_token")
            if not token:
                return
            claims = decode_jwt_claims(token)
            if not claims:
                return

        auds = _normalize_audiences(claims.get("aud"))
        if not auds:
            # absence of aud is already covered by check_jwt_audience —
            # don't double-report here
            return

        expected = _expected_audiences(result.url)
        if not expected:
            return

        # Match if any audience claim string contains any expected form
        # (substring, case-insensitive). Conservative: avoid false positives
        # when teams use opaque audience identifiers like UUIDs or service
        # IDs that don't textually resemble the URL.
        aud_blob = " ".join(auds).lower()
        matched = any(c.lower() in aud_blob for c in expected)
        if matched:
            return

        _add(
            result,
            "jwt_audience_target_match",
            "HIGH",
            "JWT aud claim does not match the MCP endpoint",
            "Server accepted a token whose audience does not include this "
            "endpoint or its host. This indicates audience validation is "
            "disabled (e.g. PyJWT verify_aud=False) and enables cross-tool "
            "token replay between services in the same trust realm "
            "(MCP-T04).",
            evidence=f"token aud={auds!r}, expected one of {sorted(expected)!r}",
        )


def _claims_indicate_read_only(claims: dict) -> tuple[bool, str]:
    """Return (is_read_only, reason) for a JWT claims dict."""
    scope = claims.get("scope", "")
    if isinstance(scope, str):
        scope_tokens = scope.lower().split()
    elif isinstance(scope, list):
        scope_tokens = [str(s).lower() for s in scope]
    else:
        scope_tokens = []
    if scope_tokens and all(t in _READ_SCOPE_TOKENS for t in scope_tokens):
        return True, f"scope={scope!r}"

    role = claims.get("role")
    if isinstance(role, str) and role.lower() in _READ_SCOPE_TOKENS:
        return True, f"role={role!r}"

    roles = claims.get("roles")
    if isinstance(roles, list) and roles:
        roles_lower = [str(r).lower() for r in roles]
        if all(r in _READ_SCOPE_TOKENS for r in roles_lower):
            return True, f"roles={roles!r}"

    return False, ""


def _tool_is_write_class(tool: dict) -> bool:
    """Heuristic: does this tool name suggest mutation, deletion, or admin?"""
    name = str(tool.get("name", "")).lower()
    for kw in _WRITE_TOOL_KEYWORDS:
        if kw in name:
            return True
    return False


def check_jwt_cross_role_replay(result: TargetResult) -> None:
    """MCP-T04: a read-only token must not be able to enumerate write tools.

    If the bearer token's claims mark it read-only (scope contains only
    read/list verbs, role/roles all read-class) but ``tools/list`` returned
    write/admin/delete tools, the same realm is issuing tokens that cross
    role boundaries. The MCP server is trusting the token's signature
    without checking the role-vs-tool match.

    This is a static check: it does NOT actually call the write tools
    (that risks side effects on the target). Behavioural confirmation is
    left to operators using ``--probe-calls`` against a curated tool list.
    """
    with time_check("jwt_cross_role_replay", result):
        claims = result.auth_context.get("jwt_claims_summary")
        if claims is None:
            token = result.auth_context.get("_raw_token")
            if not token:
                return
            claims = decode_jwt_claims(token)
            if not claims:
                return

        is_read_only, reason = _claims_indicate_read_only(claims)
        if not is_read_only:
            return

        write_tools = [
            str(t.get("name", ""))
            for t in result.tools
            if _tool_is_write_class(t)
        ]
        if not write_tools:
            return

        sample = ", ".join(write_tools[:5])
        more = f" (+{len(write_tools) - 5} more)" if len(write_tools) > 5 else ""
        _add(
            result,
            "jwt_cross_role_replay",
            "HIGH",
            "Read-only token sees write/admin tools in tools/list",
            "Token claims indicate read-only access but the MCP server "
            "exposes write, delete, or admin tools to it. Same OIDC realm "
            "for users and agents typically causes this. Confirm by "
            "attempting tools/call against one of the listed tools — if "
            "the server accepts it, role isolation is broken (MCP-T04).",
            evidence=f"{reason}; write-class tools visible: {sample}{more}",
        )
