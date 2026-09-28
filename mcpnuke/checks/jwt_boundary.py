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


def _is_resource_locator(value: str) -> bool:
    """True when aud names a place rather than a logical client or role.

    ``api://billing`` and ``other.example`` are locators. ``camazotz-gateway``
    is a name the resource server can allow on purpose.
    """
    if "://" in value:
        parsed = urlparse(value)
        return bool(parsed.scheme and parsed.netloc)
    host = value.split("/", 1)[0]
    if host.count(":") == 1 and host.rsplit(":", 1)[-1].isdigit():
        host = host.rsplit(":", 1)[0]
    return "." in host


def check_jwt_audience_target_match(result: TargetResult) -> None:
    """MCP-T04: token ``aud`` claim compared to the MCP endpoint it is sent to.

    An ``aud`` that is itself a different resource locator is HIGH: the
    server accepted a token named for somewhere else. An ``aud`` that is
    only a logical name (client id, role) is MEDIUM. That name can be the
    audience the server intentionally allows.
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

        foreign = [aud for aud in auds if _is_resource_locator(aud)]
        if foreign:
            severity = "HIGH"
            detail = (
                "Bearer token aud names a different resource than this "
                "endpoint. The server accepted it, which is cross-service "
                "token replay (MCP-T04)."
            )
        else:
            # A client id or api name is a normal allowed audience. It does
            # not show that the server skipped the aud check.
            severity = "MEDIUM"
            detail = (
                "Bearer token aud is a logical name and does not contain "
                "this endpoint or its host. That is normal when the allowed "
                "audience is a client id or api identifier (MCP-T04)."
            )
        _add(
            result,
            "jwt_audience_target_match",
            severity,
            "JWT aud claim does not match the MCP endpoint",
            detail,
            evidence=f"token aud={auds!r}, expected one of {sorted(expected)!r}",
            taxonomy_id="MCP-T04",
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
    return any(kw in name for kw in _WRITE_TOOL_KEYWORDS)


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
