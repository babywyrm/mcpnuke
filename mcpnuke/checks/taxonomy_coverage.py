"""Thin taxonomy-coverage checks for IDs that map to simple static patterns.

These are focused detectors for specific threat IDs that existing checks
partially cover but under different names. Each is a minimal schema/description
scan that tags findings with the correct taxonomy ID.

Coverage targets: MCP-T17, T22, T23, T28, T32, T34, T36, T52, T53, T57, T58
"""

from __future__ import annotations

import re

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult

_add_l1 = lane_tagged(lane=1, transport="A")
_add_l2 = lane_tagged(lane=2, transport="A")
_add_l3 = lane_tagged(lane=3, transport="A")
_add_l4 = lane_tagged(lane=4, transport="A")

# Caller-supplied identity *substitution*. Bare user_id is T35 presence, not T22.
_FORGE_PARAMS: frozenset[str] = frozenset({
    "on_behalf_of",
    "as_user",
    "acting_as",
    "claimed_identity",
    "execution_context",
    "run_as_user",
    "impersonate_user",
    "actor_id",
    "acting_user",
    "spoof_identity",
    "forge_context",
    "claimed_user",
})

_SIDECAR_RE = re.compile(
    r"\bsidecar\b|credential[ _]broker|secret[ _]volume|shared[ _]volume|"
    r"kube[ _]secret|sidecar[ _]secret",
    re.IGNORECASE,
)
_SIDECAR_PARAMS: frozenset[str] = frozenset({
    "sidecar",
    "secret_mount",
    "credential_broker",
    "shared_volume",
    "volume_mount",
    "sibling_env",
    "sidecar_secret",
})


def _param_keys(tool: dict) -> set[str]:
    props = tool.get("inputSchema", {}).get("properties", {}) or {}
    return {str(p).lower().replace("-", "_") for p in props}


def check_notification_sampling_abuse(result: TargetResult) -> None:
    """MCP-T17: Notification / Sampling Abuse.

    Detect tools that send unsolicited notifications or use sampling to
    probe the client's model — potential side-channel or DoS vector.
    """
    with time_check("notification_sampling_abuse", result):
        for tool in result.tools:
            name = tool.get("name", "").lower()
            desc = (tool.get("description", "") or "").lower()
            if any(kw in f"{name} {desc}" for kw in (
                "notify", "notification", "sampling", "sample_client",
                "push_message", "broadcast_to_client", "client_callback",
            )):
                _add_l1(
                    result, "notification_sampling_abuse", "MEDIUM",
                    f"Notification/sampling tool: '{tool.get('name', '')}'",
                    "Tool may send unsolicited notifications or sample the client's model",
                    taxonomy_id="MCP-T17",
                )


def check_delegation_depth(result: TargetResult) -> None:
    """MCP-T32: Delegation Depth — Multi-Agent Identity Dilution.

    Detect tools that enable unbounded delegation chains where identity
    attribution degrades at each hop.
    """
    with time_check("delegation_depth", result):
        for tool in result.tools:
            name = tool.get("name", "").lower()
            desc = (tool.get("description", "") or "").lower()
            props = tool.get("inputSchema", {}).get("properties", {})
            if any(kw in f"{name} {desc}" for kw in (
                "delegate", "forward_to_agent", "sub_agent", "spawn_agent",
                "create_agent", "nest", "depth", "hop",
            )) or any(p.lower() in ("agent_id", "target_agent", "delegate_to", "depth") for p in props):
                _add_l4(
                    result, "delegation_depth", "MEDIUM",
                    f"Delegation/multi-hop tool: '{tool.get('name', '')}'",
                    "Tool enables agent delegation chains — identity may dilute at each hop",
                    taxonomy_id="MCP-T32",
                )


def check_subprocess_credential_inheritance(result: TargetResult) -> None:
    """MCP-T34: Subprocess Credential Inheritance.

    Detect tools that spawn subprocesses which may inherit parent credentials.
    """
    with time_check("subprocess_cred_inheritance", result):
        for tool in result.tools:
            name = tool.get("name", "").lower()
            desc = (tool.get("description", "") or "").lower()
            if any(kw in f"{name} {desc}" for kw in (
                "subprocess", "spawn", "fork", "child_process", "worker",
                "exec_in_env", "run_as", "inherit",
            )):
                props = tool.get("inputSchema", {}).get("properties", {})
                has_env = any("env" in p.lower() or "credential" in p.lower() for p in props)
                severity = "HIGH" if has_env else "MEDIUM"
                _add_l3(
                    result, "subprocess_cred_inheritance", severity,
                    f"Subprocess tool may inherit credentials: '{tool.get('name', '')}'",
                    "Spawned processes may inherit parent tokens/credentials from environment",
                    taxonomy_id="MCP-T34",
                )


def check_tool_description_injection(result: TargetResult) -> None:
    """MCP-T36: Tool Description Injection (LangChain-style).

    Detect tools whose descriptions contain instruction-like content that
    could manipulate an agent's behavior when the tool manifest is loaded.
    """
    _INJECT_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?previous", re.IGNORECASE),
        re.compile(r"you\s+(are|must|should)\s+now", re.IGNORECASE),
        re.compile(r"system:\s*", re.IGNORECASE),
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
        re.compile(r"IMPORTANT:.*always\s+(call|use|invoke)", re.IGNORECASE),
        re.compile(r"(override|bypass|disable)\s+(safety|security)", re.IGNORECASE),
    ]
    with time_check("tool_description_injection", result):
        for tool in result.tools:
            desc = tool.get("description", "") or ""
            for pat in _INJECT_PATTERNS:
                if pat.search(desc):
                    _add_l2(
                        result, "tool_description_injection", "CRITICAL",
                        f"Injection pattern in tool description: '{tool.get('name', '')}'",
                        "Tool description contains instruction-override language that "
                        "would manipulate an agent loading this manifest",
                        evidence=desc[:300],
                        taxonomy_id="MCP-T36",
                    )
                    break


def check_pre_auth_injection(result: TargetResult) -> None:
    """MCP-T52: Pre-Authentication Injection.

    Detect if tools are invocable without authentication — the initialize
    handshake succeeded unauthenticated, meaning all tool calls are pre-auth.
    """
    with time_check("pre_auth_injection", result):
        if not result.auth_context.get("_raw_token") and result.tools:
            _add_l2(
                result, "pre_auth_injection", "HIGH",
                f"Pre-auth tool access: {len(result.tools)} tools available without authentication",
                "The MCP server accepted initialize and listed tools without any auth token. "
                "All tool invocations are pre-authentication — no identity binding.",
                taxonomy_id="MCP-T52",
                # stdio has nowhere to put a credential, so "available without
                # authentication" describes the transport rather than this
                # server. Same filter the enumerator's `auth` finding carries.
                skip_transports=["stdio"],
            )


def check_cached_session_exposure(result: TargetResult) -> None:
    """MCP-T57: Cached Session Token Exposure.

    Detect tools that reference session tokens, session IDs, or caches
    in their schema — potential credential reuse or session fixation surface.
    """
    with time_check("cached_session_exposure", result):
        for tool in result.tools:
            props = tool.get("inputSchema", {}).get("properties", {})
            session_params = [
                p for p in props
                if any(kw in p.lower() for kw in (
                    "session_id", "session_token", "cache_key", "cached_token",
                    "session", "sid",
                ))
            ]
            if session_params:
                _add_l3(
                    result, "cached_session_exposure", "MEDIUM",
                    f"Session/cache parameter in tool '{tool.get('name', '')}' ({', '.join(session_params)})",
                    "Tool accepts session identifiers that may enable session fixation or token reuse",
                    taxonomy_id="MCP-T57",
                )


def check_host_network_loopback(result: TargetResult) -> None:
    """MCP-T58: hostNetwork Loopback Bridge.

    Detect tools whose descriptions or parameters reference localhost/loopback
    addresses — potential indicator of hostNetwork access to node services.
    """
    with time_check("host_network_loopback", result):
        for tool in result.tools:
            desc = tool.get("description", "") or ""
            schema_str = str(tool.get("inputSchema", {}))
            combined = f"{desc} {schema_str}"
            if re.search(r"127\.0\.0\.1|localhost|0\.0\.0\.0|host\.docker|hostNetwork", combined, re.IGNORECASE):
                _add_l3(
                    result, "host_network_loopback", "HIGH",
                    f"Loopback/hostNetwork reference in tool '{tool.get('name', '')}'",
                    "Tool references localhost or hostNetwork — may bridge to node-local services",
                    taxonomy_id="MCP-T58",
                )


def check_role_escalation_tool(result: TargetResult) -> None:
    """MCP-T28: Teleport Role Escalation via MCP Tool.

    Detect tools that enable role changes or privilege escalation.
    """
    with time_check("role_escalation_tool", result):
        for tool in result.tools:
            name = tool.get("name", "").lower()
            desc = (tool.get("description", "") or "").lower()
            if any(kw in f"{name} {desc}" for kw in (
                "escalat", "elevat", "promote", "grant_role", "add_role",
                "set_role", "assume_role", "impersonate", "become",
            )):
                _add_l2(
                    result, "role_escalation_tool", "HIGH",
                    f"Role escalation tool: '{tool.get('name', '')}'",
                    "Tool enables privilege escalation or role changes",
                    taxonomy_id="MCP-T28",
                )


def check_shell_wrapping_injection(result: TargetResult) -> None:
    """MCP-T53: Shell Command Wrapping Injection.

    Detect tools that wrap commands in shells (sh -c, bash -c, eval) making
    them vulnerable to argument injection even with apparent input validation.
    """
    _WRAP_PATTERNS = [
        re.compile(r"sh\\s+-c|bash\s+-c|/bin/sh|eval\s*\(", re.IGNORECASE),
        re.compile(r"subprocess\.(?:call|run|Popen).*shell\s*=\s*True", re.IGNORECASE),
        re.compile(r"os\.system\s*\(|os\.popen\s*\(", re.IGNORECASE),
    ]
    with time_check("shell_wrapping_injection", result):
        for tool in result.tools:
            desc = tool.get("description", "") or ""
            schema_str = str(tool.get("inputSchema", {}))
            combined = f"{desc} {schema_str}"
            for pat in _WRAP_PATTERNS:
                if pat.search(combined):
                    _add_l3(
                        result, "shell_wrapping_injection", "HIGH",
                        f"Shell-wrapped execution in tool '{tool.get('name', '')}'",
                        "Tool uses shell wrapping (sh -c, subprocess shell=True, etc.) — "
                        "arguments may be injectable even with apparent validation",
                        taxonomy_id="MCP-T53",
                    )
                    break


def check_native_function_identity_erasure(result: TargetResult) -> None:
    """MCP-T35: Native Function-Calling Identity Erasure.

    Detect tools where the caller's identity is not preserved in the
    tool-call metadata (no caller_id, no auth_context pass-through).
    """
    with time_check("native_function_identity_erasure", result):
        # If the server has tools but no auth mechanism, identity is erased by default
        if result.tools and not result.auth_context.get("_raw_token"):
            has_identity_param = any(
                any(kw in p.lower() for kw in ("caller_id", "user_id", "auth_context", "identity"))
                for tool in result.tools
                for p in tool.get("inputSchema", {}).get("properties", {})
            )
            if not has_identity_param:
                _add_l4(
                    result, "native_function_identity_erasure", "MEDIUM",
                    f"No caller identity in tool calls ({len(result.tools)} tools)",
                    "Tools do not accept caller identity parameters and no auth token is present — "
                    "function calls have no attribution to the invoking agent or user",
                    taxonomy_id="MCP-T35",
                    # stdio has exactly one caller: the process that spawned
                    # the server, running as the user who launched it. There
                    # is no ambiguity to erase, and a caller_id parameter
                    # would be self-asserted by that same client, so both the
                    # premise and the remedy are empty on this transport.
                    skip_transports=["stdio"],
                )


def check_execution_context_forgery(result: TargetResult) -> None:
    """MCP-T22: Execution Context Forgery.

    The caller supplies the execution principal. That is not missing
    identity (T35) and not a role-grant tool (T28).
    """
    with time_check("execution_context_forgery", result):
        for tool in result.tools:
            keys = _param_keys(tool)
            name = str(tool.get("name", "")).lower().replace("-", "_")
            if keys & _FORGE_PARAMS or any(p in name for p in _FORGE_PARAMS):
                _add_l4(
                    result, "execution_context_forgery", "HIGH",
                    f"Caller-supplied execution identity on '{tool.get('name', '')}'",
                    "Tool lets the caller name who it runs as — forged attribution",
                    taxonomy_id="MCP-T22",
                )


def check_sidecar_credential_tamper(result: TargetResult) -> None:
    """MCP-T23: Credential Isolation & Sidecar Tampering.

    Tools that mutate a sidecar, credential broker, or shared secret
    volume. Hardcoded schema secrets stay on credential_in_schema (T07).
    """
    with time_check("sidecar_credential_tamper", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _SIDECAR_RE.search(blob) or (_param_keys(tool) & _SIDECAR_PARAMS):
                _add_l2(
                    result, "sidecar_credential_tamper", "HIGH",
                    f"Sidecar/credential-isolation tool: '{tool.get('name', '')}'",
                    "Tool can reach a sidecar, credential broker, or shared secret volume",
                    taxonomy_id="MCP-T23",
                )
