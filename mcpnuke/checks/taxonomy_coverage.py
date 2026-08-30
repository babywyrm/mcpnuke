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
_add_l2_c = lane_tagged(lane=2, transport="C")
_add_l2_d = lane_tagged(lane=2, transport="D")
_add_l3 = lane_tagged(lane=3, transport="A")
_add_l3_b = lane_tagged(lane=3, transport="B")
_add_l4 = lane_tagged(lane=4, transport="A")
_add_l4_b = lane_tagged(lane=4, transport="B")
_add_l4_c = lane_tagged(lane=4, transport="C")
_add_l4_d = lane_tagged(lane=4, transport="D")
_add_l4_e = lane_tagged(lane=4, transport="E")

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
    r"(sidecar.{0,48}(secret|credential|token|broker))"
    r"|((secret|credential|token|broker).{0,48}sidecar)"
    r"|credential[ _]broker"
    r"|secret[ _]volume"
    r"|kube[ _]secret"
    r"|sidecar[ _]secret",
    re.IGNORECASE,
)
_SIDECAR_PARAMS: frozenset[str] = frozenset({
    "sidecar",
    "secret_mount",
    "credential_broker",
    "sidecar_secret",
    "sibling_env",
})


def _param_keys(tool: dict) -> set[str]:
    props = tool.get("inputSchema", {}).get("properties", {}) or {}
    out: set[str] = set()
    for raw in props:
        split = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(raw))
        out.add(split.lower().replace("-", "_"))
    return out


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

    Bare "nested" / "depth" / "hop" is not this threat — those match
    filesystem mkdirs. Need a delegation signal.
    """
    _STRONG: tuple[str, ...] = (
        "delegate", "forward_to_agent", "sub_agent", "spawn_agent",
        "create_agent",
    )
    _WEAK: tuple[str, ...] = ("nest", "depth", "hop")
    _PARAMS: frozenset[str] = frozenset({"agent_id", "target_agent", "delegate_to"})
    with time_check("delegation_depth", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}".lower()
            keys = _param_keys(tool)
            strong = any(kw in blob for kw in _STRONG) or bool(keys & _PARAMS)
            weak = any(kw in blob for kw in _WEAK)
            if strong or (weak and ("agent" in blob or "delegat" in blob)):
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
            if _param_keys(tool) & _FORGE_PARAMS:
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
                    "Tool can reach a sidecar credential store, broker, or secret volume",
                    taxonomy_id="MCP-T23",
                )


_BOT_PARAMS: frozenset[str] = frozenset({
    "bot_token",
    "tbot_token",
    "bot_identity",
    "machine_cert",
    "machine_identity",
    "cert_serial",
    "tbot_secret",
})
_BOT_RE = re.compile(r"\b(tbot|bot_identity|machine_cert|bot_token)\b", re.IGNORECASE)


def check_bot_identity_theft(result: TargetResult) -> None:
    """MCP-T18: Bot Identity Theft via tbot Credential Exposure."""
    with time_check("bot_identity_theft", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _BOT_RE.search(blob) or (_param_keys(tool) & _BOT_PARAMS):
                _add_l3(
                    result, "bot_identity_theft", "HIGH",
                    f"Machine/bot identity tool: '{tool.get('name', '')}'",
                    "Tool exposes machine identity or tbot certificate credentials",
                    taxonomy_id="MCP-T18",
                )


_TENANT_PARAMS: frozenset[str] = frozenset({
    "target_tenant",
    "other_tenant",
    "cross_tenant",
    "tenant_scope",
    "all_tenants",
    "tenant_id",
    "workspace_id",
})
_TENANT_RE = re.compile(r"\b(cross[ _]tenant|all[ _]tenants|tenant[ _]isolation|across[ _]tenants)\b", re.IGNORECASE)


def check_cross_tenant_memory_leak(result: TargetResult) -> None:
    """MCP-T11: Cross-Tenant Memory Leak."""
    with time_check("cross_tenant_memory_leak", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            keys = _param_keys(tool)
            if _TENANT_RE.search(blob) or (keys & _TENANT_PARAMS):
                _add_l1(
                    result, "cross_tenant_memory_leak", "HIGH",
                    f"Cross-tenant access in tool '{tool.get('name', '')}'",
                    "Tool allows caller-specified tenant selection without strict isolation",
                    taxonomy_id="MCP-T11",
                )


_AUTH_DOWNGRADE_PARAMS: frozenset[str] = frozenset({
    "allow_unauthenticated",
    "skip_auth",
    "insecure_mode",
    "bypass_auth",
    "disable_token_validation",
    "disable_signature_check",
    "auth_mode",
    "downgrade_auth",
})
_AUTH_DOWNGRADE_RE = re.compile(
    r"\b(allow[ _]unauthenticated|skip[ _]auth|insecure[ _]mode|bypass[ _]auth|auth[ _]downgrade)\b",
    re.IGNORECASE,
)


def check_auth_pattern_downgrade(result: TargetResult) -> None:
    """MCP-T24: Authentication Pattern Downgrade."""
    with time_check("auth_pattern_downgrade", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _AUTH_DOWNGRADE_RE.search(blob) or (_param_keys(tool) & _AUTH_DOWNGRADE_PARAMS):
                _add_l2(
                    result, "auth_pattern_downgrade", "HIGH",
                    f"Authentication downgrade mechanism in tool '{tool.get('name', '')}'",
                    "Tool allows disabling auth validation or downgrading to weak authentication patterns",
                    taxonomy_id="MCP-T24",
                )


_HTTP_BYPASS_PARAMS: frozenset[str] = frozenset({
    "direct_url",
    "bypass_gateway",
    "raw_http_client",
    "transport_b",
    "backend_http_url",
    "direct_http",
})
_HTTP_BYPASS_RE = re.compile(
    r"\b(bypass[ _]gateway|direct[ _]http|transport[ _]b|raw[ _]http[ _]request)\b",
    re.IGNORECASE,
)


def check_agent_http_bypass(result: TargetResult) -> None:
    """MCP-T37: Agent HTTP Bypass — Direct Transport B Access."""
    with time_check("agent_http_bypass", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _HTTP_BYPASS_RE.search(blob) or (_param_keys(tool) & _HTTP_BYPASS_PARAMS):
                _add_l3_b(
                    result, "agent_http_bypass", "HIGH",
                    f"Direct Transport B HTTP bypass in tool '{tool.get('name', '')}'",
                    "Tool bypasses MCP gateway governance for uninspected direct HTTP calls",
                    taxonomy_id="MCP-T37",
                )


_PR_SUBPROCESS_PARAMS: frozenset[str] = frozenset({
    "pr_diff",
    "pr_content",
    "patch_content",
    "apply_patch",
    "diff_text",
    "review_diff",
    "git_patch",
})
_PR_SUBPROCESS_RE = re.compile(
    r"\b(apply[ _]patch|review[ _]diff|pr[ _]diff|patch[ _]file|linter[ _]subprocess)\b",
    re.IGNORECASE,
)


def check_code_review_subprocess_injection(result: TargetResult) -> None:
    """MCP-T38: Code Review Agent — Subprocess Injection via PR Content."""
    with time_check("code_review_subprocess_injection", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _PR_SUBPROCESS_RE.search(blob) or (_param_keys(tool) & _PR_SUBPROCESS_PARAMS):
                _add_l2_d(
                    result, "code_review_subprocess_injection", "HIGH",
                    f"Untrusted PR content in subprocess tool '{tool.get('name', '')}'",
                    "Tool applies unverified PR diffs/patches directly to local tool/linter subprocesses",
                    taxonomy_id="MCP-T38",
                )


_RAG_INJECT_PARAMS: frozenset[str] = frozenset({
    "ingest_document",
    "add_to_knowledge_base",
    "index_url",
    "store_embedding",
    "rag_doc",
    "document_text",
    "untrusted_document",
})
_RAG_INJECT_RE = re.compile(
    r"\b(ingest[ _]doc|knowledge[ _]base[ _]vector|rag[ _]ingest|store[ _]embedding|index[ _]document)\b",
    re.IGNORECASE,
)


def check_rag_pipeline_injection(result: TargetResult) -> None:
    """MCP-T39: RAG Pipeline Injection — Poisoned Document Hijacks Synthesizer."""
    with time_check("rag_pipeline_injection", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _RAG_INJECT_RE.search(blob) or (_param_keys(tool) & _RAG_INJECT_PARAMS):
                _add_l4_c(
                    result, "rag_pipeline_injection", "HIGH",
                    f"RAG ingestion tool: '{tool.get('name', '')}'",
                    "Tool ingests external untrusted documents directly into RAG retrieval index",
                    taxonomy_id="MCP-T39",
                )


_GOV_REDIRECT_PARAMS: frozenset[str] = frozenset({
    "redirect_url",
    "forward_url",
    "policy_override_url",
    "governance_redirect",
    "trusted_redirect",
})
_GOV_REDIRECT_RE = re.compile(
    r"\b(governance[ _]redirect|policy[ _]override[ _]url|trusted[ _]redirect|evaluate[ _]with[ _]redirect)\b",
    re.IGNORECASE,
)


def check_ai_governance_bypass_redirect(result: TargetResult) -> None:
    """MCP-T41: AI Governance Gate Bypass via Trusted Redirect."""
    with time_check("ai_governance_bypass_redirect", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _GOV_REDIRECT_RE.search(blob) or (_param_keys(tool) & _GOV_REDIRECT_PARAMS):
                _add_l2(
                    result, "ai_governance_bypass_redirect", "HIGH",
                    f"Governance redirect in tool '{tool.get('name', '')}'",
                    "Tool evaluates policy against a redirect or untrusted target URL",
                    taxonomy_id="MCP-T41",
                )


_DIRECT_FORWARD_PARAMS: frozenset[str] = frozenset({
    "auth_header",
    "forward_auth",
    "bearer_token_forward",
    "forward_token",
    "upstream_authorization",
})
_DIRECT_FORWARD_RE = re.compile(
    r"\b(forward[ _]auth|bearer[ _]token[ _]forward|authorization[ _]header[ _]forward|direct[ _]api[ _]credential)\b",
    re.IGNORECASE,
)


def check_direct_api_credential_forwarding(result: TargetResult) -> None:
    """MCP-T45: Agent-to-Agent Identity Dilution via Direct API Credential Forwarding."""
    with time_check("direct_api_credential_forwarding", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _DIRECT_FORWARD_RE.search(blob) or (_param_keys(tool) & _DIRECT_FORWARD_PARAMS):
                _add_l4_b(
                    result, "direct_api_credential_forwarding", "HIGH",
                    f"Direct API credential forwarding in tool '{tool.get('name', '')}'",
                    "Tool forwards raw authorization headers across direct API boundaries",
                    taxonomy_id="MCP-T45",
                )


_SDK_CACHE_PARAMS: frozenset[str] = frozenset({
    "sdk_cache",
    "token_cache",
    "in_memory_tokens",
    "cache_name",
    "dump_cache",
    "cached_credentials",
})
_SDK_CACHE_RE = re.compile(
    r"\b(sdk[ _]cache|token[ _]cache|in[ _]memory[ _]token|dump[ _]token[ _]cache)\b",
    re.IGNORECASE,
)


def check_sdk_credential_cache_exposure(result: TargetResult) -> None:
    """MCP-T46: In-Process SDK Credential Cache Exposure."""
    with time_check("sdk_credential_cache_exposure", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _SDK_CACHE_RE.search(blob) or (_param_keys(tool) & _SDK_CACHE_PARAMS):
                _add_l2_c(
                    result, "sdk_credential_cache_exposure", "HIGH",
                    f"SDK credential cache exposed in tool '{tool.get('name', '')}'",
                    "Tool provides access to in-process SDK token caches or session credentials",
                    taxonomy_id="MCP-T46",
                )


_SDK_CHAIN_PARAMS: frozenset[str] = frozenset({
    "sdk_chain",
    "call_sdk_function",
    "in_process_delegate",
    "sdk_subagent",
    "chain_sdk",
})
_SDK_CHAIN_RE = re.compile(
    r"\b(sdk[ _]chain|in[ _]process[ _]sdk|sdk[ _]delegate|sdk[ _]invocation[ _]chain)\b",
    re.IGNORECASE,
)


def check_agent_sdk_chain_identity_dilution(result: TargetResult) -> None:
    """MCP-T47: Agent Chain In-Process SDK Identity Dilution."""
    with time_check("agent_sdk_chain_identity_dilution", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _SDK_CHAIN_RE.search(blob) or (_param_keys(tool) & _SDK_CHAIN_PARAMS):
                _add_l4_c(
                    result, "agent_sdk_chain_identity_dilution", "HIGH",
                    f"In-process SDK chain tool: '{tool.get('name', '')}'",
                    "Tool chains SDK invocations without propagating caller identity attribution",
                    taxonomy_id="MCP-T47",
                )


_SUBPROC_ENV_PARAMS: frozenset[str] = frozenset({
    "env_passthrough",
    "inject_credentials",
    "child_env",
    "pass_parent_env",
    "inject_env_token",
})
_SUBPROC_ENV_RE = re.compile(
    r"\b(env[ _]passthrough|inject[ _]credential|child[ _]env|pass[ _]parent[ _]env)\b",
    re.IGNORECASE,
)


def check_agent_subprocess_credential_injection(result: TargetResult) -> None:
    """MCP-T48: Agent Chain Subprocess Credential Injection."""
    with time_check("agent_subprocess_credential_injection", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _SUBPROC_ENV_RE.search(blob) or (_param_keys(tool) & _SUBPROC_ENV_PARAMS):
                _add_l4_d(
                    result, "agent_subprocess_credential_injection", "HIGH",
                    f"Subprocess credential injection tool: '{tool.get('name', '')}'",
                    "Tool injects parent process credentials into child process environment",
                    taxonomy_id="MCP-T48",
                )


_LLM_CONTEXT_PARAMS: frozenset[str] = frozenset({
    "full_transcript",
    "raw_context",
    "system_prompt_pass",
    "conversation_history",
    "raw_conversation",
})
_LLM_CONTEXT_RE = re.compile(
    r"\b(full[ _]transcript|raw[ _]context|conversation[ _]history|system[ _]prompt[ _]pass)\b",
    re.IGNORECASE,
)


def check_agent_llm_function_context_leak(result: TargetResult) -> None:
    """MCP-T49: Agent Chain LLM Function-Calling Context Leak."""
    with time_check("agent_llm_function_context_leak", result):
        for tool in result.tools:
            blob = f"{tool.get('name', '')} {tool.get('description', '') or ''}"
            if _LLM_CONTEXT_RE.search(blob) or (_param_keys(tool) & _LLM_CONTEXT_PARAMS):
                _add_l4_e(
                    result, "agent_llm_function_context_leak", "HIGH",
                    f"LLM context leak in tool '{tool.get('name', '')}'",
                    "Tool forwards raw conversation history or system prompts into downstream function calls",
                    taxonomy_id="MCP-T49",
                )

