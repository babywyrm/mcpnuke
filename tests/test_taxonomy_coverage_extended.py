"""Comprehensive tests for extended taxonomy coverage checks (MCP-T11 to MCP-T49).

Ensures all new checks adhere to:
1. Positive detection on matching tool schemas / parameters
2. Clean negative on benign tools
3. Reference target negative (0 false positives on standard tool inventory)
4. Execution timing recorded in TargetResult.timings
5. Correct taxonomy_id, severity, and lane attribution
"""

from __future__ import annotations

from mcpnuke.checks.taxonomy_coverage import (
    check_agent_http_bypass,
    check_agent_llm_function_context_leak,
    check_agent_sdk_chain_identity_dilution,
    check_agent_subprocess_credential_injection,
    check_ai_governance_bypass_redirect,
    check_auth_pattern_downgrade,
    check_bot_identity_theft,
    check_code_review_subprocess_injection,
    check_cross_tenant_memory_leak,
    check_direct_api_credential_forwarding,
    check_rag_pipeline_injection,
    check_sdk_credential_cache_exposure,
)
from mcpnuke.core.models import TargetResult
from tests.reference_target.tools import TOOL_DEFINITIONS


def _result(tools: list[dict], *, transport: str = "http", auth_token: str | None = None) -> TargetResult:
    r = TargetResult(url="http://localhost:8080/mcp")
    r.transport = transport
    r.tools = tools
    if auth_token:
        r.auth_context["_raw_token"] = auth_token
    return r


def _findings(r: TargetResult, check_name: str) -> list:
    return [f for f in r.findings if f.check == check_name]


# --- MCP-T18: Bot Identity Theft ---

def test_bot_identity_theft_positive() -> None:
    r = _result([{
        "name": "bot.issue_certificate",
        "description": "Issue short-lived machine credentials via tbot identity",
        "inputSchema": {"properties": {"bot_token": {"type": "string"}}},
    }])
    check_bot_identity_theft(r)
    found = _findings(r, "bot_identity_theft")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T18"
    assert found[0].lane == 3


def test_bot_identity_theft_clean() -> None:
    r = _result([{"name": "status", "description": "Check status", "inputSchema": {}}])
    check_bot_identity_theft(r)
    assert _findings(r, "bot_identity_theft") == []
    assert "bot_identity_theft" in r.timings


# --- MCP-T11: Cross-Tenant Memory Leak ---

def test_cross_tenant_memory_leak_positive() -> None:
    r = _result([{
        "name": "tenant.recall_all_memories",
        "description": "Recall memories across all tenant stores",
        "inputSchema": {"properties": {"target_tenant": {"type": "string"}}},
    }])
    check_cross_tenant_memory_leak(r)
    found = _findings(r, "cross_tenant_memory_leak")
    assert len(found) == 1
    assert found[0].severity in ("HIGH", "MEDIUM")
    assert found[0].taxonomy_id == "MCP-T11"
    assert found[0].lane == 1


def test_cross_tenant_memory_leak_clean() -> None:
    r = _result([{"name": "math.add", "description": "Add two numbers", "inputSchema": {}}])
    check_cross_tenant_memory_leak(r)
    assert _findings(r, "cross_tenant_memory_leak") == []
    assert "cross_tenant_memory_leak" in r.timings


# --- MCP-T24: Authentication Pattern Downgrade ---

def test_auth_pattern_downgrade_positive() -> None:
    r = _result([{
        "name": "gateway.connect",
        "description": "Connect to remote service with optional auth bypass",
        "inputSchema": {"properties": {"allow_unauthenticated": {"type": "boolean"}}},
    }])
    check_auth_pattern_downgrade(r)
    found = _findings(r, "auth_pattern_downgrade")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T24"
    assert found[0].lane == 2


def test_auth_pattern_downgrade_clean() -> None:
    r = _result([{"name": "auth.verify", "description": "Strict token verification", "inputSchema": {}}])
    check_auth_pattern_downgrade(r)
    assert _findings(r, "auth_pattern_downgrade") == []
    assert "auth_pattern_downgrade" in r.timings


# --- MCP-T37: Agent HTTP Bypass ---

def test_agent_http_bypass_positive() -> None:
    r = _result([{
        "name": "transport.direct_request",
        "description": "Bypass MCP gateway and send direct raw HTTP request",
        "inputSchema": {"properties": {"direct_url": {"type": "string"}}},
    }])
    check_agent_http_bypass(r)
    found = _findings(r, "agent_http_bypass")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T37"
    assert found[0].lane == 3


def test_agent_http_bypass_clean() -> None:
    r = _result([{"name": "format.json", "description": "Format json string", "inputSchema": {}}])
    check_agent_http_bypass(r)
    assert _findings(r, "agent_http_bypass") == []
    assert "agent_http_bypass" in r.timings


# --- MCP-T38: Code Review PR Subprocess Injection ---

def test_code_review_subprocess_injection_positive() -> None:
    r = _result([{
        "name": "code_review.apply_and_lint",
        "description": "Apply unverified pull request diff and execute linter subprocess",
        "inputSchema": {"properties": {"pr_diff": {"type": "string"}}},
    }])
    check_code_review_subprocess_injection(r)
    found = _findings(r, "code_review_subprocess_injection")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T38"
    assert found[0].lane == 2


def test_code_review_subprocess_injection_clean() -> None:
    r = _result([{"name": "read_readme", "description": "Read project documentation", "inputSchema": {}}])
    check_code_review_subprocess_injection(r)
    assert _findings(r, "code_review_subprocess_injection") == []
    assert "code_review_subprocess_injection" in r.timings


# --- MCP-T39: RAG Pipeline Ingestion Injection ---

def test_rag_pipeline_injection_positive() -> None:
    r = _result([{
        "name": "rag.ingest_external_doc",
        "description": "Ingest unvalidated document into knowledge base vector store",
        "inputSchema": {"properties": {"document_text": {"type": "string"}}},
    }])
    check_rag_pipeline_injection(r)
    found = _findings(r, "rag_pipeline_injection")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T39"
    assert found[0].lane == 4


def test_rag_pipeline_injection_clean() -> None:
    r = _result([{"name": "search_catalog", "description": "Read-only query of search index", "inputSchema": {}}])
    check_rag_pipeline_injection(r)
    assert _findings(r, "rag_pipeline_injection") == []
    assert "rag_pipeline_injection" in r.timings


# --- MCP-T41: AI Governance Bypass via Redirect ---

def test_ai_governance_bypass_redirect_positive() -> None:
    r = _result([{
        "name": "policy.evaluate_with_redirect",
        "description": "Evaluate AI policy action with target redirect URL",
        "inputSchema": {"properties": {"redirect_url": {"type": "string"}}},
    }])
    check_ai_governance_bypass_redirect(r)
    found = _findings(r, "ai_governance_bypass_redirect")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T41"
    assert found[0].lane == 2


def test_ai_governance_bypass_redirect_clean() -> None:
    r = _result([{"name": "policy.check", "description": "Check action permission", "inputSchema": {}}])
    check_ai_governance_bypass_redirect(r)
    assert _findings(r, "ai_governance_bypass_redirect") == []
    assert "ai_governance_bypass_redirect" in r.timings


# --- MCP-T45: Direct API Credential Forwarding ---

def test_direct_api_credential_forwarding_positive() -> None:
    r = _result([{
        "name": "agent.forward_call",
        "description": "Forward request to external REST API carrying authorization header",
        "inputSchema": {"properties": {"auth_header": {"type": "string"}}},
    }])
    check_direct_api_credential_forwarding(r)
    found = _findings(r, "direct_api_credential_forwarding")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T45"
    assert found[0].lane == 4


def test_direct_api_credential_forwarding_clean() -> None:
    r = _result([{"name": "time.now", "description": "Get current timestamp", "inputSchema": {}}])
    check_direct_api_credential_forwarding(r)
    assert _findings(r, "direct_api_credential_forwarding") == []
    assert "direct_api_credential_forwarding" in r.timings


# --- MCP-T46: In-Process SDK Credential Cache Exposure ---

def test_sdk_credential_cache_exposure_positive() -> None:
    r = _result([{
        "name": "sdk.dump_token_cache",
        "description": "Dump active in-process SDK token cache",
        "inputSchema": {"properties": {"cache_name": {"type": "string"}}},
    }])
    check_sdk_credential_cache_exposure(r)
    found = _findings(r, "sdk_credential_cache_exposure")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T46"
    assert found[0].lane == 2


def test_sdk_credential_cache_exposure_clean() -> None:
    r = _result([{"name": "sdk.version", "description": "Return SDK version string", "inputSchema": {}}])
    check_sdk_credential_cache_exposure(r)
    assert _findings(r, "sdk_credential_cache_exposure") == []
    assert "sdk_credential_cache_exposure" in r.timings


# --- MCP-T47: Agent Chain SDK Identity Dilution ---

def test_agent_sdk_chain_identity_dilution_positive() -> None:
    r = _result([{
        "name": "agent_chain.dispatch_sdk",
        "description": "Dispatch in-process SDK invocation across subagent chain",
        "inputSchema": {"properties": {"sdk_chain": {"type": "string"}}},
    }])
    check_agent_sdk_chain_identity_dilution(r)
    found = _findings(r, "agent_sdk_chain_identity_dilution")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T47"
    assert found[0].lane == 4


def test_agent_sdk_chain_identity_dilution_clean() -> None:
    r = _result([{"name": "convert_units", "description": "Convert measurement units", "inputSchema": {}}])
    check_agent_sdk_chain_identity_dilution(r)
    assert _findings(r, "agent_sdk_chain_identity_dilution") == []
    assert "agent_sdk_chain_identity_dilution" in r.timings


# --- MCP-T48: Agent Chain Subprocess Credential Injection ---

def test_agent_subprocess_credential_injection_positive() -> None:
    r = _result([{
        "name": "worker.spawn_with_env",
        "description": "Spawn child worker process injecting parent credentials into environment",
        "inputSchema": {"properties": {"env_passthrough": {"type": "boolean"}}},
    }])
    check_agent_subprocess_credential_injection(r)
    found = _findings(r, "agent_subprocess_credential_injection")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T48"
    assert found[0].lane == 4


def test_agent_subprocess_credential_injection_clean() -> None:
    r = _result([{"name": "calc.sqrt", "description": "Calculate square root", "inputSchema": {}}])
    check_agent_subprocess_credential_injection(r)
    assert _findings(r, "agent_subprocess_credential_injection") == []
    assert "agent_subprocess_credential_injection" in r.timings


# --- MCP-T49: Agent Chain LLM Function Context Leak ---

def test_agent_llm_function_context_leak_positive() -> None:
    r = _result([{
        "name": "llm.dispatch_subagent",
        "description": "Dispatch subagent function call forwarding full raw conversation context",
        "inputSchema": {"properties": {"full_transcript": {"type": "string"}}},
    }])
    check_agent_llm_function_context_leak(r)
    found = _findings(r, "agent_llm_function_context_leak")
    assert len(found) == 1
    assert found[0].severity == "HIGH"
    assert found[0].taxonomy_id == "MCP-T49"
    assert found[0].lane == 4


def test_agent_llm_function_context_leak_clean() -> None:
    r = _result([{"name": "string.trim", "description": "Trim whitespace from string", "inputSchema": {}}])
    check_agent_llm_function_context_leak(r)
    assert _findings(r, "agent_llm_function_context_leak") == []
    assert "agent_llm_function_context_leak" in r.timings


# --- Reference Target Zero False Positives ---

def test_reference_target_clean_across_all_extended_checks() -> None:
    r = _result(list(TOOL_DEFINITIONS))
    check_bot_identity_theft(r)
    check_cross_tenant_memory_leak(r)
    check_auth_pattern_downgrade(r)
    check_agent_http_bypass(r)
    check_code_review_subprocess_injection(r)
    check_rag_pipeline_injection(r)
    check_ai_governance_bypass_redirect(r)
    check_direct_api_credential_forwarding(r)
    check_sdk_credential_cache_exposure(r)
    check_agent_sdk_chain_identity_dilution(r)
    check_agent_subprocess_credential_injection(r)
    check_agent_llm_function_context_leak(r)

    extended_findings = [
        f for f in r.findings
        if f.check in (
            "bot_identity_theft",
            "cross_tenant_memory_leak",
            "auth_pattern_downgrade",
            "agent_http_bypass",
            "code_review_subprocess_injection",
            "rag_pipeline_injection",
            "ai_governance_bypass_redirect",
            "direct_api_credential_forwarding",
            "sdk_credential_cache_exposure",
            "agent_sdk_chain_identity_dilution",
            "agent_subprocess_credential_injection",
            "agent_llm_function_context_leak",
        )
    ]
    assert extended_findings == [], f"Unexpected findings on reference target: {extended_findings}"
