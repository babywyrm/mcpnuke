"""MCP protocol constants and configuration."""

from __future__ import annotations

from mcpnuke import __version__

MCP_PROTOCOL_VERSION: str = "2024-11-05"


def build_jsonrpc_request(
    method: str,
    params: dict[str, object] | None = None,
    req_id: int = 1,
) -> dict[str, object]:
    """Build a JSON-RPC 2.0 request envelope."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params or {},
    }
MCP_INIT_PARAMS: dict[str, object] = {
    "protocolVersion": MCP_PROTOCOL_VERSION,
    "capabilities": {},
    "clientInfo": {"name": "mcpnuke", "version": __version__},
}

SEVERITY_WEIGHTS: dict[str, int] = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

SEV_COLOR: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

SSE_PATHS: list[str] = ["/sse", "/mcp/sse", "/v1/sse", "/stream", "/events", ""]
POST_PATHS: list[str] = ["/mcp", "/message", "/rpc", "/jsonrpc", "/v1/mcp", "/messages", ""]

ATTACK_CHAIN_PATTERNS: list[tuple[str, str]] = [
    ("prompt_injection", "code_execution"),
    ("prompt_injection", "token_theft"),
    ("code_execution", "token_theft"),
    ("code_execution", "remote_access"),
    ("indirect_injection", "token_theft"),
    ("indirect_injection", "remote_access"),
    ("tool_poisoning", "token_theft"),
    # Behavioral chains
    ("tool_response_injection", "cross_tool_manipulation"),
    ("tool_response_injection", "token_theft"),
    ("deep_rug_pull", "tool_poisoning"),
    ("deep_rug_pull", "tool_response_injection"),
    ("input_sanitization", "code_execution"),
    ("resource_poisoning", "tool_response_injection"),
    ("state_mutation", "deep_rug_pull"),
    ("notification_abuse", "token_theft"),
    ("cross_tool_manipulation", "code_execution"),
    ("cross_tool_manipulation", "token_theft"),
    ("response_credentials", "token_theft"),
    ("response_credentials", "remote_access"),
    ("config_tampering", "code_execution"),
    ("config_tampering", "tool_poisoning"),
    ("webhook_persistence", "tool_response_injection"),
    ("webhook_persistence", "token_theft"),
    ("credential_in_schema", "token_theft"),
    ("execution_context_forgery", "token_theft"),
    ("sidecar_credential_tamper", "token_theft"),
    ("ssrf_probe", "token_theft"),
    ("ssrf_probe", "remote_access"),
    ("actuator_probe", "response_credentials"),
    ("actuator_probe", "token_theft"),
    ("exfil_flow", "token_theft"),
    ("exfil_flow", "remote_access"),
    ("config_tampering", "webhook_persistence"),
    ("jwt_algorithm", "token_theft"),
    ("jwt_weak_key", "token_theft"),
    ("jwt_ttl", "token_theft"),
]

SHADOW_TARGETS: set[str] = {
    "ls", "cat", "echo", "read", "write", "open", "close", "get", "set",
    "list", "search", "find", "help", "info", "status", "ping", "run",
    "execute", "create", "delete", "update", "fetch", "send", "post",
    "memory_read", "memory_write", "file_read", "file_write",
    "web_search", "browser", "calculator", "send_email", "send_message",
    "think", "plan", "act", "observe", "reflect",
}

# Anthropic retires dated snapshot ids, which is how the previous default
# (claude-sonnet-4-20250514) came to fail every --claude run with
# not_found_error. Prefer the undated alias, and keep this the only place the
# default lives so a retirement is a one-line change rather than a hunt
# through the CLI, the scanner and six llm call sites.
DEFAULT_CLAUDE_MODEL: str = "claude-sonnet-5"

# Bedrock is a separate catalog with separate rot. The previous default
# (anthropic.claude-3-5-sonnet-20241022-v2:0) had reached end of life and was
# gone from list-foundation-models entirely, so --bedrock answered
# ResourceNotFoundException. Two constraints shape the replacement: current
# Anthropic models on Bedrock are INFERENCE_PROFILE only, so the id needs a
# geography prefix, and the undated alias (anthropic.claude-sonnet-5) returns
# AccessDenied on ordinary accounts. Hence a dated, generally available
# profile. Non-US callers substitute eu./apac./global. via --bedrock-model.
DEFAULT_BEDROCK_MODEL: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
