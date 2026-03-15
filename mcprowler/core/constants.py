"""MCP protocol constants and configuration."""

MCP_PROTOCOL_VERSION = "2024-11-05"
MCP_INIT_PARAMS = {
    "protocolVersion": MCP_PROTOCOL_VERSION,
    "capabilities": {},
    "clientInfo": {"name": "mcprowler", "version": "4.1"},
}

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}

SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

SSE_PATHS = ["/sse", "/mcp/sse", "/v1/sse", "/stream", "/events", ""]
POST_PATHS = ["/mcp", "/rpc", "/jsonrpc", "/v1/mcp", "/messages", ""]

ATTACK_CHAIN_PATTERNS = [
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
]

SHADOW_TARGETS = {
    "ls", "cat", "echo", "read", "write", "open", "close", "get", "set",
    "list", "search", "find", "help", "info", "status", "ping", "run",
    "execute", "create", "delete", "update", "fetch", "send", "post",
    "memory_read", "memory_write", "file_read", "file_write",
    "web_search", "browser", "calculator", "send_email", "send_message",
    "think", "plan", "act", "observe", "reflect",
}
