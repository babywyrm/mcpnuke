"""Probe payloads and response analysis patterns for behavioral MCP testing.

These are used by tool_probes.py and enhanced behavioral checks to actively
interact with MCP servers and detect threats that static analysis misses.
"""

import re

# Unique canary embedded in probes to detect echoing / processing
CANARY = "MCP_PROBE_8f4c2a"

# ---------------------------------------------------------------------------
# Safe default values for tool argument generation
# ---------------------------------------------------------------------------

SAFE_DEFAULTS = {
    "string": "test",
    "number": 1,
    "integer": 1,
    "boolean": False,
    "object": {},
    "array": [],
}

# Context-aware safe values keyed by param name regex
PARAM_SAFE_VALUES = [
    (r"(path|file|dir|folder)", f"/tmp/mcp_probe_{CANARY}"),
    (r"(url|uri|endpoint|href)", "http://example.com/test"),
    (r"(command|cmd|exec)", "echo hello"),
    (r"(code|script|expression)", "1+1"),
    (r"(query|sql)", "SELECT 1"),
    (r"(user|username|name)", "probe_user"),
    (r"(email)", "probe@example.com"),
    (r"(host|hostname|server)", "localhost"),
    (r"(port)", "8080"),
    (r"(password|secret|token|key|auth)", CANARY),
    (r"(action|method|operation)", "read"),
    (r"(content|text|message|body|data)", f"probe content {CANARY}"),
    (r"(language|lang)", "python"),
    (r"(format|type)", "json"),
    (r"(count|limit|size|num)", "5"),
]

# ---------------------------------------------------------------------------
# Injection probe payloads (safe but detectable)
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_PROBES = [
    f"../../../tmp/{CANARY}",
    f"/tmp/../../../etc/hostname",
    f"....//....//tmp/{CANARY}",
    f"/tmp/{CANARY}/%00.txt",
]

COMMAND_INJECTION_PROBES = [
    f"test; echo {CANARY}",
    f"test | echo {CANARY}",
    f"test && echo {CANARY}",
    f"test `echo {CANARY}`",
    f"test $({CANARY})",
]

TEMPLATE_INJECTION_PROBES = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    f"${{'{CANARY}'}}",
    "#{7*7}",
]

SQL_INJECTION_PROBES = [
    "' OR '1'='1",
    f"1; SELECT '{CANARY}'--",
    "1 UNION SELECT 1--",
]

TEMPLATE_INJECTION_PROBES_V2 = [
    ("{{1333*7}}", "9331"),    # distinctive product unlikely in normal output
    ("${1333*7}", "9331"),
    ("<%= 1333*7 %>", "9331"),
    ("#{1333*7}", "9331"),
]

# ---------------------------------------------------------------------------
# Response analysis patterns — what to look for in tool output
# ---------------------------------------------------------------------------

RESPONSE_INJECTION_PATTERNS = [
    r"ignore\s+(previous|prior|above|all)\s+instruction",
    r"you\s+(must|should|are\s+required\s+to)\s+",
    r"(do\s+not|never)\s+(tell|mention|say|reveal|disclose)",
    r"<\s*SYSTEM\s*>",
    r"\[INST\]",
    r"###\s*(instruction|system|human|assistant)",
    r"IMPORTANT:\s*(always|never|you\s+must)",
    r"your\s+new\s+(role|task|goal|instruction)",
    r"(pretend|act\s+as|you\s+are\s+now)",
    r"forget\s+(everything|all|your)",
    r"override\s+(your\s+)?(previous\s+)?instruction",
    r"(disregard|bypass)\s+(all\s+)?(safety|security|guardrail|filter)",
]

RESPONSE_EXFIL_PATTERNS = [
    r"https?://[^\s'\"<>]*(?:webhook|ngrok|burp|requestbin|pipedream|canarytokens|interactsh|oast)",
    r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/",
    r"data:[a-z]+/[a-z]+;base64,",
]

CROSS_TOOL_PATTERNS = [
    r"(?:please\s+)?(?:call|use|invoke|run|execute)\s+(?:the\s+)?['\"]?(\w+)['\"]?\s+(?:tool|function)",
    r"(?:now|next|then)\s+(?:call|use|invoke|run)\s+['\"]?(\w+)['\"]?",
    r"tools?/call.*?name[\"']?\s*:\s*[\"'](\w+)",
]

HIDDEN_CONTENT_PATTERNS = [
    r"<!--[\s\S]*?-->",
    r"<\s*hidden\s*>[\s\S]*?</\s*hidden\s*>",
    r"\[hidden\][\s\S]*?\[/hidden\]",
    r"<\s*script[\s\S]*?</\s*script\s*>",
    r"<\s*style[\s\S]*?</\s*style\s*>",
]

ERROR_LEAKAGE_PATTERNS = [
    r"Traceback \(most recent call",
    r"File \"[^\"]+\",\s*line \d+",
    r"(?:at\s+)?[\w.]+\.py:\d+",
    r"/(?:home|usr|opt|var|etc|app|srv)/[\w/.-]+\.(?:py|js|go|rs|rb|java)",
    r"(?:psycopg2|mysql|sqlite3|pymongo)\.\w+Error",
    r"(?:SECRET|PASSWORD|TOKEN|KEY|DATABASE_URL)\s*=",
    r"(?:BEGIN (?:RSA )?PRIVATE KEY)",
    r"(?:mongodb|postgres|mysql|redis)://\w+:\w+@",
    r"stack\s*trace|stacktrace",
]

STEGANOGRAPHIC_RANGES = [
    range(0x200B, 0x2010),  # zero-width chars
    range(0x202A, 0x202F),  # bidi overrides
    range(0x2060, 0x2065),  # invisible formatters
]

CSS_HIDDEN_PATTERN = re.compile(
    r"<[^>]+style\s*=\s*[\"'][^\"']*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)"
    r"[^\"']*[\"'][^>]*>[\s\S]*?</\w+>",
    re.IGNORECASE,
)

MD_IMAGE_EXFIL_PATTERN = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)")


def has_invisible_unicode(text: str, threshold: int = 3) -> list[str]:
    """Return invisible chars found in text, empty list if below threshold."""
    found = [
        ch for ch in text
        if ord(ch) == 0xFEFF or any(ord(ch) in r for r in STEGANOGRAPHIC_RANGES)
    ]
    return found if len(found) >= threshold else []


# ---------------------------------------------------------------------------
# Credential content patterns — detect actual secrets in resource/response text
# ---------------------------------------------------------------------------

CREDENTIAL_CONTENT_PATTERNS = [
    (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "password"),
    (r"(?:api[_-]?key|apikey)\s*[:=]\s*\S+", "api_key"),
    (r"sk-[a-zA-Z0-9]{20,}", "openai_key"),
    (r"ghp_[a-zA-Z0-9]{36}", "github_pat"),
    (r"(?:bearer|token)\s+[a-zA-Z0-9._\-]{20,}", "bearer_token"),
    (r"(?:postgres|mysql|mongodb|redis)://\w+:\w+@", "connection_string"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private_key"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"(?:secret|credential)\s*[:=]\s*\S+", "secret"),
    (r"(?:admin|root)\s+(?:password|pwd|pass)\s*[:=]\s*\S+", "admin_password"),
    (r"(?:database|db)\s+(?:connection|conn)\s*[:=]?\s*\S+://", "db_connection"),
]

# ---------------------------------------------------------------------------
# Input reflection — distinctive payload for detecting echo/reflection
# ---------------------------------------------------------------------------

REFLECTION_PAYLOAD = f"REFLECTION_PROBE_{CANARY}"
