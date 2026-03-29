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

INTERPRETER_INJECTION_PROBES = [
    ("perl", f'perl -e \'print "{CANARY}"\''),
    ("ruby", f'ruby -e \'puts "{CANARY}"\''),
    ("lua", f'lua -e \'print("{CANARY}")\''),
    ("awk", f"awk 'BEGIN{{print \"{CANARY}\"}}'"),
    ("python3", f'python3 -c \'print("{CANARY}")\''),
    ("node", f'node -e \'console.log("{CANARY}")\''),
    ("php", f'php -r \'echo "{CANARY}";\''),
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
    # Private keys (highest priority — unmistakable)
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key"),
    # Cloud provider keys
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"sk-ant-[a-zA-Z0-9_\-]{20,}", "anthropic_api_key"),
    (r"sk-[a-zA-Z0-9]{20,}", "openai_key"),
    (r"ghp_[a-zA-Z0-9]{36}", "github_pat"),
    (r"gho_[a-zA-Z0-9]{36}", "github_oauth_token"),
    (r"glpat-[a-zA-Z0-9\-]{20,}", "gitlab_pat"),
    (r"xox[bporas]-[a-zA-Z0-9\-]{10,}", "slack_token"),
    (r"AIza[a-zA-Z0-9_\-]{35}", "gcp_api_key"),
    # Connection strings
    (r"(?:postgres|mysql|mongodb|redis|amqp|mssql)://\w+:\S+@", "connection_string"),
    # Bearer/JWT tokens
    (r"(?:bearer|token)\s+[a-zA-Z0-9._\-]{20,}", "bearer_token"),
    (r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+", "jwt_token"),
    # Passwords in key-value output (JSON, env, config dumps)
    (r"[\"']?(?:RCON_PASSWORD|rcon_password)[\"']?\s*[:=]\s*[\"']?\S{6,}", "rcon_password"),
    (r"[\"']?(?:ADMIN[_-]?(?:API[_-]?)?KEY|admin[_-]?(?:api[_-]?)?key)[\"']?\s*[:=]\s*[\"']?\S{6,}", "admin_api_key"),
    (r"[\"']?(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?\S{6,}", "password"),
    (r"[\"']?(?:api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']?\S{6,}", "api_key"),
    (r"[\"']?(?:secret|credential)[\"']?\s*[:=]\s*[\"']?\S{6,}", "secret"),
    (r"[\"']?(?:admin|root)\s+(?:password|pwd|pass)[\"']?\s*[:=]\s*[\"']?\S{4,}", "admin_password"),
    (r"(?:database|db)\s+(?:connection|conn)\s*[:=]?\s*\S+://", "db_connection"),
    # File path references to secrets (e.g. [file:/etc/.../key], SSH_KEY: /path/to/key)
    (r"\[file:[^\]]*(?:key|secret|credential|cert|pem)[^\]]*\]", "secret_file_reference"),
    (r"(?:KEY|key|cert|pem|secret)\s*[:=]\s*[\"']?/(?:etc|var|run|opt|home)/\S+", "secret_path_reference"),
    # Kubernetes service account tokens
    (r"/var/run/secrets/kubernetes\.io/serviceaccount/token", "k8s_sa_token_path"),
    # Internal service endpoint exposure (ClusterIP, internal DNS)
    (r"(?:KUBERNETES_SERVICE_HOST|SERVICE_HOST)\s*[:=]\s*\S+", "k8s_service_endpoint"),
]

# ---------------------------------------------------------------------------
# Input reflection — distinctive payload for detecting echo/reflection
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Encoding bypass probes — 9 techniques that commonly defeat blocklists
# ---------------------------------------------------------------------------

def _encode_bypass_probes(canary: str) -> list[tuple[str, str]]:
    """Generate 9 encoding bypass variants for a canary payload."""
    import base64
    import urllib.parse

    raw = f"echo {canary}"
    return [
        ("base64", base64.b64encode(raw.encode()).decode()),
        ("hex", raw.encode().hex()),
        ("double_url", urllib.parse.quote(urllib.parse.quote(raw))),
        ("homoglyph", raw.replace("e", "\u0435").replace("o", "\u043e")),
        ("null_byte", f"test\x00; {raw}"),
        ("crlf", f"test\r\n{raw}"),
        ("fullwidth", "".join(
            chr(0xFEE0 + ord(c)) if 0x21 <= ord(c) <= 0x7E else c for c in raw
        )),
        ("concatenation", f"ec''ho {canary}"),
        ("variable_expansion", f"${{IFS}}echo${{IFS}}{canary}"),
    ]


ENCODING_BYPASS_PROBES = _encode_bypass_probes(CANARY)

REFLECTION_PAYLOAD = f"REFLECTION_PROBE_{CANARY}"
