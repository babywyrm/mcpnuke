"""Regex patterns for MCP security checks."""

INJECTION_PATTERNS = [
    r"ignore\s+(previous|prior|above|all)\s+instruction",
    r"you\s+are\s+now",
    r"do\s+not\s+follow",
    r"override\s+(your\s+)?(previous\s+)?instruction",
    r"system\s*prompt",
    r"jailbreak",
    r"disregard\s+(your\s+)?",
    r"forget\s+(everything|all|your)",
    r"new\s+persona",
    r"act\s+as\s+(if\s+you\s+are|an?\s+)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"your\s+new\s+(role|task|goal|instruction)",
    r"<\s*SYSTEM\s*>",
    r"\[INST\]",
    r"###\s*(instruction|system|human|assistant)",
    r"<\s*/?s\s*>",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[\/INST\]",
    r"IGNORE ALL PREVIOUS",
    r"END OF CONVERSATION",
    # Previously private to tool_output_poisoning, so the primary
    # prompt_injection check could not see them.
    r"system:\s*you\s+(are|must|should)",
    r"from\s+now\s+on,?\s+(always|never|do\s+not)",
    r"(override|bypass|disable)\s+(the\s+)?(safety|security|filter)",
]

# Every consumer searches with re.IGNORECASE, so these stay plain strings —
# passing a flag alongside a precompiled pattern raises.

POISON_PATTERNS = [
    r"<\s*hidden\s*>",
    r"<!--.*?-->",
    r"\[hidden\]",
    r"(send|exfil|leak|transmit|upload).{0,30}(secret|token|key|password|credential)",
    r"(POST|GET|fetch|curl|wget).{0,60}(http|https)",
    r"always\s+(respond|reply|say|output)",
    r"never\s+(mention|say|tell|reveal)",
    r"when\s+(asked|prompted|queried).{0,30}(say|respond|output)",
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]",
    r"data:text/html",
    r"javascript:",
]

# Anchored, and matched against the normalized identifier (patterns/tokens.py),
# so `run_command` matches and `trigger-long-running-operation` does not.
# Unanchored, `run` matched "running", `sh` matched "show" and "push", and
# `key` matched "monkey" — CRITICAL findings on real open-source servers for
# tools with no such capability. See docs/oss-target-baseline.md.
# Multi-word alternatives use [ _] so they match both a normalized name
# ("read file") and a raw description ("read_file").
DANGEROUS_TOOL_PATTERNS = {
    "shell_exec": (
        r"\b(shell|exec|run|execute|cmd|bash|sh|powershell|eval|system)\b",
        "CRITICAL",
    ),
    "filesystem": (
        r"\b(read[ _]file|write[ _]file|delete|remove|mkdir|listdir|readdir"
        r"|glob|file[ _]read|file[ _]write)\b",
        "HIGH",
    ),
    "network": (
        r"\b(fetch|curl|wget|http[ _]get|http[ _]post|request|socket|connect"
        r"|http[ _]request)\b",
        "HIGH",
    ),
    "database": (
        r"\b(sql|query|database|db[ _]exec|mongo|redis|execute[ _]query"
        r"|db[ _]query)\b",
        "HIGH",
    ),
    "code_eval": (
        r"\b(eval|exec|compile|__import__|subprocess|popen|code[ _]exec)\b",
        "CRITICAL",
    ),
    "secrets_access": (
        r"\b(secret|credential|password|token|key|vault|ssm|aws[ _]secret)\b",
        "HIGH",
    ),
    "cloud_api": (
        r"\b(iam|s3|ec2|gcp|azure|k8s|kubectl|terraform|cloud[ _]exec)\b",
        "HIGH",
    ),
    "process_mgmt": (
        r"\b(kill|signal|fork|spawn|process(es)?|proc[ _]exec)\b",
        "MEDIUM",
    ),
}

TOKEN_THEFT_PATTERNS = [
    r"(provide|give|send|include|pass).{0,30}(token|credential|password|secret|key|auth)",
    r"(authorization|bearer|api.?key|access.?token)",
    r"(forward|relay|proxy|tunnel|send).{0,30}(to|via|through).{0,30}(http|https|url|endpoint)",
    r"/var/run/secrets",
    r"kubernetes\.io/serviceaccount",
    r"KUBECONFIG|\.kube/config",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"instance-data\.ec2\.internal",
    r"imds",
]

CODE_EXEC_PATTERNS = [
    r"(subprocess|popen|system|exec|eval|compile)\s*\(",
    r"(os\.system|os\.popen|os\.execv)",
    r"(shell\s*=\s*True)",
    r"(bash|sh|zsh|pwsh|cmd\.exe)\s+-c",
    r"(python|node|ruby|perl|php)\s+-[ce]",
    r"`[^`]+`",
    r"\$\([^\)]+\)",
    r"&&\s*(rm|dd|mkfs|wget|curl|nc|socat)",
    r">(>?)\s*/dev/(null|tcp|udp)",
]

RATE_LIMIT_PATTERNS = [
    r"unlimited\s+(requests?|calls?|invocations?)",
    r"no\s+(rate\s+)?limit",
    r"throttle.?free",
    r"burst\s+allowed",
    r"unbounded\s+(api|request|call)",
]

PROMPT_LEAKAGE_PATTERNS = [
    r"internal\s+prompt",
    r"system\s+prompt",
    r"echo\s+(user|input|prompt)",
    r"log\s+(user|prompt|instruction)",
    r"store\s+(user|prompt|conversation)",
    r"leak\s+(prompt|instruction)",
    r"expose\s+(system|internal)\s+(prompt|instruction)",
    r"debug\s+mode.*prompt",
]

SUPPLY_CHAIN_PATTERNS = [
    r"npm\s+install\s+.*\$\{|npm\s+install\s+.*%s",
    r"pip\s+install\s+.*\$\{|pip\s+install\s+.*%s",
    r"curl\s+.*\|\s*(bash|sh|python)",
    r"wget\s+.*\|\s*(bash|sh|python)",
    r"eval\s*\(\s*.*(url|fetch|http)",
    r"install\s+from\s+(url|http|user.?provided)",
    r"dynamic\s+package\s+install",
    r"user.?controlled\s+(package|dependency|url)",
    r"user.?provided\s+(url|package|dependency)",
]

RAC_PATTERNS = {
    # Anchored for the same reason as DANGEROUS_TOOL_PATTERNS above: `nc`
    # unanchored matched "reference", "branch" and "encoding", making CRITICAL
    # reverse-shell findings out of `git branch` and `read_text_file`.
    "reverse_shell": (
        r"\b(nc|ncat|socat|netcat|bash\s+-i|/dev/tcp|reverse.?shell)\b",
        "CRITICAL",
    ),
    "port_forward": (
        r"\b(port.?forward|tunnel|socks|proxy\s+port)\b",
        "HIGH",
    ),
    "remote_desktop": (
        r"\b(vnc|rdp|teamviewer|anydesk|screenshare)\b",
        "HIGH",
    ),
    "c2_beacon": (
        r"\b(beacon|c2|command.and.control|meterpreter|cobalt.?strike|sliver"
        r"|havoc)\b",
        "CRITICAL",
    ),
    "network_scan": (
        r"\b(nmap|masscan|zmap|shodan|port.?scan|host.?discovery)\b",
        "HIGH",
    ),
    # `exfiltrat\w*` keeps the stem working: \bexfiltrat\b would never match
    # "exfiltration".
    "data_exfil": (
        r"\b(exfil|exfiltrat\w*|data.?transfer|upload.{0,20}(s3|ftp|http))\b",
        "HIGH",
    ),
}
