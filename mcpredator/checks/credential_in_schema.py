"""Detect hardcoded credentials in tool schema definitions (MCP-T07).

Scans the full tool definition JSON — including inputSchema defaults,
enum values, and descriptions — for hardcoded secrets that shouldn't
be in the schema.
"""

import json
import re

from mcpredator.core.models import TargetResult
from mcpredator.checks.base import time_check

SCHEMA_CREDENTIAL_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "openai_key"),
    (r"ghp_[a-zA-Z0-9]{36}", "github_pat"),
    (r"gho_[a-zA-Z0-9]{36}", "github_oauth"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"(?:bearer|token)\s+[a-zA-Z0-9._\-]{20,}", "bearer_token"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private_key"),
    (r"(?:postgres|mysql|mongodb|redis)://\w+:\w+@", "connection_string"),
    (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}", "jwt_token"),
    (r"xox[bpsar]-[a-zA-Z0-9-]{10,}", "slack_token"),
]


def check_credential_in_schema(result: TargetResult):
    with time_check("credential_in_schema", result):
        for tool in result.tools:
            name = tool.get("name", "")
            schema_text = json.dumps(tool, default=str)

            for pat, cred_type in SCHEMA_CREDENTIAL_PATTERNS:
                m = re.search(pat, schema_text)
                if m:
                    result.add(
                        "credential_in_schema",
                        "CRITICAL",
                        f"Hardcoded {cred_type} in tool '{name}' definition",
                        "Credential embedded in tool schema — visible to any client that calls tools/list",
                        evidence=m.group()[:200],
                    )
                    break
