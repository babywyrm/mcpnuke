"""Detect hardcoded credentials in tool schema definitions (MCP-T07).

Scans the full tool definition JSON — including inputSchema defaults,
enum values, and descriptions — for hardcoded secrets that shouldn't
be in the schema.
"""

import json

from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.credentials import SCHEMA_CREDENTIALS, find_credential

# Structural patterns only. Keyword patterns such as ``password: <value>``
# cannot tell a leaked secret from a JSON Schema property declaration —
# ``{"api_key": {"type": "string"}}`` satisfies them — and every tool that
# takes a credential parameter would be reported CRITICAL.
SCHEMA_CREDENTIAL_PATTERNS = SCHEMA_CREDENTIALS


def check_credential_in_schema(result: TargetResult):
    with time_check("credential_in_schema", result):
        for tool in result.tools:
            name = tool.get("name", "")
            schema_text = json.dumps(tool, default=str)

            hit = find_credential(schema_text, SCHEMA_CREDENTIAL_PATTERNS)
            if hit:
                cred_type, matched = hit
                result.add(
                    "credential_in_schema",
                    "CRITICAL",
                    f"Hardcoded {cred_type} in tool '{name}' definition",
                    "Credential embedded in tool schema — visible to any client that calls tools/list",
                    evidence=matched[:200],
                )
