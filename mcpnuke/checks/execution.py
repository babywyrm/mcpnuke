"""Code execution and remote access checks."""

import re

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.patterns.rules import CODE_EXEC_PATTERNS, RAC_PATTERNS

from mcpnuke.checks._lane_helpers import lane_tagged

# All findings in this module are scoped to Lane 4 / Transport "A"
# (2026-04-26 by-lane reporting spec).
_add = lane_tagged(lane=4, transport="A")


def check_code_execution(result: TargetResult):
    with time_check("code_execution", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + str(tool.get("inputSchema", {}))
            )

            for pat in CODE_EXEC_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    _add(result, 
                        "code_execution",
                        "CRITICAL",
                        f"Code execution indicator in tool '{name}'",
                        f"Pattern: {pat}",
                        evidence=combined[:300],
                    )
                    break

            for pname in tool.get("inputSchema", {}).get("properties", {}):
                if any(
                    kw in pname.lower()
                    for kw in [
                        "command",
                        "cmd",
                        "code",
                        "script",
                        "payload",
                        "exec",
                        "query",
                        "expression",
                        "statement",
                    ]
                ):
                    _add(result, 
                        "code_execution",
                        "HIGH",
                        f"Tool '{name}' has execution-like param: '{pname}'",
                    )


def check_remote_access(result: TargetResult):
    with time_check("remote_access", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = name + " " + tool.get("description", "")
            for category, (pattern, severity) in RAC_PATTERNS.items():
                if re.search(pattern, combined, re.IGNORECASE):
                    _add(result, 
                        "remote_access",
                        severity,
                        f"Remote access [{category}]: '{name}'",
                        tool.get("description", "")[:200],
                        evidence=f"Pattern: {pattern}",
                    )
