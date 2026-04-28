"""Token theft check."""

import re

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.patterns.rules import TOKEN_THEFT_PATTERNS

from mcpnuke.checks._lane_helpers import lane_tagged

# All findings in this module are scoped to Lane 2 / Transport "A"
# (2026-04-26 by-lane reporting spec).
_add = lane_tagged(lane=2, transport="A")


def check_token_theft(result: TargetResult):
    with time_check("token_theft", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + str(tool.get("inputSchema", {}))
            )

            for pat in TOKEN_THEFT_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    _add(result, 
                        "token_theft",
                        "CRITICAL",
                        f"Token theft pattern in tool '{name}'",
                        f"Pattern: {pat}",
                        evidence=combined[:300],
                    )
                    break

            for pname in tool.get("inputSchema", {}).get("properties", {}):
                if any(
                    kw in pname.lower()
                    for kw in [
                        "token",
                        "secret",
                        "password",
                        "credential",
                        "key",
                        "auth",
                    ]
                ):
                    _add(result, 
                        "token_theft",
                        "HIGH",
                        f"Tool '{name}' accepts credential param: '{pname}'",
                    )
