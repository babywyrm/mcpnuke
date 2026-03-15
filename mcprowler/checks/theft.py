"""Token theft check."""

import re

from mcprowler.core.models import TargetResult
from mcprowler.checks.base import time_check
from mcprowler.patterns.rules import TOKEN_THEFT_PATTERNS


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
                    result.add(
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
                    result.add(
                        "token_theft",
                        "HIGH",
                        f"Tool '{name}' accepts credential param: '{pname}'",
                    )
