"""Rate limiting and abuse resistance checks."""

import re

from mcprowler.core.models import TargetResult
from mcprowler.checks.base import time_check
from mcprowler.patterns.rules import RATE_LIMIT_PATTERNS


def check_rate_limit(result: TargetResult):
    """Flag tools that suggest no rate limiting or unbounded invocations."""
    with time_check("rate_limit", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + str(tool.get("inputSchema", {}))
            )

            for pat in RATE_LIMIT_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    result.add(
                        "rate_limit",
                        "MEDIUM",
                        f"Rate limit concern in tool '{name}'",
                        f"Pattern suggests unbounded or unthrottled usage: {pat}",
                        evidence=combined[:300],
                    )
                    break
