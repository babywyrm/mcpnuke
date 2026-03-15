"""Supply chain and dynamic package install checks."""

import re

from mcprowler.core.models import TargetResult
from mcprowler.checks.base import time_check
from mcprowler.patterns.rules import SUPPLY_CHAIN_PATTERNS


def check_supply_chain(result: TargetResult):
    """Flag tools that install packages from user-controlled or dynamic URLs."""
    with time_check("supply_chain", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + str(tool.get("inputSchema", {}))
            )

            for pat in SUPPLY_CHAIN_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    result.add(
                        "supply_chain",
                        "CRITICAL",
                        f"Supply chain risk in tool '{name}'",
                        f"Pattern suggests dynamic/user-controlled package install: {pat}",
                        evidence=combined[:300],
                    )
                    break
