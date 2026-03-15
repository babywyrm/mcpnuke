"""Prompt leakage and internal instruction exposure checks."""

import re

from mcprowler.core.models import TargetResult
from mcprowler.checks.base import time_check
from mcprowler.patterns.rules import PROMPT_LEAKAGE_PATTERNS


def check_prompt_leakage(result: TargetResult):
    """Flag tools that may echo, log, or expose user prompts or internal instructions."""
    with time_check("prompt_leakage", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + str(tool.get("inputSchema", {}))
            )

            for pat in PROMPT_LEAKAGE_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    result.add(
                        "prompt_leakage",
                        "HIGH",
                        f"Prompt leakage risk in tool '{name}'",
                        f"Pattern suggests prompts may be echoed, logged, or exposed: {pat}",
                        evidence=combined[:300],
                    )
                    break
