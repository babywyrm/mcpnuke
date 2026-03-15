"""Agent self-modification detection (MCP-T09).

Flags tools that can modify the agent's own configuration, system prompt,
or tool registry — the highest-severity finding in MCP security.
"""

import re

from mcpredator.core.models import TargetResult
from mcpredator.checks.base import time_check

CONFIG_TOOL_PATTERNS = [
    r"\b(set|update|modify|change|edit|write|save|register|add|remove|delete)_(config|settings|configuration|prompt|tool|webhook|hook|callback|plugin|extension)\b",
    r"\b(config|settings|configuration|prompt|tool|webhook|hook|callback|plugin|extension)_(set|update|modify|change|edit|write|save|register|add|remove|delete)\b",
]

CONFIG_DESC_PATTERNS = [
    r"modify\s+(system\s+)?prompt",
    r"(register|add|remove|update)\s+tool",
    r"(update|change|modify|set)\s+(config|configuration|settings)",
    r"(add|register|modify)\s+(webhook|callback|hook|plugin)",
    r"(change|update|set)\s+(system|agent)\s+(prompt|instruction|behavior)",
    r"self.?modify",
    r"reconfigure\s+(agent|system|server)",
]

CONFIG_PARAM_PATTERNS = [
    r"^(system_prompt|agent_prompt|instruction|system_instruction)$",
    r"^(config|configuration|settings|agent_config)$",
    r"^(tool_definition|tool_schema|tool_config|tool_name)$",
    r"^(webhook_url|callback_url|hook_url|event_url|notify_url)$",
    r"^(plugin|extension|module)$",
]


def check_config_tampering(result: TargetResult):
    with time_check("config_tampering", result):
        for tool in result.tools:
            name = tool.get("name", "")
            desc = tool.get("description", "")
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})

            for pat in CONFIG_TOOL_PATTERNS:
                if re.search(pat, name, re.IGNORECASE):
                    result.add(
                        "config_tampering",
                        "CRITICAL",
                        f"Agent self-modification tool: '{name}'",
                        "Tool name suggests ability to modify agent config, prompts, or tool registry",
                    )
                    break

            for pat in CONFIG_DESC_PATTERNS:
                if re.search(pat, desc, re.IGNORECASE):
                    result.add(
                        "config_tampering",
                        "CRITICAL",
                        f"Config tampering capability in '{name}'",
                        f"Description: {desc[:200]}",
                    )
                    break

            for pname in props:
                for pat in CONFIG_PARAM_PATTERNS:
                    if re.search(pat, pname, re.IGNORECASE):
                        result.add(
                            "config_tampering",
                            "HIGH",
                            f"Config/prompt param '{pname}' in tool '{name}'",
                            "Tool accepts parameters that could modify agent behavior",
                        )
                        break
