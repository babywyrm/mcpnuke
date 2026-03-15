"""Callback and webhook persistence detection (MCP-T14).

Flags tools that accept callback URLs or webhook registrations that could
be used for persistent re-injection across sessions.
"""

import re

from mcpredator.core.models import TargetResult
from mcpredator.checks.base import time_check

WEBHOOK_PARAM_PATTERNS = [
    r"^(callback_url|webhook_url|webhook|notify_url|callback|hook_url|event_url|notification_url|subscriber_url|listener_url)$",
    r"^(on_complete|on_finish|on_error|on_success|status_callback|result_url)$",
]

WEBHOOK_DESC_PATTERNS = [
    r"register\s+(callback|webhook|hook|notification|event\s+listener)",
    r"(webhook|callback)\s+(notification|registration|subscription)",
    r"(event|notification)\s+subscription",
    r"(notify|call\s*back|post\s+to)\s+(url|endpoint|webhook)",
    r"subscribe\s+to\s+(event|notification|update)",
]


def check_webhook_persistence(result: TargetResult):
    with time_check("webhook_persistence", result):
        for tool in result.tools:
            name = tool.get("name", "")
            desc = tool.get("description", "")
            props = tool.get("inputSchema", {}).get("properties", {})

            for pname, pdef in props.items():
                for pat in WEBHOOK_PARAM_PATTERNS:
                    if re.search(pat, pname, re.IGNORECASE):
                        result.add(
                            "webhook_persistence",
                            "HIGH",
                            f"Webhook/callback param '{pname}' in tool '{name}'",
                            "Attacker-controlled callback URLs enable persistent re-injection across sessions",
                        )
                        break

            for pat in WEBHOOK_DESC_PATTERNS:
                if re.search(pat, desc, re.IGNORECASE):
                    result.add(
                        "webhook_persistence",
                        "HIGH",
                        f"Webhook registration capability in '{name}'",
                        f"Description: {desc[:200]}",
                    )
                    break
