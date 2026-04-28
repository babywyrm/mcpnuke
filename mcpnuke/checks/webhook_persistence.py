"""Callback and webhook persistence detection (MCP-T14).

Flags tools that accept callback URLs or webhook registrations that could
be used for persistent re-injection across sessions.
"""

import re

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check

from mcpnuke.checks._lane_helpers import lane_tagged

# All findings in this module are scoped to Lane 5 / Transport "A"
# (2026-04-26 by-lane reporting spec).
_add = lane_tagged(lane=5, transport="A")

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

WEBHOOK_NAME_PATTERNS = [
    r"(webhook|hook|callback|subscribe|notify|listener)",
]


def check_webhook_persistence(result: TargetResult):
    with time_check("webhook_persistence", result):
        for tool in result.tools:
            name = tool.get("name", "")
            desc = tool.get("description", "")
            props = tool.get("inputSchema", {}).get("properties", {})

            has_url_param = any(
                "url" in pname.lower() or pdef.get("format") == "uri"
                for pname, pdef in props.items()
            )

            for pat in WEBHOOK_NAME_PATTERNS:
                if re.search(pat, name, re.IGNORECASE) and has_url_param:
                    _add(result, 
                        "webhook_persistence",
                        "HIGH",
                        f"Webhook/callback tool '{name}' accepts URL",
                        "Tool name indicates webhook/callback registration with a URL parameter "
                        "— attacker-controlled URLs enable persistent re-injection across sessions",
                    )
                    break

            for pname, pdef in props.items():
                for pat in WEBHOOK_PARAM_PATTERNS:
                    if re.search(pat, pname, re.IGNORECASE):
                        _add(result, 
                            "webhook_persistence",
                            "HIGH",
                            f"Webhook/callback param '{pname}' in tool '{name}'",
                            "Attacker-controlled callback URLs enable persistent re-injection across sessions",
                        )
                        break

            for pat in WEBHOOK_DESC_PATTERNS:
                if re.search(pat, desc, re.IGNORECASE):
                    _add(result, 
                        "webhook_persistence",
                        "HIGH",
                        f"Webhook registration capability in '{name}'",
                        f"Description: {desc[:200]}",
                    )
                    break
