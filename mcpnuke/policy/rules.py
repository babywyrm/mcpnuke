"""Mapping from mcpnuke finding types to nullfield policy actions.

Each entry maps a finding check name to a nullfield action and config.
When multiple findings affect the same tool, the strictest action wins
(DENY > HOLD > SCOPE > BUDGET > ALLOW).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PolicyRule:
    action: str
    tool_names: list[str]
    reason: str
    hold: dict[str, Any] | None = None
    scope: dict[str, Any] | None = None
    budget: dict[str, Any] | None = None


ACTION_PRIORITY = {"DENY": 4, "HOLD": 3, "SCOPE": 2, "BUDGET": 1, "ALLOW": 0}

FINDING_TO_ACTION: dict[str, dict[str, Any]] = {
    # DENY — block outright
    "webhook_persistence": {"action": "DENY", "reason": "webhook persistence vector"},
    "exfil_flow": {"action": "DENY", "reason": "data exfiltration flow"},
    "remote_access": {"action": "DENY", "reason": "remote access capability"},
    "supply_chain": {"action": "DENY", "reason": "supply chain risk"},

    # HOLD — require human approval
    "code_execution": {
        "action": "HOLD",
        "reason": "code execution capability",
        "hold": {"timeout": "5m", "onTimeout": "DENY"},
    },
    "prompt_injection": {
        "action": "HOLD",
        "reason": "prompt injection vector",
        "hold": {"timeout": "5m", "onTimeout": "DENY"},
    },
    "active_prompt_injection": {
        "action": "HOLD",
        "reason": "active prompt injection confirmed",
        "hold": {"timeout": "5m", "onTimeout": "DENY"},
    },
    "tool_poisoning": {
        "action": "HOLD",
        "reason": "tool poisoning in definition",
        "hold": {"timeout": "5m", "onTimeout": "DENY"},
    },
    "config_tampering": {
        "action": "HOLD",
        "reason": "configuration tampering capability",
        "hold": {"timeout": "3m", "onTimeout": "DENY"},
    },
    "state_mutation": {
        "action": "HOLD",
        "reason": "state mutation detected",
        "hold": {"timeout": "3m", "onTimeout": "DENY"},
    },

    # SCOPE — allow but modify
    "token_theft": {
        "action": "SCOPE",
        "reason": "credential parameter exposure",
        "scope": {
            "response": {"redactPatterns": ["password", "secret", "token", "api_key", "credential"]},
        },
    },
    "credential_in_schema": {
        "action": "SCOPE",
        "reason": "credential in tool schema",
        "scope": {
            "response": {"redactPatterns": ["password", "secret", "token", "api_key"]},
        },
    },
    "response_credentials": {
        "action": "SCOPE",
        "reason": "credentials in tool response",
        "scope": {
            "response": {"redactPatterns": ["password", "secret", "token", "api_key", "private_key"]},
        },
    },
    "config_dump": {
        "action": "SCOPE",
        "reason": "infrastructure config exposure",
        "scope": {
            "response": {"redactPatterns": ["KUBERNETES_SERVICE", "password", "secret", "private_key"]},
        },
    },
    "prompt_leakage": {
        "action": "SCOPE",
        "reason": "system prompt leakage",
        "scope": {
            "response": {"redactPatterns": ["system prompt", "you are", "instructions:"]},
        },
    },
    "error_leakage": {
        "action": "SCOPE",
        "reason": "error information leakage",
        "scope": {
            "response": {"redactPatterns": ["/var/", "/etc/", "traceback", "stack trace"]},
        },
    },

    # BUDGET — rate limit
    "rate_limit": {
        "action": "BUDGET",
        "reason": "no rate limiting detected",
        "budget": {
            "perIdentity": {"maxCallsPerHour": 100},
            "perSession": {"maxCallsPerHour": 30},
            "onExhausted": "DENY",
        },
    },
    "behavioral_rate_limit": {
        "action": "BUDGET",
        "reason": "behavioral rate limit bypass",
        "budget": {
            "perIdentity": {"maxCallsPerHour": 50},
            "perSession": {"maxCallsPerHour": 20},
            "onExhausted": "DENY",
        },
    },

    # Teleport lab findings — defense rules
    "teleport_lab_bot_theft": {
        "action": "DENY",
        "reason": "bot identity theft — tbot credential exposure",
    },
    "teleport_lab_role_escalation": {
        "action": "HOLD",
        "reason": "role self-escalation via MCP tool",
        "hold": {"timeout": "5m", "onTimeout": "DENY"},
    },
    "teleport_lab_cert_replay": {
        "action": "DENY",
        "reason": "expired certificate replay attack",
    },
}
