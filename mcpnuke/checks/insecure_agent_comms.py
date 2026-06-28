"""MCP-T13: Insecure inter-agent communication.

Static check that detects tools enabling agent-to-agent message passing without
cryptographic verification (signatures, MACs, or attestation). If one agent can
send arbitrary messages to another through a tool, and the receiving agent trusts
those messages without verification, a compromised sub-agent can inject poisoned
instructions into the orchestrator's context.

Lane 4 (Agent Chain) / Transport A (MCP JSON-RPC).
"""

from __future__ import annotations

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult

_add = lane_tagged(lane=4, transport="A")

# Tool names/descriptions suggesting inter-agent messaging
_AGENT_MSG_KEYWORDS = frozenset({
    "send_message", "forward_message", "relay", "broadcast",
    "agent_call", "delegate_to", "notify_agent", "inter_agent",
    "agent_message", "orchestrator", "sub_agent", "worker_message",
    "dispatch_task", "send_to_agent", "agent_response",
})

# Parameter names that carry inter-agent payloads
_AGENT_PAYLOAD_PARAMS = frozenset({
    "message", "payload", "instruction", "task", "context",
    "agent_input", "request_body", "forwarded_message",
})

# Keywords in descriptions suggesting unsigned message passing
_UNSIGNED_INDICATORS = frozenset({
    "forward", "relay", "pass through", "send to",
    "notify", "broadcast", "dispatch", "delegate",
})

# Keywords that indicate signatures ARE present (safe — don't flag)
_SIGNATURE_INDICATORS = frozenset({
    "sign", "signature", "verify", "hmac", "mac",
    "attest", "certificate", "jwt", "proof",
})


def check_insecure_agent_comms(
    result: TargetResult,
) -> None:
    """Detect unsigned inter-agent message passing tools (MCP-T13).

    Flags tools that enable agent-to-agent communication without any
    cryptographic verification mechanism — allowing a compromised agent
    to inject arbitrary instructions into other agents' contexts.
    """
    with time_check("insecure_agent_comms", result):
        for tool in result.tools:
            name = tool.get("name", "").lower()
            desc = (tool.get("description", "") or "").lower()
            combined = f"{name} {desc}"
            props = tool.get("inputSchema", {}).get("properties", {})
            param_names = {p.lower() for p in props}

            # Check if tool is agent-messaging related
            is_agent_msg = any(kw in combined for kw in _AGENT_MSG_KEYWORDS)
            has_payload_param = any(p in param_names for p in _AGENT_PAYLOAD_PARAMS)
            has_unsigned_desc = any(kw in desc for kw in _UNSIGNED_INDICATORS)

            if not (is_agent_msg or (has_payload_param and has_unsigned_desc)):
                continue

            # Check if signatures are mentioned (safe)
            has_signature = any(kw in combined for kw in _SIGNATURE_INDICATORS)
            has_sig_param = any(
                any(kw in p.lower() for kw in _SIGNATURE_INDICATORS)
                for p in props
            )

            if has_signature or has_sig_param:
                continue  # Tool has signing — not vulnerable

            # Flag: agent messaging without signatures
            severity = "HIGH" if is_agent_msg else "MEDIUM"
            _add(
                result,
                "insecure_agent_comms",
                severity,
                f"Unsigned inter-agent messaging: '{tool.get('name', '')}'",
                (
                    f"Tool '{tool.get('name', '')}' enables agent-to-agent message passing "
                    f"without cryptographic verification (no signature, HMAC, or attestation "
                    f"parameters detected). A compromised sub-agent can inject arbitrary "
                    f"instructions into the receiving agent's context via this tool."
                ),
                taxonomy_id="MCP-T13",
            )
