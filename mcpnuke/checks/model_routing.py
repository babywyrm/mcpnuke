"""MCP-T15: Model routing manipulation.

Static check that detects tools or server configurations where model selection
can be influenced by untrusted input — allowing an attacker to force routing to
a weaker, uncensored, or backdoored model.

Attack scenarios:
1. Tool parameter specifies which model to use (attacker picks a weak model)
2. Tool description or schema references model selection logic
3. Server config exposes model routing (via config-dump or environment)

This is the MCP-specific variant of OWASP MCP15 (Insecure Model Routing &
Fallback) — if the model serving the request can be changed by the caller,
the entire safety/alignment guarantee is undermined.

Lane 2 (Delegated) / Transport A (MCP JSON-RPC).
"""

from __future__ import annotations

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult

_add = lane_tagged(lane=2, transport="A")

# Parameter names that suggest model selection
_MODEL_PARAM_KEYWORDS = frozenset({
    "model", "model_name", "model_id", "llm", "engine",
    "backend", "provider", "inference_model", "chat_model",
    "completion_model", "embedding_model", "routing",
})

# Description keywords suggesting model routing
_ROUTING_KEYWORDS = frozenset({
    "model selection", "route to", "select model", "choose model",
    "fallback model", "override model", "model override",
    "switch model", "model routing", "inference backend",
})

# Tool names suggesting model management
_MODEL_MGMT_TOOLS = frozenset({
    "set_model", "switch_model", "change_model", "select_model",
    "configure_inference", "model_config", "set_backend",
    "route_model", "model_override",
})


def check_model_routing(
    result: TargetResult,
) -> None:
    """Detect attacker-controllable model routing (MCP-T15).

    Flags tools where model selection can be influenced by untrusted input,
    allowing an attacker to force routing to a weaker or uncensored model
    and bypass safety alignment.
    """
    with time_check("model_routing", result):
        for tool in result.tools:
            name = tool.get("name", "").lower()
            desc = (tool.get("description", "") or "").lower()
            props = tool.get("inputSchema", {}).get("properties", {})

            # Check 1: tool name suggests model management
            if any(kw in name for kw in _MODEL_MGMT_TOOLS):
                _add(
                    result,
                    "model_routing",
                    "CRITICAL",
                    f"Model management tool exposed: '{tool.get('name', '')}'",
                    (
                        f"Tool '{tool.get('name', '')}' appears to allow model selection "
                        f"or routing changes. An attacker who can invoke this tool can "
                        f"force the server to use a weaker, uncensored, or backdoored "
                        f"model — bypassing all safety alignment guarantees."
                    ),
                    taxonomy_id="MCP-T15",
                )
                continue

            # Check 2: tool accepts a model parameter
            model_params = [p for p in props if p.lower() in _MODEL_PARAM_KEYWORDS]
            if model_params:
                _add(
                    result,
                    "model_routing",
                    "HIGH",
                    f"Model selection parameter in tool '{tool.get('name', '')}' ({', '.join(model_params)})",
                    (
                        f"Tool '{tool.get('name', '')}' accepts a model/routing parameter "
                        f"({', '.join(model_params)}). If this parameter is exposed to "
                        f"untrusted callers, they can force model downgrade to bypass "
                        f"safety controls."
                    ),
                    taxonomy_id="MCP-T15",
                )

            # Check 3: description mentions model routing
            elif any(kw in desc for kw in _ROUTING_KEYWORDS):
                _add(
                    result,
                    "model_routing",
                    "MEDIUM",
                    f"Model routing mentioned in tool '{tool.get('name', '')}' description",
                    (
                        f"Tool '{tool.get('name', '')}' description references model "
                        f"routing or selection logic. Review whether callers can influence "
                        f"which model serves their requests."
                    ),
                    taxonomy_id="MCP-T15",
                )
