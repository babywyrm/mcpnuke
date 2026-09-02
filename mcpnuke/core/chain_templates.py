"""Lane-aware pre-built attack chain templates.

Templates encode common multi-hop attack patterns for each identity lane.
They are instantiated with actual tool names discovered on the target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcpnuke.core.chain_replay import ChainStep, ProposedChain


@dataclass(frozen=True)
class LaneTemplate:
    """A pre-built chain pattern for a specific identity lane."""

    name: str
    lane: int
    description: str
    steps: list[ChainStep]
    required_tool_patterns: list[str]  # regex patterns for tool matching


# Template definitions
LANE_TEMPLATES: dict[int, LaneTemplate] = {
    2: LaneTemplate(
        name="delegated_escalation",
        lane=2,
        description="Stolen credential used across service boundaries",
        steps=[
            ChainStep("read_secrets", {}),
            ChainStep("use_token", {"token": "{{step0.output}}"}),
        ],
        required_tool_patterns=[r"read|get|fetch.*secret|token|cred", r"use|call|invoke.*token|auth"],
    ),
    3: LaneTemplate(
        name="machine_to_machine",
        lane=3,
        description="Service account token theft and API abuse",
        steps=[
            ChainStep("list_service_accounts", {}),
            ChainStep("steal_token", {"sa": "{{step0.output}}"}),
            ChainStep("call_api", {"token": "{{step1.output}}"}),
        ],
        required_tool_patterns=[r"list|enum.*service|account", r"steal|get.*token", r"call|invoke.*api"],
    ),
    4: LaneTemplate(
        name="confused_deputy",
        lane=4,
        description="Tool shadowing leading to confused deputy attack",
        steps=[
            ChainStep("discover_tools", {}),
            ChainStep("shadow_tool", {"target": "{{step0.output}}"}),
            ChainStep("trigger_shadow", {}),
        ],
        required_tool_patterns=[r"discover|list.*tool", r"shadow|impersonate", r"trigger|execute"],
    ),
    5: LaneTemplate(
        name="resource_exhaustion",
        lane=5,
        description="Anonymous budget exhaustion and resource drain",
        steps=[
            ChainStep("check_budget", {}),
            ChainStep("exhaust_budget", {"amount": "{{step0.output}}"}),
        ],
        required_tool_patterns=[r"check|get.*budget|quota", r"exhaust|consume|drain"],
    ),
}


def get_template_for_lane(lane: int) -> LaneTemplate | None:
    """Return the chain template for a given identity lane, or None."""
    return LANE_TEMPLATES.get(lane)


def instantiate_template(
    template: LaneTemplate,
    tools: dict[str, dict],
) -> ProposedChain | None:
    """Instantiate a template with actual tool names from the target.

    Matches template step names to real tools using required_tool_patterns.
    Returns None if any required tool pattern has no match.
    """
    matched_steps: list[ChainStep] = []
    tool_names = list(tools.keys())

    for i, pattern in enumerate(template.required_tool_patterns):
        regex = re.compile(pattern, re.IGNORECASE)
        matches = [t for t in tool_names if regex.search(t)]
        if not matches:
            return None
        # Use first match; could be enhanced with scoring
        matched_tool = matches[0]
        original_step = template.steps[i]
        matched_steps.append(
            ChainStep(tool=matched_tool, args=original_step.args)
        )

    return ProposedChain(
        title=f"{template.name} (lane {template.lane})",
        steps=matched_steps,
        detail=template.description,
    )
