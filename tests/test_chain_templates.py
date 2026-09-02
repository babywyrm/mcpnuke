"""Tests for lane-aware chain templates."""

from mcpnuke.core.chain_templates import (
    get_template_for_lane,
    instantiate_template,
)


class TestLaneTemplates:
    def test_lane_b_template_exists(self):
        template = get_template_for_lane(2)
        assert template is not None
        assert template.name == "delegated_escalation"
        assert len(template.steps) >= 2

    def test_lane_c_template_exists(self):
        template = get_template_for_lane(3)
        assert template is not None
        assert template.name == "machine_to_machine"

    def test_lane_d_template_exists(self):
        template = get_template_for_lane(4)
        assert template is not None
        assert template.name == "confused_deputy"

    def test_lane_e_template_exists(self):
        template = get_template_for_lane(5)
        assert template is not None
        assert template.name == "resource_exhaustion"

    def test_instantiate_with_real_tools(self):
        template = get_template_for_lane(2)
        tools = {
            "read_secrets": {"name": "read_secrets", "inputSchema": {"type": "object"}},
            "use_token": {"name": "use_token", "inputSchema": {"type": "object"}},
        }
        chain = instantiate_template(template, tools)
        assert chain is not None
        assert len(chain.steps) == 2
        assert chain.steps[0].tool == "read_secrets"
        assert chain.steps[1].tool == "use_token"

    def test_instantiate_missing_tool_returns_none(self):
        template = get_template_for_lane(2)
        tools = {"unrelated": {"name": "unrelated"}}
        chain = instantiate_template(template, tools)
        assert chain is None
