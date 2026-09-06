"""Tests for model_routing check (MCP-T15)."""

from mcpnuke.checks.model_routing import check_model_routing


def test_clean_tool_no_findings(result_with_tools):
    r = result_with_tools([
        {"name": "summarize", "description": "Summarize text", "inputSchema": {}},
    ])
    check_model_routing(r)
    assert len(r.findings) == 0


def test_model_management_tool_name_critical(result_with_tools):
    """A tool named like a model-management verb is CRITICAL."""
    r = result_with_tools([
        {"name": "set_model", "description": "Admin utility", "inputSchema": {}},
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "set_model" in hits[0].title
    assert hits[0].taxonomy_id == "MCP-T15"


def test_management_name_is_substring_matched(result_with_tools):
    """Name matching is a substring check: 'reset_model_backend' contains 'set_model'."""
    r = result_with_tools([
        {"name": "reset_model_backend", "description": "Admin utility", "inputSchema": {}},
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"


def test_management_name_skips_other_checks(result_with_tools):
    """Check 1 `continue`s: a management tool with a model param yields one finding."""
    r = result_with_tools([
        {
            "name": "switch_model",
            "description": "Switch the active model",
            "inputSchema": {"properties": {"model": {"type": "string"}}},
        }
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"


def test_model_parameter_high(result_with_tools):
    """A caller-controllable model parameter is HIGH."""
    r = result_with_tools([
        {
            "name": "chat",
            "description": "Chat completion",
            "inputSchema": {
                "properties": {
                    "prompt": {"type": "string"},
                    "model": {"type": "string"},
                }
            },
        }
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "model" in hits[0].title
    assert hits[0].taxonomy_id == "MCP-T15"


def test_model_parameter_names_listed(result_with_tools):
    """Every matching parameter name appears in the title."""
    r = result_with_tools([
        {
            "name": "chat",
            "description": "Chat completion",
            "inputSchema": {
                "properties": {
                    "backend": {"type": "string"},
                    "provider": {"type": "string"},
                }
            },
        }
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 1
    assert "backend" in hits[0].title
    assert "provider" in hits[0].title


def test_parameter_match_is_exact_not_substring(result_with_tools):
    """'modelName' lowercases to 'modelname', which is not a known keyword."""
    r = result_with_tools([
        {
            "name": "chat",
            "description": "Chat completion",
            "inputSchema": {"properties": {"modelName": {"type": "string"}}},
        }
    ])
    check_model_routing(r)
    assert len(r.findings) == 0


def test_routing_description_medium(result_with_tools):
    """Routing language in the description (no model param) is MEDIUM."""
    r = result_with_tools([
        {
            "name": "chat",
            "description": "Answers questions; uses model selection based on load",
            "inputSchema": {"properties": {"prompt": {"type": "string"}}},
        }
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert hits[0].taxonomy_id == "MCP-T15"


def test_routing_description_case_insensitive(result_with_tools):
    r = result_with_tools([
        {
            "name": "chat",
            "description": "Supports MODEL ROUTING for tenants",
            "inputSchema": {},
        }
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"


def test_model_param_suppresses_description_check(result_with_tools):
    """Check 3 is an `elif`: a tool with both a model param and routing
    description yields only the HIGH parameter finding."""
    r = result_with_tools([
        {
            "name": "chat",
            "description": "Uses model selection based on load",
            "inputSchema": {"properties": {"model": {"type": "string"}}},
        }
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"


def test_multiple_tools_each_flagged(result_with_tools):
    r = result_with_tools([
        {"name": "set_backend", "description": "Admin", "inputSchema": {}},
        {
            "name": "chat",
            "description": "Chat",
            "inputSchema": {"properties": {"llm": {"type": "string"}}},
        },
        {"name": "safe", "description": "No issues", "inputSchema": {}},
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert len(hits) == 2
    assert {f.severity for f in hits} == {"CRITICAL", "HIGH"}


def test_lane_and_transport_tagged(result_with_tools):
    r = result_with_tools([
        {"name": "route_model", "description": "Admin", "inputSchema": {}},
    ])
    check_model_routing(r)
    hits = [f for f in r.findings if f.check == "model_routing"]
    assert hits[0].lane == 2
    assert hits[0].transport == "A"


def test_timing_recorded(result_with_tools):
    r = result_with_tools([])
    check_model_routing(r)
    assert "model_routing" in r.timings
