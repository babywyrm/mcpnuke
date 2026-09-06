"""Tests for insecure_agent_comms check (MCP-T13)."""

from mcpnuke.checks.insecure_agent_comms import check_insecure_agent_comms


def test_clean_tool_no_findings(result_with_tools):
    r = result_with_tools([
        {"name": "read_file", "description": "Read a file", "inputSchema": {}},
    ])
    check_insecure_agent_comms(r)
    assert len(r.findings) == 0


def test_agent_message_tool_name_high(result_with_tools):
    """A tool named for inter-agent messaging with no signing is HIGH."""
    r = result_with_tools([
        {
            "name": "send_message",
            "description": "Send a message to another agent",
            "inputSchema": {"properties": {"message": {"type": "string"}}},
        }
    ])
    check_insecure_agent_comms(r)
    hits = [f for f in r.findings if f.check == "insecure_agent_comms"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "send_message" in hits[0].title
    assert hits[0].taxonomy_id == "MCP-T13"


def test_agent_keyword_in_description_high(result_with_tools):
    """The keyword scan covers name + description combined."""
    r = result_with_tools([
        {
            "name": "messenger",
            "description": "Relay messages between agents",
            "inputSchema": {},
        }
    ])
    check_insecure_agent_comms(r)
    hits = [f for f in r.findings if f.check == "insecure_agent_comms"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"


def test_missing_description_still_flagged(result_with_tools):
    """A tool with no description key is still analyzed by name."""
    r = result_with_tools([
        {"name": "agent_call", "inputSchema": {}},
    ])
    check_insecure_agent_comms(r)
    hits = [f for f in r.findings if f.check == "insecure_agent_comms"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"


def test_payload_param_plus_forwarding_desc_medium(result_with_tools):
    """Payload param + forwarding language (no agent keyword) is MEDIUM."""
    r = result_with_tools([
        {
            "name": "proxy",
            "description": "Forward data to the worker",
            "inputSchema": {"properties": {"payload": {"type": "string"}}},
        }
    ])
    check_insecure_agent_comms(r)
    hits = [f for f in r.findings if f.check == "insecure_agent_comms"]
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"


def test_payload_param_without_forwarding_desc_no_finding(result_with_tools):
    """A payload-carrying parameter alone does not imply agent messaging."""
    r = result_with_tools([
        {
            "name": "store_text",
            "description": "Store text in the buffer",
            "inputSchema": {"properties": {"message": {"type": "string"}}},
        }
    ])
    check_insecure_agent_comms(r)
    assert len(r.findings) == 0


def test_forwarding_desc_without_payload_param_no_finding(result_with_tools):
    """Forwarding language alone (no agent keyword, no payload param) is safe."""
    r = result_with_tools([
        {
            "name": "pinger",
            "description": "Delegate work to workers",
            "inputSchema": {"properties": {"count": {"type": "integer"}}},
        }
    ])
    check_insecure_agent_comms(r)
    assert len(r.findings) == 0


def test_signature_in_description_is_safe(result_with_tools):
    """Mentioning signing/HMAC in the description suppresses the finding."""
    r = result_with_tools([
        {
            "name": "send_message",
            "description": "Send a signed message to another agent; HMAC verified",
            "inputSchema": {"properties": {"message": {"type": "string"}}},
        }
    ])
    check_insecure_agent_comms(r)
    assert len(r.findings) == 0


def test_signature_param_is_safe(result_with_tools):
    """A signature-carrying parameter suppresses the finding."""
    r = result_with_tools([
        {
            "name": "send_message",
            "description": "Send a message to another agent",
            "inputSchema": {
                "properties": {
                    "message": {"type": "string"},
                    "signature": {"type": "string"},
                }
            },
        }
    ])
    check_insecure_agent_comms(r)
    assert len(r.findings) == 0


def test_param_with_signature_substring_is_safe(result_with_tools):
    """Characterization: signature detection in params is a substring match,
    so a param named 'design' (contains 'sign') also suppresses the finding."""
    r = result_with_tools([
        {
            "name": "send_message",
            "description": "Send a message to another agent",
            "inputSchema": {
                "properties": {
                    "message": {"type": "string"},
                    "design": {"type": "string"},
                }
            },
        }
    ])
    check_insecure_agent_comms(r)
    assert len(r.findings) == 0


def test_relay_substring_matches_inflected_forms(result_with_tools):
    """Keyword matching is substring-based: 'relayed' contains 'relay'."""
    r = result_with_tools([
        {"name": "relayed_io", "description": "IO helper", "inputSchema": {}},
    ])
    check_insecure_agent_comms(r)
    hits = [f for f in r.findings if f.check == "insecure_agent_comms"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"


def test_multiple_tools_each_flagged(result_with_tools):
    r = result_with_tools([
        {"name": "broadcast", "description": "Broadcast to all", "inputSchema": {}},
        {
            "name": "proxy",
            "description": "Forward data to the worker",
            "inputSchema": {"properties": {"task": {"type": "string"}}},
        },
        {"name": "safe", "description": "No issues", "inputSchema": {}},
    ])
    check_insecure_agent_comms(r)
    hits = [f for f in r.findings if f.check == "insecure_agent_comms"]
    assert len(hits) == 2
    assert {f.severity for f in hits} == {"HIGH", "MEDIUM"}


def test_lane_and_transport_tagged(result_with_tools):
    r = result_with_tools([
        {"name": "orchestrator", "description": "Coordinate agents", "inputSchema": {}},
    ])
    check_insecure_agent_comms(r)
    hits = [f for f in r.findings if f.check == "insecure_agent_comms"]
    assert hits[0].lane == 4
    assert hits[0].transport == "A"


def test_timing_recorded(result_with_tools):
    r = result_with_tools([])
    check_insecure_agent_comms(r)
    assert "insecure_agent_comms" in r.timings
