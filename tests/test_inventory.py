"""AIBOM-style inventory block in the JSON report.

Every target dict carries an `inventory` section: server identity, transport,
auth posture, and a sha256 over the canonical tool surface. The hash pins the
tool list so a description or schema change between scans (a rug pull) is
visible as a digest mismatch without diffing full schemas.
"""

from mcpnuke.core.models import TargetResult
from mcpnuke.reporting.json_out import _build_target_dict, build_report


def _result() -> TargetResult:
    r = TargetResult(url="http://t/mcp")
    r.transport = "HTTP"
    r.protocol_mode = "stateless"
    r.server_info = {"name": "test-server", "version": "1.2.3"}
    r.tools = [
        {"name": "b_tool", "description": "second", "inputSchema": {"type": "object"}},
        {"name": "a_tool", "description": "first", "inputSchema": {}},
    ]
    r.resources = [{"uri": "file:///x"}]
    return r


class TestInventoryBlock:
    def test_server_identity_and_transport(self):
        inv = _build_target_dict(_result())["inventory"]
        assert inv["server"] == {"name": "test-server", "version": "1.2.3"}
        assert inv["transport"] == "HTTP"
        assert inv["protocol_mode"] == "stateless"

    def test_counts(self):
        inv = _build_target_dict(_result())["inventory"]
        assert inv["tools"]["count"] == 2
        assert inv["resources"]["count"] == 1
        assert inv["prompts"]["count"] == 0

    def test_tool_surface_hash_is_order_independent(self):
        r = _result()
        r.tools = list(reversed(r.tools))
        assert (
            _build_target_dict(r)["inventory"]["tools"]["sha256"]
            == _build_target_dict(_result())["inventory"]["tools"]["sha256"]
        )

    def test_tool_surface_hash_changes_on_description_drift(self):
        r = _result()
        r.tools[0]["description"] = "second — now with extra instructions"
        assert (
            _build_target_dict(r)["inventory"]["tools"]["sha256"]
            != _build_target_dict(_result())["inventory"]["tools"]["sha256"]
        )

    def test_authenticated_flag(self):
        assert _build_target_dict(_result())["inventory"]["authenticated"] is False
        r = _result()
        r.auth_context["jwt_claims_summary"] = {"iss": "http://idp"}
        assert _build_target_dict(r)["inventory"]["authenticated"] is True

    def test_missing_server_info_is_empty_strings(self):
        r = _result()
        r.server_info = {}
        assert _build_target_dict(r)["inventory"]["server"] == {
            "name": "",
            "version": "",
        }

    def test_build_report_includes_inventory(self):
        report = build_report([_result()])
        assert "inventory" in report["targets"][0]
