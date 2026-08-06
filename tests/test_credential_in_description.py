"""A credential written into description prose has no shape to match on.

Camazotz publishes `agent_http_bypass.call_direct` with "Integration note:
service API key is 'svc-internal-abc123'" in its description. Every client that
calls tools/list receives that key, and any telemetry capturing tool
descriptions logs it. The deterministic scan reported twenty findings against
that tool and none of them was the key: `credential_in_schema` scans the whole
tool definition, but only with STRUCTURAL_CREDENTIALS, and an arbitrary vendor
string has no distinctive prefix or length to match. Only the AI phase caught
it, which makes the finding unavailable to anyone scanning without a model.

The keyword tier is excluded from schema scanning for a real reason: its value
clause is satisfied by a JSON Schema property declaration, so `{"api_key":
{"type": "string"}}` would report CRITICAL against every tool that accepts a
credential parameter. The discriminator it does not use is quoting — a leaked
value is a quoted literal, a declared property is a type object.
"""

from __future__ import annotations

import json

from mcpnuke.checks.credential_in_schema import check_credential_in_schema
from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.credentials import SCHEMA_CREDENTIALS, find_credential

CAMAZOTZ_DESCRIPTION = (
    "Simulate a direct HTTP API call to the internal tool server, bypassing "
    "the MCP transport layer. Provide optional auth headers to test different "
    "difficulty levels. Integration note: service API key is 'svc-internal-abc123'"
)


def _hit(text: str) -> tuple[str, str] | None:
    return find_credential(text, SCHEMA_CREDENTIALS)


class TestTheCamazotzCase:
    def test_the_key_in_the_description_is_found(self):
        assert _hit(CAMAZOTZ_DESCRIPTION) is not None

    def test_it_survives_serialization_of_the_whole_tool(self):
        tool = {
            "name": "agent_http_bypass.call_direct",
            "description": CAMAZOTZ_DESCRIPTION,
            "inputSchema": {"properties": {"api_key": {"type": "string"}}},
        }

        assert _hit(json.dumps(tool)) is not None

    def test_the_matched_value_is_reported_as_evidence(self):
        found = _hit(CAMAZOTZ_DESCRIPTION)

        assert found is not None
        assert "svc-internal-abc123" in found[1]


class TestTheDeclarationFalsePositiveStaysFixed:
    """The reason the keyword tier is barred from schema scanning."""

    def test_a_typed_property_declaration_is_not_a_leak(self):
        assert _hit(json.dumps({"api_key": {"type": "string"}})) is None

    def test_a_full_schema_of_credential_params_is_not_a_leak(self):
        schema = {
            "properties": {
                "api_key": {"type": "string", "description": "The API key to use"},
                "token": {"type": "string"},
                "password": {"type": "string"},
            }
        }

        assert _hit(json.dumps(schema)) is None

    def test_a_tool_that_merely_mentions_credentials_is_not_a_leak(self):
        text = "Authenticate with your api key. The token is validated server side."

        assert _hit(text) is None


class TestPlaceholdersAreNotSecrets:
    def test_an_uppercase_placeholder_is_ignored(self):
        assert _hit("api_key: 'YOUR_API_KEY_HERE'") is None

    def test_an_example_value_is_ignored(self):
        assert _hit("token = 'example-token-value'") is None

    def test_a_masked_value_is_ignored(self):
        assert _hit("password: '********'") is None

    def test_an_angle_bracket_template_is_ignored(self):
        assert _hit("secret: '<your-secret-here>'") is None

    def test_a_short_value_is_ignored(self):
        assert _hit("token: 'abc'") is None


class TestTheProseFormsThatDoLeak:
    def test_a_prose_copula(self):
        assert _hit("The service token is 'a8f3c91b7d2e4f60'") is not None

    def test_a_json_assignment_with_a_literal_value(self):
        assert _hit('{"api_key":"a8f3c91b7d2e4f60"}') is not None

    def test_a_double_quoted_prose_value(self):
        assert _hit('Integration note: the secret is "a8f3c91b7d2e4f60"') is not None

    def test_a_spaced_credential_noun(self):
        assert _hit("service API key is 'a8f3c91b7d2e4f60'") is not None


class TestTheCheckReportsIt:
    def _result(self, description: str) -> TargetResult:
        result = TargetResult(url="http://localhost:8080/mcp")
        result.tools = [{"name": "svc.call", "description": description, "inputSchema": {}}]
        check_credential_in_schema(result)
        return result

    def test_a_leaked_key_is_reported_critical(self):
        result = self._result(CAMAZOTZ_DESCRIPTION)

        assert [f.severity for f in result.findings] == ["CRITICAL"]

    def test_a_clean_tool_reports_nothing(self):
        result = self._result("Call a downstream service with the supplied api key.")

        assert result.findings == []

    def test_the_timing_is_recorded(self):
        result = self._result(CAMAZOTZ_DESCRIPTION)

        assert "credential_in_schema" in result.timings


class TestStructuralDetectionIsUnaffected:
    def test_an_aws_key_is_still_found(self):
        assert _hit("AKIAIOSFODNN7EXAMPLE") is not None

    def test_a_private_key_banner_is_still_found(self):
        assert _hit("-----BEGIN RSA PRIVATE KEY-----") is not None

    def test_clean_text_is_still_clean(self):
        assert _hit("A tool that lists files in a directory.") is None
