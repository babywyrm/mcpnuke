from mcpnuke.checks.scope_pollution import check_scope_pollution
from mcpnuke.core.models import TargetResult


def _result(tools, claims=None):
    r = TargetResult(url="http://target/mcp")
    r.tools = tools
    if claims is not None:
        r.auth_context["jwt_claims_summary"] = claims
    return r


def _findings(result):
    return [f for f in result.findings if f.check == "scope_pollution"]


def test_flags_token_minter_with_caller_controlled_scope():
    r = _result([
        {
            "name": "idp.mint_token",
            "description": "Mint a service token for the requested scope",
            "inputSchema": {
                "properties": {
                    "requested_scope": {
                        "type": "string",
                        "description": "Requested scope, for example admin write",
                    }
                }
            },
        }
    ])

    check_scope_pollution(r)

    findings = _findings(r)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].taxonomy_id == "MCP-T42"
    assert findings[0].lane == 2
    assert findings[0].transport == "A"


def test_escalates_to_critical_for_low_privileged_caller_and_admin_scope():
    r = _result(
        [
            {
                "name": "idp.exchange_token",
                "description": "Exchange caller token for admin token in another service",
                "inputSchema": {
                    "properties": {
                        "scope": {"type": "string", "enum": ["admin", "write"]},
                    }
                },
            }
        ],
        claims={"sub": "analyst", "scope": "read list"},
    )

    check_scope_pollution(r)

    findings = _findings(r)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "read" in findings[0].detail


def test_does_not_flag_minter_that_advertises_scope_narrowing():
    r = _result([
        {
            "name": "idp.mint_token",
            "description": "Mint a downscoped service-bound token using an allowlist",
            "inputSchema": {
                "properties": {
                    "requested_scope": {
                        "type": "string",
                        "description": "Scope is narrowed to the caller allowlist",
                    }
                }
            },
        }
    ])

    check_scope_pollution(r)

    assert _findings(r) == []


def test_flags_shared_idp_topology_disclosure():
    r = _result([
        {
            "name": "idp.inspect_config",
            "description": "Show shared IdP realm and cross-service client_credentials config",
            "inputSchema": {"properties": {}},
        }
    ])

    check_scope_pollution(r)

    findings = _findings(r)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "Shared IdP" in findings[0].title
    assert findings[0].taxonomy_id == "MCP-T42"


def test_non_token_tool_with_scope_parameter_is_not_flagged():
    r = _result([
        {
            "name": "reports.search",
            "description": "Search report scope",
            "inputSchema": {
                "properties": {"scope": {"type": "string", "description": "report scope"}}
            },
        }
    ])

    check_scope_pollution(r)

    assert _findings(r) == []


def test_token_tool_without_requested_scope_parameter_is_not_flagged():
    r = _result([
        {
            "name": "idp.refresh_token",
            "description": "Refresh existing token",
            "inputSchema": {"properties": {"token_id": {"type": "string"}}},
        }
    ])

    check_scope_pollution(r)

    assert _findings(r) == []


def test_privileged_caller_does_not_escalate_to_critical():
    r = _result(
        [
            {
                "name": "idp.issue_token",
                "description": "Issue admin token",
                "inputSchema": {"properties": {"scope": {"type": "string"}}},
            }
        ],
        claims={"sub": "ops", "roles": ["admin"]},
    )

    check_scope_pollution(r)

    findings = _findings(r)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
