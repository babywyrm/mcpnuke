"""Tests for config_dump check (MCP-T07)."""

from mcpnuke.checks.config_dump import check_config_dump


class _Session:
    """Fake MCP session returning canned tool responses by tool name."""

    def __init__(self, responses: dict[str, str | None]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
        if method != "tools/call":
            return None
        name = params.get("name", "")
        self.calls.append(name)
        text = self.responses.get(name)
        if text is None:
            return None
        return {"result": {"content": [{"type": "text", "text": text}]}}


def _config_tool(name: str = "get_config") -> dict:
    return {
        "name": name,
        "description": "Return service configuration",
        "inputSchema": {"properties": {}},
    }


def test_no_config_tools_no_findings(result_with_tools):
    """Tools that don't look config-like are never invoked."""
    session = _Session({})
    r = result_with_tools([
        {"name": "read_file", "description": "Read a file", "inputSchema": {}},
    ])
    check_config_dump(session, r)
    assert len(r.findings) == 0
    assert session.calls == []


def test_private_key_leak_critical(result_with_tools):
    session = _Session({"get_config": "-----BEGIN PRIVATE KEY-----\nMIIBog==\n-----END PRIVATE KEY-----"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "Private key" in hits[0].detail
    assert "PRIVATE KEY" in hits[0].evidence


def test_internal_dns_name_high(result_with_tools):
    session = _Session({"get_config": "upstream: db.default.svc.cluster.local:5432"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "Kubernetes/internal DNS name" in hits[0].detail


def test_kubernetes_service_env_high(result_with_tools):
    session = _Session({"get_config": "KUBERNETES_SERVICE_HOST=10.96.0.1"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert hits[0].severity == "HIGH"
    assert "Kubernetes service env var" in hits[0].detail


def test_secret_env_var_name_high(result_with_tools):
    session = _Session({"get_config": "RCON_PASSWORD must be rotated"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert hits[0].severity == "HIGH"
    assert "Secret env var name" in hits[0].detail


def test_k8s_sa_token_path_high(result_with_tools):
    session = _Session({"get_config": "token at /var/run/secrets/kubernetes.io/serviceaccount"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert hits[0].severity == "HIGH"
    assert "Kubernetes SA token path" in hits[0].detail


def test_secret_file_path_high(result_with_tools):
    session = _Session({"get_config": "loading /etc/app/secret.pem"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert hits[0].severity == "HIGH"
    assert "Secret file path" in hits[0].detail


def test_internal_ip_port_medium(result_with_tools):
    session = _Session({"get_config": "listening on 10.0.0.5:8080"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert "Internal IP:port" in hits[0].detail


def test_internal_service_endpoint_medium(result_with_tools):
    session = _Session({"get_config": "broker redis://cache:6379"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert hits[0].severity == "MEDIUM"
    assert "Internal service endpoint" in hits[0].detail


def test_ai_safety_config_medium(result_with_tools):
    session = _Session({"get_config": "guardrail: enabled"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert hits[0].severity == "MEDIUM"
    assert "AI safety config exposure" in hits[0].detail


def test_severity_escalates_to_highest_match(result_with_tools):
    """A response mixing MEDIUM and CRITICAL leaks is reported CRITICAL."""
    session = _Session({"get_config": "10.0.0.5:8080 -----BEGIN PRIVATE KEY-----"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert hits[0].severity == "CRITICAL"


def test_match_counts_in_detail(result_with_tools):
    session = _Session({"get_config": "10.0.0.1:80 and 10.0.0.2:81"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert "Internal IP:port (2x)" in hits[0].detail


def test_detail_capped_at_six_labels(result_with_tools):
    """findings_for_tool[:6] caps the detail list even when more patterns hit;
    severity still reflects the uncapped list (characterization)."""
    text = (
        "10.0.0.5:8080 db.svc.cluster.local KUBERNETES_SERVICE_HOST=x "
        "RCON_PASSWORD=x /var/run/secrets/kubernetes /etc/app/secret.pem "
        "-----BEGIN PRIVATE KEY-----"
    )
    session = _Session({"get_config": text})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert hits[0].severity == "CRITICAL"
    # Seven patterns matched; the seventh label (Private key) is cut from detail.
    assert "Private key" not in hits[0].detail
    assert "Secret file path" in hits[0].detail


def test_clean_config_tool_no_finding(result_with_tools):
    session = _Session({"get_config": "status ok, version 1.2.3"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    assert len(r.findings) == 0
    assert session.calls == ["get_config"]


def test_empty_response_skipped(result_with_tools):
    session = _Session({"get_config": None})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    assert len(r.findings) == 0


def test_description_match_selects_tool(result_with_tools):
    """A neutral name with a config-like description is still scanned."""
    session = _Session({"probe": "KUBERNETES_SERVICE_PORT=443"})
    r = result_with_tools([
        {"name": "probe", "description": "Returns environment settings", "inputSchema": {}},
    ])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"


def test_no_invoke_skips_invocation(result_with_tools):
    session = _Session({"get_config": "KUBERNETES_SERVICE_HOST=10.96.0.1"})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r, probe_opts={"no_invoke": True})
    assert len(r.findings) == 0
    assert session.calls == []


def test_response_cache_used_instead_of_call(result_with_tools):
    """A cached response from an earlier check is reused without invoking."""
    session = _Session({})
    r = result_with_tools([_config_tool()])
    check_config_dump(
        session,
        r,
        probe_opts={"_response_cache": {"get_config": "KUBERNETES_SERVICE_HOST=10.96.0.1"}},
    )
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert session.calls == []


def test_evidence_capped_at_500_chars(result_with_tools):
    session = _Session({"get_config": "10.0.0.5:8080 " + "x" * 1000})
    r = result_with_tools([_config_tool()])
    check_config_dump(session, r)
    hits = [f for f in r.findings if f.check == "config_dump"]
    assert len(hits[0].evidence) == 500


def test_timing_recorded(result_with_tools):
    session = _Session({})
    r = result_with_tools([])
    check_config_dump(session, r)
    assert "config_dump" in r.timings
