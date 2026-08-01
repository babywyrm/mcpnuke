"""Tests for response_credentials check."""


from mcpnuke.checks.response_credentials import check_response_credentials
from mcpnuke.core.models import TargetResult


class FakeSession:
    """Mock session that returns canned tool responses."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses

    def call(self, method, params=None, timeout=None, retries=2):
        if method == "tools/call":
            name = (params or {}).get("name", "")
            text = self._responses.get(name, "")
            return {"result": {"content": [{"type": "text", "text": text}]}}
        return None


def _make(tools, responses):
    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = tools
    return r, FakeSession(responses)


def test_detects_api_key_in_response():
    tools = [{"name": "config", "description": "Get config", "inputSchema": {"properties": {}}}]
    r, session = _make(tools, {"config": '{"api_key": "sk-abc123def456ghi789jkl012mno"}'})
    check_response_credentials(session, r)
    assert any(f.check == "response_credentials" for f in r.findings)
    assert any(f.severity == "CRITICAL" for f in r.findings)


def test_detects_password_in_response():
    tools = [{"name": "env", "description": "Get env vars", "inputSchema": {"properties": {}}}]
    r, session = _make(tools, {"env": "DB_HOST=localhost\npassword=hunter2\nPORT=5432"})
    check_response_credentials(session, r)
    assert any(f.check == "response_credentials" for f in r.findings)


def test_detects_connection_string():
    tools = [{"name": "debug", "description": "Debug info", "inputSchema": {"properties": {}}}]
    r, session = _make(tools, {"debug": "connecting to postgres://admin:secret@db:5432/app"})
    check_response_credentials(session, r)
    assert any(f.check == "response_credentials" for f in r.findings)


def test_detects_private_key():
    tools = [{"name": "certs", "description": "Get certs", "inputSchema": {"properties": {}}}]
    r, session = _make(tools, {"certs": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."})
    check_response_credentials(session, r)
    assert any(f.check == "response_credentials" for f in r.findings)


def test_clean_response_no_findings():
    tools = [{"name": "health", "description": "Health check", "inputSchema": {"properties": {}}}]
    r, session = _make(tools, {"health": '{"status": "ok", "uptime": 3600}'})
    check_response_credentials(session, r)
    assert not any(f.check == "response_credentials" for f in r.findings)


def test_timing_recorded():
    tools = [{"name": "x", "description": "y", "inputSchema": {"properties": {}}}]
    r, session = _make(tools, {"x": "safe output"})
    check_response_credentials(session, r)
    assert "response_credentials" in r.timings
