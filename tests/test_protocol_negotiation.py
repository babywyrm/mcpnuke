from mcpnuke.core.enumerator import negotiate_protocol
from mcpnuke.core.models import TargetResult
from mcpnuke.core.protocol import AUTO, LEGACY, STATELESS


def test_target_result_defaults_to_unknown_protocol_mode():
    assert TargetResult(url="http://t/mcp").protocol_mode == "unknown"


class FakeSession:
    """Session double that answers only the methods it was given."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list[str] = []
        self.protocol_mode = LEGACY

    def call(self, method, params=None, timeout=None, retries=2):
        self.calls.append(method)
        return self.responses.get(method)

    def notify(self, method, params=None):
        self.calls.append(f"notify:{method}")


def test_negotiate_picks_legacy_when_initialize_succeeds():
    session = FakeSession({"initialize": {"result": {"serverInfo": {"name": "old"}}}})
    result = TargetResult(url="http://t/mcp")

    assert negotiate_protocol(session, result, AUTO) == LEGACY
    assert result.protocol_mode == LEGACY
    assert result.server_info["serverInfo"]["name"] == "old"


def test_negotiate_falls_back_to_server_discover():
    session = FakeSession({"server/discover": {"result": {"serverInfo": {"name": "new"}}}})
    result = TargetResult(url="http://t/mcp")

    assert negotiate_protocol(session, result, AUTO) == STATELESS
    assert result.protocol_mode == STATELESS
    assert session.calls == ["initialize", "server/discover"]


def test_negotiate_falls_back_to_bare_tools_list():
    session = FakeSession({"tools/list": {"result": {"tools": []}}})
    result = TargetResult(url="http://t/mcp")

    assert negotiate_protocol(session, result, AUTO) == STATELESS
    assert session.calls == ["initialize", "server/discover", "tools/list"]


def test_negotiate_returns_empty_when_nothing_answers():
    session = FakeSession({})
    result = TargetResult(url="http://t/mcp")

    assert negotiate_protocol(session, result, AUTO) == ""
    assert result.protocol_mode == "unknown"


def test_forced_legacy_mode_does_not_probe_stateless():
    session = FakeSession({})
    result = TargetResult(url="http://t/mcp")

    assert negotiate_protocol(session, result, LEGACY) == ""
    assert session.calls == ["initialize"]


def test_forced_stateless_mode_does_not_send_initialize():
    session = FakeSession({"server/discover": {"result": {}}})
    result = TargetResult(url="http://t/mcp")

    assert negotiate_protocol(session, result, STATELESS) == STATELESS
    assert "initialize" not in session.calls


def test_negotiate_sets_session_protocol_mode():
    session = FakeSession({"server/discover": {"result": {}}})
    result = TargetResult(url="http://t/mcp")

    negotiate_protocol(session, result, AUTO)
    assert session.protocol_mode == STATELESS


def test_stateless_server_records_anonymous_discovery_finding():
    session = FakeSession({"server/discover": {"result": {"serverInfo": {"name": "new"}}}})
    result = TargetResult(url="http://t/mcp")

    negotiate_protocol(session, result, AUTO)

    titles = [f.title for f in result.findings]
    assert "Unauthenticated MCP server/discover accepted" in titles
    finding = next(f for f in result.findings if f.check == "auth")
    assert finding.lane == 5
    assert finding.transport == "A"
