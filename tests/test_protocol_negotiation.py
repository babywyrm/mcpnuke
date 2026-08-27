from mcpnuke.cli import parse_args
from mcpnuke.core.enumerator import enumerate_server, negotiate_protocol
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


_IDENTITY_ERR = {
    "jsonrpc": "2.0",
    "id": 1,
    "error": {"code": -32001, "message": "identity verification failed"},
}


def test_jsonrpc_error_is_not_reported_as_silence():
    """A sidecar that answers -32001 is not a dead server (NUC :30080)."""
    session = FakeSession({
        "initialize": _IDENTITY_ERR,
        "server/discover": _IDENTITY_ERR,
        "tools/list": _IDENTITY_ERR,
    })
    result = TargetResult(url="http://t/mcp")
    enumerate_server(session, result)

    titles = [f.title for f in result.findings]
    assert not any("No response" in t for t in titles)
    init = next(f for f in result.findings if f.check == "init")
    assert "-32001" in init.title
    assert "identity verification failed" in f"{init.title} {init.detail}".lower()
    assert init.severity == "HIGH"
    assert init.lane == 5
    assert init.transport == "A"


def test_true_silence_still_says_no_response():
    session = FakeSession({})
    result = TargetResult(url="http://t/mcp")
    enumerate_server(session, result)

    init = next(f for f in result.findings if f.check == "init")
    assert init.title == "No response to MCP initialize"


def test_tools_list_result_still_wins_over_initialize_error():
    session = FakeSession({
        "initialize": _IDENTITY_ERR,
        "tools/list": {"result": {"tools": []}},
    })
    result = TargetResult(url="http://t/mcp")

    assert negotiate_protocol(session, result, AUTO) == STATELESS
    assert [f.check for f in result.findings] == []


def test_protocol_mode_flag_defaults_to_auto():
    args = parse_args(["--targets", "http://t/mcp"])
    assert args.protocol_mode == "auto"


def test_protocol_mode_flag_accepts_stateless():
    args = parse_args(["--targets", "http://t/mcp", "--protocol-mode", "stateless"])
    assert args.protocol_mode == "stateless"
