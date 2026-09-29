"""A chain step can name another MCP server.

The value captured on server A must be sent to a tool on server B, on a
session opened for that step and closed after it. Without an opener the
step is refused, and it is never sent to the session that produced A.
"""

from __future__ import annotations

from mcpnuke.cli import parse_args
from mcpnuke.core.chain_replay import (
    ChainStep,
    ProposedChain,
    parse_proposed_chains,
    replay_chain,
)


class _ScriptedSession:
    def __init__(self, responses: dict) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict]] = []
        self.closed = False

    def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
        if method != "tools/call":
            return None
        name = params.get("name", "")
        args = params.get("arguments", {})
        self.calls.append((name, args))
        resp = self._responses.get(name)
        return resp(args) if callable(resp) else resp

    def close(self) -> None:
        self.closed = True


def _text(body: str) -> dict:
    return {"result": {"content": [{"type": "text", "text": body}]}}


TOOLS = {
    "vault.read": {
        "name": "vault.read",
        "inputSchema": {"properties": {"key": {"type": "string"}}},
    },
    "net.deliver": {
        "name": "net.deliver",
        "inputSchema": {"properties": {"body": {"type": "string"}}},
    },
    "exec": {
        "name": "exec",
        "inputSchema": {"properties": {"cmd": {"type": "string"}}},
    },
}

_A = "http://a.example/mcp"
_B = "http://b.example/mcp"


def test_output_from_a_is_sent_to_b() -> None:
    server_a = _ScriptedSession({"vault.read": _text("AKIA-secret")})
    server_b = _ScriptedSession({"net.deliver": _text("ok")})
    opened: list[str] = []

    def open_session(url: str) -> _ScriptedSession:
        opened.append(url)
        return server_b if url == _B else server_a

    chain = ProposedChain(
        "cross",
        [
            ChainStep("vault.read", {"key": "token"}, target=_A),
            ChainStep("net.deliver", {"body": "{{step0.output}}"}, target=_B),
        ],
    )
    run = replay_chain(server_a, chain, TOOLS, open_session=open_session)

    assert opened == [_A, _B]
    assert server_b.calls == [("net.deliver", {"body": "AKIA-secret"})]
    assert server_a.calls == [("vault.read", {"key": "token"})]
    assert server_a.closed and server_b.closed
    assert run.completed


def test_cross_server_step_is_refused_without_an_opener() -> None:
    primary = _ScriptedSession({"vault.read": _text("AKIA-secret"), "net.deliver": _text("ok")})
    chain = ProposedChain(
        "cross",
        [
            ChainStep("vault.read", {}),
            ChainStep("net.deliver", {"body": "{{step0.output}}"}, target=_B),
        ],
    )
    run = replay_chain(primary, chain, TOOLS)

    assert [name for name, _ in primary.calls] == ["vault.read"]
    assert run.results[1].failed
    assert "cross-server" in run.results[1].reason


def test_safe_mode_refuses_the_peer_before_connecting() -> None:
    primary = _ScriptedSession({"vault.read": _text("x")})
    opened: list[str] = []

    def open_session(url: str) -> _ScriptedSession:
        opened.append(url)
        return primary

    chain = ProposedChain(
        "cross",
        [
            ChainStep("vault.read", {}),
            ChainStep("exec", {"cmd": "{{step0.output}}"}, target=_B),
        ],
    )
    run = replay_chain(primary, chain, TOOLS, safe_mode=True, open_session=open_session)

    assert opened == []
    assert run.results[1].failed
    assert "safe-mode" in run.results[1].reason


def test_parser_keeps_the_step_target() -> None:
    chains = parse_proposed_chains(
        '[{"title":"c","steps":['
        '{"tool":"vault.read","args":{}},'
        '{"tool":"net.deliver","args":{"body":"{{step0.output}}"},'
        '"target":"http://b.example/mcp"}]}]'
    )
    assert chains[0].steps[1].target == "http://b.example/mcp"
    assert chains[0].steps[0].target == ""


def test_cross_server_flag_defaults_off() -> None:
    args = parse_args(
        ["--targets", "http://localhost:9001", "--chain-replay", "--cross-server"]
    )
    assert args.cross_server is True
    bare = parse_args(["--targets", "http://localhost:9001"])
    assert bare.cross_server is False
