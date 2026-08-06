"""A sink that answers is not a sink that accepted.

`_try_sink_send` decided success with `sent = resp is not None`, and
`_call_tool` returns the response dict whenever the JSON-RPC round trip
completes — including `{"error": ...}` and `{"result": {"isError": true}}`.
So a sink replying "permission denied" produced a CRITICAL finding reading
"Live exfil confirmed" and "sink accepted payload".

The scanner cannot see egress without an out-of-band oracle, so the strongest
honest in-band claim is that the sink accepted the payload without error.
"""

from __future__ import annotations

import pytest

from mcpnuke.checks import exfil_flow
from mcpnuke.core.models import TargetResult


def _tool(name: str, desc: str = "", params: tuple[str, ...] = ("content",)) -> dict:
    return {
        "name": name,
        "description": desc,
        "inputSchema": {"properties": {p: {"type": "string"} for p in params}},
    }


class _ScriptedSession:
    """Returns a queued response per tool name."""

    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def call(self, method: str, params: dict, timeout: float = 10.0):
        name = params["name"]
        self.calls.append((name, params.get("arguments", {})))
        resp = self.responses.get(name)
        if isinstance(resp, Exception):
            raise resp
        return resp


def _ok(text: str) -> dict:
    return {"result": {"content": [{"type": "text", "text": text}]}}


def _rpc_error(message: str) -> dict:
    return {"error": {"code": -32000, "message": message}}


def _tool_error(text: str) -> dict:
    return {"result": {"isError": True, "content": [{"type": "text", "text": text}]}}


@pytest.fixture
def target() -> TargetResult:
    r = TargetResult(url="http://target/mcp")
    r.tools = [
        _tool("read_user_records", "Read customer data records"),
        _tool("send_webhook", "Send data to an external endpoint"),
    ]
    return r


def _run(result: TargetResult, session) -> None:
    exfil_flow.check_exfil_flow(result, session=session, probe_opts={})


def _live(result: TargetResult) -> list:
    return [f for f in result.findings if "Live exfil" in f.title]


class TestErrorResponsesAreNotConfirmations:
    def test_a_jsonrpc_error_from_the_sink_is_not_confirmed(self, target) -> None:
        session = _ScriptedSession({
            "read_user_records": _ok("alice,bob,carol - customer records"),
            "send_webhook": _rpc_error("permission denied"),
        })
        _run(target, session)
        assert not _live(target), "an error response was reported as confirmed exfil"

    def test_an_iserror_result_is_not_confirmed(self, target) -> None:
        session = _ScriptedSession({
            "read_user_records": _ok("alice,bob,carol - customer records"),
            "send_webhook": _tool_error("invalid destination"),
        })
        _run(target, session)
        assert not _live(target), "isError result was reported as confirmed exfil"

    def test_a_transport_failure_is_not_confirmed(self, target) -> None:
        session = _ScriptedSession({
            "read_user_records": _ok("alice,bob,carol - customer records"),
            "send_webhook": TimeoutError("no route"),
        })
        _run(target, session)
        assert not _live(target)


class TestGenuineAcceptanceStillFires:
    def test_a_clean_sink_response_is_reported(self, target) -> None:
        session = _ScriptedSession({
            "read_user_records": _ok("alice,bob,carol - customer records"),
            "send_webhook": _ok("queued for delivery"),
        })
        _run(target, session)
        hits = _live(target)
        assert hits, "a clean acceptance should still be reported"
        assert hits[0].severity == "CRITICAL"

    def test_the_finding_names_both_ends(self, target) -> None:
        session = _ScriptedSession({
            "read_user_records": _ok("alice,bob,carol - customer records"),
            "send_webhook": _ok("queued"),
        })
        _run(target, session)
        blob = _live(target)[0].title + _live(target)[0].detail
        assert "read_user_records" in blob
        assert "send_webhook" in blob

    def test_the_canary_actually_carries_source_data(self, target) -> None:
        """The point of the replay is that real data crosses the boundary."""
        session = _ScriptedSession({
            "read_user_records": _ok("alice,bob,carol - customer records"),
            "send_webhook": _ok("queued"),
        })
        _run(target, session)
        sink_args = [a for n, a in session.calls if n == "send_webhook"]
        assert sink_args
        sent = " ".join(str(v) for v in sink_args[0].values())
        assert exfil_flow.EXFIL_CANARY in sent
        assert "alice" in sent, "source data never made it into the sink payload"


class TestClaimIsProportionate:
    def test_it_does_not_claim_egress_was_observed(self, target) -> None:
        """No out-of-band oracle exists, so 'accepted' is the honest ceiling."""
        session = _ScriptedSession({
            "read_user_records": _ok("alice,bob,carol - customer records"),
            "send_webhook": _ok("queued"),
        })
        _run(target, session)
        text = (_live(target)[0].title + " " + _live(target)[0].detail).lower()
        assert "accepted" in text
        for overclaim in ("data left", "egress confirmed", "successfully routed"):
            assert overclaim not in text, f"overclaims with {overclaim!r}"


class TestSinkErrorHelper:
    @pytest.mark.parametrize(
        "resp,expected",
        [
            (None, True),
            ({"error": {"code": -1, "message": "nope"}}, True),
            ({"result": {"isError": True, "content": []}}, True),
            ({"result": {"content": [{"type": "text", "text": "ok"}]}}, False),
            ({"result": "plain string result"}, False),
            ({"result": {}}, False),
        ],
    )
    def test_rejects_only_failures(self, resp, expected) -> None:
        assert exfil_flow._is_failure(resp) is expected
