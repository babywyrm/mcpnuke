"""Egress becomes provable when the payload names an address only we know.

`exfil_flow` currently reports that a sink accepted a payload and says plainly
that delivery is not observed, because nothing in the conversation can show it.
With a listener the scanner controls, the canary carries a URL minted for that
one source-sink pair: a request arriving for it is evidence no tool response
can manufacture.

The two outcomes must stay distinguishable. A callback is confirmation. No
callback is still worth reporting — the path is callable — but must keep the
weaker wording, because a target with no outbound network is indistinguishable
from one that discarded the data.
"""

from __future__ import annotations

import contextlib
import urllib.request

import pytest

from mcpnuke.checks.exfil_flow import check_exfil_flow
from mcpnuke.core.models import TargetResult
from mcpnuke.core.oast import CanaryListener

SOURCE = {
    "name": "vault.read_secret",
    "description": "Read a stored secret credential",
    "inputSchema": {"properties": {"key": {"type": "string"}}},
}
SINK = {
    "name": "notify.send_message",
    "description": "Send a message to an external webhook",
    "inputSchema": {"properties": {"content": {"type": "string"}}},
}


class _Session:
    """A source that returns data and a sink that does what it is told."""

    def __init__(self, on_sink=None) -> None:
        self.on_sink = on_sink
        self.sink_payloads: list[str] = []

    def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
        if method != "tools/call":
            return None
        name = params.get("name")
        if name == SOURCE["name"]:
            return {"result": {"content": [{"type": "text", "text": "AKIAIOSFODNN7EXAMPLE"}]}}
        payload = " ".join(str(v) for v in (params.get("arguments") or {}).values())
        self.sink_payloads.append(payload)
        if self.on_sink:
            self.on_sink(payload)
        return {"result": {"content": [{"type": "text", "text": "queued"}]}}


def _result() -> TargetResult:
    result = TargetResult(url="http://localhost:8080/mcp")
    result.tools = [SOURCE, SINK]
    return result


def _exfil_findings(result: TargetResult) -> list:
    return [f for f in result.findings if "→" in f.title or "->" in f.title]


@pytest.fixture
def listener():
    with CanaryListener(advertised_host="127.0.0.1") as active:
        yield active


def _fetch_any_url(payload: str) -> None:
    """Stand in for a sink that really does reach out to what it was given."""
    for word in payload.split():
        if word.startswith("http://"):
            with contextlib.suppress(Exception):
                urllib.request.urlopen(word, timeout=3).close()


class TestTheCanaryCarriesTheListener:
    def test_the_payload_contains_a_canary_url(self, listener):
        session = _Session()

        check_exfil_flow(_result(), session, {"oast": listener, "oast_wait": 0.4})

        assert any("http://127.0.0.1" in p for p in session.sink_payloads)

    def test_the_payload_still_carries_the_source_data(self, listener):
        session = _Session()

        check_exfil_flow(_result(), session, {"oast": listener, "oast_wait": 0.4})

        assert any("AKIAIOSFODNN7EXAMPLE" in p for p in session.sink_payloads)

    def test_no_canary_url_is_planted_without_a_listener(self):
        session = _Session()

        check_exfil_flow(_result(), session, {})

        assert not any("http://" in p for p in session.sink_payloads)


class TestAConfirmedCallback:
    def test_egress_is_reported_as_confirmed(self, listener):
        result = _result()

        check_exfil_flow(result, _Session(on_sink=_fetch_any_url), {"oast": listener, "oast_wait": 0.4})

        assert any("confirmed" in f.title.lower() for f in _exfil_findings(result))

    def test_it_is_critical(self, listener):
        result = _result()

        check_exfil_flow(result, _Session(on_sink=_fetch_any_url), {"oast": listener, "oast_wait": 0.4})

        confirmed = [f for f in _exfil_findings(result) if "confirmed" in f.title.lower()]
        assert confirmed and all(f.severity == "CRITICAL" for f in confirmed)

    def test_the_callback_is_recorded_as_evidence(self, listener):
        result = _result()

        check_exfil_flow(result, _Session(on_sink=_fetch_any_url), {"oast": listener, "oast_wait": 0.4})

        confirmed = [f for f in _exfil_findings(result) if "confirmed" in f.title.lower()]
        assert any("GET" in f.evidence or "POST" in f.evidence for f in confirmed)

    def test_both_ends_of_the_path_are_named(self, listener):
        result = _result()

        check_exfil_flow(result, _Session(on_sink=_fetch_any_url), {"oast": listener, "oast_wait": 0.4})

        confirmed = [f for f in _exfil_findings(result) if "confirmed" in f.title.lower()]
        assert confirmed
        assert all(
            SOURCE["name"] in f.title and SINK["name"] in f.title for f in confirmed
        )


class TestNoCallback:
    def test_the_claim_stays_at_accepted(self, listener):
        """A target with no egress must not be reported as confirmed."""
        result = _result()

        check_exfil_flow(result, _Session(), {"oast": listener, "oast_wait": 0.4})

        assert not any("confirmed" in f.title.lower() for f in _exfil_findings(result))

    def test_the_path_is_still_reported(self, listener):
        result = _result()

        check_exfil_flow(result, _Session(), {"oast": listener, "oast_wait": 0.4})

        assert _exfil_findings(result)

    def test_the_wording_still_declines_to_claim_delivery(self, listener):
        result = _result()

        check_exfil_flow(result, _Session(), {"oast": listener, "oast_wait": 0.4})

        live = [f for f in _exfil_findings(result) if "Live exfil" in f.title]
        assert live and all("not observed" in f.detail for f in live)


class TestWithoutTheListenerNothingChanges:
    def test_the_existing_finding_is_unaffected(self):
        result = _result()

        check_exfil_flow(result, _Session(), {})

        live = [f for f in _exfil_findings(result) if "Live exfil" in f.title]
        assert live and all("not observed" in f.detail for f in live)

    def test_no_confirmation_is_claimed(self):
        result = _result()

        check_exfil_flow(result, _Session(on_sink=_fetch_any_url), {})

        assert not any("confirmed" in f.title.lower() for f in _exfil_findings(result))
