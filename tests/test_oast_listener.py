"""An in-band response cannot prove data left the target.

`exfil_flow` calls a source tool, feeds what it read into a sink, and reports
the path when the sink does not error. That establishes the path is callable,
which is why the finding says so and explicitly declines to claim delivery: a
sink that answers `{"status": "queued"}` is indistinguishable from one that
answers it and drops the payload.

The missing piece is an oracle outside the conversation. A listener the scanner
controls, named in the payload it plants, turns "the sink accepted this" into
"the target connected to an address only this probe knew about" — which no
amount of tool response text can fake.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from mcpnuke.core.oast import CanaryListener


@pytest.fixture
def listener():
    with CanaryListener() as active:
        yield active


def _get(url: str, timeout: float = 5.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def _post(url: str, body: bytes, timeout: float = 5.0) -> int:
    request = urllib.request.Request(url, data=body, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


class TestIssuingCanaries:
    def test_a_canary_url_is_reachable(self, listener):
        assert _get(listener.url_for(listener.issue())) == 200

    def test_each_canary_is_unique(self, listener):
        assert listener.issue() != listener.issue()

    def test_the_token_appears_in_its_url(self, listener):
        token = listener.issue()

        assert token in listener.url_for(token)

    def test_a_canary_is_unhit_until_something_calls_it(self, listener):
        assert listener.hits(listener.issue()) == []


class TestObservingCallbacks:
    def test_a_request_is_recorded_against_its_canary(self, listener):
        token = listener.issue()

        _get(listener.url_for(token))

        assert len(listener.hits(token)) == 1

    def test_a_hit_is_not_attributed_to_another_canary(self, listener):
        called, quiet = listener.issue(), listener.issue()

        _get(listener.url_for(called))

        assert listener.hits(quiet) == []

    def test_the_method_is_recorded(self, listener):
        token = listener.issue()

        _post(listener.url_for(token), b"x")

        assert listener.hits(token)[0].method == "POST"

    def test_the_body_is_captured_because_it_carries_the_exfiltrated_data(self, listener):
        token = listener.issue()

        _post(listener.url_for(token), b"AWS_SECRET_ACCESS_KEY=abc123")

        assert "AWS_SECRET_ACCESS_KEY=abc123" in listener.hits(token)[0].body

    def test_the_headers_are_captured(self, listener):
        token = listener.issue()

        _get(listener.url_for(token))

        assert listener.hits(token)[0].headers

    def test_repeat_callbacks_are_all_recorded(self, listener):
        token = listener.issue()

        _get(listener.url_for(token))
        _get(listener.url_for(token))

        assert len(listener.hits(token)) == 2

    def test_a_query_string_does_not_break_attribution(self, listener):
        """A sink may append its own parameters to the URL it was given."""
        token = listener.issue()

        _get(listener.url_for(token) + "?ref=svc&n=1")

        assert len(listener.hits(token)) == 1

    def test_a_trailing_path_does_not_break_attribution(self, listener):
        token = listener.issue()

        _get(listener.url_for(token) + "/callback")

        assert len(listener.hits(token)) == 1


class TestUnknownPaths:
    def test_an_unknown_path_still_answers(self, listener):
        assert _get(f"{listener.base_url}/not-a-canary") == 200

    def test_an_unknown_path_is_attributed_to_nothing(self, listener):
        token = listener.issue()

        _get(f"{listener.base_url}/not-a-canary")

        assert listener.hits(token) == []


class TestReachabilityFromTheTarget:
    """A container or a remote host cannot reach the scanner's loopback."""

    def test_the_advertised_host_can_be_overridden(self):
        with CanaryListener(advertised_host="host.docker.internal") as active:
            assert "host.docker.internal" in active.url_for(active.issue())

    def test_the_port_is_still_the_real_one_when_the_host_is_overridden(self):
        with CanaryListener(advertised_host="10.0.0.5") as active:
            assert f":{active.port}" in active.base_url

    def test_a_port_can_be_requested_for_a_firewall_hole(self):
        with CanaryListener(port=0) as active:
            assert active.port > 0


class TestLifecycle:
    def test_the_port_is_released_on_stop(self):
        listener = CanaryListener()
        listener.start()
        port = listener.port
        listener.stop()

        with CanaryListener(port=port) as reused:
            assert reused.port == port

    def test_stopping_twice_is_harmless(self):
        listener = CanaryListener()
        listener.start()
        listener.stop()
        listener.stop()

    def test_hits_for_an_unknown_token_are_empty_not_an_error(self, listener):
        assert listener.hits("never-issued") == []

    def test_any_hit_reports_whether_anything_called_back(self, listener):
        token = listener.issue()
        assert not listener.any_hit()

        _get(listener.url_for(token))

        assert listener.any_hit()

    def test_await_hits_waits_for_a_delayed_callback(self, listener):
        import threading
        import time

        token = listener.issue()
        url = listener.url_for(token)

        def _later() -> None:
            time.sleep(0.2)
            _get(url)

        threading.Thread(target=_later, daemon=True).start()
        assert listener.hits(token) == []
        hits = listener.await_hits(token, wait=1.0)
        assert len(hits) == 1
        assert hits[0].token == token
