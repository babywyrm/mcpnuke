"""Bounded re-proposal: a halted chain can be repaired and replayed."""

from mcpnuke.checks.llm_analysis import _replay_with_retries
from mcpnuke.core.chain_replay import ChainStep, ProposedChain


class _Session:
    """First-proposed 'bad_tool' errors; the revised 'good_tool' succeeds."""

    def call(self, method, params, timeout=10.0):
        if params["name"] == "bad_tool":
            return {
                "result": {
                    "isError": True,
                    "content": [{"type": "text", "text": "nope"}],
                }
            }
        return {"result": {"content": [{"type": "text", "text": "SECRET"}]}}


class _Backend:
    def __init__(self):
        self.revise_calls = 0

    def revise_chain(self, chain, transcript, tools, model, log=None):
        self.revise_calls += 1
        return ProposedChain(
            title=chain.title,
            steps=[
                ChainStep("read_ok"),
                ChainStep("good_tool", {"x": "{{step0.output}}"}),
            ],
        )


TOOLS = {
    "read_ok": {"name": "read_ok", "description": "read"},
    "bad_tool": {"name": "bad_tool", "description": "read"},
    "good_tool": {"name": "good_tool", "description": "read"},
}


def _halting_chain() -> ProposedChain:
    return ProposedChain(
        title="c",
        steps=[
            ChainStep("read_ok"),
            ChainStep("bad_tool", {"x": "{{step0.output}}"}),
        ],
    )


def test_retry_repairs_and_reruns():
    backend = _Backend()
    run, _verdict = _replay_with_retries(
        _Session(),
        _halting_chain(),
        TOOLS,
        backend,
        model="m",
        log=lambda _m: None,
        retries=1,
        safe_mode=False,
        oast=None,
    )
    assert backend.revise_calls == 1
    assert run.completed


def test_zero_retries_does_not_revise():
    backend = _Backend()
    run, _verdict = _replay_with_retries(
        _Session(),
        _halting_chain(),
        TOOLS,
        backend,
        model="m",
        log=lambda _m: None,
        retries=0,
        safe_mode=False,
        oast=None,
    )
    assert backend.revise_calls == 0
    assert not run.completed


def test_retry_logs_the_repair_attempt():
    logs: list[str] = []
    _replay_with_retries(
        _Session(),
        _halting_chain(),
        TOOLS,
        _Backend(),
        model="m",
        log=logs.append,
        retries=1,
        safe_mode=False,
        oast=None,
    )
    assert any("revis" in m.lower() or "repair" in m.lower() for m in logs)
