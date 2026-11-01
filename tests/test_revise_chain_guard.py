"""A revision from the model is used only if it is a real ProposedChain."""

from mcpnuke.checks.llm_analysis import _revise_chain
from mcpnuke.core.chain_replay import ChainStep, ProposedChain

_CHAIN = ProposedChain(title="t", steps=[ChainStep(tool="read", args={})])


class _Backend:
    def __init__(self, reply: object) -> None:
        self.reply = reply

    def revise_chain(self, *_a: object, **_k: object) -> object:
        return self.reply


def test_a_proposed_chain_is_returned() -> None:
    revised = ProposedChain(title="r", steps=[ChainStep(tool="send", args={})])
    assert _revise_chain(_Backend(revised), _CHAIN, "", [], "m", lambda _m: None) is revised


def test_anything_else_is_dropped() -> None:
    reply = {"title": "r", "steps": []}
    assert _revise_chain(_Backend(reply), _CHAIN, "", [], "m", lambda _m: None) is None
