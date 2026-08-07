"""Optional LLM judge upgrades callable-but-unproven when data moved via transform."""

from mcpnuke.checks.llm_analysis import _judge_chain


class _Backend:
    def __init__(self, verdict):
        self._verdict = verdict
        self.calls = 0

    def judge_chain_run(self, title, transcript, model, log=None):
        self.calls += 1
        return self._verdict  # (bool, str)


def test_judge_reports_semantic_movement():
    backend = _Backend((True, "step0 secret appears base64-encoded in step1 body"))
    moved, why = _judge_chain(backend, "c", "transcript...", "m", lambda _m: None)
    assert moved is True
    assert "base64" in why


def test_judge_absent_backend_returns_false():
    moved, why = _judge_chain(object(), "c", "t", "m", lambda _m: None)
    assert moved is False
    assert why == ""
