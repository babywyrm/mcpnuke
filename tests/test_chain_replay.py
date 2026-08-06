"""A proposed chain stays an argument until something runs it.

Phase 3 names the tools in a chain and the value carrying data between steps,
which is a hypothesis about what the target will do. Replaying it — calling the
steps in order, threading each response into the next — is what turns "these
tools compose" into "these tools composed, here is the transcript".

The executor is deterministic and takes an injected session, so the threading,
the substitution and the verdict are testable without a model or a live target.
"""

from __future__ import annotations

from mcpnuke.core.chain_replay import (
    ChainStep,
    ProposedChain,
    replay_chain,
    summarize_run,
)


class _ScriptedSession:
    """Answers tools/call from a name→response script and logs the calls."""

    def __init__(self, responses: dict) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict]] = []

    def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
        if method != "tools/call":
            return None
        name = params.get("name", "")
        args = params.get("arguments", {})
        self.calls.append((name, args))
        resp = self._responses.get(name)
        return resp(args) if callable(resp) else resp


def _text(s: str) -> dict:
    return {"result": {"content": [{"type": "text", "text": s}]}}


def _error(msg: str) -> dict:
    return {"result": {"isError": True, "content": [{"type": "text", "text": msg}]}}


TOOLS = {
    "vault.read": {"name": "vault.read", "inputSchema": {"properties": {"key": {"type": "string"}}}},
    "net.send": {"name": "net.send", "inputSchema": {"properties": {"body": {"type": "string"}}}},
}


class TestStepsRunInOrder:
    def test_every_step_is_called(self):
        session = _ScriptedSession({"vault.read": _text("secret"), "net.send": _text("ok")})
        chain = ProposedChain(
            title="read then send",
            steps=[ChainStep("vault.read", {}), ChainStep("net.send", {})],
        )

        replay_chain(session, chain, TOOLS)

        assert [name for name, _ in session.calls] == ["vault.read", "net.send"]

    def test_the_run_records_each_response(self):
        session = _ScriptedSession({"vault.read": _text("AKIA-secret"), "net.send": _text("queued")})
        chain = ProposedChain("c", [ChainStep("vault.read", {}), ChainStep("net.send", {})])

        run = replay_chain(session, chain, TOOLS)

        assert run.results[0].response_text == "AKIA-secret"
        assert run.results[1].response_text == "queued"


class TestDataThreadsBetweenSteps:
    def test_a_prior_output_placeholder_is_substituted(self):
        session = _ScriptedSession({"vault.read": _text("AKIA-secret"), "net.send": _text("ok")})
        chain = ProposedChain(
            "exfil",
            [
                ChainStep("vault.read", {}),
                ChainStep("net.send", {"body": "{{step0.output}}"}),
            ],
        )

        replay_chain(session, chain, TOOLS)

        sent = dict(session.calls)["net.send"]
        assert sent["body"] == "AKIA-secret"

    def test_a_placeholder_can_be_embedded_in_a_larger_string(self):
        session = _ScriptedSession({"vault.read": _text("s3cr3t"), "net.send": _text("ok")})
        chain = ProposedChain(
            "exfil",
            [ChainStep("vault.read", {}), ChainStep("net.send", {"body": "leak: {{step0.output}}!"})],
        )

        replay_chain(session, chain, TOOLS)

        assert dict(session.calls)["net.send"]["body"] == "leak: s3cr3t!"

    def test_an_unresolved_placeholder_is_left_alone_not_crashed(self):
        session = _ScriptedSession({"net.send": _text("ok")})
        chain = ProposedChain("c", [ChainStep("net.send", {"body": "{{step9.output}}"})])

        run = replay_chain(session, chain, TOOLS)

        assert run.results[0].request_args["body"] == "{{step9.output}}"


class TestFailureStopsTheChain:
    def test_a_step_error_halts_the_run(self):
        session = _ScriptedSession({"vault.read": _error("denied"), "net.send": _text("ok")})
        chain = ProposedChain("c", [ChainStep("vault.read", {}), ChainStep("net.send", {})])

        run = replay_chain(session, chain, TOOLS)

        assert [name for name, _ in session.calls] == ["vault.read"]
        assert not run.completed

    def test_the_failing_step_is_marked(self):
        session = _ScriptedSession({"vault.read": _error("denied")})
        chain = ProposedChain("c", [ChainStep("vault.read", {})])

        run = replay_chain(session, chain, TOOLS)

        assert run.results[0].failed

    def test_a_step_naming_an_unknown_tool_fails_without_calling(self):
        session = _ScriptedSession({})
        chain = ProposedChain("c", [ChainStep("does.not.exist", {})])

        run = replay_chain(session, chain, TOOLS)

        assert run.results[0].failed
        assert session.calls == []

    def test_a_fully_successful_chain_is_marked_completed(self):
        session = _ScriptedSession({"vault.read": _text("x"), "net.send": _text("y")})
        chain = ProposedChain("c", [ChainStep("vault.read", {}), ChainStep("net.send", {})])

        run = replay_chain(session, chain, TOOLS)

        assert run.completed


class TestTheVerdict:
    def _run(self, responses, steps):
        session = _ScriptedSession(responses)
        return replay_chain(session, ProposedChain("c", steps), TOOLS)

    def test_a_halted_chain_is_not_reproduced(self):
        run = self._run({"vault.read": _error("no")}, [ChainStep("vault.read", {})])

        verdict = summarize_run(run)

        assert not verdict.reproduced

    def test_a_completed_chain_that_moves_data_is_reproduced(self):
        run = self._run(
            {"vault.read": _text("AKIA-secret"), "net.send": _text("ok")},
            [ChainStep("vault.read", {}), ChainStep("net.send", {"body": "{{step0.output}}"})],
        )

        verdict = summarize_run(run)

        assert verdict.reproduced

    def test_the_verdict_notes_which_data_moved(self):
        run = self._run(
            {"vault.read": _text("AKIA-secret"), "net.send": _text("ok")},
            [ChainStep("vault.read", {}), ChainStep("net.send", {"body": "{{step0.output}}"})],
        )

        verdict = summarize_run(run)

        assert "AKIA-secret"[:8] in verdict.evidence or "step 0" in verdict.detail

    def test_a_completed_chain_that_threads_nothing_is_only_callable(self):
        """Every step ran, but no output fed a later input: reachable, not proven."""
        run = self._run(
            {"vault.read": _text("x"), "net.send": _text("ok")},
            [ChainStep("vault.read", {}), ChainStep("net.send", {"body": "static"})],
        )

        verdict = summarize_run(run)

        assert not verdict.reproduced
        assert verdict.callable_end_to_end

    def test_a_single_step_chain_is_rejected_as_not_a_chain(self):
        run = self._run({"vault.read": _text("x")}, [ChainStep("vault.read", {})])

        verdict = summarize_run(run)

        assert not verdict.reproduced


class TestSafeArgsAreFilledIn:
    def test_required_params_absent_from_the_template_are_supplied(self):
        session = _ScriptedSession({"vault.read": _text("x")})
        tools = {
            "vault.read": {
                "name": "vault.read",
                "inputSchema": {
                    "properties": {"key": {"type": "string"}},
                    "required": ["key"],
                },
            }
        }
        chain = ProposedChain("c", [ChainStep("vault.read", {})])

        replay_chain(session, chain, tools)

        assert "key" in dict(session.calls)["vault.read"]

    def test_the_template_overrides_the_safe_default(self):
        session = _ScriptedSession({"vault.read": _text("x")})
        tools = {
            "vault.read": {
                "name": "vault.read",
                "inputSchema": {
                    "properties": {"key": {"type": "string"}},
                    "required": ["key"],
                },
            }
        }
        chain = ProposedChain("c", [ChainStep("vault.read", {"key": "chosen"})])

        replay_chain(session, chain, tools)

        assert dict(session.calls)["vault.read"]["key"] == "chosen"
