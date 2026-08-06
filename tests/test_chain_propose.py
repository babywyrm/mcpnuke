"""Phase 3 must emit chains the executor can run, not just describe them.

A finding that says "vault.read feeds net.send" is an argument. A finding that
also carries `steps: [{tool, args}]` with `{{step0.output}}` placeholders is a
program. The executor only understands the second form, so the prompt has to
ask for it and the parser has to reject prose that pretends to be one.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from mcpnuke.core import llm
from mcpnuke.core.chain_replay import ProposedChain, parse_proposed_chains


class TestParsingExecutableChains:
    def test_a_well_formed_chain_is_accepted(self):
        text = json.dumps(
            [
                {
                    "severity": "CRITICAL",
                    "title": "read then send",
                    "detail": "vault.read feeds net.send",
                    "taxonomy_id": "MCP-T12",
                    "steps": [
                        {"tool": "vault.read", "args": {}},
                        {"tool": "net.send", "args": {"body": "{{step0.output}}"}},
                    ],
                }
            ]
        )

        chains = parse_proposed_chains(text)

        assert len(chains) == 1
        assert chains[0].steps[0].tool == "vault.read"
        assert chains[0].steps[1].args["body"] == "{{step0.output}}"

    def test_a_chain_without_steps_is_rejected(self):
        text = json.dumps(
            [{"severity": "HIGH", "title": "vague", "detail": "something bad"}]
        )

        assert parse_proposed_chains(text) == []

    def test_a_single_step_is_rejected(self):
        text = json.dumps(
            [
                {
                    "severity": "HIGH",
                    "title": "not a chain",
                    "detail": "one tool",
                    "steps": [{"tool": "vault.read", "args": {}}],
                }
            ]
        )

        assert parse_proposed_chains(text) == []

    def test_a_step_naming_no_tool_is_rejected(self):
        text = json.dumps(
            [
                {
                    "severity": "HIGH",
                    "title": "broken",
                    "detail": "x",
                    "steps": [{"args": {}}, {"tool": "net.send", "args": {}}],
                }
            ]
        )

        assert parse_proposed_chains(text) == []

    def test_truncated_output_still_yields_complete_chains(self):
        text = json.dumps(
            [
                {
                    "severity": "CRITICAL",
                    "title": "good",
                    "detail": "works",
                    "steps": [
                        {"tool": "a.read", "args": {}},
                        {"tool": "b.send", "args": {"body": "{{step0.output}}"}},
                    ],
                },
                {
                    "severity": "HIGH",
                    "title": "cut",
                    "detail": "partial",
                    "steps": [{"tool": "c.x", "args": {}}],
                },
            ]
        )[:-40]

        chains = parse_proposed_chains(text)

        assert [c.title for c in chains] == ["good"]

    def test_taxonomy_and_detail_are_kept(self):
        text = json.dumps(
            [
                {
                    "severity": "CRITICAL",
                    "title": "t",
                    "detail": "explanation",
                    "taxonomy_id": "MCP-T12",
                    "steps": [
                        {"tool": "a", "args": {}},
                        {"tool": "b", "args": {}},
                    ],
                }
            ]
        )

        chain = parse_proposed_chains(text)[0]

        assert chain.detail == "explanation"
        assert chain.taxonomy_id == "MCP-T12"


class TestTheProposePromptAsksForSteps:
    def _system(self, monkeypatch) -> str:
        seen: dict = {}

        class _Messages:
            def create(self, **kw):
                seen["system"] = kw["system"]
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="[]")],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))
        llm.propose_chains(
            [{"name": "t", "description": "d", "inputSchema": {}}],
            [{"check": "c", "severity": "HIGH", "title": "t"}],
        )
        return seen["system"]

    def test_the_prompt_requires_a_steps_field(self, monkeypatch):
        assert "steps" in self._system(monkeypatch)

    def test_the_prompt_shows_the_placeholder_form(self, monkeypatch):
        assert "{{step0.output}}" in self._system(monkeypatch)

    def test_the_prompt_rejects_prose_only_chains(self, monkeypatch):
        system = self._system(monkeypatch).lower()

        assert "without steps" in system or "omit" in system


class TestProposeChainsReturnsProposedChains:
    def test_the_return_type_is_a_list_of_proposed_chains(self, monkeypatch):
        payload = json.dumps(
            [
                {
                    "severity": "CRITICAL",
                    "title": "exfil",
                    "detail": "a then b",
                    "steps": [
                        {"tool": "a", "args": {}},
                        {"tool": "b", "args": {"x": "{{step0.output}}"}},
                    ],
                }
            ]
        )

        class _Messages:
            def create(self, **kw):
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text=payload)],
                    usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
        monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))

        out = llm.propose_chains(
            [{"name": "a"}, {"name": "b"}],
            [{"check": "c", "severity": "HIGH", "title": "t"}],
        )

        assert isinstance(out[0], ProposedChain)
        assert out[0].steps[1].args["x"] == "{{step0.output}}"
