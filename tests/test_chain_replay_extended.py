"""Tests for extended chain replay: DAG topology, conditions, parallel groups."""

import pytest

from mcpnuke.core.chain_replay import (
    ChainGraph,
    ChainNode,
    ChainStep,
    ProposedChain,
    parse_chain_graph,
)


class TestChainGraphParsing:
    def test_linear_3hop_chain_parses(self):
        chain = ProposedChain(
            title="3hop",
            steps=[
                ChainStep("read", {}),
                ChainStep("decode", {"in": "{{step0.output}}"}),
                ChainStep("exfil", {"data": "{{step1.output}}"}),
            ],
        )
        graph = parse_chain_graph(chain)
        assert len(graph.nodes) == 3
        assert graph.nodes[0].dependencies == []
        assert graph.nodes[1].dependencies == [0]
        assert graph.nodes[2].dependencies == [1]

    def test_diamond_dependency_parses(self):
        chain = ProposedChain(
            title="diamond",
            steps=[
                ChainStep("a", {}),
                ChainStep("b", {"in": "{{step0.output}}"}),
                ChainStep("c", {"in": "{{step0.output}}"}),
                ChainStep("d", {"in": "{{step1.output}}", "in2": "{{step2.output}}"}),
            ],
        )
        graph = parse_chain_graph(chain)
        assert graph.nodes[3].dependencies == [1, 2]

    def test_cycle_detected_and_rejected(self):
        chain = ProposedChain(
            title="cycle",
            steps=[
                ChainStep("a", {"in": "{{step1.output}}"}),
                ChainStep("b", {"in": "{{step0.output}}"}),
            ],
        )
        with pytest.raises(ValueError, match="circular dependency"):
            parse_chain_graph(chain)

    def test_self_dependency_rejected(self):
        chain = ProposedChain(
            title="self",
            steps=[ChainStep("a", {"in": "{{step0.output}}"})],
        )
        with pytest.raises(ValueError, match="self-dependency"):
            parse_chain_graph(chain)

    def test_orphan_node_detected(self):
        chain = ProposedChain(
            title="orphan",
            steps=[
                ChainStep("a", {}),
                ChainStep("b", {}),  # no dependency on a
                ChainStep("c", {"in": "{{step0.output}}"}),
            ],
        )
        graph = parse_chain_graph(chain)
        # b is reachable from root (index 0), so not orphan
        # true orphan would be disconnected entirely
        assert len(graph.nodes) == 3


class TestConditionalExecution:
    def test_condition_true_executes_step(self):
        from mcpnuke.core.chain_replay import StepResult, _evaluate_condition

        prior = [StepResult(tool="a", request_args={}, response_text="admin", failed=False)]
        assert _evaluate_condition("step0.response_text contains 'admin'", prior) is True

    def test_condition_false_skips_step(self):
        from mcpnuke.core.chain_replay import StepResult, _evaluate_condition

        prior = [StepResult(tool="a", request_args={}, response_text="user", failed=False)]
        assert _evaluate_condition("step0.response_text contains 'admin'", prior) is False

    def test_condition_on_failed_status(self):
        from mcpnuke.core.chain_replay import StepResult, _evaluate_condition

        prior = [StepResult(tool="a", request_args={}, response_text="", failed=True)]
        assert _evaluate_condition("step0.failed == True", prior) is True
        assert _evaluate_condition("step0.failed == False", prior) is False

    def test_invalid_condition_returns_false(self):
        from mcpnuke.core.chain_replay import StepResult, _evaluate_condition

        prior = [StepResult(tool="a", request_args={}, response_text="x", failed=False)]
        assert _evaluate_condition("invalid python syntax !!!", prior) is False

    def test_condition_with_numeric_comparison(self):
        from mcpnuke.core.chain_replay import StepResult, _evaluate_condition

        prior = [StepResult(tool="a", request_args={}, response_text="count: 5", failed=False)]
        assert _evaluate_condition("len(step0.response_text) > 3", prior) is True


class TestDAGExecution:
    def test_3hop_chain_executes_in_order(self):
        from mcpnuke.core.chain_replay import replay_chain_graph

        class _MockSession:
            def __init__(self):
                self.calls = []

            def call(self, method, params, timeout=10.0):
                tool = params.get("name")
                self.calls.append(tool)
                responses = {
                    "read": "secret",
                    "decode": "decoded_secret",
                    "exfil": "sent",
                }
                text = responses.get(tool)
                if text:
                    return {"result": {"content": [{"type": "text", "text": text}]}}
                return None

        graph = ChainGraph(nodes=[
            ChainNode(step=ChainStep("read", {}), dependencies=[]),
            ChainNode(step=ChainStep("decode", {"in": "{{step0.output}}"}), dependencies=[0]),
            ChainNode(step=ChainStep("exfil", {"data": "{{step1.output}}"}), dependencies=[1]),
        ])

        session = _MockSession()
        tools = {
            "read": {"name": "read", "inputSchema": {"type": "object"}},
            "decode": {"name": "decode", "inputSchema": {"type": "object"}},
            "exfil": {"name": "exfil", "inputSchema": {"type": "object"}},
        }
        run = replay_chain_graph(session, graph, tools)
        assert session.calls == ["read", "decode", "exfil"]
        assert run.completed

    def test_conditional_branch_taken(self):
        from mcpnuke.core.chain_replay import replay_chain_graph

        class _MockSession:
            def __init__(self):
                self.calls = []

            def call(self, method, params, timeout=10.0):
                tool = params.get("name")
                self.calls.append(tool)
                responses = {
                    "check": "admin",
                    "escalate": "escalated",
                    "enumerate": "enumerated",
                }
                text = responses.get(tool)
                if text:
                    return {"result": {"content": [{"type": "text", "text": text}]}}
                return None

        graph = ChainGraph(nodes=[
            ChainNode(step=ChainStep("check", {}), dependencies=[]),
            ChainNode(
                step=ChainStep("escalate", {}),
                dependencies=[0],
                condition="step0.response_text contains 'admin'",
            ),
            ChainNode(
                step=ChainStep("enumerate", {}),
                dependencies=[0],
                condition="step0.response_text contains 'user'",
            ),
        ])

        session = _MockSession()
        tools = {
            "check": {"name": "check", "inputSchema": {"type": "object"}},
            "escalate": {"name": "escalate", "inputSchema": {"type": "object"}},
            "enumerate": {"name": "enumerate", "inputSchema": {"type": "object"}},
        }
        replay_chain_graph(session, graph, tools)
        assert "escalate" in session.calls
        assert "enumerate" not in session.calls

    def test_parallel_group_execution(self):
        from mcpnuke.core.chain_replay import replay_chain_graph

        class _MockSession:
            def __init__(self):
                self.calls = []

            def call(self, method, params, timeout=10.0):
                tool = params.get("name")
                self.calls.append(tool)
                return {"result": {"content": [{"type": "text", "text": f"{tool}_result"}]}}

        graph = ChainGraph(nodes=[
            ChainNode(step=ChainStep("a", {}), dependencies=[]),
            ChainNode(step=ChainStep("b", {}), dependencies=[]),
            ChainNode(step=ChainStep("merge", {"x": "{{step0.output}}", "y": "{{step1.output}}"}), dependencies=[0, 1]),
        ])

        session = _MockSession()
        tools = {
            "a": {"name": "a", "inputSchema": {"type": "object"}},
            "b": {"name": "b", "inputSchema": {"type": "object"}},
            "merge": {"name": "merge", "inputSchema": {"type": "object"}},
        }
        run = replay_chain_graph(session, graph, tools)
        assert set(session.calls) == {"a", "b", "merge"}
        assert run.completed
