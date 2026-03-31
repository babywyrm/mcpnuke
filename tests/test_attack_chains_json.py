"""Tests for structured attack chain JSON output with evidence-based tool names."""

from mcpnuke.core.models import TargetResult, AttackChain


def test_attack_chain_dataclass():
    chain = AttackChain(source="prompt_injection", target="code_execution")
    assert chain.source == "prompt_injection"
    assert chain.target == "code_execution"
    assert chain.evidence_tools == []


def test_attack_chain_with_evidence_tools():
    chain = AttackChain(
        source="input_sanitization",
        target="code_execution",
        evidence_tools=["execute_command", "run_query"],
    )
    assert chain.evidence_tools == ["execute_command", "run_query"]


def test_target_result_has_attack_chains_field():
    r = TargetResult(url="http://test")
    assert hasattr(r, "attack_chains")
    assert isinstance(r.attack_chains, list)
    assert len(r.attack_chains) == 0


def test_check_attack_chains_populates_both():
    from mcpnuke.checks.chaining import check_attack_chains

    r = TargetResult(url="http://test")
    r.add("prompt_injection", "CRITICAL", "test")
    r.add("code_execution", "CRITICAL", "test")
    check_attack_chains(r)

    assert len(r.attack_chains) > 0
    chain = r.attack_chains[0]
    assert chain.source == "prompt_injection"
    assert chain.target == "code_execution"

    chain_findings = [f for f in r.findings if f.check == "attack_chain"]
    assert len(chain_findings) > 0


def test_check_attack_chains_extracts_tool_names():
    from mcpnuke.checks.chaining import check_attack_chains

    r = TargetResult(url="http://test")
    r.add("input_sanitization", "HIGH", "Tool 'execute_command' reflects probe canary unsanitized")
    r.add("code_execution", "CRITICAL", "Dangerous capability [shell_exec]: 'execute_command'")
    check_attack_chains(r)

    assert len(r.attack_chains) > 0
    chain = r.attack_chains[0]
    assert "execute_command" in chain.evidence_tools

    chain_finding = [f for f in r.findings if f.check == "attack_chain"][0]
    assert "execute_command" in chain_finding.title


def test_json_output_includes_evidence_tools():
    from mcpnuke.reporting.json_out import _build_target_dict

    r = TargetResult(url="http://test")
    r.attack_chains.append(
        AttackChain(source="a", target="b", evidence_tools=["tool_x", "tool_y"])
    )
    d = _build_target_dict(r)
    assert "attack_chains" in d
    assert d["attack_chains"][0]["source"] == "a"
    assert d["attack_chains"][0]["target"] == "b"
    assert d["attack_chains"][0]["evidence_tools"] == ["tool_x", "tool_y"]
