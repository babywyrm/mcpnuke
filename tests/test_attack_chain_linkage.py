"""A chain claim should say what links the two ends.

`check_attack_chains` intersects the set of checks that fired with a table of
34 pairs and emits CRITICAL "Attack chain: A -> B". It never asks whether the
two findings can reach each other, so two unrelated tools with unrelated flaws
produce the same CRITICAL as a genuine source-to-sink path.

Where both sides name tools and the sets are disjoint, that is positive
evidence of no shared tool and the claim is graded down and labelled. Where
either side is target-scoped (auth, transport), linkage is unknowable from
findings alone and the severity is left where it was — the basis is stated
instead of guessed.
"""

from __future__ import annotations

from mcpnuke.checks.chaining import check_attack_chains
from mcpnuke.core.models import Finding, TargetResult


def _result(tools: list[str]) -> TargetResult:
    r = TargetResult(url="http://target/mcp")
    r.tools = [{"name": t, "description": "", "inputSchema": {}} for t in tools]
    return r


def _finding(check: str, title: str) -> Finding:
    return Finding(
        target="http://target/mcp",
        check=check,
        severity="HIGH",
        title=title,
        detail="",
    )


def _chain_findings(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "attack_chain"]


class TestSharedToolIsStrongEvidence:
    def _shared(self) -> TargetResult:
        r = _result(["run_query"])
        r.findings = [
            _finding("prompt_injection", "Injection in tool 'run_query'"),
            _finding("code_execution", "Code execution via tool 'run_query'"),
        ]
        return r

    def test_it_is_reported(self) -> None:
        r = self._shared()
        check_attack_chains(r)
        assert _chain_findings(r)

    def test_it_stays_critical(self) -> None:
        r = self._shared()
        check_attack_chains(r)
        assert _chain_findings(r)[0].severity == "CRITICAL"

    def test_the_shared_tool_is_named(self) -> None:
        r = self._shared()
        check_attack_chains(r)
        detail = _chain_findings(r)[0].detail
        assert "run_query" in detail
        assert "same tool" in detail.lower()

    def test_the_chain_records_the_shared_tool(self) -> None:
        r = self._shared()
        check_attack_chains(r)
        assert r.attack_chains[0].shared_tools == ["run_query"]


class TestDisjointToolsAreGradedDown:
    def _disjoint(self) -> TargetResult:
        r = _result(["run_query", "fetch_docs"])
        r.findings = [
            _finding("prompt_injection", "Injection in tool 'fetch_docs'"),
            _finding("code_execution", "Code execution via tool 'run_query'"),
        ]
        return r

    def test_it_is_still_reported(self) -> None:
        """Downgrade the confidence, not the visibility."""
        r = self._disjoint()
        check_attack_chains(r)
        assert _chain_findings(r)

    def test_it_is_not_critical(self) -> None:
        r = self._disjoint()
        check_attack_chains(r)
        assert _chain_findings(r)[0].severity == "HIGH"

    def test_the_absence_of_a_shared_tool_is_stated(self) -> None:
        r = self._disjoint()
        check_attack_chains(r)
        assert "no shared tool" in _chain_findings(r)[0].detail.lower()

    def test_no_shared_tools_recorded(self) -> None:
        r = self._disjoint()
        check_attack_chains(r)
        assert r.attack_chains[0].shared_tools == []


class TestTargetScopedFindingsKeepTheirSeverity:
    """auth and sse_security name no tool; absence of a name is not evidence
    of absence of a path, so these must not be graded down."""

    def _target_scoped(self) -> TargetResult:
        r = _result(["run_query"])
        r.findings = [
            _finding("prompt_injection", "Injection in tool 'run_query'"),
            _finding("token_theft", "Credentials returned without authentication"),
        ]
        return r

    def test_it_stays_critical(self) -> None:
        r = self._target_scoped()
        check_attack_chains(r)
        assert _chain_findings(r)[0].severity == "CRITICAL"

    def test_the_basis_is_stated_as_co_occurrence(self) -> None:
        r = self._target_scoped()
        check_attack_chains(r)
        assert "co-occurrence" in _chain_findings(r)[0].detail.lower()


class TestUnchangedBehaviour:
    def test_no_pair_no_chain(self) -> None:
        r = _result(["fetch_docs"])
        r.findings = [_finding("prompt_injection", "Injection in tool 'fetch_docs'")]
        check_attack_chains(r)
        assert not _chain_findings(r)

    def test_evidence_tools_still_populated(self) -> None:
        r = _result(["run_query", "fetch_docs"])
        r.findings = [
            _finding("prompt_injection", "Injection in tool 'fetch_docs'"),
            _finding("code_execution", "Code execution via tool 'run_query'"),
        ]
        check_attack_chains(r)
        assert set(r.attack_chains[0].evidence_tools) == {"run_query", "fetch_docs"}

    def test_timing_is_recorded(self) -> None:
        r = _result(["run_query"])
        check_attack_chains(r)
        assert "attack_chains" in r.timings

    def test_the_json_report_carries_the_linkage_evidence(self) -> None:
        """The grading is only useful if it reaches the report."""
        from mcpnuke.reporting.json_out import _build_target_dict

        r = _result(["run_query"])
        r.findings = [
            _finding("prompt_injection", "Injection in tool 'run_query'"),
            _finding("code_execution", "Code execution via tool 'run_query'"),
        ]
        check_attack_chains(r)
        chain = _build_target_dict(r)["attack_chains"][0]
        assert chain["shared_tools"] == ["run_query"]
        assert chain["linkage"] == "shared-tool"

    def test_the_serializer_emits_every_chain_field(self) -> None:
        """The chain dict is hand-built, so a new dataclass field is dropped
        silently — which is exactly how shared_tools first went missing."""
        import dataclasses

        from mcpnuke.core.models import AttackChain
        from mcpnuke.reporting.json_out import _build_target_dict

        r = _result(["run_query"])
        r.findings = [
            _finding("prompt_injection", "Injection in tool 'run_query'"),
            _finding("code_execution", "Code execution via tool 'run_query'"),
        ]
        check_attack_chains(r)
        emitted = set(_build_target_dict(r)["attack_chains"][0])
        declared = {f.name for f in dataclasses.fields(AttackChain)}
        assert declared <= emitted, f"not serialized: {sorted(declared - emitted)}"

    def test_the_pair_is_still_named_in_the_title(self) -> None:
        r = _result(["run_query"])
        r.findings = [
            _finding("prompt_injection", "Injection in tool 'run_query'"),
            _finding("code_execution", "Code execution via tool 'run_query'"),
        ]
        check_attack_chains(r)
        title = _chain_findings(r)[0].title
        assert "prompt_injection" in title and "code_execution" in title
