"""A CRITICAL multi-vector claim should not rest on evidence we graded LOW.

Without this floor the error-reflection downgrade is cosmetic: both chaining
checks build their vector set from finding *names* alone, so a demoted finding
still counts as a fully active attack vector and keeps feeding the loudest
finding in the report.
"""

from __future__ import annotations

from mcpnuke.checks.chaining import check_attack_chains, check_multi_vector
from mcpnuke.core.constants import ATTACK_CHAIN_PATTERNS
from mcpnuke.core.models import TargetResult


def _result_with(*findings: tuple[str, str]) -> TargetResult:
    r = TargetResult(url="http://fixture.example/mcp")
    for check, severity in findings:
        r.add(check, severity, f"{check} title")
    return r


def _fired(result: TargetResult, check: str) -> bool:
    return any(f.check == check for f in result.findings)


class TestMultiVector:
    def test_two_low_vectors_do_not_make_a_multi_vector(self):
        r = _result_with(("active_prompt_injection", "LOW"), ("code_execution", "LOW"))
        check_multi_vector(r)
        assert not _fired(r, "multi_vector")

    def test_two_real_vectors_still_do(self):
        r = _result_with(
            ("active_prompt_injection", "CRITICAL"), ("code_execution", "HIGH")
        )
        check_multi_vector(r)
        assert _fired(r, "multi_vector")

    def test_medium_counts_as_a_vector(self):
        """The floor is MEDIUM, not HIGH — MEDIUM is still real evidence."""
        r = _result_with(
            ("active_prompt_injection", "MEDIUM"), ("code_execution", "MEDIUM")
        )
        check_multi_vector(r)
        assert _fired(r, "multi_vector")

    def test_one_real_and_one_low_is_not_two_vectors(self):
        r = _result_with(
            ("active_prompt_injection", "CRITICAL"), ("code_execution", "LOW")
        )
        check_multi_vector(r)
        assert not _fired(r, "multi_vector")

    def test_a_check_with_both_low_and_high_still_counts(self):
        """One weak finding must not disqualify a check that also has a strong
        one — the floor is per-check, not per-finding."""
        r = _result_with(
            ("active_prompt_injection", "LOW"),
            ("active_prompt_injection", "CRITICAL"),
            ("code_execution", "HIGH"),
        )
        check_multi_vector(r)
        assert _fired(r, "multi_vector")


class TestAttackChains:
    def _pattern(self):
        return ATTACK_CHAIN_PATTERNS[0]

    def test_a_low_link_breaks_the_chain(self):
        a, b = self._pattern()
        r = _result_with((a, "LOW"), (b, "LOW"))
        check_attack_chains(r)
        assert not _fired(r, "attack_chain")

    def test_a_real_chain_is_still_reported(self):
        a, b = self._pattern()
        r = _result_with((a, "CRITICAL"), (b, "HIGH"))
        check_attack_chains(r)
        assert _fired(r, "attack_chain")
