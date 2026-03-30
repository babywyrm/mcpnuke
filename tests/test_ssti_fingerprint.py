"""Tests for SSTI engine fingerprinting and LLM-aware classification."""

import pytest
from mcpnuke.patterns.probes import SSTI_ENGINE_FINGERPRINTS


def test_ssti_fingerprints_contain_all_engines():
    engines = {fp["engine"] for fp in SSTI_ENGINE_FINGERPRINTS}
    assert "jinja2" in engines
    assert "mako" in engines
    assert "erb" in engines
    assert "el" in engines


def test_ssti_fingerprints_have_required_fields():
    for fp in SSTI_ENGINE_FINGERPRINTS:
        assert "payload" in fp
        assert "expected" in fp
        assert "engine" in fp
        assert isinstance(fp["expected"], str)
        assert len(fp["expected"]) >= 2


class TestLlmSstiClassification:
    """Verify the heuristic that distinguishes LLM math from code SSTI."""

    def test_math_only_classified_as_llm(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=True, engine_hits=[], response_latency=1.5
        )
        assert result == "llm_evaluated"

    def test_engine_hit_classified_as_code_ssti(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=True, engine_hits=["jinja2"], response_latency=0.5
        )
        assert result == "jinja2"

    def test_multiple_engines_returns_first(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=True, engine_hits=["mako", "el"], response_latency=0.3
        )
        assert result == "mako"

    def test_fast_response_prefers_code_ssti(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=True, engine_hits=[], response_latency=0.02
        )
        assert result == "code_ssti"

    def test_no_math_hit_returns_unknown(self):
        from mcpnuke.checks.tool_probes import _classify_ssti
        result = _classify_ssti(
            math_hit=False, engine_hits=[], response_latency=1.0
        )
        assert result == "unknown"
