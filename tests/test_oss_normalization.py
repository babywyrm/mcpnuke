"""Snapshot normalization must remove what varies and keep what means something.

Not gated behind MCPNUKE_OSS_TARGETS: this is a pure function and no server
has to be running to check it.
"""

from __future__ import annotations

from dataclasses import dataclass

from tests.oss_targets.runner import normalize_findings


@dataclass
class _F:
    check: str
    severity: str
    title: str


class TestVolatileFieldsAreStripped:
    def test_elapsed_seconds_are_replaced(self):
        """`behavioral_rate_limit` puts a stopwatch reading in its title.

        Observed drifting 0.0s → 0.8s → 0.9s between runs of the same server,
        which would fail the snapshot every time on a scanner that had not
        changed at all.
        """
        rows = normalize_findings(
            [_F("behavioral_rate_limit", "MEDIUM", "10/10 rapid calls succeeded in 0.8s")]
        )
        assert "0.8s" not in rows[0]["title"]
        assert rows[0]["title"] == "10/10 rapid calls succeeded in <duration>"

    def test_two_runs_with_different_timings_normalize_equal(self):
        a = normalize_findings([_F("c", "LOW", "done in 0.0s")])
        b = normalize_findings([_F("c", "LOW", "done in 12.75s")])
        assert a == b


class TestMeaningfulNumbersSurvive:
    """Counts are properties of the server. Drift in them is real signal."""

    def test_tool_counts_are_kept(self):
        rows = normalize_findings(
            [_F("pre_auth_injection", "HIGH", "Pre-auth tool access: 13 tools available")]
        )
        assert "13 tools" in rows[0]["title"]

    def test_category_counts_are_kept(self):
        rows = normalize_findings(
            [_F("multi_vector", "CRITICAL", "Multi-vector attack: 5 categories active")]
        )
        assert "5 categories" in rows[0]["title"]
