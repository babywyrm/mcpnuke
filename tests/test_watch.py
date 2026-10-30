"""--watch prints what changed per lane between successive scans."""

import pytest

from mcpnuke.cli import parse_args
from mcpnuke.reporting.by_lane import format_lane_delta


def _report(lane1: int = 0, high: int = 0) -> dict:
    tally = {"HIGH": high} if high else {}
    return {
        "schema": "v1",
        "by_lane": {
            "1": {
                "slug": "human-direct",
                "finding_count": lane1,
                "severity_tally": tally,
            }
        },
        "total_findings": lane1,
    }


def test_an_unchanged_lane_says_so() -> None:
    assert format_lane_delta(_report(), _report()) == "no lane change"


def test_a_new_finding_names_the_lane_and_severity() -> None:
    text = format_lane_delta(_report(), _report(lane1=1, high=1))
    assert "human-direct: 0 -> 1" in text
    assert "HIGH: 0 -> 1" in text


def test_watch_requires_at_least_one_second() -> None:
    with pytest.raises(SystemExit):
        parse_args(["--targets", "http://x", "--watch", "0"])


def test_watch_interval_parses() -> None:
    args = parse_args(["--targets", "http://x", "--watch", "30"])
    assert args.watch == 30
