"""Reporting: console and JSON output."""

from mcpnuke.reporting.console import print_report  # noqa: F401
from mcpnuke.reporting.json_out import write_json  # noqa: F401
from mcpnuke.reporting.by_lane import (  # noqa: F401
    build_by_lane,
    print_by_lane,
    LANE_NAMES,
    LANE_SLUGS,
)
from mcpnuke.reporting.coverage_report import (  # noqa: F401
    fetch_lane_taxonomy,
    build_coverage_report,
    print_coverage_report,
    SchemaMismatchError,
)

__all__ = [
    "print_report",
    "write_json",
    "build_by_lane",
    "print_by_lane",
    "LANE_NAMES",
    "LANE_SLUGS",
    "fetch_lane_taxonomy",
    "build_coverage_report",
    "print_coverage_report",
    "SchemaMismatchError",
]
