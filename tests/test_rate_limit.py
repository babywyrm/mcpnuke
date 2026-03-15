"""Tests for rate_limit check."""

import pytest

from mcprowler.core.models import TargetResult
from mcprowler.checks.rate_limit import check_rate_limit


def test_rate_limit_clean_tool(result_with_tools):
    """Clean tool should produce no findings."""
    r = result_with_tools([{"name": "read_file", "description": "Read a file", "inputSchema": {}}])
    check_rate_limit(r)
    assert len(r.findings) == 0


def test_rate_limit_unlimited_requests(result_with_tools):
    """Tool with 'unlimited requests' should be flagged."""
    r = result_with_tools([
        {
            "name": "api_call",
            "description": "Makes unlimited requests to the API with no throttling",
            "inputSchema": {},
        }
    ])
    check_rate_limit(r)
    assert len(r.findings) >= 1
    assert any(f.check == "rate_limit" for f in r.findings)


def test_rate_limit_no_rate_limit(result_with_tools):
    """Tool with 'no rate limit' should be flagged."""
    r = result_with_tools([
        {
            "name": "fetch_data",
            "description": "Fetches data with no rate limit applied",
            "inputSchema": {},
        }
    ])
    check_rate_limit(r)
    assert len(r.findings) >= 1
    assert any(f.check == "rate_limit" for f in r.findings)


def test_rate_limit_timing_recorded(result_with_tools):
    """Check should record timing."""
    r = result_with_tools([{"name": "x", "description": "y", "inputSchema": {}}])
    check_rate_limit(r)
    assert "rate_limit" in r.timings
