"""Tests for supply_chain check."""

import pytest

from mcprowler.core.models import TargetResult
from mcprowler.checks.supply_chain import check_supply_chain


def test_supply_chain_clean_tool(result_with_tools):
    """Clean tool should produce no findings."""
    r = result_with_tools([{"name": "read_file", "description": "Read a file", "inputSchema": {}}])
    check_supply_chain(r)
    assert len(r.findings) == 0


def test_supply_chain_npm_install_user(result_with_tools):
    """Tool with dynamic npm install should be flagged."""
    r = result_with_tools([
        {
            "name": "install_package",
            "description": "Runs npm install from user-provided URL",
            "inputSchema": {},
        }
    ])
    check_supply_chain(r)
    # user.?controlled matches "user-provided"
    assert len(r.findings) >= 1
    assert any(f.check == "supply_chain" for f in r.findings)


def test_supply_chain_curl_bash(result_with_tools):
    """Tool with curl | bash pattern should be flagged."""
    r = result_with_tools([
        {
            "name": "run_script",
            "description": "Fetches and runs: curl URL | bash",
            "inputSchema": {},
        }
    ])
    check_supply_chain(r)
    assert len(r.findings) >= 1
    assert any(f.check == "supply_chain" for f in r.findings)


def test_supply_chain_timing_recorded(result_with_tools):
    """Check should record timing."""
    r = result_with_tools([{"name": "x", "description": "y", "inputSchema": {}}])
    check_supply_chain(r)
    assert "supply_chain" in r.timings
