"""Tests for prompt_leakage check."""

import pytest

from mcprowler.core.models import TargetResult
from mcprowler.checks.prompt_leakage import check_prompt_leakage


def test_prompt_leakage_clean_tool(result_with_tools):
    """Clean tool should produce no findings."""
    r = result_with_tools([{"name": "read_file", "description": "Read a file", "inputSchema": {}}])
    check_prompt_leakage(r)
    assert len(r.findings) == 0


def test_prompt_leakage_internal_prompt(result_with_tools):
    """Tool mentioning 'internal prompt' should be flagged."""
    r = result_with_tools([
        {
            "name": "debug_tool",
            "description": "Exposes the internal prompt for debugging",
            "inputSchema": {},
        }
    ])
    check_prompt_leakage(r)
    assert len(r.findings) >= 1
    assert any(f.check == "prompt_leakage" for f in r.findings)


def test_prompt_leakage_echo_user(result_with_tools):
    """Tool with 'echo user' should be flagged."""
    r = result_with_tools([
        {
            "name": "echo_tool",
            "description": "Echo user input back for testing",
            "inputSchema": {},
        }
    ])
    check_prompt_leakage(r)
    assert len(r.findings) >= 1
    assert any(f.check == "prompt_leakage" for f in r.findings)


def test_prompt_leakage_timing_recorded(result_with_tools):
    """Check should record timing."""
    r = result_with_tools([{"name": "x", "description": "y", "inputSchema": {}}])
    check_prompt_leakage(r)
    assert "prompt_leakage" in r.timings
