"""Tests for permissions debouncing — weak signals require 2+ categories."""

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.permissions import check_excessive_permissions, _WEAK_SIGNAL_THRESHOLD


def test_weak_signal_threshold_is_two():
    assert _WEAK_SIGNAL_THRESHOLD == 2


def test_name_match_always_reported():
    """A tool whose name matches a dangerous pattern should always be reported."""
    r = TargetResult(url="http://test")
    r.tools = [{
        "name": "execute_command",
        "description": "Runs a simple task",
        "inputSchema": {"type": "object", "properties": {}},
    }]
    check_excessive_permissions(r)
    findings = [f for f in r.findings if f.check == "excessive_permissions"]
    assert len(findings) >= 1


def test_single_desc_match_suppressed():
    """A tool with only one description-only category match should be suppressed."""
    r = TargetResult(url="http://test")
    r.tools = [{
        "name": "get_status",
        "description": "Reads file metadata from the system",
        "inputSchema": {"type": "object", "properties": {}},
    }]
    check_excessive_permissions(r)
    perm_findings = [
        f for f in r.findings
        if f.check == "excessive_permissions" and "Dangerous capability" in f.title
    ]
    assert len(perm_findings) == 0


def test_two_desc_matches_reported():
    """A tool with 2+ description-only category matches should be reported."""
    r = TargetResult(url="http://test")
    r.tools = [{
        "name": "fancy_helper",
        "description": "This tool can execute shell commands and read_file from disk",
        "inputSchema": {"type": "object", "properties": {}},
    }]
    check_excessive_permissions(r)
    perm_findings = [
        f for f in r.findings
        if f.check == "excessive_permissions" and "Dangerous capability" in f.title
    ]
    assert len(perm_findings) >= 2


def test_mixed_name_and_desc_hits():
    """Name hits reported unconditionally; desc-only hits subject to threshold."""
    r = TargetResult(url="http://test")
    r.tools = [{
        "name": "run_query",
        "description": "Connects to database for analytics",
        "inputSchema": {"type": "object", "properties": {}},
    }]
    check_excessive_permissions(r)
    perm_findings = [
        f for f in r.findings
        if f.check == "excessive_permissions" and "Dangerous capability" in f.title
    ]
    name_findings = [f for f in perm_findings if "run" in f.title.lower() or "shell_exec" in f.title.lower()]
    assert len(name_findings) >= 1
