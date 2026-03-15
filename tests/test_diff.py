"""Tests for differential scanning."""

import json
import tempfile
from pathlib import Path

import pytest

from mcprowler.core.models import TargetResult
from mcprowler.diff import (
    diff_against_baseline,
    load_baseline,
    save_baseline,
    DiffResult,
)


def test_diff_no_changes():
    """Identical baseline and current should yield no changes."""
    tools = [{"name": "read_file", "description": "Read a file", "inputSchema": {}}]
    resources = [{"uri": "file:///a", "name": "a"}]
    prompts = [{"name": "greet", "description": "Say hello"}]

    diff = diff_against_baseline(
        tools, resources, prompts,
        tools, resources, prompts,
        url="http://localhost:9001",
    )
    assert not diff.has_changes()
    assert len(diff.added_tools) == 0
    assert len(diff.removed_tools) == 0
    assert len(diff.modified_tools) == 0


def test_diff_added_tool():
    """New tool in current should be in added_tools."""
    base_tools = [{"name": "a", "description": "A", "inputSchema": {}}]
    curr_tools = [
        {"name": "a", "description": "A", "inputSchema": {}},
        {"name": "run_shell", "description": "Execute shell", "inputSchema": {}},
    ]

    diff = diff_against_baseline(
        curr_tools, [], [],
        base_tools, [], [],
        url="http://localhost:9001",
    )
    assert diff.has_changes()
    assert len(diff.added_tools) == 1
    assert diff.added_tools[0]["name"] == "run_shell"


def test_diff_removed_tool():
    """Removed tool in current should be in removed_tools."""
    base_tools = [
        {"name": "a", "description": "A", "inputSchema": {}},
        {"name": "b", "description": "B", "inputSchema": {}},
    ]
    curr_tools = [{"name": "a", "description": "A", "inputSchema": {}}]

    diff = diff_against_baseline(
        curr_tools, [], [],
        base_tools, [], [],
        url="http://localhost:9001",
    )
    assert diff.has_changes()
    assert len(diff.removed_tools) == 1
    assert diff.removed_tools[0]["name"] == "b"


def test_diff_modified_tool():
    """Changed tool description should be in modified_tools."""
    base_tools = [{"name": "x", "description": "Old", "inputSchema": {}}]
    curr_tools = [{"name": "x", "description": "New", "inputSchema": {}}]

    diff = diff_against_baseline(
        curr_tools, [], [],
        base_tools, [], [],
        url="http://localhost:9001",
    )
    assert diff.has_changes()
    assert len(diff.modified_tools) == 1
    assert diff.modified_tools[0][0]["description"] == "Old"
    assert diff.modified_tools[0][1]["description"] == "New"


def test_diff_added_resource():
    """New resource in current should be in added_resources."""
    base_res = [{"uri": "file:///a"}]
    curr_res = [{"uri": "file:///a"}, {"uri": "file:///etc/passwd"}]

    diff = diff_against_baseline(
        [], curr_res, [],
        [], base_res, [],
        url="http://localhost:9001",
    )
    assert diff.has_changes()
    assert len(diff.added_resources) == 1
    assert diff.added_resources[0]["uri"] == "file:///etc/passwd"


def test_diff_removed_prompt():
    """Removed prompt should be in removed_prompts."""
    base_prompts = [{"name": "p1"}, {"name": "p2"}]
    curr_prompts = [{"name": "p1"}]

    diff = diff_against_baseline(
        [], [], curr_prompts,
        [], [], base_prompts,
        url="http://localhost:9001",
    )
    assert diff.has_changes()
    assert len(diff.removed_prompts) == 1
    assert diff.removed_prompts[0]["name"] == "p2"


def test_save_and_load_baseline():
    """Save baseline and load it back."""
    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = [{"name": "t1", "description": "D", "inputSchema": {}}]
    r.resources = [{"uri": "file:///x"}]
    r.prompts = [{"name": "p1"}]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    try:
        save_baseline([r], path)
        data = json.loads(path.read_text())
        assert data.get("baseline") is True
        assert "targets" in data
        assert r.url in data["targets"]
        t = data["targets"][r.url]
        assert len(t["tools"]) == 1
        assert t["tools"][0]["name"] == "t1"
        assert len(t["resources"]) == 1
        assert len(t["prompts"]) == 1

        loaded = load_baseline(path)
        assert r.url in loaded
        assert loaded[r.url]["tools"][0]["name"] == "t1"
    finally:
        path.unlink()


def test_load_baseline_nonexistent():
    """Nonexistent baseline returns empty dict."""
    loaded = load_baseline(Path("/nonexistent/baseline.json"))
    assert loaded == {}


def test_print_diff_report_no_crash():
    """print_diff_report should not crash."""
    from mcprowler.diff import print_diff_report
    from rich.console import Console

    diff = DiffResult(url="http://localhost:9001")
    diff.added_tools = [{"name": "new_tool"}]
    print_diff_report([diff], "baseline.json", console=Console())
