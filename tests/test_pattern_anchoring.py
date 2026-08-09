"""Dangerous-capability patterns must match words, not substrings.

Every false positive below was observed against a real open-source MCP server
(see docs/oss-target-baseline.md) or is a direct consequence of the same
unanchored alternative. Each true positive is the reason the pattern exists
and must survive.
"""

from __future__ import annotations

import pytest

from mcpnuke.checks.execution import check_remote_access
from mcpnuke.checks.permissions import check_excessive_permissions
from mcpnuke.core.models import TargetResult


@pytest.fixture
def capability_titles(result_with_tools):
    """Titles that check_excessive_permissions emits for a single tool."""

    def _run(name: str, description: str = "") -> list[str]:
        r: TargetResult = result_with_tools(
            [{"name": name, "description": description, "inputSchema": {}}]
        )
        check_excessive_permissions(r)
        return [f.title for f in r.findings]

    return _run


@pytest.fixture
def remote_titles(result_with_tools):
    """Titles that check_remote_access emits for a single tool."""

    def _run(name: str, description: str = "") -> list[str]:
        r: TargetResult = result_with_tools(
            [{"name": name, "description": description, "inputSchema": {}}]
        )
        check_remote_access(r)
        return [f.title for f in r.findings]

    return _run


class TestTruePositivesSurvive:
    """The reason each pattern exists. Anchoring must not cost us these."""

    @pytest.mark.parametrize(
        "name", ["run_command", "exec_shell", "subprocess_run", "execute_query"]
    )
    def test_shell_exec_still_fires(self, capability_titles, name):
        assert any("shell_exec" in t for t in capability_titles(name))

    @pytest.mark.parametrize("name", ["read_file", "readFile", "write_file"])
    def test_filesystem_still_fires(self, capability_titles, name):
        assert any("filesystem" in t for t in capability_titles(name))

    @pytest.mark.parametrize("name", ["get_secret", "aws_secret_read"])
    def test_secrets_access_still_fires(self, capability_titles, name):
        assert any("secrets_access" in t for t in capability_titles(name))

    @pytest.mark.parametrize("name", ["list_processes", "kill_process"])
    def test_process_mgmt_survives_the_plural(self, capability_titles, name):
        assert any("process_mgmt" in t for t in capability_titles(name))

    @pytest.mark.parametrize("name", ["nc", "netcat_listener", "socat_relay"])
    def test_reverse_shell_still_fires(self, remote_titles, name):
        assert any("reverse_shell" in t for t in remote_titles(name))

    def test_underscored_description_still_matches(self, capability_titles):
        """Descriptions are matched raw, so `[ _]` has to cover both forms.

        Two categories, because description-only hits are debounced behind
        _WEAK_SIGNAL_THRESHOLD and a single hit deliberately stays quiet.
        """
        titles = capability_titles("helper", "Calls read_file then http_get")
        assert any("filesystem" in t for t in titles), titles
        assert any("network" in t for t in titles), titles


class TestObservedFalsePositives:
    """Each of these fired against a real server during baseline capture."""

    def test_long_running_operation_is_not_shell_exec(self, capability_titles):
        """server-everything: `run` matched inside "running"."""
        titles = capability_titles("trigger-long-running-operation")
        assert not any("shell_exec" in t for t in titles), titles

    @pytest.mark.parametrize("name", ["get-resource-reference", "get-resource-links"])
    def test_reference_is_not_a_reverse_shell(self, remote_titles, name):
        """server-everything: `nc` matched inside "reference"."""
        titles = remote_titles(name)
        assert not any("reverse_shell" in t for t in titles), titles

    def test_git_show_is_not_shell_exec(self, capability_titles):
        """server-git: `sh` matched inside "show". CRITICAL, on `git show`."""
        titles = capability_titles("git_show")
        assert not any("shell_exec" in t for t in titles), titles

    @pytest.mark.parametrize("name", ["git_branch", "git_checkout", "git_create_branch"])
    def test_git_branch_is_not_a_reverse_shell(self, remote_titles, name):
        """server-git: `nc` matched inside "branch"."""
        titles = remote_titles(name)
        assert not any("reverse_shell" in t for t in titles), titles

    def test_encoding_is_not_a_reverse_shell(self, remote_titles):
        """server-filesystem: `nc` matched inside "encoding" in a description."""
        titles = remote_titles("read_text_file", "Read a file with the given encoding")
        assert not any("reverse_shell" in t for t in titles), titles


class TestSameDefectElsewhere:
    """`sh`, `key`, `eval` and `process` had the same unanchored shape."""

    @pytest.mark.parametrize("name", ["push_to_github", "publish_article"])
    def test_sh_inside_a_word_is_not_a_shell(self, capability_titles, name):
        titles = capability_titles(name)
        assert not any("shell_exec" in t for t in titles), titles

    def test_monkey_is_not_a_secret(self, capability_titles):
        titles = capability_titles("monkey_patch_config")
        assert not any("secrets_access" in t for t in titles), titles

    def test_retrieval_is_not_code_eval(self, capability_titles):
        titles = capability_titles("document_retrieval")
        assert not any("code_eval" in t for t in titles), titles
