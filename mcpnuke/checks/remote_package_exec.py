"""MCP-T08: Remote package execution via tool schema.

Static check that detects tools whose schema or description indicates they fetch
and execute remote code (npm/npx packages, pip install from URLs, curl|sh patterns,
git clone + execute flows). These represent supply-chain attack vectors where an
attacker who controls the package source gets code execution on the MCP server.

Lane 4 (Agent Chain) / Transport A (MCP JSON-RPC).
"""

from __future__ import annotations

import re

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult

_add = lane_tagged(lane=4, transport="A")

# Patterns in tool descriptions/names that indicate remote fetch+exec
_REMOTE_EXEC_PATTERNS = [
    {
        "pattern": re.compile(r"npx\s+[@a-z]", re.IGNORECASE),
        "category": "npx_remote_package",
        "severity": "CRITICAL",
        "detail": "Tool executes a remote npm package via npx without pinning",
    },
    {
        "pattern": re.compile(r"uvx\s+[a-z]", re.IGNORECASE),
        "category": "uvx_remote_package",
        "severity": "CRITICAL",
        "detail": "Tool executes a remote Python package via uvx without pinning",
    },
    {
        "pattern": re.compile(r"pip\s+install\s+.*https?://", re.IGNORECASE),
        "category": "pip_install_url",
        "severity": "CRITICAL",
        "detail": "Tool installs a Python package from an arbitrary URL",
    },
    {
        "pattern": re.compile(r"curl\s+.*\|\s*(sh|bash|python|node)", re.IGNORECASE),
        "category": "curl_pipe_shell",
        "severity": "CRITICAL",
        "detail": "Tool fetches and executes remote code via curl|sh pattern",
    },
    {
        "pattern": re.compile(r"wget\s+.*(-O\s*-\s*\||\|\s*(sh|bash))", re.IGNORECASE),
        "category": "wget_pipe_shell",
        "severity": "CRITICAL",
        "detail": "Tool fetches and executes remote code via wget pipe",
    },
    {
        "pattern": re.compile(r"git\s+clone\s+.*&&.*(?:make|install|build|run)", re.IGNORECASE),
        "category": "git_clone_execute",
        "severity": "HIGH",
        "detail": "Tool clones a repository and executes build/install commands",
    },
    {
        "pattern": re.compile(r"eval\s*\(\s*fetch\s*\(", re.IGNORECASE),
        "category": "eval_fetch",
        "severity": "CRITICAL",
        "detail": "Tool fetches remote content and evaluates it",
    },
    {
        "pattern": re.compile(r"require\s*\(\s*['\"]https?://", re.IGNORECASE),
        "category": "require_remote_url",
        "severity": "HIGH",
        "detail": "Tool requires/imports from a remote URL",
    },
]

# Parameter names that suggest URL inputs for fetch+exec
_REMOTE_URL_PARAMS = frozenset({
    "package_url", "script_url", "source_url", "install_url",
    "plugin_url", "extension_url", "module_url", "repo_url",
})

# Tool names suggesting dynamic loading
_DYNAMIC_LOAD_KEYWORDS = frozenset({
    "install", "plugin", "extension", "addon", "module",
    "package", "import", "load", "fetch_and_run",
})


def check_remote_package_execution(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Detect tools that fetch and execute remote code (MCP-T08).

    Static analysis of tool schemas and descriptions for patterns indicating
    the tool downloads and runs code from external sources — a supply-chain
    vector where controlling the source means code execution on the server.
    """
    opts = probe_opts or {}

    with time_check("remote_package_execution", result):
        for tool in result.tools:
            name = tool.get("name", "").lower()
            desc = tool.get("description", "") or ""
            schema_str = str(tool.get("inputSchema", {}))
            combined = f"{name} {desc} {schema_str}"

            # Check description/schema for remote-exec patterns
            for probe in _REMOTE_EXEC_PATTERNS:
                if probe["pattern"].search(combined):
                    _add(
                        result,
                        "remote_package_execution",
                        probe["severity"],
                        f"Remote code execution pattern in tool '{tool.get('name', '')}': {probe['category']}",
                        f"{probe['detail']}. Found in tool '{tool.get('name', '')}' — "
                        f"an attacker who controls the remote source achieves "
                        f"code execution on the MCP server.",
                        taxonomy_id="MCP-T08",
                    )
                    break

            # Check for URL parameters combined with execution keywords in name
            props = tool.get("inputSchema", {}).get("properties", {})
            url_params = [p for p in props if p.lower() in _REMOTE_URL_PARAMS]
            if url_params and any(kw in name for kw in _DYNAMIC_LOAD_KEYWORDS):
                _add(
                    result,
                    "remote_package_execution",
                    "HIGH",
                    f"Dynamic loading tool '{tool.get('name', '')}' accepts URL parameter ({', '.join(url_params)})",
                    f"Tool '{tool.get('name', '')}' has keywords suggesting dynamic code loading "
                    f"AND accepts URL parameters ({', '.join(url_params)}). An attacker can "
                    f"supply a malicious URL to achieve remote code execution.",
                    taxonomy_id="MCP-T08",
                )
