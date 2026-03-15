"""
Smoke tests against public MCP servers.

Fast transport-detection only — no full scans (those are slow and flaky).
Run with:  pytest mcprowler/tests/test_public_targets.py -v
Skip with: MCP_ATTACK_SKIP_REMOTE=1 pytest ...
"""

import os
import pytest

from mcprowler.core.session import detect_transport
from mcprowler.core.models import TargetResult
from mcprowler.core.enumerator import enumerate_server

skip_remote = pytest.mark.skipif(
    os.environ.get("MCP_ATTACK_SKIP_REMOTE", "0") == "1",
    reason="MCP_ATTACK_SKIP_REMOTE=1",
)

TARGETS = {
    "deepwiki": "https://mcp.deepwiki.com/mcp",
    "gitmcp": "https://gitmcp.io/punkpeye/awesome-mcp-servers",
    "context7": "https://mcp.context7.com/mcp",
}


@skip_remote
@pytest.mark.parametrize("name,url", list(TARGETS.items()))
def test_transport_detected(name, url):
    """Public target should expose a valid MCP transport."""
    session = detect_transport(url, connect_timeout=12.0)
    assert session is not None, f"{name}: no transport at {url}"
    assert session.post_url, f"{name}: no post_url"
    session.close()


@skip_remote
@pytest.mark.parametrize("name,url", list(TARGETS.items()))
def test_has_tools(name, url):
    """Public target should expose at least 1 tool."""
    session = detect_transport(url, connect_timeout=12.0)
    assert session is not None
    result = TargetResult(url=url)
    enumerate_server(session, result)
    session.close()
    assert len(result.tools) > 0, f"{name}: no tools found"
