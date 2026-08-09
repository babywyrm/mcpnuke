"""The reference target must be a working MCP server before it can measure anything.

These tests prove the target itself behaves. `tests/test_false_positives.py`
then measures mcpnuke against it. Keeping them apart matters: if they were one
file, a broken target would read as a scanner regression.
"""

from __future__ import annotations

import httpx
import pytest

from mcpnuke.core.enumerator import enumerate_server
from mcpnuke.core.models import TargetResult
from mcpnuke.core.protocol import LEGACY
from mcpnuke.core.session import detect_transport
from tests.reference_target import start_reference_server


@pytest.fixture(scope="module")
def reference_server():
    server = start_reference_server()
    try:
        yield server
    finally:
        server.stop()


def test_transport_is_detected(reference_server):
    session = detect_transport(reference_server.url, auth_token=reference_server.token)
    assert session is not None


def test_legacy_handshake_negotiated(reference_server):
    """A failed initialize falls through to stateless, where the enumerator
    itself adds a HIGH auth finding — a false positive of our own making."""
    session = detect_transport(reference_server.url, auth_token=reference_server.token)
    result = TargetResult(url=reference_server.url)
    enumerate_server(session, result)
    assert result.protocol_mode == LEGACY


def test_four_tools_enumerated(reference_server):
    session = detect_transport(reference_server.url, auth_token=reference_server.token)
    result = TargetResult(url=reference_server.url)
    enumerate_server(session, result)
    names = sorted(t["name"] for t in result.tools)
    assert names == ["docs.search", "file.read", "http.fetch", "ticket.create"]


def test_unauthenticated_calls_are_rejected(reference_server):
    r = httpx.post(
        reference_server.url,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        timeout=5,
    )
    assert r.status_code == 401
