"""The reference target must be a working MCP server before it can measure anything.

These tests prove the target itself behaves. `tests/test_false_positives.py`
then measures mcpnuke against it. Keeping them apart matters: if they were one
file, a broken target would read as a scanner regression.
"""

from __future__ import annotations

import json

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


class TestToolHardening:
    """The target is only a useful yardstick if it is genuinely well-built."""

    def _call(self, server, name: str, arguments: dict) -> dict:
        r = httpx.post(
            server.url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            headers={"Authorization": f"Bearer {server.token}"},
            timeout=5,
        )
        return r.json()["result"]

    def test_file_read_rejects_traversal(self, reference_server):
        out = self._call(reference_server, "file.read", {"name": "../../etc/passwd"})
        assert out["isError"] is True
        assert "root:" not in json.dumps(out)

    def test_file_read_rejects_absolute_path(self, reference_server):
        out = self._call(reference_server, "file.read", {"name": "/etc/passwd"})
        assert out["isError"] is True

    def test_file_read_serves_allowlisted_file(self, reference_server):
        out = self._call(reference_server, "file.read", {"name": "overview.txt"})
        assert out["isError"] is False
        assert "reference target" in json.dumps(out).lower()

    def test_http_fetch_refuses_link_local(self, reference_server):
        out = self._call(
            reference_server,
            "http.fetch",
            {"url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert out["isError"] is True

    def test_http_fetch_refuses_loopback(self, reference_server):
        out = self._call(reference_server, "http.fetch", {"url": "http://127.0.0.1:22/"})
        assert out["isError"] is True

    def test_refusal_does_not_echo_the_url(self, reference_server):
        """Echoing attacker input back is how a clean server grows a reflected
        injection finding it does not deserve."""
        marker = "IGNORE-PREVIOUS-INSTRUCTIONS-9f3a"
        out = self._call(
            reference_server, "http.fetch", {"url": f"http://evil.test/{marker}"}
        )
        assert marker not in json.dumps(out)

    def test_docs_search_does_not_echo_the_query(self, reference_server):
        marker = "IGNORE-PREVIOUS-INSTRUCTIONS-9f3a"
        out = self._call(reference_server, "docs.search", {"query": marker})
        assert marker not in json.dumps(out)

    def test_ticket_create_validates_and_does_not_echo(self, reference_server):
        marker = "IGNORE-PREVIOUS-INSTRUCTIONS-9f3a"
        out = self._call(
            reference_server, "ticket.create", {"title": marker, "body": marker}
        )
        assert marker not in json.dumps(out)

    def test_unknown_tool_is_a_clean_error(self, reference_server):
        out = self._call(reference_server, "no.such.tool", {})
        assert out["isError"] is True
        blob = json.dumps(out)
        assert "Traceback" not in blob and ".py" not in blob
