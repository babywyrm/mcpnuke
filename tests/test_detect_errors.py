"""A failed transport detection says why, instead of only that it failed."""

import socket

import pytest

from mcpnuke.core.session import detect_transport
from mcpnuke.scanner import scan_target


@pytest.fixture
def closed_url() -> str:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}/mcp"


def test_detection_records_why_each_probe_failed(closed_url: str) -> None:
    errors: list[str] = []
    assert detect_transport(closed_url, connect_timeout=2, errors=errors) is None
    assert any("ConnectError" in e for e in errors), errors
    assert len(errors) == len(set(errors))


def test_errors_are_optional(closed_url: str) -> None:
    assert detect_transport(closed_url, connect_timeout=2) is None


def test_no_endpoint_finding_names_the_error(closed_url: str) -> None:
    result = scan_target(closed_url, [], timeout=2)
    (finding,) = [f for f in result.findings if f.check == "transport"]
    assert "ConnectError" in finding.detail
