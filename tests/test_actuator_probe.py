"""Tests for actuator_probe check."""

import httpx

from mcpnuke.checks.actuator_probe import DEBUG_ENDPOINTS, SENSITIVE_CONTENT_PATTERNS, check_actuator_probe
from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.credentials import find_credential


def test_debug_endpoints_list():
    assert len(DEBUG_ENDPOINTS) >= 15
    assert any("/actuator/env" in ep[0] for ep in DEBUG_ENDPOINTS)
    assert any("/.env" in ep[0] for ep in DEBUG_ENDPOINTS)


def test_sensitive_patterns_match():
    for body in (
        "password=hunter2",
        "AKIAIOSFODNN7EXAMPLE",
        "postgres://admin:pass@db:5432",
    ):
        assert find_credential(body, SENSITIVE_CONTENT_PATTERNS), body


def test_sensitive_patterns_no_false_positive():
    assert find_credential("Hello world, status OK", SENSITIVE_CONTENT_PATTERNS) is None


def test_bare_prefix_no_longer_escalates():
    """The local list matched a lone "sk-"; the shared tier needs a real token."""
    assert find_credential("task sk-1 queued", SENSITIVE_CONTENT_PATTERNS) is None
    assert find_credential("key sk-" + "a" * 32, SENSITIVE_CONTENT_PATTERNS)


def test_timing_recorded_on_unreachable():
    from unittest.mock import MagicMock, patch

    mock_client = MagicMock()
    mock_client.get.side_effect = httpx.ConnectError("unreachable")
    mock_client.__enter__ = lambda s: s
    mock_client.__exit__ = MagicMock(return_value=False)

    r = TargetResult(url="http://192.0.2.1:1/sse")
    with patch("mcpnuke.checks.actuator_probe.httpx.Client", return_value=mock_client):
        check_actuator_probe("http://192.0.2.1:1", r)
    assert "actuator_probe" in r.timings
