"""Tests for actuator_probe check."""

import httpx
import pytest
from mcpnuke.core.models import TargetResult
from mcpnuke.checks.actuator_probe import check_actuator_probe, DEBUG_ENDPOINTS, SENSITIVE_CONTENT_PATTERNS


def test_debug_endpoints_list():
    assert len(DEBUG_ENDPOINTS) >= 15
    assert any("/actuator/env" in ep[0] for ep in DEBUG_ENDPOINTS)
    assert any("/.env" in ep[0] for ep in DEBUG_ENDPOINTS)


def test_sensitive_patterns_match():
    import re
    assert any(re.search(p, "password=hunter2", re.IGNORECASE) for p in SENSITIVE_CONTENT_PATTERNS)
    assert any(re.search(p, "AKIAIOSFODNN7EXAMPLE", re.IGNORECASE) for p in SENSITIVE_CONTENT_PATTERNS)
    assert any(re.search(p, "postgres://admin:pass@db:5432", re.IGNORECASE) for p in SENSITIVE_CONTENT_PATTERNS)


def test_sensitive_patterns_no_false_positive():
    import re
    assert not any(re.search(p, "Hello world, status OK", re.IGNORECASE) for p in SENSITIVE_CONTENT_PATTERNS)


def test_timing_recorded_on_unreachable():
    from unittest.mock import patch, MagicMock

    mock_client = MagicMock()
    mock_client.get.side_effect = httpx.ConnectError("unreachable")
    mock_client.__enter__ = lambda s: s
    mock_client.__exit__ = MagicMock(return_value=False)

    r = TargetResult(url="http://192.0.2.1:1/sse")
    with patch("mcpnuke.checks.actuator_probe.httpx.Client", return_value=mock_client):
        check_actuator_probe("http://192.0.2.1:1", r)
    assert "actuator_probe" in r.timings
