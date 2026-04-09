"""Tests for transport-aware finding filter and stdio auth skip."""

from __future__ import annotations

import pytest

from mcpnuke.core.models import TargetResult


class TestSkipTransports:
    """TargetResult.add() respects skip_transports."""

    def test_skip_when_transport_matches(self):
        r = TargetResult(url="stdio://test")
        r.transport = "stdio"
        result = r.add("auth", "HIGH", "Unauthenticated", skip_transports=["stdio"])
        assert result is None
        assert len(r.findings) == 0

    def test_no_skip_when_transport_differs(self):
        r = TargetResult(url="http://test:9090")
        r.transport = "SSE"
        result = r.add("auth", "HIGH", "Unauthenticated", skip_transports=["stdio"])
        assert result is not None
        assert len(r.findings) == 1

    def test_no_skip_when_no_filter(self):
        r = TargetResult(url="stdio://test")
        r.transport = "stdio"
        result = r.add("auth", "HIGH", "Unauthenticated")
        assert result is not None
        assert len(r.findings) == 1

    def test_multiple_transports_in_skip_list(self):
        r = TargetResult(url="test")
        r.transport = "HTTP"
        result = r.add("auth", "HIGH", "Test", skip_transports=["stdio", "HTTP"])
        assert result is None
        assert len(r.findings) == 0

    def test_return_type_is_finding_when_not_skipped(self):
        from mcpnuke.core.models import Finding
        r = TargetResult(url="http://test:9090")
        r.transport = "SSE"
        result = r.add("test_check", "LOW", "Test finding")
        assert isinstance(result, Finding)
