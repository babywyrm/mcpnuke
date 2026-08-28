"""Tests for rate_limit check."""

from __future__ import annotations

from mcpnuke.checks.rate_limit import check_behavioral_rate_limit, check_rate_limit
from mcpnuke.core.models import TargetResult


class _BurstSession:
    """Immediate tools/call success. No HTTP layer — stdio-shaped."""

    protocol_mode: str = "legacy"

    def __init__(self, text: str = "ok", *, stdio: bool = False) -> None:
        self._text = text
        self.calls: int = 0
        if stdio:
            self._proc: object = object()

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        self.calls += 1
        return {"result": {"content": [{"type": "text", "text": self._text}]}}

    def notify(self, method: str, params: dict | None = None) -> None:
        return None

    def close(self) -> None:
        return None

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return True


def _echo_result(url: str = "stdio://echo") -> TargetResult:
    r = TargetResult(url=url)
    r.transport = "stdio"
    r.tools = [{"name": "echo", "description": "Echo a string", "inputSchema": {}}]
    return r


def test_rate_limit_clean_tool(result_with_tools):
    """Clean tool should produce no findings."""
    r = result_with_tools([{"name": "read_file", "description": "Read a file", "inputSchema": {}}])
    check_rate_limit(r)
    assert len(r.findings) == 0


def test_rate_limit_unlimited_requests(result_with_tools):
    """Tool with 'unlimited requests' should be flagged."""
    r = result_with_tools([
        {
            "name": "api_call",
            "description": "Makes unlimited requests to the API with no throttling",
            "inputSchema": {},
        }
    ])
    check_rate_limit(r)
    assert len(r.findings) >= 1
    assert any(f.check == "rate_limit" for f in r.findings)


def test_rate_limit_no_rate_limit(result_with_tools):
    """Tool with 'no rate limit' should be flagged."""
    r = result_with_tools([
        {
            "name": "fetch_data",
            "description": "Fetches data with no rate limit applied",
            "inputSchema": {},
        }
    ])
    check_rate_limit(r)
    assert len(r.findings) >= 1
    assert any(f.check == "rate_limit" for f in r.findings)


def test_rate_limit_timing_recorded(result_with_tools):
    """Check should record timing."""
    r = result_with_tools([{"name": "x", "description": "y", "inputSchema": {}}])
    check_rate_limit(r)
    assert "rate_limit" in r.timings


def test_rate_limit_static_finding_is_t27(result_with_tools):
    r = result_with_tools([
        {
            "name": "api_call",
            "description": "Makes unlimited requests to the API with no throttling",
            "inputSchema": {},
        }
    ])
    check_rate_limit(r)
    found = [f for f in r.findings if f.check == "rate_limit"]
    assert found
    assert all(f.taxonomy_id == "MCP-T27" for f in found)


def test_behavioral_rate_limit_flags_unthrottled_burst():
    r = _echo_result()
    check_behavioral_rate_limit(_BurstSession(), r)
    found = [f for f in r.findings if f.check == "behavioral_rate_limit"]
    assert len(found) == 1
    assert found[0].severity == "MEDIUM"
    assert found[0].taxonomy_id == "MCP-T27"


def test_behavioral_rate_limit_silent_when_throttled():
    r = _echo_result()
    check_behavioral_rate_limit(_BurstSession(text="429 rate limited"), r)
    assert [f for f in r.findings if f.check == "behavioral_rate_limit"] == []


def test_behavioral_rate_limit_timing_recorded():
    r = _echo_result()
    check_behavioral_rate_limit(_BurstSession(), r)
    assert "behavioral_rate_limit" in r.timings


def test_behavioral_rate_limit_still_fires_on_stdio():
    """Stdio has one caller, but an agent loop can still hammer it."""
    r = _echo_result()
    session = _BurstSession(stdio=True)
    check_behavioral_rate_limit(session, r)
    found = [f for f in r.findings if f.check == "behavioral_rate_limit"]
    assert found
    assert found[0].taxonomy_id == "MCP-T27"
