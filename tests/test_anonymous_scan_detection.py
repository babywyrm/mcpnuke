"""Findings that say "unauthenticated" must only fire on unauthenticated scans.

Claiming a server accepts anonymous access when the scanner authenticated is the
most expensive kind of false positive: it tells an operator their access control
is missing when it is working, and it is unfalsifiable from the report alone.
"""

from __future__ import annotations

from mcpnuke.core.enumerator import enumerate_server
from mcpnuke.core.models import TargetResult
from mcpnuke.core.protocol import LEGACY


class _LegacySession:
    """Answers initialize, so negotiation settles on the legacy handshake."""

    def __init__(self):
        self.protocol_mode = LEGACY

    def call(self, method, params=None, timeout=None, retries=2):
        if method == "initialize":
            return {"result": {"serverInfo": {"name": "ref", "version": "1.0.0"}}}
        if method == "tools/list":
            return {"result": {"tools": [{"name": "t", "description": "d"}]}}
        return {"result": {}}

    def notify(self, method, params=None):
        pass


def _auth_findings(result: TargetResult) -> list:
    return [f for f in result.findings if f.check == "auth"]


class TestAnonymousInitializeFinding:
    def test_fires_when_no_credential_was_used(self):
        """The true positive this check exists for must survive the fix."""
        result = TargetResult(url="http://t/mcp")
        enumerate_server(_LegacySession(), result)
        titles = [f.title for f in _auth_findings(result)]
        assert "Unauthenticated MCP initialize accepted" in titles

    def test_silent_when_the_scan_supplied_a_bearer_token(self):
        result = TargetResult(url="http://t/mcp")
        result.auth_context["_raw_token"] = "an-opaque-token"
        enumerate_server(_LegacySession(), result)
        assert _auth_findings(result) == [], (
            "claimed initialize was accepted without credentials, but the scan "
            "sent a bearer token"
        )

    def test_silent_when_the_scan_supplied_jwt_claims(self):
        result = TargetResult(url="http://t/mcp")
        result.auth_context["jwt_claims_summary"] = {"sub": "svc"}
        enumerate_server(_LegacySession(), result)
        assert _auth_findings(result) == []


class TestScannedAnonymously:
    def test_true_with_empty_auth_context(self):
        assert TargetResult(url="http://t/mcp").scanned_anonymously() is True

    def test_false_with_raw_token(self):
        r = TargetResult(url="http://t/mcp")
        r.auth_context["_raw_token"] = "x"
        assert r.scanned_anonymously() is False

    def test_false_with_oidc_or_introspection(self):
        r = TargetResult(url="http://t/mcp")
        r.auth_context["oidc_url"] = "https://issuer.example/"
        assert r.scanned_anonymously() is False

        r2 = TargetResult(url="http://t/mcp")
        r2.auth_context["introspection_active"] = True
        assert r2.scanned_anonymously() is False
