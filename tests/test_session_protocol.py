"""Structural contract for transport sessions.

Checks accept a ``session`` and call methods on it, but there was no shared
base class or Protocol across MCPSession, HTTPSession, ToolServerSession, and
StdioSession — so the parameter was untyped everywhere and nothing verified
that a new transport implements what checks actually call.

These tests are the enforcement: every transport must satisfy the Protocol, and
the Protocol must not drift wider than what all four genuinely provide.
"""

from __future__ import annotations

import inspect

from mcpnuke.core.session import (
    HTTPSession,
    MCPSession,
    StdioSession,
    ToolServerSession,
)
from mcpnuke.core.transports.base import HTTPCapableSession, MCPSessionProtocol

ALL_TRANSPORTS = (MCPSession, HTTPSession, ToolServerSession, StdioSession)

# post_raw is an HTTP-layer capability. stdio has no headers for a DPoP proof
# to live in, which is why it is a separate Protocol rather than an optional
# member of the base one.
HTTP_TRANSPORTS = (MCPSession, HTTPSession, ToolServerSession)


class TestEveryTransportSatisfiesTheProtocol:
    def test_all_transports_are_structural_subtypes(self):
        for cls in ALL_TRANSPORTS:
            missing = [
                m
                for m in ("call", "notify", "close", "wait_ready")
                if not callable(getattr(cls, m, None))
            ]
            assert not missing, f"{cls.__name__} missing {missing}"

    def test_call_signatures_are_compatible(self):
        """A check calling session.call(...) must work on any transport."""
        reference = inspect.signature(MCPSessionProtocol.call)
        ref_params = list(reference.parameters)
        for cls in ALL_TRANSPORTS:
            actual = list(inspect.signature(cls.call).parameters)
            assert actual == ref_params, f"{cls.__name__}.call{tuple(actual)}"

    def test_http_transports_expose_post_raw(self):
        for cls in HTTP_TRANSPORTS:
            assert callable(getattr(cls, "post_raw", None)), cls.__name__

    def test_stdio_does_not_claim_http_capability(self):
        """The DPoP probes gate on this; if it ever gains post_raw the gate
        silently starts probing a transport with no headers."""
        assert not hasattr(StdioSession, "post_raw")


class TestProtocolShape:
    def test_base_protocol_only_declares_the_universal_surface(self):
        declared = {
            n for n in vars(MCPSessionProtocol) if not n.startswith("_")
        }
        assert declared == {"call", "notify", "close", "wait_ready"}, declared

    def test_base_protocol_carries_the_negotiated_mode(self):
        """enumerator.negotiate_protocol writes this on whatever it is given,
        so every transport must actually have somewhere to put it."""
        assert "protocol_mode" in MCPSessionProtocol.__annotations__
        for cls in ALL_TRANSPORTS:
            assert "protocol_mode" in inspect.getsource(cls.__init__), cls.__name__

    def test_http_protocol_extends_the_base(self):
        # issubclass() is unavailable on a Protocol with data members, so check
        # the inheritance directly.
        assert MCPSessionProtocol in HTTPCapableSession.__mro__

    def test_protocols_are_runtime_checkable(self):
        """Checks use isinstance/hasattr gating for optional capabilities."""
        session = HTTPSession("http://mcp.test", "http://mcp.test/mcp")
        assert isinstance(session, MCPSessionProtocol)
        assert isinstance(session, HTTPCapableSession)
