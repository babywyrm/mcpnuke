"""Structural types for transport sessions.

Every check takes a ``session`` and calls methods on it, but the four
transports — ``MCPSession`` (SSE), ``HTTPSession``, ``ToolServerSession``, and
``StdioSession`` — share no base class. The parameter was therefore untyped in
every check signature, so nothing verified that a transport implements what
checks call, and mypy could not see through ``session.call(...)`` at all.

Protocols rather than an ABC, because the transports are already written and
structural typing needs no changes to them. Two of them, because the surface is
genuinely not uniform: a DPoP proof lives in an HTTP header, and stdio has no
header layer for one to live in. Splitting that out keeps the capability
explicit instead of leaving ``post_raw`` as a member some transports raise on.

The file split of ``core/session.py`` into this package is separate work; this
module intentionally defines only the contract.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class MCPSessionProtocol(Protocol):
    """What every transport provides, and all a general check may rely on."""

    # Written by enumerator.negotiate_protocol on whichever transport it is
    # handed, so it belongs to the shared contract even though only the HTTP
    # transport currently varies its framing on it.
    protocol_mode: str

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        """Send a JSON-RPC request and return the parsed response, or None."""
        ...

    def notify(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification, which expects no response."""
        ...

    def close(self) -> None:
        """Release transport resources. Must tolerate being called twice."""
        ...

    def wait_ready(self, timeout: float = 10.0) -> bool:
        """Block until the transport can carry requests."""
        ...


@runtime_checkable
class HTTPCapableSession(MCPSessionProtocol, Protocol):
    """A transport with an HTTP request layer a check can address directly.

    Needed by probes that set transport headers themselves or read the HTTP
    status rather than the JSON-RPC body — the DPoP proof checks, which must
    distinguish "missing proof" from "missing token". Checks gate on this with
    ``hasattr(session, "post_raw")``.
    """

    post_url: str

    def post_raw(
        self,
        payload: dict,
        extra_headers: dict | None = None,
        timeout: float | None = None,
    ) -> Any:
        """POST *payload* to the endpoint and return the raw HTTP response."""
        ...
