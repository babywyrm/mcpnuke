"""An out-of-band oracle for proving that data left the target.

Every other signal the scanner has is in band: it asks a tool something and
reads what the tool says back. That is enough to show a path is *callable* —
`exfil_flow` reports exactly that, and declines to claim more — but it cannot
show the payload went anywhere. A sink answering `{"status": "sent"}` and a
sink answering it while discarding the data are the same conversation.

A listener the scanner controls closes that gap. Each probe is issued a token,
the token is planted in the payload as a URL, and if a request for that token
ever arrives then something on the target side reached an address that appeared
nowhere except in that one probe. Tool output cannot fabricate it.

Reachability is the operator's problem, not this module's: a container cannot
resolve the scanner's loopback and a remote target cannot route to a private
address. `advertised_host` exists so the URL handed to the target can differ
from the interface actually bound.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import cast
from uuid import uuid4

# Enough of a body to hold a credential or a record, bounded so a target that
# streams at the listener cannot exhaust memory.
_MAX_BODY_BYTES: int = 65536

_TOKEN_PREFIX: str = "mcpnuke"

# serve_forever polls for the shutdown flag, so its interval is the floor on
# how long stop() blocks. The default 0.5s is paid on every listener the scan
# opens, which is once per probe.
_SHUTDOWN_POLL_SECONDS: float = 0.02


@dataclass(frozen=True)
class Callback:
    """One request that arrived for an issued token."""

    token: str
    method: str
    path: str
    headers: dict[str, str]
    body: str
    peer: str
    at: float = field(default_factory=time.time)


class _Handler(BaseHTTPRequestHandler):
    # BaseHTTPRequestHandler logs every request to stderr, which would scribble
    # over the scan output.
    def log_message(self, _format: str, *_args: object) -> None:
        return

    @property
    def _listener(self) -> CanaryListener:
        return cast("CanaryListener", self.server._listener)  # type: ignore[attr-defined]

    def _record(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, _MAX_BODY_BYTES)) if length > 0 else b""
        self._listener._record(
            Callback(
                token=self._listener._token_in(self.path),
                method=method,
                path=self.path,
                headers={k: v for k, v in self.headers.items()},
                body=raw.decode("utf-8", "replace"),
                peer=self.client_address[0] if self.client_address else "",
            )
        )
        # Always 200: a sink that retries on failure would double-count, and an
        # error might discourage the very callback being measured.
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self) -> None:
        self._record("GET")

    def do_POST(self) -> None:
        self._record("POST")

    def do_PUT(self) -> None:
        self._record("PUT")

    def do_HEAD(self) -> None:
        self._record("HEAD")

    def do_OPTIONS(self) -> None:
        self._record("OPTIONS")


class CanaryListener:
    """Issues canary URLs and records who calls them back.

    Usage::

        with CanaryListener(advertised_host="host.docker.internal") as oast:
            token = oast.issue()
            send_to_sink(oast.url_for(token))
            if oast.hits(token):
                ...  # egress proven, not inferred
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 0,
        advertised_host: str | None = None,
    ) -> None:
        self._host = host
        self._requested_port = port
        self._advertised_host = advertised_host
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._callbacks: list[Callback] = []
        self._issued: set[str] = set()

    # ── lifecycle ─────────────────────────────────────────────────────

    def start(self) -> CanaryListener:
        if self._server is not None:
            return self
        server = ThreadingHTTPServer((self._host, self._requested_port), _Handler)
        server._listener = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(
            target=lambda: server.serve_forever(poll_interval=_SHUTDOWN_POLL_SECONDS),
            name="mcpnuke-oast",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> CanaryListener:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    # ── addressing ────────────────────────────────────────────────────

    @property
    def port(self) -> int:
        if self._server is None:
            return 0
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        host = self._advertised_host or _routable_host()
        return f"http://{host}:{self.port}"

    def issue(self) -> str:
        """Mint a token that has never been used anywhere else."""
        token = f"{_TOKEN_PREFIX}{uuid4().hex[:16]}"
        with self._lock:
            self._issued.add(token)
        return token

    def url_for(self, token: str) -> str:
        return f"{self.base_url}/{token}"

    # ── observation ───────────────────────────────────────────────────

    def _token_in(self, path: str) -> str:
        """The issued token this request path refers to, or ''.

        Substring rather than exact match: a sink is free to append its own
        query string or path segment to the URL it was handed, and such a
        request is still proof the address was reached.
        """
        with self._lock:
            issued = tuple(self._issued)
        for token in issued:
            if token in path:
                return token
        return ""

    def _record(self, callback: Callback) -> None:
        with self._lock:
            self._callbacks.append(callback)

    def hits(self, token: str) -> list[Callback]:
        with self._lock:
            return [c for c in self._callbacks if c.token == token]

    def any_hit(self) -> bool:
        with self._lock:
            return any(c.token for c in self._callbacks)

    def all_callbacks(self) -> list[Callback]:
        with self._lock:
            return list(self._callbacks)


def _routable_host() -> str:
    """A local address a target on the same network could plausibly reach.

    Loopback is the wrong default — the target is another process, often
    another host — so prefer the address the kernel would use to leave this
    machine. Falls back to loopback, which at least works for a target sharing
    the network namespace.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No traffic is sent; this only asks the routing table for a source
        # address, so it works without the destination existing.
        probe.connect(("192.0.2.1", 9))
        return str(probe.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()
