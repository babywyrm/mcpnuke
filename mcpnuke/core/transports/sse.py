"""SSE transport: a GET event stream for responses, POSTs to the endpoint it announces."""

from __future__ import annotations

import contextlib
import json
import queue
import threading
import time

import httpx

from mcpnuke.core.constants import build_jsonrpc_request as _jrpc
from mcpnuke.core.protocol import LEGACY
from mcpnuke.core.transports.http import _auth_headers, _mcp_headers


class MCPSession:
    """SSE-based MCP session."""

    def __init__(
        self,
        base: str,
        sse_path: str,
        timeout: float = 25.0,
        auth_token: str | None = None,
        verify_tls: bool = False,
        extra_headers: dict | None = None,
    ):
        self.base = base
        self.sse_url = base + sse_path
        self.post_url: str = ""
        self.timeout = timeout
        # Negotiated by enumerator.negotiate_protocol. Only HTTPSession
        # varies its framing on this today; the rest carry it so the
        # negotiated mode is readable from any transport.
        self.protocol_mode = LEGACY
        self._auth_token = auth_token
        self._verify_tls = verify_tls
        self._extra_headers = extra_headers or {}
        self._req_id = 0
        self._session_id: str | None = None
        self._q: queue.Queue[dict] = queue.Queue()
        self._stop = threading.Event()
        self._endpoint_ready = threading.Event()
        self._client = httpx.Client(
            verify=verify_tls, timeout=timeout, follow_redirects=True
        )
        self._listener = threading.Thread(
            target=self._listen, daemon=True, name=f"sse-{base}"
        )
        self._listener.start()

    def _listen(self) -> None:
        headers = _auth_headers(self._auth_token, self._extra_headers)
        headers["Accept"] = "text/event-stream"
        try:
            with self._client.stream(
                "GET",
                self.sse_url,
                headers=headers,
            ) as resp:
                for k, v in resp.headers.items():
                    if k.lower() == "mcp-session-id" and v:
                        self._session_id = v
                        break
                event_type = "message"
                for raw in resp.iter_lines():
                    if self._stop.is_set():
                        break
                    line = raw.strip()
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data = line[5:].strip()
                        if event_type == "endpoint" and data:
                            self.post_url = (
                                data
                                if data.startswith("http")
                                else self.base + data
                            )
                            self._endpoint_ready.set()
                        elif event_type != "endpoint" and data:
                            try:
                                msg = json.loads(data)
                                self._q.put(msg)
                            except json.JSONDecodeError:
                                pass
                        event_type = "message"
        except Exception:
            pass
        finally:
            self._endpoint_ready.set()

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return self._endpoint_ready.wait(timeout=timeout)

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        wait = timeout or self.timeout
        for attempt in range(retries + 1):
            self._req_id += 1
            payload = _jrpc(method, params, self._req_id)
            headers = _mcp_headers(self._auth_token, self._extra_headers)
            if self._session_id:
                headers["Mcp-Session-Id"] = self._session_id
            try:
                r = self._client.post(
                    self.post_url,
                    json=payload,
                    headers=headers,
                    timeout=10,
                )
                if r.status_code not in (200, 202, 204):
                    if attempt < retries:
                        time.sleep(0.5)
                        continue
                    return None
            except Exception:
                if attempt < retries:
                    time.sleep(0.5)
                    continue
                return None

            deadline = time.time() + wait
            pending: list[dict] = []
            while time.time() < deadline:
                try:
                    msg = self._q.get(timeout=0.3)
                    if isinstance(msg, dict) and msg.get("id") == self._req_id:
                        for m in pending:
                            self._q.put(m)
                        return msg
                    pending.append(msg)
                except queue.Empty:
                    pass
            for m in pending:
                self._q.put(m)
            if attempt < retries:
                time.sleep(1.0)
        return None

    def notify(self, method: str, params: dict | None = None) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        headers = _mcp_headers(self._auth_token, self._extra_headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        with contextlib.suppress(Exception):
            self._client.post(
                self.post_url,
                json=payload,
                headers=headers,
                timeout=5,
            )

    def post_raw(
        self,
        payload: dict,
        extra_headers: dict | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """POST *payload* to the SSE message endpoint, returning the raw response.

        See HTTPSession.post_raw. Requires post_url, which is only known after
        the SSE handshake resolves the message endpoint.
        """
        headers = _mcp_headers(self._auth_token, self._extra_headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        if extra_headers:
            headers.update(extra_headers)
        return self._client.post(
            self.post_url,
            json=payload,
            headers=headers,
            timeout=timeout or self.timeout,
        )

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(Exception):
            self._client.close()

