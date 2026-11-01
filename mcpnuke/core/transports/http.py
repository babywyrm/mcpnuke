"""Plain HTTP POST transport and the header and SSE-body helpers every HTTP transport shares."""

from __future__ import annotations

import contextlib
import json
import time

import httpx

from mcpnuke.core.constants import build_jsonrpc_request as _jrpc
from mcpnuke.core.protocol import LEGACY, STATELESS, inject_meta, routing_headers


def _auth_headers(auth_token: str | None, extra_headers: dict | None = None) -> dict:
    """Build headers with optional Authorization Bearer."""
    h = {"Accept": "text/event-stream"}
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    if extra_headers:
        h.update(extra_headers)
    return h


def _mcp_headers(auth_token: str | None, extra_headers: dict | None = None) -> dict:
    """Build MCP request headers with optional Authorization Bearer."""
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    if extra_headers:
        h.update(extra_headers)
    return h



def _parse_sse_json(text: str, req_id: int | None = None) -> dict | None:
    """Extract JSON-RPC response from SSE body (event: message / data: {...})."""
    for line in text.splitlines():
        if line.startswith("data:"):
            data = line[5:].strip()
            if data:
                try:
                    msg = json.loads(data)
                    if isinstance(msg, dict) and (
                        req_id is None or msg.get("id") == req_id
                    ):
                        return msg
                except json.JSONDecodeError:
                    pass
    return None


class HTTPSession:
    """Plain HTTP POST fallback (no SSE). Handles both application/json and text/event-stream responses."""

    def __init__(
        self,
        base: str,
        post_url: str,
        timeout: float = 25.0,
        headers: dict | None = None,
        verify_tls: bool = False,
        protocol_mode: str = LEGACY,
    ):
        self.base = base
        self.sse_url = ""
        self.post_url = post_url
        self.timeout = timeout
        self.protocol_mode = protocol_mode
        self._req_id = 0
        self._session_id: str | None = None
        self._headers = headers or {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        self._client = httpx.Client(
            verify=verify_tls, timeout=timeout, follow_redirects=True
        )

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return True

    def _request_headers(
        self,
        method: str = "",
        params: dict | None = None,
    ) -> dict:
        h = dict(self._headers)
        if self.protocol_mode == STATELESS:
            h.update(routing_headers(method, params, self.protocol_mode))
            return h
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    def _capture_session_id(self, resp_headers: httpx.Headers) -> None:
        if self.protocol_mode == STATELESS:
            return
        for k, v in resp_headers.items():
            if k.lower() == "mcp-session-id" and v:
                self._session_id = v
                break

    def post_raw(
        self,
        payload: dict,
        extra_headers: dict | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """POST *payload* to the MCP endpoint and return the raw httpx response.

        For checks that must set transport headers themselves or read the HTTP
        status directly — the DPoP proof probes, which need a request that is
        otherwise fully authorized so a 401 means "missing proof" rather than
        "missing token". Ordinary callers want call(), which owns request ids,
        retries, and response parsing.

        Defined only on HTTP transports, so ``hasattr(session, "post_raw")``
        is the capability test for "this transport has headers to probe".
        """
        headers = self._request_headers(
            payload.get("method", ""), payload.get("params"),
        )
        if extra_headers:
            headers.update(extra_headers)
        return self._client.post(
            self.post_url,
            json=payload,
            headers=headers,
            timeout=timeout or self.timeout,
        )

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        for attempt in range(retries + 1):
            self._req_id += 1
            sent_params = (
                inject_meta(params, self.protocol_mode)
                if params or self.protocol_mode == STATELESS
                else params
            )
            try:
                r = self._client.post(
                    self.post_url,
                    json=_jrpc(method, sent_params, self._req_id),
                    headers=self._request_headers(method, params),
                    timeout=timeout or self.timeout,
                )
                self._capture_session_id(r.headers)
                if r.status_code in (200, 202):
                    ct = r.headers.get("content-type", "")
                    if "application/json" in ct:
                        body = r.json()
                        if isinstance(body, dict):
                            return body
                    if "text/event-stream" in ct or "jsonrpc" in r.text:
                        parsed = _parse_sse_json(r.text, self._req_id)
                        if parsed:
                            return parsed
                        try:
                            body = r.json()
                            if isinstance(body, dict):
                                return body
                        except Exception:
                            pass
            except Exception:
                if attempt < retries:
                    time.sleep(0.5)
        return None

    def notify(self, method: str, params: dict | None = None) -> None:
        sent_params = (
            inject_meta(params, self.protocol_mode)
            if params or self.protocol_mode == STATELESS
            else (params or {})
        )
        with contextlib.suppress(Exception):
            self._client.post(
                self.post_url,
                json={
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": sent_params,
                },
                headers=self._request_headers(method, params),
                timeout=5,
            )

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._client.close()
