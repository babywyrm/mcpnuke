"""A deliberately well-built MCP server, used to measure mcpnuke's false-positive rate.

Speaks JSON-RPC over a single POST endpoint using only the standard library, so
it is importable in CI, which installs --extra dev and therefore has neither
FastAPI nor uvicorn.
"""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tests.reference_target.tools import TOOL_DEFINITIONS

PROTOCOL_VERSION = "2025-06-18"

_PARSE_ERROR = -32700
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_UNAUTHORIZED = -32001


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        if not self._authorized():
            self._send_json(
                401,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": _UNAUTHORIZED, "message": "Authentication required"},
                },
                extra_headers={"WWW-Authenticate": 'Bearer realm="reference-target"'},
            )
            return

        try:
            request = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self._send_parse_error()
            return

        if not isinstance(request, dict):
            self._send_parse_error()
            return

        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            params = {}

        if req_id is None and method:
            self._send_json(202, {})
            return

        self._send_json(200, self._dispatch(req_id, method, params))

    def do_GET(self) -> None:
        # No SSE stream. 405 lets the SSE probe fail fast instead of hanging.
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorized(self) -> bool:
        expected: str = self.server.token  # type: ignore[attr-defined]
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        return secrets.compare_digest(header[len("Bearer ") :].strip(), expected)

    def _dispatch(self, req_id: Any, method: str, params: dict) -> dict:
        if method == "initialize":
            return self._ok(
                req_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "reference-target", "version": "1.0.0"},
                },
            )
        if method == "tools/list":
            return self._ok(req_id, {"tools": TOOL_DEFINITIONS})
        if method == "resources/list":
            return self._ok(req_id, {"resources": []})
        if method == "prompts/list":
            return self._ok(req_id, {"prompts": []})
        if method == "tools/call":
            from tests.reference_target.tools_runtime import call_tool

            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                # A missing tool name is a malformed request, not a failed tool
                # call, so it belongs in `error`. Answering with a success
                # envelope tells a client the call was understood.
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": _INVALID_PARAMS, "message": "Invalid params"},
                }
            return self._ok(
                req_id,
                call_tool(tool_name, params.get("arguments") or {}),
            )
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": _METHOD_NOT_FOUND, "message": "Method not found"},
        }

    @staticmethod
    def _ok(req_id: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _send_parse_error(self) -> None:
        self._send_json(
            200,
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": _PARSE_ERROR, "message": "Parse error"},
            },
        )

    def _send_json(
        self,
        status: int,
        payload: dict,
        extra_headers: dict | None = None,
    ) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        """Silence per-request logging so pytest output stays readable."""


class ReferenceServer:
    """A running reference target. Use start_reference_server() to build one."""

    def __init__(self, httpd: ThreadingHTTPServer, token: str):
        self._httpd = httpd
        self.token = token
        self.port = httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/mcp"

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def start_reference_server() -> ReferenceServer:
    """Start the reference target on an ephemeral port.

    The bearer token is generated per process and never committed, so the
    harness adds no secret-shaped strings to the repository.
    """
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    token = secrets.token_urlsafe(24)
    httpd.token = token  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return ReferenceServer(httpd, token)
