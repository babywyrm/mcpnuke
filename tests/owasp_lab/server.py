"""A tiny unauthenticated MCP server with one planted marker per OWASP category.

Stdlib only, same shape as the hardened reference target, and not part of
the installed package. tools/call returns a fixed string and never runs
the arguments.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tests.owasp_lab.tools import TOOL_DEFINITIONS

PROTOCOL_VERSION = "2025-06-18"

_PARSE_ERROR = -32700
_METHOD_NOT_FOUND = -32601
_MARKER = "owasp lab marker"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
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
        if not isinstance(method, str):
            method = ""
        raw_params = request.get("params") or {}
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        if req_id is None and method:
            self._send_json(202, {})
            return
        self._send_json(200, self._dispatch(req_id, method, params))

    def do_GET(self) -> None:
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dispatch(self, req_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return self._ok(
                req_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "owasp-lab", "version": "1.0.0"},
                },
            )
        if method == "tools/list":
            return self._ok(req_id, {"tools": TOOL_DEFINITIONS})
        if method == "resources/list":
            return self._ok(req_id, {"resources": []})
        if method == "prompts/list":
            return self._ok(req_id, {"prompts": []})
        if method == "tools/call":
            if not isinstance(params.get("name"), str) or not params.get("name"):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": _METHOD_NOT_FOUND, "message": "Invalid params"},
                }
            return self._ok(
                req_id,
                {"content": [{"type": "text", "text": _MARKER}], "isError": False},
            )
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": _METHOD_NOT_FOUND, "message": "Method not found"},
        }

    @staticmethod
    def _ok(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
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

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        """Silence per-request logging so pytest output stays readable."""


class OwaspLab:
    def __init__(self, httpd: ThreadingHTTPServer):
        self._httpd = httpd
        self.port = httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/mcp"

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def start_owasp_lab() -> OwaspLab:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return OwaspLab(httpd)
