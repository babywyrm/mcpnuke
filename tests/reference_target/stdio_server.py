"""The reference target, spoken over stdin/stdout instead of HTTP.

Same tool schemas and the same hardened handlers as the HTTP target in
`server.py` — only the transport differs. It exists because the
false-positive harness measured HTTP alone, while stdio is the transport
most users actually have, and two auth checks shipped reporting HIGH
findings on it that were true of every stdio server ever written.

No authentication, deliberately. stdio has no header layer to carry a
credential, so a fixture that demanded one would resemble no real stdio
server, and would hide exactly the class of bug this fixture exists to
catch.

Framing is newline-delimited JSON, matching StdioSession: exactly one JSON
object per line, and nothing else on stdout ever. A stray print corrupts the
stream for every message after it.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from tests.reference_target.tools import TOOL_DEFINITIONS

PROTOCOL_VERSION = "2025-06-18"

_PARSE_ERROR = -32700
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602


def _ok(req_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def dispatch(req_id: Any, method: str, params: dict) -> dict:
    """Answer one request. Mirrors ``_Handler._dispatch`` in server.py."""
    if method == "initialize":
        return _ok(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "reference-target-stdio", "version": "1.0.0"},
        })
    if method == "tools/list":
        return _ok(req_id, {"tools": TOOL_DEFINITIONS})
    if method == "resources/list":
        return _ok(req_id, {"resources": []})
    if method == "prompts/list":
        return _ok(req_id, {"prompts": []})
    if method == "tools/call":
        from tests.reference_target.tools_runtime import call_tool

        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            # A missing tool name is a malformed request, not a failed tool
            # call, so it belongs in `error`. Answering with a success
            # envelope tells a client the call was understood.
            return _error(req_id, _INVALID_PARAMS, "Invalid params")
        return _ok(req_id, call_tool(tool_name, params.get("arguments") or {}))
    return _error(req_id, _METHOD_NOT_FOUND, "Method not found")


def _emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def main() -> None:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except ValueError:
            # A scanner sends deliberate garbage. Answer and carry on; exiting
            # would look like a crash-on-malformed-input this server does not
            # actually have.
            _emit(_error(None, _PARSE_ERROR, "Parse error"))
            continue

        if not isinstance(request, dict):
            _emit(_error(None, _PARSE_ERROR, "Parse error"))
            continue

        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params")
        if not isinstance(params, dict):
            params = {}

        # A request with no id is a notification. Answering one would shift
        # every later reply by a message.
        if req_id is None and method:
            continue

        _emit(dispatch(req_id, method, params))


if __name__ == "__main__":
    main()
