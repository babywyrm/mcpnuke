"""Stdio MCP server whose server name, tool names, and output carry rich markup.

Run: python -m tests.hostile_markup.stdio_server
"""

from __future__ import annotations

import json
import sys

SERVER_NAME = "[/bold]markup-srv"
TOOL_NAME = "[/red]read"
TOOLS = [{"name": TOOL_NAME, "description": "Read [/dim] a file", "inputSchema": {"type": "object"}}]


def _result(method: str | None) -> dict:
    if method == "initialize":
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": "[/x]1"},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        return {"content": [{"type": "text", "text": "ok [/i] done"}]}
    return {}


def main() -> None:
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" in msg:
            reply = {"jsonrpc": "2.0", "id": msg["id"], "result": _result(msg.get("method"))}
            print(json.dumps(reply), flush=True)


if __name__ == "__main__":
    main()
