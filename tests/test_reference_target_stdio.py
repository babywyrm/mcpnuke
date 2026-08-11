"""The stdio reference target speaks MCP over stdin/stdout.

Protocol-level tests only. The false-positive measurement built on top of
this fixture lives in tests/test_false_positives_stdio.py.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys

STDIO_COMMAND = f"{shlex.quote(sys.executable)} -m tests.reference_target.stdio_server"


def _exchange(*requests: dict) -> list[dict]:
    """Send newline-delimited JSON-RPC, return the parsed replies.

    Matches StdioSession's framing exactly: one JSON object per line, and
    nothing else on stdout ever. Anything the server prints for its own
    benefit corrupts the stream for every message after it.
    """
    proc = subprocess.run(
        shlex.split(STDIO_COMMAND),
        input="".join(json.dumps(r) + "\n" for r in requests).encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def test_initialize_returns_server_info():
    (reply,) = _exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert reply["id"] == 1
    assert reply["result"]["serverInfo"]["name"] == "reference-target-stdio"
    assert "protocolVersion" in reply["result"]


def test_tools_list_returns_the_shared_definitions():
    """The point of the fixture: same tools as the HTTP target, new transport."""
    from tests.reference_target.tools import TOOL_DEFINITIONS

    (reply,) = _exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [t["name"] for t in reply["result"]["tools"]]
    assert names == [t["name"] for t in TOOL_DEFINITIONS]


def test_tools_call_dispatches_to_the_shared_handlers():
    (reply,) = _exchange({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "docs.search", "arguments": {"query": "hello"}},
    })
    assert reply["result"]["isError"] is False


def test_unknown_method_is_a_jsonrpc_error():
    (reply,) = _exchange({"jsonrpc": "2.0", "id": 4, "method": "no/such"})
    assert reply["error"]["code"] == -32601


def test_missing_tool_name_is_invalid_params():
    """A malformed request is an error envelope, not a failed tool call --
    the same rule the HTTP target follows, and one protocol_robustness
    checks for."""
    (reply,) = _exchange({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {},
    })
    assert reply["error"]["code"] == -32602


def test_a_notification_gets_no_reply():
    """id-less requests are notifications. Replying to one desynchronises
    every subsequent response in a newline-delimited stream."""
    replies = _exchange(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 6, "method": "initialize"},
    )
    assert len(replies) == 1
    assert replies[0]["id"] == 6


def test_malformed_line_does_not_kill_the_server():
    """A scanner sends deliberate garbage. Dying on it would manufacture a
    crash-on-malformed-input finding the fixture does not intend."""
    proc = subprocess.run(
        shlex.split(STDIO_COMMAND),
        input=b"not json\n"
        + json.dumps({"jsonrpc": "2.0", "id": 7, "method": "initialize"}).encode()
        + b"\n",
        capture_output=True,
        timeout=30,
        check=False,
    )
    replies = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert replies[-1]["id"] == 7


def test_nothing_but_json_on_stdout():
    """Every line must parse. A stray print corrupts the framing, and the
    failure mode is a confusing scanner error rather than an obvious one."""
    proc = subprocess.run(
        shlex.split(STDIO_COMMAND),
        input=json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/list"}).encode()
        + b"\n",
        capture_output=True,
        timeout=30,
        check=False,
    )
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    # Without this the test passes when the server produces nothing at all,
    # which is exactly the state it is supposed to detect.
    assert lines, f"no output at all; stderr={proc.stderr.decode()[:400]}"
    for line in lines:
        json.loads(line)
