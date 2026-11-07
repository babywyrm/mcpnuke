"""Stdio transport: newline-delimited JSON-RPC to a local MCP server process."""

from __future__ import annotations

import contextlib
import json
import os
import queue
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterable
from typing import Any

from mcpnuke.core.constants import build_jsonrpc_request as _jrpc
from mcpnuke.core.protocol import LEGACY

# The MCP SDK stdio client's default inheritance. A server under test is
# untrusted, so the scanner's own API keys and tokens never reach it unless
# named with --stdio-env.
INHERITED_ENV: tuple[str, ...] = (
    (
        "APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PROCESSOR_ARCHITECTURE",
        "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "USERNAME", "USERPROFILE", "PROGRAMFILES",
    )
    if sys.platform == "win32"
    else ("HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER")
)


def child_env(passthrough: Iterable[str] = ()) -> dict[str, str]:
    """The defaults plus named variables, minus exported shell functions."""
    names = (*INHERITED_ENV, *passthrough)
    return {
        name: os.environ[name]
        for name in names
        if name in os.environ and not os.environ[name].startswith("()")
    }


def _close_inherited_on_exec() -> bool:
    """Mark every inheritable descriptor above stderr close-on-exec.

    False when the descriptors cannot be listed; the caller must then
    close them in the child instead.
    """
    if sys.platform == "win32":
        return False
    try:
        fds = [int(name) for name in os.listdir("/dev/fd")]
    except OSError:
        return False
    for fd in fds:
        if fd > 2:
            with contextlib.suppress(OSError):
                if os.get_inheritable(fd):
                    os.set_inheritable(fd, False)
    return True


class StdioSession:
    """JSON-RPC over stdin/stdout for local MCP servers (npm, npx, python, etc.).

    Launches a subprocess with the given command and communicates via
    newline-delimited JSON-RPC over the process's stdin/stdout.
    """

    def __init__(
        self,
        cmd: str | list[str],
        timeout: float = 25.0,
        env: dict[str, str] | None = None,
        inherit: Iterable[str] = (),
    ):
        if isinstance(cmd, str):
            self.cmd = shlex.split(cmd)
        else:
            self.cmd = list(cmd)
        self.timeout = timeout
        # Negotiated by enumerator.negotiate_protocol. Only HTTPSession
        # varies its framing on this today; the rest carry it so the
        # negotiated mode is readable from any transport.
        self.protocol_mode = LEGACY
        self.post_url = f"stdio://{' '.join(self.cmd)}"
        self.sse_url = ""
        self._req_id = 0
        self._q: queue.Queue[dict[str, Any]] = queue.Queue()
        self._stop = threading.Event()

        proc_env = {**child_env(inherit), **(env or {})}
        program = shutil.which(self.cmd[0], path=proc_env.get("PATH")) if self.cmd else None

        # A full program path and close_fds=False let Popen posix_spawn
        # instead of fork(). A macOS fork() child can segfault in
        # Network.framework's atfork handler. The server is untrusted, so
        # descriptors the scanner inherited are made close-on-exec first.
        self._proc = subprocess.Popen(
            self.cmd,
            executable=program,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=proc_env,
            close_fds=not _close_inherited_on_exec(),
        )
        self._reader = threading.Thread(
            target=self._read_stdout, daemon=True, name="stdio-reader"
        )
        self._reader.start()

    def _read_stdout(self) -> None:
        assert self._proc.stdout is not None
        for raw in self._proc.stdout:
            if self._stop.is_set():
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                self._q.put(msg)
            except json.JSONDecodeError:
                pass

    def wait_ready(self, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                return False
            time.sleep(0.1)
            if self._proc.stdout and self._proc.stdout.readable():
                return True
        return self._proc.poll() is None

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict[str, Any] | None:
        wait = timeout or self.timeout
        for attempt in range(retries + 1):
            self._req_id += 1
            payload = _jrpc(method, params, self._req_id)
            try:
                assert self._proc.stdin is not None
                line = json.dumps(payload) + "\n"
                self._proc.stdin.write(line.encode("utf-8"))
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError):
                if attempt < retries:
                    time.sleep(0.5)
                    continue
                return None

            deadline = time.time() + wait
            pending: list[dict[str, Any]] = []
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
                time.sleep(0.5)
        return None

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        try:
            assert self._proc.stdin is not None
            line = json.dumps(payload) + "\n"
            self._proc.stdin.write(line.encode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def close(self) -> None:
        self._stop.set()
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:
            with contextlib.suppress(Exception):
                self._proc.kill()

