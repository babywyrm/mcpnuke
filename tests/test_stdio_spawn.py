"""StdioSession starts the server with posix_spawn, never fork().

On macOS a fork() child runs Network.framework's atfork handler, which
segfaults once the parent has made a network call. posix_spawn runs no
atfork handlers. On Linux it avoids forking a threaded scanner.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from mcpnuke.core.transports.stdio import StdioSession

pytestmark = pytest.mark.skipif(
    not subprocess._USE_POSIX_SPAWN,  # type: ignore[attr-defined]
    reason="this libc cannot posix_spawn for subprocess",
)


def test_server_gets_no_inherited_descriptor() -> None:
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    probe = f"import os,sys; os.fstat({write_fd}); sys.exit(3)"
    session = StdioSession([sys.executable, "-c", probe])
    try:
        assert session._proc.wait(timeout=20) == 1, "server inherited the scanner's descriptor"
    finally:
        session.close()
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.parametrize("program", [sys.executable, os.path.basename(sys.executable)])
def test_session_uses_posix_spawn(monkeypatch: pytest.MonkeyPatch, program: str) -> None:
    calls: list[str] = []
    real = os.posix_spawn

    def _spy(path: str, *args: object, **kwargs: object) -> int:
        calls.append(path)
        return real(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "posix_spawn", _spy)
    monkeypatch.setenv("PATH", os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", ""))
    session = StdioSession(f"{program} -c pass")
    try:
        assert len(calls) == 1
        assert os.path.isabs(calls[0])
    finally:
        session.close()
