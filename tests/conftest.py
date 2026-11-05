"""Pytest fixtures for mcpnuke tests."""

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Ensure mcpnuke is importable (run from project root or mcpnuke/)
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

if sys.platform == "darwin":
    # A fork() child of this threaded test process can segfault in
    # Network.framework's atfork handler. Popen posix_spawns, which runs no
    # atfork handlers, only with a full program path, close_fds=False, and
    # no cwd. Test children are trusted, so open descriptors do not matter.
    _popen_init = subprocess.Popen.__init__

    def _spawning_popen_init(self: subprocess.Popen, args: Any, *a: Any, **kw: Any) -> None:
        if kw.get("cwd") is not None and Path(kw["cwd"]).resolve() == Path.cwd().resolve():
            kw["cwd"] = None
        kw.setdefault("close_fds", False)
        if not a and kw.get("executable") is None and not kw.get("shell") and isinstance(args, list | tuple):
            kw["executable"] = shutil.which(str(args[0])) or None
        _popen_init(self, args, *a, **kw)

    subprocess.Popen.__init__ = _spawning_popen_init  # type: ignore[method-assign]


@pytest.fixture
def target_result():
    """Create a TargetResult with sample tools for testing checks."""
    from mcpnuke.core.models import TargetResult

    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = [
        {
            "name": "safe_tool",
            "description": "A safe tool with no issues",
            "inputSchema": {"properties": {}},
        },
    ]
    return r


@pytest.fixture
def result_with_tools():
    """TargetResult factory that accepts tools list."""
    from mcpnuke.core.models import TargetResult

    def _make(tools: list, url: str = "http://localhost:9001/sse"):
        r = TargetResult(url=url)
        r.tools = tools
        return r

    return _make
