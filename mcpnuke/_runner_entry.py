"""Console-script shim for ``mcpnuke-runner``.

The runner needs the optional ``server`` extra (fastapi, uvicorn, pydantic),
but its console script is installed by the base package. Pointing the script
straight at ``mcpnuke.server.app:run`` meant a plain ``pip install mcpnuke``
followed by ``mcpnuke-runner`` printed a ModuleNotFoundError traceback.

This module sits deliberately *outside* ``mcpnuke.server``: that package's
``__init__`` imports pydantic through ``models``, so any handler written
inside it would need the very dependency it is trying to report on.

Nothing here may import the server package at module level.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

# The distribution names that make up the `server` extra. A missing import
# outside this set is a real bug in the server package, and is re-raised
# rather than reported as a missing extra.
_SERVER_EXTRA_MODULES: frozenset[str] = frozenset({"fastapi", "uvicorn", "pydantic"})

_EXIT_MISSING_EXTRA: int = 2


def _load_run() -> Callable[[], None]:
    """Import the real entry point. Kept separate so tests can replace it."""
    from mcpnuke.server.app import run

    return run


def main() -> None:
    try:
        run = _load_run()
    except ImportError as exc:
        missing = (getattr(exc, "name", "") or "").split(".")[0]
        if missing not in _SERVER_EXTRA_MODULES:
            raise
        sys.stderr.write(
            f"mcpnuke-runner needs the 'server' extra, and {missing} is not installed.\n"
            "\n"
            "  uv tool install 'mcpnuke[server]'\n"
            "  pip install 'mcpnuke[server]'\n"
            "\n"
            "The scanner itself does not need it — plain 'mcpnuke' works without.\n"
        )
        raise SystemExit(_EXIT_MISSING_EXTRA) from None
    run()


if __name__ == "__main__":
    main()
