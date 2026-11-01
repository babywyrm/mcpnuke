"""Write scan output readable by its owner only.

Reports, SARIF, baselines, and generated policy describe exploitable paths
and the tool surface of the target. A shared host's default umask leaves
them world-readable, so every writer goes through here instead.
"""

from __future__ import annotations

import os
from pathlib import Path

PRIVATE_MODE: int = 0o600


def write_private(path: str | Path, text: str) -> None:
    """Write *text* to *path* with mode 0600, tightening an existing file."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_MODE)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, PRIVATE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
