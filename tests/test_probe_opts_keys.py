"""Every probe option a check reads is declared on ProbeOpts.

mypy rejects opts["typo"] but types opts.get("typo") as object without an
error, and nearly every read is a .get(). A misspelled key would read as
None and quietly switch a probe off, so the spelling is checked here.
"""

from __future__ import annotations

import re
from pathlib import Path

import mcpnuke
from mcpnuke.core.models import ProbeOpts

_READ = re.compile(
    r'\b(?:opts|probe_opts|scan_opts|scratch_opts)'
    r'(?:\.get\(|\.setdefault\(|\.pop\(|\[)\s*"([A-Za-z_0-9]+)"'
)


def _reads() -> list[tuple[str, str]]:
    root = Path(mcpnuke.__file__).parent
    return [
        (str(path.relative_to(root)), key)
        for path in sorted(root.rglob("*.py"))
        for key in _READ.findall(path.read_text())
    ]


def test_every_option_read_is_declared() -> None:
    declared = ProbeOpts.__required_keys__ | ProbeOpts.__optional_keys__
    unknown = sorted({f"{path}: {key}" for path, key in _reads() if key not in declared})
    assert unknown == []


def test_the_scan_sees_the_reads() -> None:
    """An empty scan must not read as every key being declared."""
    keys = {key for _, key in _reads()}
    assert {"tls_verify", "no_invoke", "_log", "claude_phase2_workers"} <= keys
