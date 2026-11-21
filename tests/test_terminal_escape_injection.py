"""Server-controlled text must not drive the operator's terminal.

The scan target names its tools and writes its responses. Raw escape
sequences in either could erase a CRITICAL row, clear the screen, retitle
the window, or plant a disguised hyperlink (CWE-150). Rich passes them
through, and parses stray markup as tags.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.progress import Progress

from mcpnuke.core import terminal
from mcpnuke.core.models import TargetResult
from mcpnuke.core.terminal import escape, guard_console
from mcpnuke.reporting.console import print_report

_INJECTED: tuple[str, ...] = (
    "\x1b]0;",  # OSC: window title
    "\x1b]8;;",  # OSC 8: hyperlink
    "\x1b[2J",  # clear screen
    "\x1b[1A",  # cursor up, to overwrite a row
    "\x9b",  # 8-bit CSI
)
_EVIL: str = (
    "x\x1b]0;pwned\x07 \x1b]8;;http://evil.example\x1b\\click\x1b]8;;\x1b\\"
    " \x1b[2J\x1b[1A\x1b[2K \x9b2J [/bold] [link=http://evil.example]y[/link]"
)


def _rendered(render: Callable[[Console], None]) -> str:
    buf = io.StringIO()
    console = guard_console(Console(file=buf, force_terminal=True, width=300))
    render(console)
    return buf.getvalue()


def test_escape_makes_control_characters_visible() -> None:
    out = escape("a\x1b[2Jb\x07c\x9bd\n\te [/bold]")
    assert out == "a\\x1b[2Jb\\x07c\\x9bd\n\te \\[/bold]"


def test_report_does_not_emit_injected_sequences() -> None:
    result = TargetResult(url="http://mcp.lab/mcp")
    result.add("tool_poisoning", "CRITICAL", f"Poisoned tool {_EVIL}", _EVIL, evidence=_EVIL)
    for group in (False, True):
        out = _rendered(lambda c, g=group: print_report([result], group_findings=g, console=c))
        assert "pwned" in out
        assert not [seq for seq in _INJECTED if seq in out]


def test_print_under_live_progress_is_still_guarded() -> None:
    def render(console: Console) -> None:
        with Progress(console=console) as progress:
            task = progress.add_task("Scanning 1 target(s)", total=1)
            console.print(_EVIL, markup=False)
            progress.advance(task)

    out = _rendered(render)
    assert "pwned" in out
    # Progress redraws with its own cursor-up and erase-line codes.
    assert not [seq for seq in ("\x1b]0;", "\x1b]8;;", "\x1b[2J", "\x9b") if seq in out]


def test_only_terminal_module_imports_rich_escape() -> None:
    root = Path(terminal.__file__).parent.parent
    offenders = [
        str(p.relative_to(root))
        for p in root.rglob("*.py")
        if p.name != "terminal.py" and "from rich.markup import escape" in p.read_text()
    ]
    assert offenders == []
