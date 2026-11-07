"""Make server-controlled text safe to print on the operator's terminal.

The scan target names its tools and writes its responses. Rich passes
escape sequences in that text through, so a target could clear the screen,
overwrite a CRITICAL row, retitle the window, or plant a hyperlink.
Control characters are shown as ``\\xNN`` rather than dropped: the bytes
are evidence.
"""

from __future__ import annotations

import re

from rich.console import (
    Console,
    ConsoleOptions,
    ConsoleRenderable,
    RenderableType,
    RenderHook,
    RenderResult,
)
from rich.markup import escape as _markup_escape
from rich.segment import Segment

# C0 except tab and newline, DEL, and C1 (0x9b is an 8-bit CSI).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _visible(text: str) -> str:
    return _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def escape(text: str) -> str:
    """Rich markup escape that also shows control characters as ``\\xNN``."""
    return _markup_escape(_visible(text))


class _VisibleControls:
    def __init__(self, renderable: RenderableType) -> None:
        self._renderable = renderable

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        for seg in console.render(self._renderable, options):
            yield seg if seg.control else Segment(_visible(seg.text), seg.style)


class _ControlFilter(RenderHook):
    def process_renderables(
        self, renderables: list[ConsoleRenderable]
    ) -> list[ConsoleRenderable]:
        return [_VisibleControls(r) for r in renderables]


def guard_console(console: Console) -> Console:
    """Show control characters in everything *console* prints.

    Rich's own colour and cursor codes are generated from styles and
    control segments at write time, so they are untouched.

    ponytail: a live display (Progress, status) renders through its own
    later hook and is not covered. Keep server text out of task
    descriptions, or wrap them in escape().
    """
    console.push_render_hook(_ControlFilter())
    return console
