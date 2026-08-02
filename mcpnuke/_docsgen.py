"""Render reference documentation from source.

The CLI reference is derived from the argparse parser rather than maintained by
hand, because the hand-maintained copy drifted 14 flags behind before anyone
noticed. tests/test_docs_current.py fails the build if the committed output
stops matching the parser.

Regenerate: uv run python -m mcpnuke._docsgen
"""

from __future__ import annotations

import argparse
from pathlib import Path

from mcpnuke.cli import build_parser

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
CLI_REFERENCE_PATH: Path = REPO_ROOT / "docs" / "cli-reference.md"

BANNER: str = (
    "<!-- GENERATED FILE — do not edit by hand.\n"
    "     Regenerate: uv run python -m mcpnuke._docsgen\n"
    "     Source: mcpnuke/cli.py -->"
)

# argparse's own groups. "options" holds only -h/--help after the flags were
# split into named groups, so rendering it would emit a stub section.
_SKIP_TITLES: frozenset[str] = frozenset({"positional arguments", "options"})

# Hand-written, because `mcpnuke diff` never reaches build_parser(): __main__
# intercepts argv[1] == "diff" and builds a separate parser. Merging the two
# parsers would change dispatch behaviour, so this section is static text and
# is the one part of this file that can drift from the code.
DIFF_SECTION: str = """## Subcommand: `mcpnuke diff`

Compares two saved scan reports. This subcommand is dispatched before the main
parser runs and has its own options; see `mcpnuke diff --help`.

```bash
mcpnuke diff OLD.json NEW.json
```
"""


def _invocation(parser: argparse.ArgumentParser, action: argparse.Action) -> str:
    """Format a flag exactly as --help would, metavars included."""
    return parser._get_formatter()._format_action_invocation(action)


def _help_text(action: argparse.Action) -> str:
    """The help string as `--help` shows it, without expanding any values.

    argparse %-formats help strings before printing, so a literal percent is
    written `%%` in the source. Undoing that escape here keeps the doc matching
    `--help`. Note this is *not* argparse's `_expand_help`: that would also
    substitute `%(default)s`, and fourteen defaults come from `os.environ.get`,
    several of them secrets. Nothing here ever reads a default.
    """
    return (action.help or "").replace("%%", "%")


def _cell(text: str) -> str:
    """Collapse whitespace and escape pipes so a table row survives markdown."""
    return " ".join(text.split()).replace("|", "\\|")


def render_cli_reference(parser: argparse.ArgumentParser) -> str:
    """Render the full CLI reference for `parser` as markdown.

    Only the invocation and help text are emitted. Fourteen flags default to
    `os.environ.get(...)`, several of them secrets, so a defaults column would
    bake the generating machine's credentials into a committed file.
    """
    lines: list[str] = [
        BANNER,
        "",
        "# CLI Reference",
        "",
        "Every option `mcpnuke` accepts, grouped as `--help` groups them.",
        "Generated from the parser, so it cannot fall behind the code.",
        "",
    ]
    for group in parser._action_groups:
        if group.title in _SKIP_TITLES:
            continue
        actions = [
            a
            for a in group._group_actions
            if a.help != argparse.SUPPRESS and a.option_strings
        ]
        if not actions:
            continue
        lines += [
            f"## {group.title}",
            "",
            "| Option | Description |",
            "|--------|-------------|",
        ]
        for action in actions:
            lines.append(
                f"| `{_cell(_invocation(parser, action))}` "
                f"| {_cell(_help_text(action))} |"
            )
        lines.append("")
    lines.append(DIFF_SECTION)
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    CLI_REFERENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CLI_REFERENCE_PATH.write_text(render_cli_reference(build_parser()))
    print(f"wrote {CLI_REFERENCE_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
