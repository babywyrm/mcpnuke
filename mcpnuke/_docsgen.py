"""Render reference documentation from source.

The CLI reference is derived from the argparse parser rather than maintained by
hand, because the hand-maintained copy drifted 14 flags behind before anyone
noticed. tests/test_docs_current.py fails the build if the committed output
stops matching the parser.

Regenerate: uv run python -m mcpnuke._docsgen

Never import this module from runtime code. REPO_ROOT walks up from __file__
to find a checkout, which is meaningless in an installed wheel — the package
ships whole, so this file is present but its paths point nowhere useful. It is
a build-time tool that happens to live inside the package so it can import the
parsers it documents.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
from typing import TypeGuard

from mcpnuke.__main__ import _build_diff_parser
from mcpnuke.cli import build_parser

REPO_ROOT: Path = Path(__file__).resolve().parent.parent
CLI_REFERENCE_PATH: Path = REPO_ROOT / "docs" / "cli-reference.md"

# Hand-written, unlike the CLI reference: severity and detection prose cannot be
# derived from source. Named here so the completeness test that guards it does
# not have to rebuild a repo-root path of its own.
CHECKS_PATH: Path = REPO_ROOT / "docs" / "checks.md"

# Read as text, not imported: the association between an env var and the flag
# it backs exists only in the source, since argparse keeps the resolved value
# and throws the variable name away.
CLI_SOURCE_PATH: Path = Path(__file__).resolve().parent / "cli.py"

BANNER: str = (
    "<!-- GENERATED FILE — do not edit by hand.\n"
    "     Regenerate: uv run python -m mcpnuke._docsgen\n"
    "     Source: mcpnuke/cli.py -->"
)

# argparse's own groups. "options" holds only -h/--help after the flags were
# split into named groups, so rendering it would emit a stub section.
_SKIP_TITLES: frozenset[str] = frozenset({"positional arguments", "options"})

ENV_HEADING: str = "Environment Variables"
DIFF_HEADING: str = "Subcommand: `mcpnuke diff`"

# The only prose in the generated document. Everything factual — every option,
# positional and variable name — comes from a parser or from the source.
_DIFF_PROSE: str = (
    "Compares two saved scan reports. `diff` is dispatched off `sys.argv` "
    "before the main parser runs, so it takes its own arguments and none of "
    "the options above."
)
_DIFF_EXIT_NOTE: str = (
    "Exits 1 when the newer report contains findings the baseline did not, "
    "so it can gate a CI job."
)
_ENV_PROSE: str = (
    "Each variable supplies the default for one flag; passing the flag wins. "
    "Only names are listed here — a value is a credential."
)


def _is_environ_get(node: ast.AST) -> TypeGuard[ast.Call]:
    """True for an `os.environ.get(...)` call node."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and getattr(node.func.value, "attr", "") == "environ"
        and bool(node.args)
    )


def _module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level `NAME = "literal"` bindings, for resolving indirection.

    `--auth-token` reads `os.environ.get(AUTH_TOKEN_ENV)`. A literal-only walk
    finds 13 of the 14 variables and drops MCP_AUTH_TOKEN, the one most worth
    documenting.
    """
    return {
        target.id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        for target in node.targets
        if isinstance(target, ast.Name)
    }


def _environ_name(node: ast.AST, constants: dict[str, str]) -> str | None:
    """The variable name an `os.environ.get(...)` call reads, if it is static."""
    if not _is_environ_get(node):
        return None
    key = node.args[0]
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value
    if isinstance(key, ast.Name):
        return constants.get(key.id)
    return None


def _parse_cli_source() -> tuple[ast.Module, dict[str, str]]:
    tree = ast.parse(CLI_SOURCE_PATH.read_text())
    return tree, _module_string_constants(tree)


def count_environ_reads() -> int:
    """How many `os.environ.get(...)` calls cli.py makes with a static name.

    Exists so a test can assert the flag association below loses none of them;
    a silent drop would put a variable back in the undocumented pile.
    """
    tree, constants = _parse_cli_source()
    return len({
        name
        for node in ast.walk(tree)
        if (name := _environ_name(node, constants)) is not None
    })


def env_var_flag_pairs() -> list[tuple[str, str]]:
    """Every env var cli.py reads, paired with the flag whose default it sets.

    Walks `add_argument` calls and takes the first string positional as the
    flag, so the pairing comes from the source rather than a list someone has
    to remember to update.
    """
    tree, constants = _parse_cli_source()
    pairs: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
        ):
            continue
        flag = next(
            (
                arg.value
                for arg in node.args
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            ),
            None,
        )
        if flag is None:
            continue
        for inner in ast.walk(node):
            name = _environ_name(inner, constants)
            if name is not None:
                pairs.add((name, flag))
    return sorted(pairs)


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


def _row(formatter: argparse.HelpFormatter, action: argparse.Action) -> str:
    """One table row: the invocation exactly as --help prints it, plus help."""
    invocation = formatter._format_action_invocation(action)
    return f"| `{_cell(invocation)}` | {_cell(_help_text(action))} |"


def _table(header: str) -> list[str]:
    return [f"| {header} | Description |", "|---|---|"]


def _render_flag_groups(parser: argparse.ArgumentParser) -> list[str]:
    """One section per curated argument group, in declaration order."""
    formatter = parser._get_formatter()
    lines: list[str] = []
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
        lines += [f"## {group.title}", "", *_table("Option")]
        lines += [_row(formatter, a) for a in actions]
        lines.append("")
    return lines


def _render_env_vars() -> list[str]:
    return [
        f"## {ENV_HEADING}",
        "",
        _ENV_PROSE,
        "",
        "| Variable | Flag |",
        "|---|---|",
        *(f"| `{var}` | `{flag}` |" for var, flag in env_var_flag_pairs()),
        "",
    ]


def _render_diff_subcommand(parser: argparse.ArgumentParser) -> list[str]:
    """The `diff` section, tables generated, prose hand-written.

    Rendered separately because `diff` has positionals, which the main
    renderer filters out rather than loosening its own filter for one section.
    """
    formatter = parser._get_formatter()
    actions = [
        a
        for a in parser._actions
        if a.help != argparse.SUPPRESS and "--help" not in a.option_strings
    ]
    return [
        f"## {DIFF_HEADING}",
        "",
        _DIFF_PROSE,
        "",
        "```bash",
        "mcpnuke diff OLD.json NEW.json",
        "```",
        "",
        *_table("Argument"),
        *(_row(formatter, a) for a in actions),
        "",
        _DIFF_EXIT_NOTE,
    ]


def render_cli_reference(
    parser: argparse.ArgumentParser,
    diff_parser: argparse.ArgumentParser | None = None,
) -> str:
    """Render the full CLI reference as markdown.

    Only invocations and help text are emitted. Fourteen flags default to
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
        *_render_flag_groups(parser),
        *_render_env_vars(),
        *_render_diff_subcommand(diff_parser or _build_diff_parser()),
    ]
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    CLI_REFERENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CLI_REFERENCE_PATH.write_text(render_cli_reference(build_parser()))
    print(f"wrote {CLI_REFERENCE_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
