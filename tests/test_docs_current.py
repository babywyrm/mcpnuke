"""Reference docs are derived from source, so they cannot drift from it."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcpnuke.cli import build_parser, parse_args

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestParserFactory:
    def test_build_parser_returns_a_parser(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_build_parser_does_not_consume_argv(self, monkeypatch):
        """Constructing the parser must not parse argv — a stray parse_args()
        inside the factory would raise SystemExit on an unrecognised flag."""
        monkeypatch.setattr(sys, "argv", ["mcpnuke", "--definitely-not-a-flag"])
        build_parser()  # must not raise

    def test_parse_args_still_works(self):
        args = parse_args(["--targets", "http://example.test/mcp"])
        assert args.targets == ["http://example.test/mcp"]

    def test_parse_args_delegates_to_the_factory(self):
        """parse_args must stay a thin delegator; divergent post-processing
        would show up as a namespace mismatch."""
        argv = ["--targets", "http://example.test/mcp", "--protocol-mode", "stateless"]
        assert parse_args(argv) == build_parser().parse_args(argv)


# Order is load-bearing: the reference generator walks _action_groups in
# sequence to emit its sections, so reordering build_parser silently reshuffles
# both --help and the generated document.
EXPECTED_GROUP_ORDER: tuple[str, ...] = (
    "Target Selection",
    "Authentication",
    "Scan Options",
    "Stdio Transport",
    "Safety Controls",
    "Performance",
    "AI Analysis",
    "Tool Server",
    "Output",
    "Policy Generation",
    "Lane Reporting & Cross-Project Coverage",
    "Differential",
    "Inference Backend",
    "Kubernetes",
    "Diagnostics",
)
EXPECTED_GROUPS = frozenset(EXPECTED_GROUP_ORDER)

# argparse's own groups, which hold only -h/--help and are not curated.
_ARGPARSE_DEFAULT_GROUPS = frozenset({"options", "positional arguments"})

# Families named by a shared prefix. A new --k8s-* or --claude-* flag filed
# anywhere else is a misfiling, and this is where that is most likely to happen.
GROUP_PREFIX_RULES: tuple[tuple[str, str], ...] = (
    ("--k8s-", "Kubernetes"),
    ("--claude", "AI Analysis"),
    ("--bedrock", "AI Analysis"),
    ("--ollama", "AI Analysis"),
    ("--policy-", "Policy Generation"),
    ("--generate-policy", "Policy Generation"),
    ("--inference", "Inference Backend"),
    ("--oidc-", "Authentication"),
    ("--token-introspect-", "Authentication"),
)


def _flag_to_group() -> dict[str, str]:
    """Map every option string to the title of the group holding it."""
    return {
        option: group.title
        for group in build_parser()._action_groups
        for action in group._group_actions
        for option in action.option_strings
    }


class TestArgumentGroups:
    def test_all_curated_groups_exist(self):
        titles = {g.title for g in build_parser()._action_groups}
        assert titles >= EXPECTED_GROUPS

    def test_every_flag_lands_in_a_named_group(self):
        parser = build_parser()
        ungrouped = set()
        for group in parser._action_groups:
            if group.title in EXPECTED_GROUPS:
                continue
            for action in group._group_actions:
                # -h/--help is argparse's own and stays in the default group.
                if action.option_strings and action.option_strings != ["-h", "--help"]:
                    ungrouped.update(action.option_strings)
        assert not ungrouped, f"flags outside any curated group: {sorted(ungrouped)}"

    def test_groups_are_declared_in_the_documented_order(self):
        titles = tuple(
            g.title
            for g in build_parser()._action_groups
            if g.title not in _ARGPARSE_DEFAULT_GROUPS
        )
        assert titles == EXPECTED_GROUP_ORDER

    def test_prefix_families_land_in_their_group(self):
        flag_group = _flag_to_group()
        misfiled = {
            flag: (actual, expected)
            for prefix, expected in GROUP_PREFIX_RULES
            for flag, actual in flag_group.items()
            if flag.startswith(prefix) and actual != expected
        }
        assert not misfiled, f"flags in the wrong group: {misfiled}"

    def test_every_prefix_rule_matches_something(self):
        """A rule matching nothing passes vacuously — that hides a typo in the
        rule or a flag that has since been renamed."""
        flags = _flag_to_group()
        unmatched = [
            prefix
            for prefix, _ in GROUP_PREFIX_RULES
            if not any(f.startswith(prefix) for f in flags)
        ]
        assert not unmatched, f"prefix rules matching no flag: {unmatched}"


class TestGeneratedCLIReference:
    def test_file_exists(self):
        assert (REPO_ROOT / "docs/cli-reference.md").is_file()

    def test_content_matches_the_parser(self):
        from mcpnuke._docsgen import render_cli_reference

        expected = render_cli_reference(build_parser())
        actual = (REPO_ROOT / "docs/cli-reference.md").read_text()
        assert actual == expected, (
            "docs/cli-reference.md is stale. "
            "Regenerate with: uv run python -m mcpnuke._docsgen"
        )

    def test_every_parser_flag_appears(self):
        from mcpnuke._docsgen import render_cli_reference

        rendered = render_cli_reference(build_parser())
        for action in build_parser()._actions:
            for opt in action.option_strings:
                assert opt in rendered, f"{opt} missing from generated reference"

    def test_carries_a_do_not_edit_banner(self):
        text = (REPO_ROOT / "docs/cli-reference.md").read_text()
        assert "GENERATED FILE" in text

    def test_no_environment_value_leaks_into_the_doc(self, monkeypatch):
        """14 flags default to os.environ.get(...), several of them secrets.

        The renderer must never emit a default, or running the generator on a
        machine with MCP_AUTH_TOKEN set would bake that token into a committed
        file. This is a security scanner; that file ends up in a public repo.
        """
        from mcpnuke._docsgen import render_cli_reference

        canary = "s3cr3t-canary-value-do-not-emit"
        for var in (
            "MCP_AUTH_TOKEN",
            "MCP_CLIENT_SECRET",
            "MCP_INTROSPECT_CLIENT_SECRET",
            "MCPNUKE_K8S_TOKEN",
        ):
            monkeypatch.setenv(var, canary)

        assert canary not in render_cli_reference(build_parser())

    def test_no_help_string_interpolates_a_default(self):
        """The renderer deliberately never expands help strings, so a
        `%(default)s` would print literally in the doc — and any code that
        "fixed" that by expanding would write env-var defaults, several of
        them secrets, into a committed file. Keep help strings literal.
        """
        offenders = [
            action.option_strings
            for action in build_parser()._actions
            if "%(" in (action.help or "")
        ]
        assert not offenders, f"help strings interpolating a value: {offenders}"

    def test_argparse_percent_escapes_are_unescaped(self):
        """argparse %-formats help strings, so `--coverage` writes `%%` to get
        one `%` in --help. Rendered markdown must show what --help shows.
        """
        from mcpnuke._docsgen import render_cli_reference

        rendered = render_cli_reference(build_parser())
        assert "~20% of a 100-tool server" in rendered
        assert "%%" not in rendered
