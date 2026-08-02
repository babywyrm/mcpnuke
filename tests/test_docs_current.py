"""Reference docs are derived from source, so they cannot drift from it."""
from __future__ import annotations

import argparse
import sys

from mcpnuke.cli import build_parser, parse_args


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
