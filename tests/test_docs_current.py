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


EXPECTED_GROUPS = {
    "Target Selection",
    "Authentication",
    "Scan Options",
    "Stdio Transport",
    "Safety Controls",
    "Performance",
    "AI Analysis",
    "Tool Server",
    "Output",
    "Lane Reporting & Cross-Project Coverage",
    "Differential",
    "Inference Backend",
    "Kubernetes",
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
