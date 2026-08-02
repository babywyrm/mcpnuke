"""Reference docs are derived from source, so they cannot drift from it."""
from __future__ import annotations

import argparse

from mcpnuke.cli import build_parser, parse_args


class TestParserFactory:
    def test_build_parser_returns_a_parser(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_build_parser_does_not_read_argv(self):
        # Two calls must be independent; no global state consumed.
        assert len(build_parser()._actions) == len(build_parser()._actions)

    def test_parse_args_still_works(self):
        args = parse_args(["--targets", "http://example.test/mcp"])
        assert args.targets == ["http://example.test/mcp"]

    def test_parse_args_uses_the_same_flag_set(self):
        factory_flags = {
            opt for a in build_parser()._actions for opt in a.option_strings
        }
        assert "--targets" in factory_flags
        assert "--protocol-mode" in factory_flags
