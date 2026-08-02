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
