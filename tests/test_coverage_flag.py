"""Tests for --coverage N tool sampling knob."""

import pytest
from mcpnuke.cli import parse_args
from mcpnuke.checks import _pick_security_relevant


class TestCoverageCLI:
    def test_coverage_flag_parses_integer(self):
        args = parse_args(["--targets", "http://localhost:8080/mcp", "--coverage", "20"])
        assert args.coverage == 20

    def test_fast_flag_still_works(self):
        args = parse_args(["--targets", "http://localhost:8080/mcp", "--fast"])
        assert args.fast is True

    def test_coverage_zero_means_all(self):
        args = parse_args(["--targets", "http://localhost:8080/mcp", "--coverage", "0"])
        assert args.coverage == 0

    def test_coverage_default_is_none_or_zero(self):
        args = parse_args(["--targets", "http://localhost:8080/mcp"])
        assert getattr(args, "coverage", None) in (None, 0)

    def test_coverage_negative_rejected(self):
        with pytest.raises(SystemExit):
            parse_args(["--targets", "http://localhost:8080/mcp", "--coverage", "-1"])


class TestCoveragePickSecurityRelevant:
    TOOLS = [
        {"name": f"tool_{i}", "description": "test tool", "inputSchema": {}}
        for i in range(20)
    ]

    def test_coverage_n_limits_tools(self):
        result = _pick_security_relevant(self.TOOLS, 7)
        assert len(result) == 7

    def test_coverage_n_zero_returns_all(self):
        result = _pick_security_relevant(self.TOOLS, 0)
        assert len(result) == len(self.TOOLS)

    def test_fast_still_means_coverage_5(self):
        result = _pick_security_relevant(self.TOOLS, 5)
        assert len(result) == 5

    def test_n_larger_than_list_returns_all(self):
        result = _pick_security_relevant(self.TOOLS, 999)
        assert len(result) == len(self.TOOLS)
