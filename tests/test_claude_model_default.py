"""The default Claude model must be one the API still serves.

`claude-sonnet-4-20250514` was retired; every `--claude` run failed with
`not_found_error` before anyone noticed, because the id was duplicated across
eight call sites with no single source of truth.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from mcpnuke.core.constants import DEFAULT_CLAUDE_MODEL

_REPO = Path(__file__).resolve().parents[1]
_RETIRED = "claude-sonnet-4-20250514"


class TestDefaultModelConstant:
    def test_the_constant_is_not_the_retired_model(self) -> None:
        assert DEFAULT_CLAUDE_MODEL != _RETIRED

    def test_the_constant_looks_like_a_claude_model(self) -> None:
        assert DEFAULT_CLAUDE_MODEL.startswith("claude-")

    def test_the_default_is_an_undated_alias(self) -> None:
        """Dated snapshots get retired; aliases roll forward. That retirement
        is the whole reason this test file exists."""
        assert not re.search(r"-\d{8}$", DEFAULT_CLAUDE_MODEL), (
            f"{DEFAULT_CLAUDE_MODEL} pins a dated snapshot, which will be "
            "retired out from under us again"
        )


class TestEverySiteUsesTheConstant:
    def test_the_cli_default_is_the_constant(self) -> None:
        from mcpnuke.cli import build_parser

        args = build_parser().parse_args([])
        assert args.claude_model == DEFAULT_CLAUDE_MODEL

    def test_the_llm_entrypoints_default_to_the_constant(self) -> None:
        import inspect

        from mcpnuke.core import llm

        for name in ("analyze_tools", "analyze_findings", "analyze_response"):
            fn = getattr(llm, name, None)
            if fn is None:
                continue
            default = inspect.signature(fn).parameters["model"].default
            assert default == DEFAULT_CLAUDE_MODEL, f"{name} defaults to {default!r}"

    def test_no_module_hardcodes_the_retired_id(self) -> None:
        """Guards the duplication that let this rot unnoticed.

        Inspects string literals rather than raw text, so prose explaining the
        retirement does not count as using it.
        """
        offenders = []
        for path in (_REPO / "mcpnuke").rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and node.value == _RETIRED:
                    offenders.append(f"{path.relative_to(_REPO)}:{node.lineno}")
        assert not offenders, f"retired model id still hardcoded at: {offenders}"

    def test_the_cli_help_does_not_advertise_retired_models(self) -> None:
        help_text = (_REPO / "mcpnuke" / "cli.py").read_text()
        stale = re.findall(r"claude-(?:sonnet|opus)-4-20250514", help_text)
        assert not stale, f"cli help still names retired models: {set(stale)}"
