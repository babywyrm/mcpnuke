"""Default model ids must be ones the providers still serve.

`claude-sonnet-4-20250514` was retired; every `--claude` run failed with
`not_found_error` before anyone noticed, because the id was duplicated across
eight call sites with no single source of truth. The Bedrock default
`anthropic.claude-3-5-sonnet-20241022-v2:0` had reached end of life and was
absent from the catalog entirely.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from mcpnuke.core.constants import DEFAULT_BEDROCK_MODEL, DEFAULT_CLAUDE_MODEL

_REPO = Path(__file__).resolve().parents[1]
_RETIRED = "claude-sonnet-4-20250514"
_EOL_BEDROCK = "anthropic.claude-3-5-sonnet-20241022-v2:0"


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


class TestBedrockDefaultConstant:
    def test_it_is_not_the_end_of_life_id(self) -> None:
        assert DEFAULT_BEDROCK_MODEL != _EOL_BEDROCK

    def test_it_is_an_inference_profile(self) -> None:
        """Current Bedrock Anthropic models are INFERENCE_PROFILE only, so a
        bare `anthropic.*` id fails with ValidationException on invoke."""
        assert re.match(r"^(us|eu|apac|global)\.anthropic\.", DEFAULT_BEDROCK_MODEL), (
            f"{DEFAULT_BEDROCK_MODEL} is not a region-prefixed inference "
            "profile and cannot be invoked directly"
        )

    def test_it_does_not_chase_an_entitlement_gated_alias(self) -> None:
        """`anthropic.claude-sonnet-5` is in the catalog but returns
        AccessDenied on ordinary accounts, so it would fail out of the box the
        same way the retired id did. Bedrock has no generally available alias,
        which is why this one id is allowed to carry a date."""
        assert "sonnet-5" not in DEFAULT_BEDROCK_MODEL


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

    def test_the_bedrock_default_is_the_constant(self) -> None:
        from mcpnuke.cli import build_parser

        args = build_parser().parse_args([])
        assert args.bedrock_model == DEFAULT_BEDROCK_MODEL

    def test_the_bedrock_runtime_config_uses_the_constant(self) -> None:
        from mcpnuke.core.llm import _bedrock_config

        assert _bedrock_config["model"] == DEFAULT_BEDROCK_MODEL

    def test_no_module_hardcodes_the_eol_bedrock_id(self) -> None:
        offenders = []
        for path in (_REPO / "mcpnuke").rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and node.value == _EOL_BEDROCK:
                    offenders.append(f"{path.relative_to(_REPO)}:{node.lineno}")
        assert not offenders, f"end-of-life Bedrock id still hardcoded at: {offenders}"

    def test_the_cli_help_does_not_advertise_retired_models(self) -> None:
        help_text = (_REPO / "mcpnuke" / "cli.py").read_text()
        stale = re.findall(r"claude-(?:sonnet|opus)-4-20250514", help_text)
        assert not stale, f"cli help still names retired models: {set(stale)}"
