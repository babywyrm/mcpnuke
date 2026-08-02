"""Reference docs are derived from source, so they cannot drift from it."""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

from mcpnuke import _docsgen
from mcpnuke import checks as checks_pkg
from mcpnuke.__main__ import _build_diff_parser
from mcpnuke._docsgen import render_cli_reference
from mcpnuke.checks import _build_deep_checks
from mcpnuke.cli import build_parser, parse_args
from mcpnuke.core.models import TargetResult


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


def _table_invocations(text: str) -> set[str]:
    """Option strings appearing in the first cell of a rendered table row.

    Substring matching over the whole document is too weak to test with: `-h`
    is a substring of `--inference-host`, `--help` occurs in the prose, and
    `--inference` occurs inside `--inference-host`'s own row.
    """
    found: set[str] = set()
    for line in text.splitlines():
        cell = re.match(r"^\| `([^`]+)` \|", line)
        if not cell:
            continue
        for part in cell.group(1).split(","):
            token = part.strip().split(" ")[0]
            if token.startswith("-"):
                found.add(token)
    return found


class TestGeneratedCLIReference:
    def test_file_exists(self):
        assert _docsgen.CLI_REFERENCE_PATH.is_file()

    def test_content_matches_the_parser(self):
        expected = render_cli_reference(build_parser())
        actual = _docsgen.CLI_REFERENCE_PATH.read_text()
        assert actual == expected, (
            "docs/cli-reference.md is stale. "
            "Regenerate with: uv run python -m mcpnuke._docsgen"
        )

    def test_every_parser_flag_appears_in_a_table_row(self):
        """Exact set equality against the rows, not substring containment.

        `-h`/`--help` are the only deliberate omissions: they live in the
        argparse-owned group the renderer skips.
        """
        documented = _table_invocations(render_cli_reference(build_parser()))
        declared = {o for a in build_parser()._actions for o in a.option_strings}
        deliberately_absent = {"-h", "--help"}
        assert documented == declared - deliberately_absent

    def test_the_main_parser_has_no_positionals(self):
        """The renderer skips argparse's `positional arguments` group and
        filters on `option_strings`, so a positional added to the main parser
        would vanish from the document. `mcpnuke diff` has positionals and is
        rendered by a separate path that handles them.
        """
        positionals = [
            a.dest for a in build_parser()._actions if not a.option_strings
        ]
        assert not positionals, f"main parser gained positionals: {positionals}"

    def test_carries_a_do_not_edit_banner(self):
        assert "GENERATED FILE" in _docsgen.CLI_REFERENCE_PATH.read_text()

    def test_generator_never_writes_the_hand_written_doc(self):
        """_docsgen names two documents and may only ever write one.

        docs/checks.md is hand-written and cannot be regenerated. Wiring
        CHECKS_PATH into main() for symmetry with CLI_REFERENCE_PATH would
        destroy it on a command whose contract is "safe to re-run".
        """
        source = Path(_docsgen.__file__).read_text()
        main_fn = next(
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        assert "CHECKS_PATH" not in ast.unparse(main_fn), (
            "_docsgen.main() references CHECKS_PATH — it would overwrite a "
            "hand-written document. Read the module docstring."
        )

    def test_no_environment_value_leaks_into_the_doc(self, monkeypatch):
        """14 flags default to os.environ.get(...), several of them secrets.

        The renderer must never emit a default, or running the generator on a
        machine with MCP_AUTH_TOKEN set would bake that token into a committed
        file. This is a security scanner; that file ends up in a public repo.

        The Environment Variables section names these variables, which makes
        the distinction load-bearing: the name is documentation, the value is
        a credential.
        """
        canary = "s3cr3t-canary-value-do-not-emit"
        secret_vars = (
            "MCP_AUTH_TOKEN",
            "MCP_CLIENT_SECRET",
            "MCP_INTROSPECT_CLIENT_SECRET",
            "MCPNUKE_K8S_TOKEN",
        )
        for var in secret_vars:
            monkeypatch.setenv(var, canary)

        rendered = render_cli_reference(build_parser())
        assert canary not in rendered
        for var in secret_vars:
            assert var in rendered, f"{var} should be named, just never valued"

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
        rendered = render_cli_reference(build_parser())
        assert "~20% of a 100-tool server" in rendered
        assert "%%" not in rendered

    def test_no_short_option_takes_an_argument(self):
        """Guards render stability across the 3.11/3.12/3.13 CI matrix.

        Python 3.13 changed HelpFormatter._format_action_invocation: 3.11 and
        3.12 render `-f FOO, --foo FOO`, 3.13+ render `-f, --foo FOO`. Today
        the document is byte-identical on all three only because `--verbose,
        -v` is the sole flag with a short form and it takes no argument. Add
        `-o, --output FILE` and test_content_matches_the_parser goes red on
        part of the matrix while passing locally, telling whoever sees it to
        regenerate a file that is not stale.

        The fix is to keep short options argument-free, not to reimplement
        argparse's formatter — nargs="+" and choices metavars would mean
        reimplementing _format_args and _metavar_formatter too.
        """
        offenders = [
            action.option_strings
            for action in build_parser()._actions
            if action.nargs != 0
            and any(len(o) == 2 and not o.startswith("--") for o in action.option_strings)
        ]
        assert not offenders, (
            f"short option strings that take an argument render differently on "
            f"Python 3.13 than on 3.11/3.12: {offenders}"
        )


class TestRenderedDocumentStructure:
    def test_headings_match_the_declared_group_order(self):
        """EXPECTED_GROUP_ORDER claims to govern the document, but every other
        assertion checks only the parser, and test_content_matches_the_parser
        compares the renderer against itself — regenerating makes the file
        agree with whatever came out. If a curated group emptied or its title
        collided with the renderer's skip list, a whole section would vanish
        with a green suite. Read the committed headings instead.
        """
        headings = tuple(
            line.removeprefix("## ").strip()
            for line in _docsgen.CLI_REFERENCE_PATH.read_text().splitlines()
            if line.startswith("## ")
        )
        assert headings == (
            *EXPECTED_GROUP_ORDER,
            _docsgen.ENV_HEADING,
            _docsgen.DIFF_HEADING,
        )

    def test_cell_escapes_pipes(self):
        """No help string contains a `|` today, so an unescaped pipe would
        break a table row silently the first time one does.
        """
        assert _docsgen._cell("a | b") == "a \\| b"

    def test_cell_collapses_whitespace(self):
        assert _docsgen._cell("a\n  b\tc") == "a b c"


class TestDiffSubcommandSection:
    """`mcpnuke diff` is dispatched on sys.argv before the main parser runs, so
    build_parser() cannot see it. It gets its own parser and its own rendering
    path; the first hand-written version of this section omitted --json.
    """

    def test_build_diff_parser_returns_a_parser(self):
        assert isinstance(_build_diff_parser(), argparse.ArgumentParser)

    def test_diff_parser_spec_is_unchanged_by_the_extraction(self):
        actions = {
            a.dest: a.option_strings for a in _build_diff_parser()._actions
        }
        assert actions == {
            "help": ["-h", "--help"],
            "before": [],
            "after": [],
            "json": ["--json"],
        }

    def test_diff_parser_still_parses(self):
        args = _build_diff_parser().parse_args(["a.json", "b.json", "--json", "d.json"])
        assert (args.before, args.after, args.json) == ("a.json", "b.json", "d.json")

    def test_every_diff_argument_is_rendered(self):
        """Including the positionals, which the main renderer filters out."""
        rendered = render_cli_reference(build_parser())
        section = rendered.split(f"## {_docsgen.DIFF_HEADING}")[1]
        for expected in ("`before`", "`after`", "`--json FILE`"):
            assert expected in section, f"{expected} missing from the diff section"

    def test_diff_section_omits_the_help_action(self):
        rendered = render_cli_reference(build_parser())
        section = rendered.split(f"## {_docsgen.DIFF_HEADING}")[1]
        assert "`-h" not in section

    def test_diff_section_documents_the_exit_code(self):
        rendered = render_cli_reference(build_parser())
        section = rendered.split(f"## {_docsgen.DIFF_HEADING}")[1]
        assert "exit" in section.lower()


class TestEnvironmentVariableSection:
    """Thirteen env-var defaults were reachable only where a help string
    happened to mention one; seven were documented nowhere. The mapping is
    AST-derived from cli.py so it cannot drift the way a hand-written list did.
    """

    def test_every_environ_get_in_cli_is_associated_with_a_flag(self):
        pairs = _docsgen.env_var_flag_pairs()
        assert len(pairs) == _docsgen.count_environ_reads()
        assert all(var and flag.startswith("--") for var, flag in pairs)

    def test_the_indirect_constant_resolves(self):
        """--auth-token reads os.environ.get(AUTH_TOKEN_ENV), a module-level
        constant rather than a literal. A literal-only AST walk finds 13 of
        the 14 and silently drops the most important one.
        """
        assert ("MCP_AUTH_TOKEN", "--auth-token") in _docsgen.env_var_flag_pairs()

    def test_previously_undocumented_variables_now_appear(self):
        rendered = render_cli_reference(build_parser())
        section = rendered.split(f"## {_docsgen.ENV_HEADING}")[1]
        for var in (
            "MCP_DPOP_PROOF",
            "MCP_INTROSPECT_CLIENT_ID",
            "MCP_INTROSPECT_CLIENT_SECRET",
            "MCP_INTROSPECT_URL",
            "MCP_JWKS_URL",
            "MCP_OIDC_SCOPE",
            "MCP_OIDC_URL",
        ):
            assert f"`{var}`" in section, f"{var} still undocumented"

    def test_each_variable_names_the_flag_it_backs(self):
        rendered = render_cli_reference(build_parser())
        section = rendered.split(f"## {_docsgen.ENV_HEADING}")[1]
        for var, flag in _docsgen.env_var_flag_pairs():
            assert f"| `{var}` | `{flag}` |" in section

    def test_the_flags_named_are_real_flags(self):
        """A stale AST association would name a flag that no longer exists."""
        declared = {o for a in build_parser()._actions for o in a.option_strings}
        unknown = [f for _, f in _docsgen.env_var_flag_pairs() if f not in declared]
        assert not unknown, f"env section names non-existent flags: {unknown}"


def _deep_probe_names() -> set[str]:
    """The probe names in `_build_deep_checks`'s plan, read from its source.

    Read statically rather than by calling the builder, because the builder
    returns the plan for one particular input. A probe added behind a condition
    would be missing from a stub call's plan, and a missing probe is precisely
    what the guard below exists to catch.
    """
    tree = ast.parse(Path(checks_pkg.__file__).read_text())
    builder = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_build_deep_checks"
    )
    return {
        entry.elts[0].value
        for node in ast.walk(builder)
        if isinstance(node, ast.List)
        for entry in node.elts
        if isinstance(entry, ast.Tuple)
        and entry.elts
        and isinstance(entry.elts[0], ast.Constant)
        and isinstance(entry.elts[0].value, str)
    }


class TestChecksDocumented:
    """docs/checks.md is written by hand, so only its completeness is testable.

    That is the property worth guarding: inference_guardrail_variance and the
    three DPoP findings all ran in production scans while appearing in no
    document, which is the failure this test makes loud.

    Severities and detection prose cannot be derived from source and are not
    tested — they are verified by hand against the emitting `result.add(...)`.
    """

    def _registry_names(self) -> set[str]:
        import mcpnuke.checks as checks

        names: set[str] = set()
        for key, value in vars(checks).items():
            if key.endswith("_CHECK_NAMES") and isinstance(value, tuple):
                names.update(value)
        return names

    def test_registry_is_not_empty(self):
        """A renamed tuple suffix would empty the set and pass everything."""
        assert len(self._registry_names()) > 50

    def test_every_registered_check_is_documented(self):
        doc = _docsgen.CHECKS_PATH.read_text()
        missing = sorted(n for n in self._registry_names() if f"`{n}`" not in doc)
        assert not missing, (
            f"{len(missing)} checks run but are undocumented in docs/checks.md: {missing}"
        )

    def test_deep_probe_parse_agrees_with_the_built_plan(self):
        """The AST walk must lose nothing the builder actually emits.

        A reshaped plan — entries built by a helper call, or names composed at
        runtime — would quietly shrink the parsed set and let the guard below
        pass vacuously. Comparing against a real plan makes that loud.
        """
        result = TargetResult(url="http://t/mcp")
        plan, _ = _build_deep_checks(None, result, {}, fast_mode=False)
        built = {name for name, *_ in plan}

        assert len(built) > 20, f"expected the full deep suite, got {len(built)}"
        assert _deep_probe_names() == built

    def test_every_deep_probe_is_documented(self):
        """Deep probes are a plan, not a registry, so the tuple walk misses them.

        They are two thirds of what a default scan actually does, including
        ssrf_probe and sdk_cache_poisoning.
        """
        doc = _docsgen.CHECKS_PATH.read_text()
        missing = sorted(n for n in _deep_probe_names() if f"`{n}`" not in doc)
        assert not missing, (
            f"{len(missing)} deep probes run but are undocumented in "
            f"docs/checks.md: {missing}"
        )

    def test_dpop_findings_are_documented(self):
        """Probe labels and the finding names users actually see both appear.

        The registry holds the time_check labels (dpop_no_header, ...); a report
        shows the finding names. Documenting only one half leaves whoever is
        reading a finding with nothing to search for.
        """
        doc = _docsgen.CHECKS_PATH.read_text()
        for name in (
            "dpop_not_enforced",
            "dpop_header_not_validated",
            "dpop_binding_not_enforced",
        ):
            assert f"`{name}`" in doc
