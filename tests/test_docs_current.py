"""Reference docs are derived from source, so they cannot drift from it."""
from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path

from mcpnuke import _docsgen
from mcpnuke import checks as checks_pkg
from mcpnuke.__main__ import _build_diff_parser
from mcpnuke._docsgen import render_cli_reference
from mcpnuke.checks import FAST_SKIP_CHECKS, _build_deep_checks
from mcpnuke.cli import build_parser, parse_args
from mcpnuke.core.constants import ATTACK_CHAIN_PATTERNS
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


def _fast_help() -> str:
    action = next(a for a in build_parser()._actions if "--fast" in a.option_strings)
    return action.help or ""


# The parenthesised probe list inside --fast's help, e.g. "skip heavy probes
# (a, b, c)". A reworded help string that loses the list yields no match, and
# the empty set fails the comparison rather than passing vacuously.
_FAST_PROBE_LIST = re.compile(r"probes \(([^)]*)\)")


class TestFastSkipHelp:
    """--help must match the code, not just the document match --help.

    Generating docs/cli-reference.md from the parser closed the gap between the
    document and `--help`. It says nothing about the gap between `--help` and
    behaviour, and that one was open: the help string named four skipped probes
    while FAST_SKIP_CHECKS held five, having gained sdk_cache_poisoning. The
    generator reproduced the wrong four faithfully, and the generated document
    contradicted the hand-written docs/checks.md, which had it right.
    """

    def _named_probes(self) -> set[str]:
        match = _FAST_PROBE_LIST.search(_fast_help())
        if not match:
            return set()
        return {part.strip() for part in match.group(1).split(",") if part.strip()}

    def test_the_probe_list_is_parseable(self):
        """An unparseable help string would make the comparison below vacuous
        in the direction that matters least — say so separately."""
        assert self._named_probes(), f"no probe list found in: {_fast_help()!r}"

    def test_help_names_exactly_the_skipped_checks(self):
        assert self._named_probes() == FAST_SKIP_CHECKS

    def test_the_generated_document_carries_the_same_list(self):
        """The rendered row is the copy operators read; assert on it directly
        rather than trusting that regeneration happened."""
        rendered = render_cli_reference(build_parser())
        row = next(ln for ln in rendered.splitlines() if ln.startswith("| `--fast`"))
        for name in FAST_SKIP_CHECKS:
            assert name in row, f"{name} missing from the rendered --fast row"


# A chain row, e.g. "| `ssrf_probe → token_theft` | ... |". Scoped to the
# section below so the worked example in the surrounding prose cannot stand in
# for a missing row.
_CHAIN_ROW = re.compile(r"^\| `([a-z0-9_]+) → ([a-z0-9_]+)` \|", re.M)
_CHAIN_HEADING = "## Attack Chain Detection"


class TestAttackChainsDocumented:
    """ATTACK_CHAIN_PATTERNS is a module-level list of tuples — machine
    readable, and documented by hand anyway. The table sat at 18 of 34 entries,
    missing all three JWT chains and both halves of ssrf_probe and
    actuator_probe, with nothing to notice.
    """

    def _documented(self) -> set[tuple[str, str]]:
        text = (_docsgen.REPO_ROOT / "docs" / "methodology.md").read_text()
        section = text.split(_CHAIN_HEADING)[1].split("\n## ")[0]
        return set(_CHAIN_ROW.findall(section))

    def test_the_section_is_found(self):
        """A renamed heading would empty the parse and fail the comparison for
        the wrong reason."""
        text = (_docsgen.REPO_ROOT / "docs" / "methodology.md").read_text()
        assert text.count(_CHAIN_HEADING) == 1

    def test_the_documented_chains_are_exactly_the_coded_ones(self):
        documented = self._documented()
        coded = set(ATTACK_CHAIN_PATTERNS)
        assert documented == coded, (
            f"undocumented chains: {sorted(coded - documented)}; "
            f"documented but not detected: {sorted(documented - coded)}"
        )

    def test_the_constant_has_no_duplicate_pairs(self):
        """The comparison above is set-to-set, so a duplicated tuple would be
        invisible to it while inflating every count taken off the list."""
        dupes = {p for p in ATTACK_CHAIN_PATTERNS if ATTACK_CHAIN_PATTERNS.count(p) > 1}
        assert not dupes, f"duplicated in ATTACK_CHAIN_PATTERNS: {sorted(dupes)}"


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


def _registry_check_names() -> set[str]:
    """Every name in the `*_CHECK_NAMES` inventory tables in mcpnuke.checks."""
    names: set[str] = set()
    for key, value in vars(checks_pkg).items():
        if key.endswith("_CHECK_NAMES") and isinstance(value, tuple):
            names.update(value)
    return names


def _documented_row_names() -> set[str]:
    """The leading backticked token of every table row in docs/checks.md.

    Row-scoped rather than a sweep for backticks, because the prose is full of
    `--fast`, `tools/list`, `result.add(...)` and file paths. The rows are
    where the doc makes a claim about a specific check.
    """
    return set(re.findall(r"^\| `([a-z0-9_]+)`", _docsgen.CHECKS_PATH.read_text(), re.M))


# Row names in docs/checks.md that are deliberately not registered checks.
# The doc names what a reader sees in a *report* as well as what the progress
# counter shows, and those are two vocabularies: a check emits findings under
# names of its own. Every entry here is one of those, or the one thing that is
# not a check at all.
_DOCUMENTED_NON_CHECKS: frozenset[str] = frozenset({
    # Emitted by the enumerator while connecting, not by any check, so it
    # reaches reports with no entry in the check inventory at all.
    "auth",
    # Emitted by tool_response_injection in the same pass, under its own name.
    "cross_tool_manipulation",
    # The three findings of the dpop_no_header / dpop_malformed /
    # dpop_missing_binding probes. Documenting only the probe labels leaves
    # whoever is reading a finding with nothing to search for.
    "dpop_not_enforced",
    "dpop_header_not_validated",
    "dpop_binding_not_enforced",
    # The four findings of the single `inference_backend` check.
    "inference_model_enum",
    "inference_no_auth",
    "inference_mgmt_exposed",
    "inference_network_exposed",
    # The four findings of the single `model_integrity` check.
    "model_tampered",
    "model_removed",
    "model_injected",
    "model_size_drift",
    # actuator_probe's second finding, emitted once discovery finds a live
    # actuator and the write probes are attempted.
    "actuator_exploitation",
})


class TestChecksDocumented:
    """docs/checks.md is written by hand, so only its completeness is testable.

    That is the property worth guarding: inference_guardrail_variance and the
    three DPoP findings all ran in production scans while appearing in no
    document, which is the failure this test makes loud.

    Severities and detection prose cannot be derived from source and are not
    tested — they are verified by hand against the emitting `result.add(...)`.
    """

    def _registry_names(self) -> set[str]:
        return _registry_check_names()

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

    def test_every_documented_row_is_something_that_exists(self):
        """The converse of the two tests above, which only push names *in*.

        Renaming a check adds a row for the new name and leaves the old row
        behind forever: nothing reads it, nothing contradicts it, and the next
        reader trusts it. This is the direction that catches that.
        """
        known = _registry_check_names() | _deep_probe_names() | _DOCUMENTED_NON_CHECKS
        stale = sorted(_documented_row_names() - known)
        assert not stale, (
            f"{len(stale)} rows in docs/checks.md name nothing that runs: {stale}. "
            "If one is a finding name rather than a check name, add it to "
            "_DOCUMENTED_NON_CHECKS with the check that emits it."
        )

    def test_the_row_sweep_finds_the_tables(self):
        """An over-tight row regex would empty the set and excuse everything."""
        assert len(_documented_row_names()) > 50

    def test_no_allowlist_entry_is_stale(self):
        """An excused name that no longer appears is an excuse for nothing —
        and after a rename it is the residue of exactly the row this guard
        exists to catch."""
        absent = sorted(_DOCUMENTED_NON_CHECKS - _documented_row_names())
        assert not absent, f"_DOCUMENTED_NON_CHECKS excuses absent rows: {absent}"

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


class TestProseCounts:
    """Three hardcoded totals, in two documents, both of them computable.

    Adding a check is the most common change to this codebase, and it makes all
    three wrong at once with a green suite. The sentences are matched by shape
    rather than in full, so a rewording fails as "sentence not found" instead of
    as a wrong number — re-pin it, do not delete the guard.
    """

    def _readme(self) -> str:
        return (_docsgen.REPO_ROOT / "README.md").read_text()

    def test_the_two_populations_do_not_overlap(self):
        """The prose adds the registry to the deep plan. That is only the count
        of distinct checks while nothing is in both."""
        both = _registry_check_names() & _deep_probe_names()
        assert not both, f"counted twice by the prose total: {sorted(both)}"

    def test_readme_states_the_real_total(self):
        expected = len(_registry_check_names() | _deep_probe_names())
        match = re.search(r"runs (\d+) checks", self._readme())
        assert match, "README no longer states a check total in the expected shape"
        assert int(match.group(1)) == expected

    def test_checks_doc_states_the_real_breakdown(self):
        doc = _docsgen.CHECKS_PATH.read_text()
        registry, deep = _registry_check_names(), _deep_probe_names()

        totals = re.search(r"(\d+) checks in total: (\d+) in the check inventory", doc)
        assert totals, "docs/checks.md no longer states the breakdown in the expected shape"
        assert int(totals.group(1)) == len(registry | deep)
        assert int(totals.group(2)) == len(registry)

        probes = re.search(r"the (\d+) deep behavioral probes", doc)
        assert probes, "docs/checks.md no longer states the deep probe count"
        assert int(probes.group(1)) == len(deep)


class TestNoRetiredModelIds:
    """Model ids rot on the provider's schedule, not ours.

    `claude-sonnet-4-20250514` was retired and
    `anthropic.claude-3-5-sonnet-20241022-v2:0` reached end of life while both
    were still named as defaults across code and prose. Verified against
    `GET /v1/models` and `bedrock list-foundation-models`; add an id here when
    a provider drops one.
    """

    # Files whose job is to describe the retirement, and so must name it.
    _MAY_NAME_RETIRED = frozenset({
        "CHANGELOG.md",              # history
        "constants.py",              # comment explaining why the default moved
        "test_claude_model_default.py",
        "test_docs_current.py",      # this file
    })

    # Prose is not the only place an id hides: demo_ai.sh sets MODEL= and
    # workflows pin flags, and a markdown-only sweep would never see either.
    _SWEPT_SUFFIXES = frozenset({".md", ".py", ".sh", ".yml", ".yaml", ".json", ".toml"})

    RETIRED: frozenset[str] = frozenset({
        "claude-sonnet-4-20250514",
        "claude-opus-4-20250514",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "claude-3-5-sonnet-20241022",
    })

    def _swept(self) -> list[Path]:
        """Tracked files only.

        Scoping by directory instead would mean chasing every tool cache:
        .mypy_cache alone vendors the Anthropic SDK's type stubs, which name
        every model the SDK has ever known.
        """
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=_docsgen.REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return [
            _docsgen.REPO_ROOT / rel
            for rel in out.stdout.split("\0")
            if rel
            and Path(rel).suffix in self._SWEPT_SUFFIXES
            and not (_SKIPPED_PARTS & set(Path(rel).parts))
            and Path(rel).name not in self._MAY_NAME_RETIRED
        ]

    def test_nothing_names_a_retired_model(self) -> None:
        offenders: list[str] = []
        for path in self._swept():
            text = path.read_text(errors="ignore")
            for dead in self.RETIRED:
                if dead in text:
                    offenders.append(f"{path.relative_to(_docsgen.REPO_ROOT)}: {dead}")
        assert not offenders, f"retired model ids still present: {offenders}"

    def test_the_shipped_defaults_are_not_retired(self) -> None:
        from mcpnuke.core.constants import DEFAULT_BEDROCK_MODEL, DEFAULT_CLAUDE_MODEL

        assert DEFAULT_CLAUDE_MODEL not in self.RETIRED
        assert DEFAULT_BEDROCK_MODEL not in self.RETIRED

    def test_the_sweep_reaches_prose_code_and_harnesses(self) -> None:
        """Vacuity guard: an over-broad skip list would pass trivially, and a
        markdown-only sweep is how demo_ai.sh went unwatched."""
        names = {p.name for p in self._swept()}
        assert {"README.md", "ai-analysis.md", "cli-reference.md"} <= names
        assert "demo_ai.sh" in names, "shell harnesses are not being swept"
        assert "cli.py" in names, "source is not being swept"

    def test_the_exemptions_are_all_real_files(self) -> None:
        """A renamed exemption silently widens into a hole."""
        present = {p.name for p in _docsgen.REPO_ROOT.rglob("*") if p.is_file()}
        assert present >= self._MAY_NAME_RETIRED


MD_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")

# Vendored, generated and tool-owned trees. `1/` is a stray virtualenv created
# by a mistyped redirect; DVMCP is a third-party checkout under tests/.
_SKIPPED_PARTS = frozenset(
    {"test_targets", "superpowers", ".venv", "1", ".pytest_cache", ".cursor"}
)


class TestDocLinks:
    """Splitting one document into six turns every relative link into a
    liability: `(docs/checks.md)` is correct in the README and wrong the moment
    the line holding it moves into docs/. Nothing else in the suite reads a
    link, so a move that silently breaks navigation stays green.
    """

    def _markdown_files(self) -> list[Path]:
        return [
            p
            for p in _docsgen.REPO_ROOT.rglob("*.md")
            if _SKIPPED_PARTS.isdisjoint(p.parts)
        ]

    def test_the_file_sweep_finds_the_project_documents(self):
        """An over-broad exclusion would empty the sweep and pass vacuously."""
        swept = {p.name for p in self._markdown_files()}
        assert {"README.md", "QUICKSTART.md", "checks.md"} <= swept

    def test_relative_links_resolve(self):
        broken: list[str] = []
        for path in self._markdown_files():
            for target in MD_LINK.findall(path.read_text()):
                if target.startswith(("http://", "https://", "#", "mailto:")):
                    continue
                resolved = (path.parent / target.split("#")[0]).resolve()
                if not resolved.exists():
                    broken.append(f"{path.relative_to(_docsgen.REPO_ROOT)} -> {target}")
        assert not broken, f"broken relative links: {broken}"

    def _fragment_links(self) -> list[tuple[Path, str, Path, str]]:
        """Every link carrying a `#fragment`, with the document it lands in.

        A bare `#anchor` lands in the file that wrote it; `other.md#anchor`
        lands in the other file. Targets that are not markdown have no headings
        to name and are dropped — their existence is the other test's job.
        """
        found: list[tuple[Path, str, Path, str]] = []
        for path in self._markdown_files():
            for target in MD_LINK.findall(path.read_text()):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                file_part, _, fragment = target.partition("#")
                if not fragment:
                    continue
                landing = (path.parent / file_part).resolve() if file_part else path
                if landing.suffix == ".md" and landing.is_file():
                    found.append((path, target, landing, fragment))
        return found

    def test_the_sweep_finds_fragment_links(self):
        """Every table of contents is built out of these, so an empty sweep
        means the extraction broke, not that nobody deep-links."""
        assert len(self._fragment_links()) >= 10

    def test_link_fragments_name_real_headings(self):
        """The fragment used to be split off and discarded, so
        `docs/checks.md#no-such-heading` passed on the strength of the file
        existing. Splitting one document into six makes a deep link into
        another document the natural thing to write, and the first one would
        have gone unchecked.
        """
        broken = [
            f"{path.relative_to(_docsgen.REPO_ROOT)} -> {target}"
            for path, target, landing, fragment in self._fragment_links()
            if fragment not in _heading_anchors(landing.read_text())
        ]
        assert not broken, f"links to headings that do not exist: {broken}"

    def test_expected_docs_exist(self):
        for name in (
            "cli-reference.md",
            "checks.md",
            "scan-modes.md",
            "ai-analysis.md",
            "kubernetes.md",
            "methodology.md",
            "spec-surface.md",
        ):
            assert (_docsgen.REPO_ROOT / "docs" / name).is_file(), f"docs/{name} missing"

    def test_spec_surface_is_the_speak_scan_ready_map(self):
        """A stub that exists would satisfy the row above and hide a deleted map.

        The five area headings are the MCP 2026-08-22 roadmap. The two Ready
        rows are current-spec gaps we can probe without guessing a SEP; if they
        vanish the later-build queue has nowhere to start.
        """
        text = (_docsgen.REPO_ROOT / "docs" / "spec-surface.md").read_text()
        for heading in (
            "Agentic messaging primitives",
            "HTTP-native transport unification and hardening",
            "Agent identity and enterprise-ready security",
            "Improved primitives",
            "Improved SDK developer experience",
        ):
            assert heading in text, f"missing area: {heading}"
        for column in ("Speak", "Scan", "Ready"):
            assert f"**{column}**" in text or f"| {column} |" in text, (
                f"spec-surface.md lost the {column} column"
            )
        assert "ttlMs" in text and "cacheScope" in text
        assert "structuredContent" in text


def _heading_anchors(text: str) -> set[str]:
    """The anchor GitHub generates for every `##`/`###` heading.

    Lowercase, drop everything that is not alphanumeric, space or hyphen, then
    hyphenate the spaces. A dropped `&` leaves the spaces on both sides of it,
    so `Identity Lanes & Transports` anchors as `identity-lanes--transports` —
    the intuitive single-hyphen form links nowhere.
    """
    return {
        re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
        for heading in re.findall(r"^#{2,3} (.+)$", text, re.M)
    }


def _toc_anchors(text: str) -> list[str]:
    """In-page anchors linked from the `## Contents` block, in order.

    Scoped to the block so a working anchor elsewhere in the document cannot
    stand in for a broken one in the table of contents.
    """
    toc = text.split("## Contents")[1].split("\n## ")[0]
    return re.findall(r"\]\(#([a-z0-9-]+)\)", toc)


# Headings the README's Contents block deliberately does not list. The reverse
# guard below was originally not applied here at all, on the reasoning that a
# handoff section need not be indexed — and the two sections that fell out,
# CLI Reference and Kubernetes Deployment, were handoffs. They are now listed;
# an entry here is a decision someone recorded, not a section that slipped.
_README_TOC_EXEMPT: frozenset[str] = frozenset({
    # An h3 under How It Works, which is listed. Indexing a section's own
    # subsections in a six-item Contents block costs more than it finds.
    "scan-phases",
})


class TestReadmeShape:
    """Navigation and length, the two things that made the 1018-line README
    unusable. Anchors are derived from the headings rather than listed, so
    renaming a section is caught rather than silently orphaning a link.
    """

    def _readme(self) -> str:
        return (_docsgen.REPO_ROOT / "README.md").read_text()

    def test_has_a_table_of_contents(self):
        assert "## Contents" in self._readme()

    def test_toc_anchors_match_real_headings(self):
        text = self._readme()
        headings = _heading_anchors(text)
        missing = [a for a in _toc_anchors(text) if a not in headings]
        assert not missing, f"TOC anchors with no heading: {missing}"

    def test_the_toc_actually_links_somewhere(self):
        """A Contents block holding no in-page anchors satisfies the check
        above vacuously."""
        assert len(_toc_anchors(self._readme())) >= 5

    def test_there_is_one_document_index(self):
        """Two lists of documents in one README is the duplication this
        restructure exists to remove: they disagree the first time a document
        is added to one of them. `## Contents` is the only index."""
        text = self._readme()
        assert text.count("## Contents") == 1
        assert "## Documentation Hub" not in text

    def test_the_toc_reaches_every_section(self):
        """The forward check only proves every listed anchor exists. Two
        sections were reachable only by scrolling, and one of them —
        Exit Code's neighbour, CLI Reference — is where QUICKSTART.md sends
        readers. An unlisted section is either a bug or an exemption.
        """
        text = self._readme()
        listed = set(_toc_anchors(text))
        unreachable = sorted(
            _heading_anchors(text) - listed - {"contents"} - _README_TOC_EXEMPT
        )
        assert not unreachable, (
            f"sections missing from the README's Contents: {unreachable}. "
            "List them, or add them to _README_TOC_EXEMPT with a reason."
        )

    def test_no_toc_exemption_is_stale(self):
        """An exemption for a heading that no longer exists excuses nothing
        and hides the next rename."""
        gone = sorted(_README_TOC_EXEMPT - _heading_anchors(self._readme()))
        assert not gone, f"_README_TOC_EXEMPT names absent headings: {gone}"

    def test_stays_navigable(self):
        n = len(self._readme().splitlines())
        assert n < 400, f"README is {n} lines; reference belongs in docs/"


class TestChecksDocShape:
    """234 lines and nine headings, arrived at mid-file by search. The same
    anchor rule applies, and `Token & Identity` and `Teleport / Machine
    Identity` both hit the double-hyphen case."""

    def _checks(self) -> str:
        return _docsgen.CHECKS_PATH.read_text()

    def test_has_a_table_of_contents(self):
        assert "## Contents" in self._checks()

    def test_toc_anchors_match_real_headings(self):
        text = self._checks()
        headings = _heading_anchors(text)
        missing = [a for a in _toc_anchors(text) if a not in headings]
        assert not missing, f"TOC anchors with no heading: {missing}"

    def test_the_toc_reaches_every_section(self):
        """Unlike the README, nothing here is a handoff — every heading holds
        a table, so an unlisted one is unreachable from the top of the file."""
        text = self._checks()
        listed = set(_toc_anchors(text))
        unreachable = sorted(_heading_anchors(text) - listed - {"contents"})
        assert not unreachable, f"sections missing from the TOC: {unreachable}"


class TestChainReplayDocsCurrency:
    """Prose for Phase 4 / OAST / safe-mode must name the behaviours we ship.

    cli-reference.md is generated from argparse help; ai-analysis.md is curated.
    Both drifted once already when await_hits and webhook sinks landed.
    """

    def test_cli_help_describes_graded_chain_replay(self) -> None:
        help_text = " ".join(
            a.help or ""
            for a in build_parser()._actions
            if "--chain-replay" in (a.option_strings or [])
            and a.option_strings == ["--chain-replay"]
        )
        lowered = help_text.lower()
        assert "medium" in lowered
        assert "critical" in lowered
        assert "out-of-band" in lowered or "oast" in lowered or "egress" in lowered

    def test_cli_help_names_webhook_and_egress_under_safe_mode(self) -> None:
        help_text = next(
            a.help or ""
            for a in build_parser()._actions
            if "--safe-mode" in (a.option_strings or [])
        ).lower()
        assert "webhook" in help_text
        assert "egress" in help_text or "exfil" in help_text

    def test_ai_analysis_documents_oast_await_and_fetch_guidance(self) -> None:
        text = (_docsgen.REPO_ROOT / "docs" / "ai-analysis.md").read_text().lower()
        assert "await" in text or "grace" in text
        assert "{{oast.url}}" in text or "oast.url" in text
        assert "fetch" in text or "send-now" in text or "immediate" in text
        assert "revis" in text  # revise / retry visibility
        assert "priority actions" in text

    def test_checks_doc_mentions_oast_for_exfil_flow(self) -> None:
        text = (_docsgen.REPO_ROOT / "docs" / "checks.md").read_text().lower()
        row = next(
            (line for line in text.splitlines() if "| `exfil_flow`" in line or "| exfil_flow |" in line),
            "",
        )
        assert row, "exfil_flow row missing from docs/checks.md"
        assert "oast" in row or "out-of-band" in row

    def test_quickstart_documents_proved_chain_policy_hops(self) -> None:
        text = (_docsgen.REPO_ROOT / "QUICKSTART.md").read_text().lower()
        assert "proved chain sink" in text or "deny on the sink" in text
        assert "hold" in text and "source" in text
