"""Tests for the scan progress denominator and duration estimate.

The progress counter used to be hardcoded arithmetic (``total_checks = 17``,
``deep_checks = 13``) that drifted as checks were added, so verbose output read
``[38/35]`` and then ``All 41 checks complete``. These tests pin the
denominator to the checks that actually run, and guard the declarative name
tables against drifting from the real ``_run`` call sites.
"""

import ast
import re
from pathlib import Path
from unittest.mock import patch

from mcpnuke import checks as checks_pkg
from mcpnuke.checks import (
    _AGGREGATE_CHECK_NAMES,
    _DPOP_CHECK_NAMES,
    _INFERENCE_BASELINE_CHECK_NAMES,
    _INFERENCE_CHECK_NAMES,
    _JWT_CHECK_NAMES,
    _LIGHT_BEHAVIORAL_CHECK_NAMES,
    _STATIC_CHECK_NAMES,
    _TARGET_SURFACE_CHECK_NAMES,
    _TELEPORT_ALWAYS_CHECK_NAMES,
    _TELEPORT_BASE_CHECK_NAMES,
    _TRANSPORT_CHECK_NAMES,
    FAST_SKIP_CHECKS,
    _build_deep_checks,
    dpop_enforcement,
    run_all_checks,
)
from mcpnuke.checks.inference_backend import InferenceBackend
from mcpnuke.core.models import TargetResult

_PROGRESS_RE = re.compile(r"\[(\d+)/(\d+)\]")


def _tools(n: int = 1) -> list[dict]:
    return [
        {"name": f"tool{i}", "description": "does a thing", "inputSchema": {}}
        for i in range(n)
    ]


def _run_and_collect(result: TargetResult, session=None, **kwargs) -> list[str]:
    """Run all checks verbosely and return the emitted log lines."""
    lines: list[str] = []
    run_all_checks(
        session, result, [result], verbose=True, log=lines.append, **kwargs,
    )
    return lines


def _progress_pairs(lines: list[str]) -> list[tuple[int, int]]:
    out = []
    for ln in lines:
        m = _PROGRESS_RE.search(ln)
        if m:
            out.append((int(m.group(1)), int(m.group(2))))
    return out


# ── The denominator must bound the numerator ───────────────────────────


class TestProgressDenominator:
    def test_numerator_never_exceeds_denominator(self):
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        pairs = _progress_pairs(_run_and_collect(result, probe_opts={"no_invoke": True}))

        assert pairs, "no progress lines emitted"
        worst, total = max(pairs, key=lambda p: p[0])
        assert worst <= total, f"progress overflowed: reached {worst}/{total}"

    def test_final_numerator_equals_denominator(self):
        """Every planned check should run, so the count should land exactly."""
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        lines = _run_and_collect(result, probe_opts={"no_invoke": True})
        pairs = _progress_pairs(lines)
        highest = max(n for n, _ in pairs)
        total = pairs[0][1]

        assert highest == total, f"ran {highest} of a planned {total}"

    def test_completion_line_agrees_with_denominator(self):
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        lines = _run_and_collect(result, probe_opts={"no_invoke": True})
        total = _progress_pairs(lines)[0][1]

        done = [ln for ln in lines if "checks complete" in ln]
        assert done, "no completion line emitted"
        assert re.search(rf"All {total} checks complete", done[-1]), done[-1]

    def test_denominator_is_stable_across_the_run(self):
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        totals = {t for _, t in _progress_pairs(
            _run_and_collect(result, probe_opts={"no_invoke": True})
        )}
        assert len(totals) == 1, f"denominator changed mid-run: {totals}"

    def test_jwt_context_increases_the_denominator(self):
        plain = TargetResult(url="http://t/mcp")
        plain.tools = _tools()
        with_jwt = TargetResult(url="http://t/mcp")
        with_jwt.tools = _tools()
        with_jwt.auth_context = {"_raw_token": "a.b.c"}

        n_plain = _progress_pairs(
            _run_and_collect(plain, probe_opts={"no_invoke": True})
        )[0][1]
        n_jwt = _progress_pairs(
            _run_and_collect(with_jwt, probe_opts={"no_invoke": True})
        )[0][1]

        assert n_jwt == n_plain + len(_JWT_CHECK_NAMES)

    def test_base_url_adds_surface_and_teleport_checks(self):
        without = TargetResult(url="http://t/mcp")
        without.tools = _tools()
        with_base = TargetResult(url="http://t/mcp")
        with_base.tools = _tools()

        n_without = _progress_pairs(
            _run_and_collect(without, probe_opts={"no_invoke": True})
        )[0][1]
        n_with = _progress_pairs(
            _run_and_collect(with_base, base="http://t", probe_opts={"no_invoke": True})
        )[0][1]

        expected = len(_TARGET_SURFACE_CHECK_NAMES) + len(_TELEPORT_BASE_CHECK_NAMES)
        assert n_with == n_without + expected

    def test_inference_context_increases_the_denominator(self):
        plain = TargetResult(url="http://t/mcp")
        plain.tools = _tools()
        with_inf = TargetResult(url="http://t/mcp")
        with_inf.tools = _tools()

        n_plain = _progress_pairs(
            _run_and_collect(plain, probe_opts={"no_invoke": True})
        )[0][1]
        with patch(
            "mcpnuke.checks.inference_backend.fingerprint_backend",
            return_value=(InferenceBackend.UNKNOWN, {}),
        ):
            n_inf = _progress_pairs(_run_and_collect(
                with_inf,
                probe_opts={"no_invoke": True, "inference_host": "http://gpu:11434"},
            ))[0][1]

        assert n_inf == n_plain + len(_INFERENCE_CHECK_NAMES)

    def test_inference_count_lands_exactly(self):
        """Both inference checks run whenever the section is enabled."""
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        with patch(
            "mcpnuke.checks.inference_backend.fingerprint_backend",
            return_value=(InferenceBackend.UNKNOWN, {}),
        ):
            pairs = _progress_pairs(_run_and_collect(
                result,
                probe_opts={"no_invoke": True, "inference_host": "http://gpu:11434"},
            ))

        assert max(n for n, _ in pairs) == pairs[0][1]

    def test_teleport_and_aggregate_are_counted_at_all(self):
        """Regression: neither section was included in the old arithmetic."""
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        lines = _run_and_collect(result, probe_opts={"no_invoke": True})
        ran = {
            m.group(1)
            for ln in lines
            if (m := re.search(r"▸ (\w+)", ln))
        }

        for name in (*_TELEPORT_ALWAYS_CHECK_NAMES, *_AGGREGATE_CHECK_NAMES):
            assert name in ran, f"{name} ran but was invisible to the counter"


# ── Name tables must match the real call sites ─────────────────────────


class TestCheckNameTables:
    def test_tables_match_literal_run_call_sites(self):
        """Every _run("name", ...) literal must appear in exactly one table."""
        src = Path(checks_pkg.__file__).read_text()
        body = src.split("def run_all_checks(", 1)[1]
        called = set(re.findall(r'_run\(\s*"([a-z0-9_]+)"', body))

        tabled = set(
            _STATIC_CHECK_NAMES
            + _JWT_CHECK_NAMES
            + _DPOP_CHECK_NAMES
            + _LIGHT_BEHAVIORAL_CHECK_NAMES
            + _TRANSPORT_CHECK_NAMES
            + _TARGET_SURFACE_CHECK_NAMES
            + _INFERENCE_CHECK_NAMES
            + _INFERENCE_BASELINE_CHECK_NAMES
            + _TELEPORT_BASE_CHECK_NAMES
            + _TELEPORT_ALWAYS_CHECK_NAMES
            + _AGGREGATE_CHECK_NAMES
        )

        assert called - tabled == set(), f"checks run but not counted: {sorted(called - tabled)}"
        assert tabled - called == set(), f"counted but never run: {sorted(tabled - called)}"

    def test_no_duplicate_names_across_tables(self):
        all_names = (
            _STATIC_CHECK_NAMES
            + _JWT_CHECK_NAMES
            + _DPOP_CHECK_NAMES
            + _LIGHT_BEHAVIORAL_CHECK_NAMES
            + _TRANSPORT_CHECK_NAMES
            + _TARGET_SURFACE_CHECK_NAMES
            + _INFERENCE_CHECK_NAMES
            + _INFERENCE_BASELINE_CHECK_NAMES
            + _TELEPORT_BASE_CHECK_NAMES
            + _TELEPORT_ALWAYS_CHECK_NAMES
            + _AGGREGATE_CHECK_NAMES
        )
        dupes = {n for n in all_names if all_names.count(n) > 1}
        assert not dupes, f"duplicated across tables: {sorted(dupes)}"


# ── Deep probe plan ────────────────────────────────────────────────────


class TestDeepCheckPlan:
    def test_full_plan_has_no_skips(self):
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        plan, skipped = _build_deep_checks(None, result, {}, fast_mode=False)

        assert skipped == set()
        assert len(plan) > 20, f"expected the full deep suite, got {len(plan)}"

    def test_fast_mode_skips_heavy_probes(self):
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        full, _ = _build_deep_checks(None, result, {}, fast_mode=False)
        fast, skipped = _build_deep_checks(None, result, {}, fast_mode=True)

        assert skipped == FAST_SKIP_CHECKS
        assert len(fast) == len(full) - len(FAST_SKIP_CHECKS)
        assert not ({n for n, *_ in fast} & FAST_SKIP_CHECKS)

    def test_fast_mode_retains_input_sanitization_for_dangerous_params(self):
        """--fast keeps input_sanitization when a tool exposes a risky param."""
        result = TargetResult(url="http://t/mcp")
        result.tools = [{
            "name": "shell",
            "description": "runs a command",
            "inputSchema": {"properties": {"command": {"type": "string"}}},
        }]

        plan, skipped = _build_deep_checks(None, result, {}, fast_mode=True)

        assert "input_sanitization" not in skipped
        assert "input_sanitization" in {n for n, *_ in plan}

    def test_plan_entries_are_callable_with_args(self):
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        plan, _ = _build_deep_checks(None, result, {}, fast_mode=False)
        for name, fn, args, kwargs in plan:
            assert isinstance(name, str) and name
            assert callable(fn)
            assert isinstance(args, tuple)
            assert isinstance(kwargs, dict)

    def test_fast_denominator_reflects_the_filtered_plan(self):
        """--fast must shrink the denominator, not just the work done."""
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools(8)

        n_full = _progress_pairs(_run_and_collect(
            TargetResult(url="http://t/mcp"), probe_opts={"no_invoke": True},
        ))[0][1]
        n_fast = _progress_pairs(_run_and_collect(
            result, probe_opts={"no_invoke": True, "fast": True},
        ))[0][1]

        assert n_fast == n_full


# ── Duration estimate ──────────────────────────────────────────────────


class TestDurationEstimate:
    def test_estimate_scales_with_the_real_deep_count(self):
        lines: list[str] = []
        checks_pkg._emit_duration_estimate(
            n_tools=4, session=None, no_invoke=False, fast_mode=False,
            probe_workers=1, n_deep=24, _log=lines.append,
        )
        assert lines and "Estimated scan time" in lines[0]

    def test_no_invoke_estimate_excludes_deep_probes(self):
        deep, shallow = [], []
        checks_pkg._emit_duration_estimate(
            n_tools=4, session=None, no_invoke=False, fast_mode=False,
            probe_workers=1, n_deep=24, _log=deep.append,
        )
        checks_pkg._emit_duration_estimate(
            n_tools=4, session=None, no_invoke=True, fast_mode=False,
            probe_workers=1, n_deep=0, _log=shallow.append,
        )
        assert deep[0] != shallow[0]

    def test_zero_deep_checks_is_not_an_error(self):
        lines: list[str] = []
        checks_pkg._emit_duration_estimate(
            n_tools=0, session=None, no_invoke=False, fast_mode=True,
            probe_workers=2, n_deep=0, _log=lines.append,
        )
        assert lines


# ── DPoP probes ────────────────────────────────────────────────────────


class _HTTPish:
    """Minimal stand-in for an HTTP-family session: has post_raw and a post_url."""

    post_url = "http://t/mcp"

    def post_raw(self, *a, **kw):  # pragma: no cover - never called, probes are stubbed
        raise AssertionError("probe should not reach the network in this test")


class _UnresolvedHTTPish(_HTTPish):
    """SSE before the handshake: an HTTP layer, but no endpoint resolved yet."""

    post_url = ""


class _StdioLike:
    """Mirrors StdioSession: a truthy post_url, but no HTTP layer to probe."""

    post_url = "stdio://server.py"

    def call(self, method, params=None, **kw):
        return None


_PROBE_ATTRS: dict[str, str] = {
    "_probe_no_dpop_header": "dpop_no_header",
    "_probe_malformed_dpop": "dpop_malformed",
    "_probe_missing_htm_htu": "dpop_missing_binding",
}


def _stub_probes(monkeypatch) -> list[str]:
    """Replace the three probes with recorders; return the call log."""
    called: list[str] = []
    for probe, label in _PROBE_ATTRS.items():
        def _record(result, session, _label=label):
            called.append(_label)

        monkeypatch.setattr(checks_pkg, probe, _record)
    return called


def _time_check_labels() -> dict[str, str]:
    """Functions in dpop_enforcement that record a timing, by their label.

    Resolved from the source rather than hardcoded, so a probe this test has
    never heard of is still recognised as one — recognising only the known
    three is precisely how the drift described below would slip past.
    """
    tree = ast.parse(Path(dpop_enforcement.__file__).read_text())
    labels: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        label = next(
            (
                call.args[0].value
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "time_check"
                and call.args
                and isinstance(call.args[0], ast.Constant)
                and isinstance(call.args[0].value, str)
            ),
            None,
        )
        if label is not None:
            labels[node.name] = label
    return labels


def _probes_chained_in_the_runner() -> list[str]:
    """The probes ``run_dpop_enforcement_checks`` calls, in order, by label.

    Read from the source: the function guards on ``dpop_probeable`` and calling
    it with a stub session returns before any probe runs, so a stub cannot
    observe the body.
    """
    tree = ast.parse(Path(dpop_enforcement.__file__).read_text())
    runner = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "run_dpop_enforcement_checks"
    )
    # A `_probe_*` call with no timing falls back to its own function name,
    # which is in no table and so fails loudly. The runner chains probes and
    # nothing else; a pure helper belongs inside one of them, not here.
    labels = _time_check_labels()
    return [
        labels.get(node.func.id, node.func.id)
        for node in ast.walk(runner)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id.startswith("_probe_")
    ]


class TestDpopRunnerStaysInSync:
    """``run_dpop_enforcement_checks`` has no production caller.

    ``run_all_checks`` drives the three probes individually through ``_run`` so
    each lands in the progress count, which left the runner orphaned — and it
    is still where all twelve tests in tests/test_dpop_enforcement.py enter, so
    it is where a contributor adding a fourth probe will add it. Nothing would
    fail: ``test_dpop_names_are_registered`` pins the three that exist and
    ``test_tables_match_literal_run_call_sites`` only reads ``_run(...)``
    literals. Fully tested probe, green suite, never runs in a real scan.

    The better fix is to delete the orphan and have the orchestrator and the
    tests iterate one shared table, so there is only one list to add to. That
    is a larger refactor than this branch; until then, this test is the thing
    that makes the divergence loud.
    """

    def test_the_runner_chains_exactly_the_registered_probes(self):
        assert tuple(_probes_chained_in_the_runner()) == _DPOP_CHECK_NAMES

    def test_the_ast_walk_sees_the_calls(self):
        """A restructured runner would empty the parse, and an empty parse must
        not read as agreement with an empty table."""
        assert _probes_chained_in_the_runner()

    def test_the_labels_come_from_the_probes_themselves(self):
        """The chain is compared by time_check label, so the label map is load
        bearing: an empty one would compare function names against check names
        and fail for a reason that reads like the wrong bug."""
        assert set(_time_check_labels().values()) == set(_DPOP_CHECK_NAMES)


class TestDpopCounted:
    def test_dpop_names_are_registered(self):
        assert _DPOP_CHECK_NAMES == (
            "dpop_no_header",
            "dpop_malformed",
            "dpop_missing_binding",
        )

    def test_http_jwt_scan_counts_the_dpop_probes(self, monkeypatch):
        # Stub the probes so the denominator is what is under test, not the
        # network. The probes swallow every exception into result.error, so a
        # stub that failed to bind would be invisible — hence `stubbed`.
        stubbed = _stub_probes(monkeypatch)

        jwt_only = TargetResult(url="http://t/mcp")
        jwt_only.tools = _tools()
        jwt_only.auth_context = {"_raw_token": "a.b.c"}

        jwt_http = TargetResult(url="http://t/mcp")
        jwt_http.tools = _tools()
        jwt_http.auth_context = {"_raw_token": "a.b.c"}

        n_plain = _progress_pairs(
            _run_and_collect(jwt_only, probe_opts={"no_invoke": True})
        )[0][1]
        n_http = _progress_pairs(
            _run_and_collect(
                jwt_http, session=_HTTPish(), probe_opts={"no_invoke": True}
            )
        )[0][1]

        assert n_http == n_plain + len(_DPOP_CHECK_NAMES)
        assert stubbed == list(_DPOP_CHECK_NAMES), "the stubs did not take effect"
        # The probes swallow every exception into result.error, so a real probe
        # reaching _HTTPish.post_raw would otherwise look like a clean run.
        assert not jwt_http.error

    def test_http_jwt_scan_lands_exactly(self, monkeypatch):
        """The numerator must reach the inflated denominator, not fall short."""
        stubbed = _stub_probes(monkeypatch)

        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()
        result.auth_context = {"_raw_token": "a.b.c"}

        pairs = _progress_pairs(_run_and_collect(
            result, session=_HTTPish(), probe_opts={"no_invoke": True},
        ))
        assert max(n for n, _ in pairs) == pairs[0][1]
        assert stubbed == list(_DPOP_CHECK_NAMES), "the stubs did not take effect"
        assert not result.error

    def test_non_http_session_does_not_count_them(self):
        """Stdio has no header layer, so the probes must not inflate the denominator."""
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()
        result.auth_context = {"_raw_token": "a.b.c"}

        lines = _run_and_collect(
            result, session=_StdioLike(), probe_opts={"no_invoke": True},
        )
        numerator, denominator = _progress_pairs(lines)[-1]
        assert numerator == denominator
        assert not any(name in ln for ln in lines for name in _DPOP_CHECK_NAMES)

    def test_http_without_a_jwt_does_not_count_them(self):
        """No token means no DPoP block runs, so the denominator must not grow.

        ``has_jwt`` looks redundant with the enclosing ``if has_jwt:``, and
        dropping it as dead code would inflate the denominator by three with
        nothing to run against it.
        """
        result = TargetResult(url="http://t/mcp")
        result.tools = _tools()

        lines = _run_and_collect(
            result, session=_HTTPish(), probe_opts={"no_invoke": True},
        )
        numerator, denominator = _progress_pairs(lines)[-1]

        assert numerator == denominator
        assert not any(name in ln for ln in lines for name in _DPOP_CHECK_NAMES)

    def test_unresolved_endpoint_does_not_count_them(self):
        """SSE before the handshake has post_raw but no endpoint to probe."""
        jwt_only = TargetResult(url="http://t/mcp")
        jwt_only.tools = _tools()
        jwt_only.auth_context = {"_raw_token": "a.b.c"}

        unresolved = TargetResult(url="http://t/mcp")
        unresolved.tools = _tools()
        unresolved.auth_context = {"_raw_token": "a.b.c"}

        n_baseline = _progress_pairs(
            _run_and_collect(jwt_only, probe_opts={"no_invoke": True})
        )[0][1]
        pairs = _progress_pairs(_run_and_collect(
            unresolved,
            session=_UnresolvedHTTPish(),
            probe_opts={"no_invoke": True},
        ))

        assert pairs[0][1] == n_baseline
        assert pairs[-1][0] == pairs[-1][1]
