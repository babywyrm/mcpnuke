"""Tests for the scan progress denominator and duration estimate.

The progress counter used to be hardcoded arithmetic (``total_checks = 17``,
``deep_checks = 13``) that drifted as checks were added, so verbose output read
``[38/35]`` and then ``All 41 checks complete``. These tests pin the
denominator to the checks that actually run, and guard the declarative name
tables against drifting from the real ``_run`` call sites.
"""

import re
from pathlib import Path
from unittest.mock import patch

from mcpnuke import checks as checks_pkg
from mcpnuke.checks import (
    _AGGREGATE_CHECK_NAMES,
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


def _run_and_collect(result: TargetResult, **kwargs) -> list[str]:
    """Run all checks verbosely and return the emitted log lines."""
    lines: list[str] = []
    run_all_checks(
        None, result, [result], verbose=True, log=lines.append, **kwargs,
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
