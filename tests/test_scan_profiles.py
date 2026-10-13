"""Scan profiles: named sets of flag defaults, applied without clobbering
anything the user set explicitly."""

from mcpnuke.cli import SCAN_PROFILES, _apply_profile, build_parser, parse_args


def test_a_profile_fills_a_value_the_user_left_unset() -> None:
    p = build_parser()
    args = p.parse_args(["--targets", "http://x"])
    _apply_profile(args, p, {"probe_calls": 99})
    assert args.probe_calls == 99


def test_an_explicit_flag_beats_the_profile() -> None:
    p = build_parser()
    args = p.parse_args(["--targets", "http://x", "--probe-calls", "3"])
    _apply_profile(args, p, {"probe_calls": 99})
    assert args.probe_calls == 3


def test_every_builtin_profile_names_only_real_dests() -> None:
    valid = {a.dest for a in build_parser()._actions}
    for name, overrides in SCAN_PROFILES.items():
        unknown = set(overrides) - valid
        assert not unknown, f"profile {name!r} names unknown dests: {unknown}"


def test_named_profile_applies_through_parse_args() -> None:
    args = parse_args(["--targets", "http://x", "--scan-profile", "stdio"])
    assert args.safe_mode is True


def test_unknown_profile_is_rejected() -> None:
    import pytest

    with pytest.raises(SystemExit):
        parse_args(["--targets", "http://x", "--scan-profile", "does-not-exist"])
