"""Tests for exit code semantics: 0=clean, 1=findings, 2=error."""


def test_exit_code_constants_importable():
    from mcpnuke.__main__ import EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR

    assert EXIT_CLEAN == 0
    assert EXIT_FINDINGS == 1
    assert EXIT_ERROR == 2


def test_exit_codes_distinct():
    from mcpnuke.__main__ import EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR

    assert len({EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR}) == 3
