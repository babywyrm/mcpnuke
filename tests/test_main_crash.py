"""A crashed scan exits 2 and says why, without echoing a credential."""

import pytest

from mcpnuke import __main__ as cli_main
from mcpnuke.__main__ import EXIT_ERROR


def test_crash_exits_error_and_names_the_cause(monkeypatch, capsys) -> None:
    def _boom() -> None:
        raise RuntimeError("upstream said no for AKIAIOSFODNN7EXAMPLE")

    monkeypatch.setattr(cli_main, "_main_inner", _boom)
    with pytest.raises(SystemExit) as exc:
        cli_main.main()
    assert exc.value.code == EXIT_ERROR
    err = capsys.readouterr().err
    assert "RuntimeError: upstream said no" in err
    assert "AKIAIOSFODNN7EXAMPLE" not in err
