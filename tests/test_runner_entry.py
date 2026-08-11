"""The mcpnuke-runner console script must not traceback in a base install.

`mcpnuke-runner` is installed by the base package but its implementation
needs the optional `server` extra. Before this shim, running it after a plain
`pip install mcpnuke` printed a raw ModuleNotFoundError for pydantic — which
reads as "broken" rather than "needs an extra", and does so at exactly the
moment a new user is deciding whether the tool works.

Most tests here drive `_load_run` directly rather than the real import, so
they assert the shim's dispatch logic instead of whichever extras happen to
be installed in the environment running them.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from mcpnuke import _runner_entry


def _raise(exc: BaseException):
    def _loader():
        raise exc

    return _loader


def test_missing_extra_exits_two_with_a_message(monkeypatch, capsys):
    monkeypatch.setattr(
        _runner_entry,
        "_load_run",
        _raise(ModuleNotFoundError("No module named 'pydantic'", name="pydantic")),
    )

    with pytest.raises(SystemExit) as exc:
        _runner_entry.main()

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "mcpnuke[server]" in err, err
    assert "Traceback" not in err


@pytest.mark.parametrize("missing", ["fastapi", "uvicorn", "pydantic"])
def test_the_message_names_the_module_that_was_missing(monkeypatch, capsys, missing):
    """Naming the module is the difference between a user installing the
    extra and hunting a broken environment."""
    monkeypatch.setattr(
        _runner_entry,
        "_load_run",
        _raise(ModuleNotFoundError(f"No module named {missing!r}", name=missing)),
    )

    with pytest.raises(SystemExit):
        _runner_entry.main()

    assert missing in capsys.readouterr().err


def test_a_submodule_of_an_extra_is_still_recognised(monkeypatch, capsys):
    """uvicorn's import failures surface as e.g. uvicorn.loops.auto."""
    monkeypatch.setattr(
        _runner_entry,
        "_load_run",
        _raise(ModuleNotFoundError("...", name="uvicorn.loops.auto")),
    )

    with pytest.raises(SystemExit) as exc:
        _runner_entry.main()

    assert exc.value.code == 2
    assert "uvicorn" in capsys.readouterr().err


def test_an_unrelated_import_error_still_propagates(monkeypatch):
    """A shim that swallowed every ImportError would turn a genuine bug
    inside the server package into a friendly "install the extra" message and
    hide it. Only the known optional dependencies are absorbed."""
    monkeypatch.setattr(
        _runner_entry,
        "_load_run",
        _raise(ModuleNotFoundError("No module named 'mcpnuke.server.oops'",
                                   name="mcpnuke.server.oops")),
    )

    with pytest.raises(ModuleNotFoundError):
        _runner_entry.main()


def test_calls_through_when_the_extra_is_present(monkeypatch):
    called: list[bool] = []
    monkeypatch.setattr(
        _runner_entry, "_load_run", lambda: (lambda: called.append(True))
    )

    _runner_entry.main()

    assert called == [True]


def test_importing_the_shim_does_not_import_the_server_package():
    """The whole point: the shim sits above mcpnuke.server, whose __init__
    imports pydantic. If importing the shim pulled that in, the friendly
    error could never run."""
    for mod in [m for m in sys.modules if m.startswith("mcpnuke.server")]:
        del sys.modules[mod]
    importlib.reload(_runner_entry)

    assert not [m for m in sys.modules if m.startswith("mcpnuke.server")]


@pytest.mark.skipif(
    importlib.util.find_spec("pydantic") is not None,
    reason="server extra is installed, so the real import succeeds",
)
def test_the_real_import_path_produces_the_friendly_error(capsys):
    """No mocking at all: the environment genuinely lacks the extra, which is
    the case CI and a fresh `pip install mcpnuke` both hit."""
    with pytest.raises(SystemExit) as exc:
        _runner_entry.main()

    assert exc.value.code == 2
    assert "mcpnuke[server]" in capsys.readouterr().err
