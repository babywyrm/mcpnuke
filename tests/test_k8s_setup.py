"""CLI Kubernetes setup: token sources, the checks, and discovered targets."""

from unittest.mock import patch

import pytest
from rich.console import Console

from mcpnuke import __main__ as cli_main
from mcpnuke.__main__ import EXIT_ERROR
from mcpnuke.k8s.discovery import DiscoveredEndpoint

_QUIET = Console(quiet=True)


def _args(*flags: str):
    return cli_main.parse_args(["--targets", "http://127.0.0.1:9/mcp", *flags])


def test_missing_token_file_is_an_error(tmp_path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli_main._k8s_setup(_args("--k8s-token-file", str(tmp_path / "absent")), [], _QUIET)
    assert exc.value.code == EXIT_ERROR


def test_token_file_reaches_the_checks(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("MCPNUKE_K8S_TOKEN", raising=False)
    token = tmp_path / "token"
    token.write_text("lab-k8s-token\n")
    with (
        patch.object(cli_main, "run_k8s_checks") as checks,
        patch.object(cli_main, "fingerprint_services"),
    ):
        cli_main._k8s_setup(_args("--k8s-token-file", str(token)), [], _QUIET)
    assert checks.call_args.kwargs["token"] == "lab-k8s-token"


def test_no_k8s_skips_the_checks() -> None:
    with patch.object(cli_main, "run_k8s_checks") as checks:
        cli_main._k8s_setup(_args("--no-k8s"), [], _QUIET)
    checks.assert_not_called()


def test_discovered_endpoints_join_the_targets_once() -> None:
    urls = ["http://already/mcp"]
    found = [
        DiscoveredEndpoint(url="http://already/mcp", service_name="a", namespace="n", port=1),
        DiscoveredEndpoint(url="http://new/mcp", service_name="b", namespace="n", port=2),
    ]
    with patch.object(cli_main, "discover_services", return_value=found):
        cli_main._k8s_setup(_args("--no-k8s", "--k8s-discover"), urls, _QUIET)
    assert urls == ["http://already/mcp", "http://new/mcp"]
