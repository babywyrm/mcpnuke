"""Auth secrets can come from a file so they stay off argv."""

import argparse

import pytest

from mcpnuke.cli import parse_args
from mcpnuke.core.auth import load_auth_secret_files


def test_parse_secret_file_flags() -> None:
    args = parse_args(
        [
            "--targets",
            "http://localhost:9001",
            "--auth-token-file",
            "token.txt",
            "--client-secret-file",
            "secret.txt",
        ]
    )
    assert args.auth_token_file == "token.txt"
    assert args.client_secret_file == "secret.txt"


def _args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "auth_token": None,
        "auth_token_file": None,
        "client_secret": None,
        "client_secret_file": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_token_file_is_stripped(tmp_path) -> None:
    path = tmp_path / "token"
    path.write_text("abc.def.ghi\n")
    args = _args(auth_token_file=str(path))
    load_auth_secret_files(args)
    assert args.auth_token == "abc.def.ghi"


def test_explicit_token_wins_over_file(tmp_path) -> None:
    path = tmp_path / "token"
    path.write_text("from-file\n")
    args = _args(auth_token="from-flag", auth_token_file=str(path))
    load_auth_secret_files(args)
    assert args.auth_token == "from-flag"


def test_client_secret_file_fills_empty_secret(tmp_path) -> None:
    path = tmp_path / "secret"
    path.write_text("s3cr3t\n")
    args = _args(client_secret_file=str(path))
    load_auth_secret_files(args)
    assert args.client_secret == "s3cr3t"


def test_missing_secret_file_names_the_path() -> None:
    args = _args(auth_token_file="/no/such/mcpnuke-token")
    with pytest.raises(RuntimeError, match="not found"):
        load_auth_secret_files(args)


def test_empty_secret_file_is_rejected(tmp_path) -> None:
    path = tmp_path / "token"
    path.write_text(" \n")
    args = _args(auth_token_file=str(path))
    with pytest.raises(RuntimeError, match="empty"):
        load_auth_secret_files(args)
