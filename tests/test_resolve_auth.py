"""CLI auth resolution: the token, its decoded claims, and the context checks read."""

import base64
import io
import json

import pytest
from rich.console import Console

from mcpnuke import __main__ as cli_main
from mcpnuke import cli_steps
from mcpnuke.core.auth import AuthInfo


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


_SYNTHETIC_JWT = f"{_b64({'alg': 'none'})}.{_b64({'sub': 'lab-user', 'aud': 'mcp'})}.sig"


def _resolve(*flags: str) -> tuple[str | None, dict]:
    args = cli_main.parse_args(["--targets", "http://127.0.0.1:9/mcp", *flags])
    return cli_main._resolve_auth(args, [], {}, Console(quiet=True))


def test_no_token_yields_empty_context() -> None:
    token, context = _resolve()
    assert token is None
    assert context == {}


def test_jwt_token_is_carried_with_its_claims() -> None:
    token, context = _resolve("--auth-token", _SYNTHETIC_JWT)
    assert token == _SYNTHETIC_JWT
    assert context["_raw_token"] == _SYNTHETIC_JWT
    assert context["jwt_claims_summary"]["sub"] == "lab-user"


def test_hostile_auth_metadata_prints_literally(monkeypatch: pytest.MonkeyPatch) -> None:
    info = AuthInfo(requires_auth=True, realm="[/bold]realm", token_endpoint="http://x/[/i]token")
    monkeypatch.setattr(cli_steps, "detect_auth_requirements", lambda *a, **k: info)
    out = io.StringIO()
    args = cli_main.parse_args(["--targets", "http://127.0.0.1:9/mcp", "--verbose"])
    cli_main._resolve_auth(args, ["http://127.0.0.1:9/mcp"], {}, Console(file=out))
    assert "[/bold]realm" in out.getvalue()
    assert "http://x/[/i]token" in out.getvalue()


def test_hostile_error_text_prints_literally(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(*a: object, **k: object) -> dict:
        raise RuntimeError("Response: [/red]denied")

    monkeypatch.setattr(cli_steps, "fetch_jwks", _fail)
    out = io.StringIO()
    args = cli_main.parse_args(["--targets", "http://127.0.0.1:9/mcp", "--jwks-url", "http://127.0.0.1:9/jwks"])
    cli_main._resolve_auth(args, [], {}, Console(file=out))
    assert "[/red]denied" in out.getvalue()


def test_opaque_token_has_no_claims_summary() -> None:
    token, context = _resolve("--auth-token", "opaque-lab-token")
    assert token == "opaque-lab-token"
    assert "jwt_claims_summary" not in context
