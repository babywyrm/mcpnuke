"""RFC 8707 resource indicator on the client_credentials token request."""

import argparse

import httpx

from mcpnuke.cli import parse_args
from mcpnuke.core.auth import fetch_client_credentials_token, resolve_auth_token


def test_parse_args_oidc_resource() -> None:
    args = parse_args(
        [
            "--targets",
            "http://localhost:9001",
            "--oidc-resource",
            "http://mcp.example/mcp",
        ]
    )
    assert args.oidc_resource == "http://mcp.example/mcp"


def test_oidc_resource_env_default(monkeypatch) -> None:
    monkeypatch.setenv("MCP_OIDC_RESOURCE", "http://mcp.example/mcp")
    args = parse_args(["--targets", "http://localhost:9001"])
    assert args.oidc_resource == "http://mcp.example/mcp"


class _TokenResponse:
    status_code = 200
    text = ""

    def json(self) -> dict[str, str]:
        return {"access_token": "tok"}


def _install_client(monkeypatch, seen: dict[str, object]) -> None:
    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def post(
            self,
            url: str,
            data: dict[str, str] | None = None,
            headers: dict[str, str] | None = None,
        ) -> _TokenResponse:
            seen["url"] = url
            seen["data"] = dict(data or {})
            return _TokenResponse()

        def close(self) -> None:
            return None

    monkeypatch.setattr(httpx, "Client", _Client)


def test_fetch_posts_resource(monkeypatch) -> None:
    seen: dict[str, object] = {}
    _install_client(monkeypatch, seen)
    token = fetch_client_credentials_token(
        "https://issuer.example/oauth/token",
        "client",
        "secret",
        resource="http://mcp.example/mcp",
    )
    assert token == "tok"
    data = seen["data"]
    assert isinstance(data, dict)
    assert data["grant_type"] == "client_credentials"
    assert data["resource"] == "http://mcp.example/mcp"


def test_fetch_omits_resource_when_unset(monkeypatch) -> None:
    seen: dict[str, object] = {}
    _install_client(monkeypatch, seen)
    fetch_client_credentials_token(
        "https://issuer.example/oauth/token",
        "client",
        "secret",
    )
    data = seen["data"]
    assert isinstance(data, dict)
    assert "resource" not in data


def test_resolve_forwards_oidc_resource(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake(
        oidc_url: str,
        client_id: str,
        client_secret: str,
        **kwargs: object,
    ) -> str:
        captured["oidc_url"] = oidc_url
        captured.update(kwargs)
        return "tok"

    monkeypatch.setattr(
        "mcpnuke.core.auth.fetch_client_credentials_token",
        _fake,
    )
    args = argparse.Namespace(
        auth_token=None,
        client_id="client",
        client_secret="secret",
        oidc_url="https://issuer.example",
        tls_verify=False,
        oidc_scope=None,
        header=None,
        oidc_resource="http://mcp.example/mcp",
    )
    assert resolve_auth_token(args) == "tok"
    assert captured["resource"] == "http://mcp.example/mcp"
