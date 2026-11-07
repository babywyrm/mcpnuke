"""An auto-detected token endpoint must stay on the scanned host.

Without --oidc-url the scanned server names the realm, so an unpinned
auto-detect lets the target choose where the client secret is posted.
"""

from __future__ import annotations

import argparse

import httpx
import pytest

from mcpnuke.core import auth

_SECRET = "synthetic-client-secret"
_TARGET = "http://mcp.lab:9000/mcp"
_DISCOVERY = "/.well-known/openid-configuration"


def _lab(monkeypatch, realm: str, token_endpoint: str) -> list[str]:
    """Serve a target that advertises *realm*; return hosts that received the secret."""
    leaked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.path == "/mcp":
            return httpx.Response(401, headers={"www-authenticate": f'Bearer realm="{realm}"'})
        if url.path.endswith(_DISCOVERY):
            issuer = str(url).removesuffix(_DISCOVERY)
            return httpx.Response(200, json={"issuer": issuer, "token_endpoint": token_endpoint})
        if _SECRET in request.content.decode():
            leaked.append(url.host)
            return httpx.Response(200, json={"access_token": "tok"})
        return httpx.Response(404)

    real = httpx.Client
    monkeypatch.setattr(
        auth.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw)
    )
    return leaked


def _args(oidc_url: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        auth_token=None,
        client_id="client",
        client_secret=_SECRET,
        oidc_url=oidc_url,
        tls_verify=False,
        oidc_scope=None,
        header=None,
        oidc_resource=None,
        targets=[_TARGET],
    )


def test_realm_on_another_host_is_refused(monkeypatch) -> None:
    leaked = _lab(monkeypatch, "http://evil.example/realms/x", "http://evil.example/token")

    with pytest.raises(RuntimeError, match="--oidc-url"):
        auth.resolve_auth_token(_args())

    assert leaked == []


def test_token_endpoint_moved_off_host_by_discovery_is_refused(monkeypatch) -> None:
    leaked = _lab(monkeypatch, "http://mcp.lab:8080/realms/lab", "http://evil.example/token")

    with pytest.raises(RuntimeError, match="--oidc-url"):
        auth.resolve_auth_token(_args())

    assert leaked == []


def test_same_host_keycloak_on_another_port_still_works(monkeypatch) -> None:
    endpoint = "http://mcp.lab:8080/realms/lab/protocol/openid-connect/token"
    leaked = _lab(monkeypatch, "http://mcp.lab:8080/realms/lab", endpoint)

    assert auth.resolve_auth_token(_args()) == "tok"
    assert leaked == ["mcp.lab"]


def test_explicit_oidc_url_is_trusted_on_any_host(monkeypatch) -> None:
    leaked = _lab(monkeypatch, "http://evil.example/realms/x", "http://idp.example/token")

    assert auth.resolve_auth_token(_args("http://idp.example/realms/corp")) == "tok"
    assert leaked == ["idp.example"]
