"""The scanned server writes the auth responses. A malformed one is an auth
failure the CLI reports, never a crash that ends the scan."""

from __future__ import annotations

import argparse
from collections.abc import Callable

import httpx
import pytest

from mcpnuke.core import auth

_TARGET = "http://mcp.lab/mcp"
_WELL_KNOWN = "/realms/x/.well-known/openid-configuration"
_DEEP = "[" * 100_000


def _serve(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> None:
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


def _args() -> argparse.Namespace:
    return argparse.Namespace(targets=[_TARGET], client_id="lab-client", client_secret="synthetic-secret")


@pytest.mark.parametrize(
    "doc",
    [
        {"issuer": ["http://mcp.lab/realms/x"], "token_endpoint": {"u": 1}},
        {"issuer": 7, "token_endpoint": None},
        ["not", "an", "object"],
        _DEEP,
    ],
)
def test_non_string_discovery_fields_are_ignored(monkeypatch: pytest.MonkeyPatch, doc: object) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(401, headers={"www-authenticate": 'Bearer realm="http://mcp.lab/realms/x"'})
        if request.url.path == _WELL_KNOWN:
            return httpx.Response(200, text=doc) if isinstance(doc, str) else httpx.Response(200, json=doc)
        return httpx.Response(404)

    _serve(monkeypatch, handler)
    info = auth.detect_auth_requirements(_TARGET)
    assert info.requires_auth
    assert (info.issuer, info.token_endpoint) == ("", "")
    with pytest.raises(RuntimeError, match="Cannot determine OIDC URL"):
        auth.resolve_auth_token(_args())


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, text=_DEEP),
        httpx.Response(200, json=["access_token"]),
        httpx.Response(200, json={"access_token": 5}),
    ],
)
def test_malformed_token_response_is_an_auth_failure(
    monkeypatch: pytest.MonkeyPatch, response: httpx.Response
) -> None:
    _serve(monkeypatch, lambda request: response)
    with pytest.raises(RuntimeError):
        auth.fetch_client_credentials_token("http://idp.lab/token", "lab-client", "synthetic-secret")


@pytest.mark.parametrize(
    "fetch",
    [
        lambda: auth.fetch_token_introspection("http://idp.lab/introspect", "opaque-lab-token"),
        lambda: auth.fetch_jwks("http://idp.lab/jwks"),
    ],
)
@pytest.mark.parametrize("body", ["<html>not json</html>", _DEEP])
def test_non_json_metadata_is_an_auth_failure(
    monkeypatch: pytest.MonkeyPatch, fetch: Callable[[], object], body: str
) -> None:
    _serve(monkeypatch, lambda request: httpx.Response(200, text=body))
    with pytest.raises(RuntimeError):
        fetch()


def test_unreachable_target_is_reported_not_read_as_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _serve(monkeypatch, handler)
    info = auth.detect_auth_requirements(_TARGET)
    assert "ConnectError" in info.error
    with pytest.raises(RuntimeError, match="ConnectError"):
        auth.resolve_auth_token(_args())
