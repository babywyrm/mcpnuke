"""Auth fetch errors print to the console and CI logs, so they carry no token."""

from collections.abc import Callable

import httpx
import pytest

from mcpnuke.core import auth

_JWT_PAYLOAD = "eyJzdWIiOiJzeW50aGV0aWMtbGFiIn0"
_JWT = f"eyJhbGciOiJIUzI1NiJ9.{_JWT_PAYLOAD}.c2lnbmF0dXJl"


def _serve(monkeypatch, status: int, body: str) -> None:
    real = httpx.Client
    transport = httpx.MockTransport(lambda _req: httpx.Response(status, text=body))
    monkeypatch.setattr(auth.httpx, "Client", lambda **kw: real(transport=transport, **kw))


_FETCHERS: dict[str, Callable[[], object]] = {
    "token": lambda: auth.fetch_client_credentials_token(
        "https://idp.lab/token", "lab-client", "synthetic-secret"
    ),
    "introspection": lambda: auth.fetch_token_introspection("https://idp.lab/introspect", "t"),
    "jwks": lambda: auth.fetch_jwks("https://idp.lab/jwks"),
}


@pytest.mark.parametrize("name", sorted(_FETCHERS))
def test_error_body_is_redacted(monkeypatch, name: str) -> None:
    _serve(monkeypatch, 400, f'{{"error":"invalid_request","hint":"{_JWT}"}}')
    with pytest.raises(RuntimeError) as exc:
        _FETCHERS[name]()
    assert "HTTP 400" in str(exc.value)
    assert _JWT_PAYLOAD not in str(exc.value)


def test_missing_access_token_names_keys_not_values(monkeypatch) -> None:
    _serve(monkeypatch, 200, f'{{"id_token":"{_JWT}","token_type":"Bearer"}}')
    with pytest.raises(RuntimeError) as exc:
        _FETCHERS["token"]()
    assert "id_token" in str(exc.value)
    assert _JWT_PAYLOAD not in str(exc.value)
