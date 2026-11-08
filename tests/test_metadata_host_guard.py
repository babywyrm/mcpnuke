"""A target must not steer the scanner at a cloud metadata service.

The scanner follows URLs the target names: redirects, the WWW-Authenticate
realm, and RFC 9728 resource_metadata. Run in a cloud pod, those reach the
instance metadata service on the scanner's own network.
"""

from __future__ import annotations

import contextlib

import httpx
import pytest

from mcpnuke.checks.protected_resource_metadata import _httpx_get_json
from mcpnuke.core import auth
from mcpnuke.core.transports import http as http_transport
from mcpnuke.core.transports.http import HTTPSession, is_metadata_host

_TARGET = "http://mcp.lab:9000"
_IMDS = "http://169.254.169.254/latest/meta-data"


@pytest.mark.parametrize(
    "host",
    ["169.254.169.254", "fe80::1", "::ffff:169.254.169.254", "metadata.google.internal"],
)
def test_metadata_hosts(host: str) -> None:
    assert is_metadata_host(host)


@pytest.mark.parametrize("host", ["10.0.0.5", "127.0.0.1", "::1", "mcp.lab", "not-an-ip"])
def test_lab_hosts_are_not_metadata(host: str) -> None:
    assert not is_metadata_host(host)


_REALM: list[str] = [""]


@pytest.fixture
def requested(monkeypatch) -> list[str]:
    """mcp.lab answers 401 naming _REALM[0], and 307 on /redirect?to=."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url.host))
        if request.url.host != "mcp.lab":
            return httpx.Response(404)
        if request.url.path == "/redirect":
            return httpx.Response(307, headers={"location": request.url.params["to"]})
        return httpx.Response(401, headers={"www-authenticate": f'Bearer realm="{_REALM[0]}"'})

    real = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw)
    )
    return seen


def test_realm_is_not_fetched_from_metadata_host(requested: list[str]) -> None:
    _REALM[0] = _IMDS
    auth.detect_auth_requirements(f"{_TARGET}/mcp")
    assert "169.254.169.254" not in requested


def test_realm_on_another_host_is_still_fetched(requested: list[str]) -> None:
    _REALM[0] = "http://idp.lab/realms/x"
    auth.detect_auth_requirements(f"{_TARGET}/mcp")
    assert "idp.lab" in requested


def test_redirect_to_metadata_host_is_refused(requested: list[str]) -> None:
    session = HTTPSession(_TARGET, f"{_TARGET}/redirect?to={_IMDS}")
    with contextlib.suppress(httpx.HTTPError):
        session.post_raw({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert requested == ["mcp.lab"]


def test_prm_fetch_skips_metadata_host(requested: list[str]) -> None:
    assert _httpx_get_json(_IMDS) is None
    assert requested == []


_DNS: dict[str, list[str]] = {
    "imds.attacker.lab": ["10.0.0.9", "169.254.169.254"],
    "internal.lab": ["10.0.0.5"],
}


@pytest.fixture
def dns(monkeypatch) -> None:
    monkeypatch.setattr(http_transport, "_resolve", lambda host: _DNS.get(host, []))


def test_name_resolving_to_metadata_is_metadata(dns: None) -> None:
    assert is_metadata_host("imds.attacker.lab")
    assert not is_metadata_host("internal.lab")


def test_redirect_to_name_resolving_to_metadata_is_refused(dns: None, requested: list[str]) -> None:
    session = HTTPSession(_TARGET, f"{_TARGET}/redirect?to=http://imds.attacker.lab/latest")
    with contextlib.suppress(httpx.HTTPError):
        session.post_raw({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert requested == ["mcp.lab"]


def test_prm_fetch_skips_name_resolving_to_metadata(dns: None, requested: list[str]) -> None:
    assert _httpx_get_json("http://imds.attacker.lab/.well-known/x") is None
    assert requested == []


def test_redirect_to_private_name_is_still_followed(dns: None, requested: list[str]) -> None:
    session = HTTPSession(_TARGET, f"{_TARGET}/redirect?to=http://internal.lab/mcp")
    with contextlib.suppress(httpx.HTTPError):
        session.post_raw({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert requested == ["mcp.lab", "internal.lab"]
