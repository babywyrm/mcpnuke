"""RFC 9728 PRM + CIMD advertisement (silent when the document is absent)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from mcpnuke.checks.protected_resource_metadata import (
    check_protected_resource_metadata,
)
from mcpnuke.core.models import TargetResult

_RS = "https://rs.example/mcp"
_PRM_PATH = "https://rs.example/.well-known/oauth-protected-resource/mcp"
_PRM_ROOT = "https://rs.example/.well-known/oauth-protected-resource"
_AS = "https://auth.example"
_AS_META = "https://auth.example/.well-known/oauth-authorization-server"


class _HTTP:
    def __init__(
        self,
        *,
        post_url: str = _RS,
        status: int = 200,
        www_authenticate: str = "",
        have_post_raw: bool = True,
    ) -> None:
        self.post_url = post_url
        self.protocol_mode = "legacy"
        self._status = status
        self._www = www_authenticate
        self._have_post_raw = have_post_raw

    def call(self, method, params=None, timeout=None, retries=2):
        return None

    def notify(self, method, params=None) -> None:
        return None

    def close(self) -> None:
        return None

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return True

    def post_raw(self, payload, extra_headers=None, timeout=None):
        if not self._have_post_raw:
            raise AssertionError("post_raw should not run")
        headers = {}
        if self._www:
            headers["www-authenticate"] = self._www
        return SimpleNamespace(status_code=self._status, headers=headers)


def _result() -> TargetResult:
    return TargetResult(url=_RS)


def _opts(table: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
    def get_json(url: str) -> dict[str, Any] | None:
        if url not in table:
            return None
        return table[url]

    return {"get_json": get_json}


def _hits(r: TargetResult) -> list:
    return [f for f in r.findings if f.check == "protected_resource_metadata"]


def test_silence_without_post_url() -> None:
    session = _HTTP(post_url="")
    r = _result()
    check_protected_resource_metadata(session, r, _opts({}))
    assert _hits(r) == []
    assert "protected_resource_metadata" in r.timings


def test_silence_when_prm_absent() -> None:
    r = _result()
    check_protected_resource_metadata(_HTTP(), r, _opts({}))
    assert _hits(r) == []


def test_silence_when_well_known_is_html_shaped_json() -> None:
    r = _result()
    check_protected_resource_metadata(
        _HTTP(),
        r,
        _opts({_PRM_PATH: {"title": "Not metadata"}}),
    )
    assert _hits(r) == []


def test_prm_without_authorization_servers_is_high() -> None:
    r = _result()
    check_protected_resource_metadata(
        _HTTP(),
        r,
        _opts({_PRM_PATH: {"resource": "https://rs.example/mcp"}}),
    )
    hits = _hits(r)
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "authorization_servers" in hits[0].title
    assert hits[0].lane == 5


def test_insecure_authorization_server_is_medium() -> None:
    r = _result()
    check_protected_resource_metadata(
        _HTTP(),
        r,
        _opts({
            _PRM_PATH: {
                "resource": "https://rs.example/mcp",
                "authorization_servers": ["http://auth.example"],
            },
        }),
    )
    hits = _hits(r)
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert "not HTTPS" in hits[0].title


def test_loopback_http_authorization_server_is_quiet() -> None:
    r = _result()
    check_protected_resource_metadata(
        _HTTP(),
        r,
        _opts({
            _PRM_PATH: {
                "resource": "https://rs.example/mcp",
                "authorization_servers": ["http://127.0.0.1:8080"],
            },
        }),
    )
    assert _hits(r) == []


def test_issuer_mismatch_is_high() -> None:
    r = _result()
    check_protected_resource_metadata(
        _HTTP(),
        r,
        _opts({
            _PRM_PATH: {
                "resource": "https://rs.example/mcp",
                "authorization_servers": [_AS],
            },
            _AS_META: {"issuer": "https://attacker.example"},
        }),
    )
    hits = _hits(r)
    assert len(hits) == 1
    assert hits[0].severity == "HIGH"
    assert "issuer mismatch" in hits[0].title.lower()


def test_dcr_without_cimd_is_medium() -> None:
    r = _result()
    check_protected_resource_metadata(
        _HTTP(),
        r,
        _opts({
            _PRM_PATH: {
                "resource": "https://rs.example/mcp",
                "authorization_servers": [_AS],
            },
            _AS_META: {
                "issuer": _AS,
                "registration_endpoint": "https://auth.example/register",
            },
        }),
    )
    hits = _hits(r)
    assert len(hits) == 1
    assert hits[0].severity == "MEDIUM"
    assert "CIMD" in hits[0].title


def test_cimd_advertised_is_quiet() -> None:
    r = _result()
    check_protected_resource_metadata(
        _HTTP(),
        r,
        _opts({
            _PRM_PATH: {
                "resource": "https://rs.example/mcp",
                "authorization_servers": [_AS],
            },
            _AS_META: {
                "issuer": _AS,
                "registration_endpoint": "https://auth.example/register",
                "client_id_metadata_document_supported": True,
            },
        }),
    )
    assert _hits(r) == []


def test_resource_metadata_header_is_tried_first() -> None:
    header_url = "https://rs.example/custom-prm.json"
    session = _HTTP(
        status=401,
        www_authenticate=(
            'Bearer error="invalid_token", '
            f'resource_metadata="{header_url}"'
        ),
    )
    r = _result()
    check_protected_resource_metadata(
        session,
        r,
        _opts({
            header_url: {"resource": "https://rs.example/mcp"},
            _PRM_PATH: {
                "resource": "https://rs.example/mcp",
                "authorization_servers": [_AS],
            },
        }),
    )
    hits = _hits(r)
    assert len(hits) == 1
    assert "authorization_servers" in hits[0].title


def test_timing_recorded() -> None:
    r = _result()
    check_protected_resource_metadata(_HTTP(), r, _opts({}))
    assert "protected_resource_metadata" in r.timings
