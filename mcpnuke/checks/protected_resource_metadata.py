"""RFC 9728 protected resource metadata and CIMD advertisement.

Absence is not a finding. Most MCP servers still omit the document; flagging
that would fire on every HTTP target. When a document *is* present, MCP
requires ``authorization_servers``. When we then fetch AS metadata, DCR
without ``client_id_metadata_document_supported`` is the 2026-07-28
registration downgrade: CIMD is preferred, DCR is compatibility-only.

Issuer-bound client credentials and RFC 9207 authorization-response ``iss``
are client behavior. This check does not claim them.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol

_CHECK: str = "protected_resource_metadata"
_add = lane_tagged(lane=5, transport="A")
_WWW_META_RE = re.compile(
    r'resource_metadata\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)
GetJson = Callable[[str], dict[str, Any] | None]


def _httpx_get_json(url: str) -> dict[str, Any] | None:
    try:
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            resp = client.get(url)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _header(headers: object, name: str) -> str:
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return ""
    for key in (name, name.lower(), name.title()):
        value = getter(key)
        if value:
            return str(value)
    return ""


def _resource_metadata_url(www_authenticate: str) -> str | None:
    match = _WWW_META_RE.search(www_authenticate or "")
    return match.group(1) if match else None


def _well_known_prm_urls(post_url: str) -> list[str]:
    parsed = urlparse(post_url)
    if not parsed.scheme or not parsed.netloc:
        return []
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    urls: list[str] = []
    if path:
        urls.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    urls.append(f"{origin}/.well-known/oauth-protected-resource")
    return urls


def _as_metadata_urls(issuer: str) -> list[str]:
    parsed = urlparse(issuer.rstrip("/"))
    if not parsed.scheme or not parsed.netloc:
        return []
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.strip("/")
    if path:
        return [
            f"{origin}/.well-known/oauth-authorization-server/{path}",
            f"{origin}/.well-known/openid-configuration/{path}",
            f"{origin}/{path}/.well-known/openid-configuration",
        ]
    return [
        f"{origin}/.well-known/oauth-authorization-server",
        f"{origin}/.well-known/openid-configuration",
    ]


def _is_prm(doc: object) -> dict[str, Any] | None:
    if not isinstance(doc, dict):
        return None
    resource = doc.get("resource")
    if isinstance(resource, str) and resource:
        return doc
    return None


def _https_or_loopback(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    return parsed.scheme == "https"


def _issuers_match(advertised: str, fetched: str) -> bool:
    return advertised.rstrip("/") == fetched.rstrip("/")


def check_protected_resource_metadata(
    session: MCPSessionProtocol | None,
    result: TargetResult,
    probe_opts: dict[str, Any] | None = None,
) -> None:
    with time_check(_CHECK, result):
        if session is None:
            return
        post_url = getattr(session, "post_url", "") or ""
        if urlparse(post_url).scheme not in {"http", "https"}:
            return
        opts = probe_opts or {}
        get_json: GetJson = opts.get("get_json") or _httpx_get_json

        candidates: list[str] = []
        post_raw = getattr(session, "post_raw", None)
        if callable(post_raw):
            try:
                resp = post_raw(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                        "params": {},
                    },
                    timeout=10,
                )
            except Exception:
                resp = None
            if getattr(resp, "status_code", None) in (401, 403):
                www = _header(getattr(resp, "headers", None), "www-authenticate")
                meta = _resource_metadata_url(www)
                if meta:
                    candidates.append(meta)
        for url in _well_known_prm_urls(post_url):
            if url not in candidates:
                candidates.append(url)

        prm: dict[str, Any] | None = None
        for url in candidates:
            parsed = _is_prm(get_json(url))
            if parsed is not None:
                prm = parsed
                break
        if prm is None:
            return

        servers = prm.get("authorization_servers")
        if not isinstance(servers, list) or not any(
            isinstance(item, str) and item for item in servers
        ):
            _add(
                result,
                _CHECK,
                "HIGH",
                "Protected resource metadata has no authorization_servers",
                "MCP 2026-07-28 requires RFC 9728 metadata to name at least "
                "one authorization server.",
                evidence=str(prm)[:300],
            )
            return

        insecure = [
            item
            for item in servers
            if isinstance(item, str) and item and not _https_or_loopback(item)
        ]
        if insecure:
            _add(
                result,
                _CHECK,
                "MEDIUM",
                f"Authorization server is not HTTPS: {insecure[0]}",
                "MCP clients must discover the AS over a protected channel.",
                evidence=str(servers)[:300],
            )

        issuer = next(
            (item for item in servers if isinstance(item, str) and item),
            "",
        )
        as_doc: dict[str, Any] | None = None
        for url in _as_metadata_urls(issuer):
            doc = get_json(url)
            if isinstance(doc, dict) and isinstance(doc.get("issuer"), str):
                as_doc = doc
                break
        if as_doc is None:
            return
        advertised = str(as_doc["issuer"])
        if not _issuers_match(advertised, issuer):
            _add(
                result,
                _CHECK,
                "HIGH",
                "Authorization server metadata issuer mismatch",
                f"Fetched metadata for {issuer} advertised issuer={advertised}. "
                "RFC 8414 requires they match; mix-up is the failure.",
                evidence=str(as_doc)[:300],
            )
            return
        registration = as_doc.get("registration_endpoint")
        has_dcr = isinstance(registration, str) and bool(registration)
        cimd = as_doc.get("client_id_metadata_document_supported") is True
        if has_dcr and not cimd:
            _add(
                result,
                _CHECK,
                "MEDIUM",
                "Authorization server advertises DCR but not CIMD",
                "MCP 2026-07-28 prefers Client ID Metadata Documents; "
                "Dynamic Client Registration is compatibility-only.",
                evidence=str(as_doc)[:300],
            )
