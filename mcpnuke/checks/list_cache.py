"""SEP-2549 list-result cache hints (ttlMs, cacheScope).

Absence is not a finding. The fields are optional and backward compatible;
flagging servers that omit them would fire on every target, including the
false-positive harness.

When they *are* present, a negative or non-integer ttlMs or an unknown
cacheScope is a freshness-contract lie (MCP-T16). cacheScope that changes
across pages of the same *list* request is HIGH — mixed public/private lets
a shared cache serve the wrong caller. Different ``resources/read`` URIs are
independently cacheable, so mixed scope across reads is not that finding.

``resources/read`` is sampled (up to five URIs) when a session is present
and ``--no-invoke`` is off. Absence of the fields is still not a finding.
"""

from __future__ import annotations

from typing import Any

from mcpnuke.checks.base import time_check
from mcpnuke.core.cache_hints import cache_fields_from_result
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol

_VALID_SCOPES: frozenset[str] = frozenset({"public", "private"})
_TAXONOMY_ID: str = "MCP-T16"
_LIST_METHODS: frozenset[str] = frozenset(
    {"tools/list", "resources/list", "prompts/list"}
)
_READ_CAP: int = 5


def _has_cache_fields(page: dict[str, Any]) -> bool:
    return "ttlMs" in page or "cacheScope" in page


def _ttl_invalid(value: object) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return value < 0
    if isinstance(value, float):
        return value < 0 or not value.is_integer()
    return True


def _effective_scope(page: dict[str, Any]) -> str:
    """Omitted cacheScope defaults to public (SEP-2549)."""
    scope = page.get("cacheScope")
    if scope is None:
        return "public"
    return str(scope)


def _sample_resource_reads(
    session: MCPSessionProtocol,
    result: TargetResult,
) -> None:
    if result.list_cache.get("resources/read"):
        return
    pages: list[dict[str, Any]] = []
    attempted = 0
    for resource in result.resources:
        if attempted >= _READ_CAP:
            break
        uri = resource.get("uri")
        if not isinstance(uri, str) or not uri:
            continue
        attempted += 1
        try:
            resp = session.call("resources/read", {"uri": uri}, timeout=15)
        except Exception:
            continue
        raw = resp.get("result") if resp else None
        if not isinstance(raw, dict):
            continue
        page = cache_fields_from_result(raw)
        page["uri"] = uri
        pages.append(page)
    if pages:
        result.list_cache["resources/read"] = pages


def _grade_cache_pages(result: TargetResult) -> None:
    for method, pages in result.list_cache.items():
        if not any(_has_cache_fields(p) for p in pages):
            continue
        for page in pages:
            if "ttlMs" in page and _ttl_invalid(page["ttlMs"]):
                result.add(
                    "list_cache",
                    "MEDIUM",
                    f"Invalid ttlMs on {method}",
                    f"{method} advertised ttlMs={page['ttlMs']!r}; "
                    "SEP-2549 requires a non-negative integer millisecond TTL.",
                    evidence=str(page)[:300],
                    taxonomy_id=_TAXONOMY_ID,
                )
            if "cacheScope" in page and page["cacheScope"] not in _VALID_SCOPES:
                result.add(
                    "list_cache",
                    "MEDIUM",
                    f"Invalid cacheScope on {method}",
                    f"{method} advertised cacheScope={page['cacheScope']!r}; "
                    'SEP-2549 allows only "public" or "private".',
                    evidence=str(page)[:300],
                    taxonomy_id=_TAXONOMY_ID,
                )
        if method not in _LIST_METHODS:
            continue
        scopes = {_effective_scope(p) for p in pages}
        if len(scopes) > 1:
            result.add(
                "list_cache",
                "HIGH",
                f"cacheScope mismatch across {method} pages",
                f"{method} pages disagree on cacheScope ({sorted(scopes)}). "
                "SEP-2549 requires the same scope on every page; mixed "
                "public/private lets a shared cache serve the wrong caller.",
                evidence=str(pages)[:400],
                taxonomy_id=_TAXONOMY_ID,
            )


def check_list_cache(
    result: TargetResult,
    session: MCPSessionProtocol | None = None,
    probe_opts: dict[str, Any] | None = None,
) -> None:
    opts = probe_opts or {}
    with time_check("list_cache", result):
        if session is not None and not opts.get("no_invoke"):
            _sample_resource_reads(session, result)
        _grade_cache_pages(result)
