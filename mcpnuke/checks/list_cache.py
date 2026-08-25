"""SEP-2549 list-result cache hints (ttlMs, cacheScope).

Absence is not a finding. The fields are optional and backward compatible;
flagging servers that omit them would fire on every target, including the
false-positive harness.

When they *are* present, a negative or non-integer ttlMs, an unknown
cacheScope, or a cacheScope that changes across pages of the same list is a
freshness-contract lie (MCP-T16). Mixed public/private pages also let a
shared cache serve the wrong authorization context.
"""

from __future__ import annotations

from typing import Any

from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult

_VALID_SCOPES: frozenset[str] = frozenset({"public", "private"})
_TAXONOMY_ID: str = "MCP-T16"


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


def check_list_cache(result: TargetResult) -> None:
    with time_check("list_cache", result):
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
