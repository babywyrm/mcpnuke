"""SEP-2549 ttlMs / cacheScope extraction.

Shared by the enumerator (list pages) and list_cache (resources/read).
Lives in core so enumerator does not import a check module.
"""

from __future__ import annotations

from typing import Any


def cache_fields_from_result(result: dict[str, Any]) -> dict[str, Any]:
    """ttlMs / cacheScope from one cacheable result; omitted keys stay omitted."""
    page: dict[str, Any] = {}
    if "ttlMs" in result:
        page["ttlMs"] = result["ttlMs"]
    if "cacheScope" in result:
        page["cacheScope"] = result["cacheScope"]
    return page
