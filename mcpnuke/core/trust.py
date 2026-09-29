"""Which targets in one run share an agent.

An empty declaration means the whole run is one agent, which is what a
multi-target scan already assumed. A declaration limits cross-server
chains, name collisions, and replay peers to one set. A target named in
no set is not chained to the others.
"""

from __future__ import annotations

from mcpnuke.core.models import TargetResult


def parse_trust_sets(
    raw: list[str] | None,
    targets: list[str] | None = None,
) -> list[frozenset[str]]:
    """Turn repeatable ``URL,URL`` groups into sets.

    A URL in two groups is rejected. When *targets* is given, every URL
    must be one of them.
    """
    if not raw:
        return []
    seen: dict[str, int] = {}
    groups: list[frozenset[str]] = []
    for index, chunk in enumerate(raw):
        urls = [part.strip() for part in chunk.split(",") if part.strip()]
        if len(urls) < 2:
            raise ValueError(f"trust set {index + 1} needs at least two URLs")
        group = frozenset(urls)
        if len(group) < 2:
            raise ValueError(f"trust set {index + 1} needs at least two URLs")
        for url in group:
            if url in seen:
                raise ValueError(f"{url} is in more than one trust set")
            seen[url] = index
        groups.append(group)
    if targets is not None:
        known = set(targets)
        for url in seen:
            if url not in known:
                raise ValueError(f"{url} is not a target")
    return groups


def trusted_with(
    url: str,
    results: list[TargetResult],
    trust_sets: list[frozenset[str]] | None,
) -> list[TargetResult]:
    """Other results that share an agent with *url*."""
    if not trust_sets:
        return [item for item in results if item.url != url]
    group: frozenset[str] | None = None
    for item in trust_sets:
        if url in item:
            group = item
            break
    if group is None:
        return []
    return [item for item in results if item.url != url and item.url in group]


def trust_sets_from_opts(opts: dict | None) -> list[frozenset[str]]:
    """Read the probe_opts form (lists of URL strings)."""
    raw = (opts or {}).get("trust_sets") or []
    return [frozenset(str(url) for url in group) for group in raw]
