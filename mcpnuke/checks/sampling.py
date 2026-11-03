"""Rank tools by security relevance for --fast and --coverage sampling."""

from __future__ import annotations


def _pick_security_relevant(tools: list[dict], n: int) -> list[dict]:
    """Select the top N most security-relevant tools for coverage-limited scanning.

    n=0 means return all tools (full coverage, sorted by security relevance).
    n>len(tools) returns all tools sorted by security relevance.
    """
    ranked = sorted(
        tools,
        key=lambda tool: (-_tool_security_score(tool), str(tool.get("name", ""))),
    )
    if n == 0 or n >= len(tools):
        return ranked
    return ranked[:n]


# ---------------------------------------------------------------------------
# Tool security relevance scoring
#
# Categorises keywords by threat class and assigns differentiated weights
# so that a zero-param secrets-leaking tool always outranks a five-param
# movement helper.
# ---------------------------------------------------------------------------

# Weight applied when keyword appears in tool *name* vs *description*.
_NAME_MULTIPLIER: int = 3
_DESC_MULTIPLIER: int = 1

# Keyword categories ordered by descending security impact.
# Each tuple: (keywords frozenset, per-match weight)
_KEYWORD_TIERS: list[tuple[frozenset[str], int]] = [
    # Tier 1 — direct execution / shell access
    (frozenset({
        "exec", "execute", "eval", "shell", "bash", "spawn", "system",
    }), 10),
    # Tier 2 — sensitive data exposure (including SDK/cache token material)
    (frozenset({
        "secret", "credential", "password", "token", "key", "config",
        "leak", "dump", "env", "private",
        # SDK cache-tamper surface (MCP-T33): tools that read/write cached
        # JWTs are as dangerous as raw secret exposure — an unsigned token
        # written to the cache grants admin-level access on misconfigured SDKs.
        "cache", "cached",
    }), 8),
    # Tier 3 — outbound / persistence channels
    (frozenset({
        "webhook", "callback", "notify", "hook", "subscribe",
        "fetch", "proxy", "egress", "curl", "request",
    }), 7),
    # Tier 4 — dangerous operations
    (frozenset({
        "run", "command", "cmd", "deploy", "maintenance",
        "delete", "drop", "destroy", "kill", "purge",
    }), 6),
    # Tier 5 — data movement / filesystem
    (frozenset({
        "upload", "write", "send", "transfer", "backup",
        "read", "file", "path", "query", "sql",
    }), 4),
    # Tier 6 — administrative / elevated scope
    (frozenset({
        "admin", "root", "sudo", "manage", "install",
        "email", "sms", "broadcast",
    }), 3),
]

# Parameter names that signal attack surface regardless of tool name.
_DANGEROUS_PARAM_NAMES: frozenset[str] = frozenset({
    "url", "uri", "path", "file", "filename",
    "command", "cmd", "code", "query", "script",
    "host", "address", "endpoint", "callback",
    # SDK / auth token material — a tool that accepts a raw JWT or a
    # role override is a cache-tamper candidate even if its name is benign.
    "jwt", "bearer", "cached_role", "cached_token",
})

# Minimum score floor for tools whose names strongly indicate secrets or
# config exposure — prevents zero-param leak tools from being outranked
# by benign high-param tools.
_HIGH_VALUE_NAME_KEYWORDS: frozenset[str] = frozenset({
    "secret", "credential", "password", "token", "config",
    "leak", "dump", "env", "private", "key",
    # Writable cache tools: sdk.write_cache, set_token_cache, etc. are
    # high-value regardless of param count — they're the write half of MCP-T33.
    "cache", "cached",
})
_HIGH_VALUE_FLOOR: int = 15


def _tool_security_score(tool: dict) -> int:
    """Score a single MCP tool definition for security relevance.

    Higher scores indicate greater likelihood of exploitable behaviour.
    The algorithm intentionally favours tool *name* signals over schema
    complexity so that a zero-param ``server-config`` outranks a
    five-param ``move-to-position``.
    """
    name: str = tool.get("name", "").lower()
    desc: str = tool.get("description", "").lower()
    props: dict = tool.get("inputSchema", {}).get("properties", {})

    score: int = 0

    # --- Keyword tier scoring ---
    for keywords, weight in _KEYWORD_TIERS:
        for kw in keywords:
            if kw in name:
                score += weight * _NAME_MULTIPLIER
            elif kw in desc:
                score += weight * _DESC_MULTIPLIER

    # --- Dangerous parameter names ---
    for pname in props:
        if pname.lower() in _DANGEROUS_PARAM_NAMES:
            score += 8

    # --- Schema complexity (capped to avoid domination by benign tools) ---
    score += min(len(props), 3)

    # --- Floor for high-value tool names ---
    if any(kw in name for kw in _HIGH_VALUE_NAME_KEYWORDS):
        score = max(score, _HIGH_VALUE_FLOOR)

    return score
