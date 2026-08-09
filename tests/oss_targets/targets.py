"""The pinned target set.

One table so "what did we measure" has a single answer. Versions are exact:
an unpinned target makes every snapshot unreproducible and every diff
ambiguous between "we changed" and "they changed".

server-git and server-fetch are Python packages on PyPI, not npm. Every
version below was read from the registry on 2026-08-09, not assumed. If a
registry has moved on by the time you run this, update the pin and re-capture
the snapshot rather than leaving the two out of step.

Both uvx targets also pin the `mcp` SDK. Left to resolve freely, uvx installs
the newest SDK, and neither server survives the 2.0 breaking changes:
server-git dies with `'Server' object has no attribute 'list_tools'` and
server-fetch with `cannot import name 'McpError'`. mcpnuke correctly reported
"No response to MCP initialize" for both — accurate, but it measures a crashed
process rather than a false-positive rate.
"""

from __future__ import annotations

from dataclasses import dataclass

# Last 1.x SDK. The uvx servers below predate the 2.0 renames and crash on it.
_SDK_PIN = "1.29.0"


@dataclass(frozen=True)
class Target:
    name: str
    launcher: str  # "npx" or "uvx"
    version: str
    command: str
    why: str


TARGETS: dict[str, Target] = {
    "server-everything": Target(
        name="server-everything",
        launcher="npx",
        version="2026.7.4",
        command="npx -y @modelcontextprotocol/server-everything@2026.7.4",
        why="Exercises every MCP feature. 13 tools, 7 resources, 4 prompts — "
        "the only target with resources and prompts.",
    ),
    "server-filesystem": Target(
        name="server-filesystem",
        launcher="npx",
        version="2026.7.10",
        command="npx -y @modelcontextprotocol/server-filesystem@2026.7.10 /tmp",
        why="Genuinely reads files. Tests whether capability findings are "
        "proportionate to real capability.",
    ),
    "server-memory": Target(
        name="server-memory",
        launcher="npx",
        version="2026.7.4",
        command="npx -y @modelcontextprotocol/server-memory@2026.7.4",
        why="Deliberately boring. A server with almost no surface should be "
        "almost silent.",
    ),
    "server-git": Target(
        name="server-git",
        launcher="uvx",
        version="2026.7.10",
        command=(
            f"uvx --with 'mcp=={_SDK_PIN}' mcp-server-git@2026.7.10 --repository ."
        ),
        why="Real repository access; a different capability shape.",
    ),
    "server-fetch": Target(
        name="server-fetch",
        launcher="uvx",
        version="2026.7.10",
        command=f"uvx --with 'mcp=={_SDK_PIN}' mcp-server-fetch@2026.7.10",
        why="Real outbound fetch — the honest comparison against our own "
        "hardened http.fetch.",
    ),
}
