"""Profile system for target-aware scan enrichment.

A profile is a simple JSON file (hand-writable in 5 minutes) that maps
tool names to security metadata: lane, transport surface, threat ID, and
freeform notes.  Profiles are *optional* — mcpnuke works fully without one
via auto-discovery.  A profile just upgrades the quality of AI prompts and
lane/transport attribution on findings.

Schema
------
{
  "name": "<target-name>",           // required
  "version": "1",                    // optional, for future compat
  "description": "...",              // optional human note
  "tools": [
    {
      "name": "tool_name",           // required - exact MCP tool name
      "lane": 2,                     // optional int 1..5
      "transport": "A",              // optional str A|B|C|D
      "threat_id": "MCP-T06",        // optional OWASP MCP threat ID
      "notes": "free text"           // optional context for AI prompts
    }
  ]
}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProfileData:
    name: str
    version: str = "1"
    description: str = ""
    tools: list[dict] = field(default_factory=list)
    # Built index: tool_name -> tool dict
    _index: dict[str, dict] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        self._index = {t["name"]: t for t in self.tools if "name" in t}


def load_profile(path: str) -> ProfileData:
    """Load and validate a profile JSON file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Profile not found: {path}")
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid profile JSON at {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Profile must be a JSON object, got {type(data).__name__}: {path}")
    if "name" not in data:
        raise ValueError(f"Profile missing required 'name' field: {path}")

    return ProfileData(
        name=data["name"],
        version=str(data.get("version", "1")),
        description=data.get("description", ""),
        tools=data.get("tools", []),
    )


def _get_tool(profile: ProfileData, tool_name: str) -> dict | None:
    return profile._index.get(tool_name)


def lane_for(profile: ProfileData, tool_name: str) -> int | None:
    """Return the lane number for a tool, or None if not in profile."""
    t = _get_tool(profile, tool_name)
    if t is None:
        return None
    val = t.get("lane")
    return int(val) if val is not None else None


def transport_for(profile: ProfileData, tool_name: str) -> str | None:
    """Return the transport surface (A|B|C|D) for a tool, or None."""
    t = _get_tool(profile, tool_name)
    if t is None:
        return None
    return t.get("transport") or None


def threat_id_for(profile: ProfileData, tool_name: str) -> str:
    """Return the OWASP MCP threat ID for a tool, or empty string."""
    t = _get_tool(profile, tool_name)
    if t is None:
        return ""
    return t.get("threat_id", "") or ""


def notes_for(profile: ProfileData, tool_name: str) -> str:
    """Return freeform notes for a tool, or empty string."""
    t = _get_tool(profile, tool_name)
    if t is None:
        return ""
    return t.get("notes", "") or ""


def enrich_tool(profile: ProfileData, tool: dict) -> dict:
    """Return a shallow copy of tool dict enriched with profile metadata."""
    name = tool.get("name", "")
    enriched = dict(tool)
    lane = lane_for(profile, name)
    tr = transport_for(profile, name)
    tid = threat_id_for(profile, name)
    n = notes_for(profile, name)
    if lane is not None:
        enriched["_profile_lane"] = lane
    if tr is not None:
        enriched["_profile_transport"] = tr
    if tid:
        enriched["_profile_threat_id"] = tid
    if n:
        enriched["_profile_notes"] = n
    return enriched
