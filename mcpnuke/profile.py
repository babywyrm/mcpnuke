"""Profile system for target-aware scan enrichment.

A profile is a simple JSON file (hand-writable in 5 minutes) that maps
tool names to security metadata: lane, transport surface, threat ID, and
freeform notes.  Profiles are *optional* — mcpnuke works fully without one
via auto-discovery.  A profile fills threat ID, lane, and transport on
findings for the tools it names, where the check set none.

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
import re
from dataclasses import dataclass, field
from pathlib import Path

from mcpnuke.core.models import TargetResult
from mcpnuke.policy.generator import _extract_tool_name

_QUOTED_RE: re.Pattern[str] = re.compile(r"'([^']+)'")


@dataclass
class ProfileData:
    name: str
    version: str = "1"
    description: str = ""
    tools: list[dict] = field(default_factory=list)
    # Built index: tool_name -> tool dict
    _index: dict[str, dict] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
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


def attribute_findings(profile: ProfileData, results: list[TargetResult]) -> None:
    """Fill threat ID, lane, and transport from the profile where a finding has none."""
    for r in results:
        for f in r.findings:
            names = [_extract_tool_name(f), f.evidence, *_QUOTED_RE.findall(f.title)]
            tool = next((t for n in names if (t := _get_tool(profile, n))), None)
            if tool is None:
                continue
            if not f.taxonomy_id:
                f.taxonomy_id = tool.get("threat_id", "") or ""
            if f.lane is None and tool.get("lane") is not None:
                f.lane = int(tool["lane"])
            if f.transport is None:
                f.transport = tool.get("transport") or None
