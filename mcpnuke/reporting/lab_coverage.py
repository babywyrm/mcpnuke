"""Which labs in a target profile have a check that can attribute their threat.

A lab is the tool-name prefix before the first dot. ``agent_http_bypass.call``
and ``agent_http_bypass.get_access_log`` are one lab. A name with no dot is
its own lab. The check side is the taxonomy catalog: a timing name that
attributes the lab's threat ID.
"""

from __future__ import annotations

from typing import Any


def _lab_name(tool_name: str) -> str:
    return tool_name.split(".", 1)[0]


def _checks_for(threat_id: str, catalog: dict[str, frozenset[str]]) -> list[str]:
    return sorted(name for name, ids in catalog.items() if threat_id in ids)


def build_lab_coverage(
    profile: dict[str, Any],
    catalog: dict[str, frozenset[str]],
) -> dict[str, Any]:
    """One row per lab. ``gap`` is true when none of its threat IDs have a check."""
    labs: dict[str, dict[str, Any]] = {}
    unmapped = 0
    for tool in profile.get("tools", []):
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name", ""))
        threat_id = str(tool.get("threat_id", "") or "")
        if not name or not threat_id:
            unmapped += 1
            continue
        lab = _lab_name(name)
        row = labs.setdefault(
            lab,
            {"lab": lab, "tools": 0, "threat_ids": set(), "checks": set()},
        )
        row["tools"] += 1
        row["threat_ids"].add(threat_id)
        row["checks"].update(_checks_for(threat_id, catalog))

    rows: list[dict[str, Any]] = []
    for lab in sorted(labs):
        row = labs[lab]
        checks = sorted(row["checks"])
        rows.append(
            {
                "lab": lab,
                "tools": row["tools"],
                "threat_ids": sorted(row["threat_ids"]),
                "checks": checks,
                "gap": not checks,
            }
        )
    return {
        "name": str(profile.get("name", "")),
        "labs": rows,
        "summary": {
            "labs": len(rows),
            "gaps": sum(1 for row in rows if row["gap"]),
            "unmapped": unmapped,
        },
    }


def print_lab_coverage(report: dict[str, Any], console: Any = None) -> None:
    """Print gap labs in full. Covered labs are one line each."""

    def _w(line: str = "") -> None:
        if console is not None:
            console.print(line)
        else:
            print(line)

    summary = report["summary"]
    _w(
        f"{report['name']}: {summary['labs']} labs, {summary['gaps']} with no check, "
        f"{summary['unmapped']} tools unmapped"
    )
    for row in report["labs"]:
        threats = " ".join(row["threat_ids"])
        if row["gap"]:
            _w(f"  GAP  {row['lab']}  {row['tools']} tools  {threats}")
        else:
            _w(f"  {row['lab']}  {row['tools']} tools  {threats}  {', '.join(row['checks'])}")
