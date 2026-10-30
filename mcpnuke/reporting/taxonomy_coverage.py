"""Pass, fail, or untested for each vendored threat ID.

fail: a finding in this scan carries the ID.
pass: a check that can attribute the ID has a timing, and none of them fired.
untested: no such check ran. An ID with no check in the tree is untested
until a finding attributes it anyway.

ponytail: the catalog is per module. If one module attributes two IDs and
records two timings, either timing marks both IDs tested. Split the module
to make the two checks independent.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from mcpnuke.core.constants import SEVERITY_WEIGHTS
from mcpnuke.core.models import Finding, TargetResult

_CHECKS_DIR: Path = Path(__file__).resolve().parent.parent / "checks"
_LITERAL_RE: re.Pattern[str] = re.compile(r'taxonomy_id\s*=\s*"(MCP-T\d+)"')
_CONST_RE: re.Pattern[str] = re.compile(
    r'^(\w*TAXONOMY\w*)(?:\s*:\s*\w+)?\s*=\s*"(MCP-T\d+)"', re.M
)
_TIMING_RE: re.Pattern[str] = re.compile(r'time_check\(\s*["\']([^"\']+)["\']')


def check_taxonomy_catalog() -> dict[str, frozenset[str]]:
    """Map each recorded timing name to the threat IDs that module can attribute."""
    catalog: dict[str, set[str]] = defaultdict(set)
    for path in sorted(_CHECKS_DIR.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        ids = set(_LITERAL_RE.findall(text))
        for name, value in _CONST_RE.findall(text):
            if re.search(rf"taxonomy_id\s*=\s*{name}\b", text):
                ids.add(value)
        if not ids:
            continue
        timings = _TIMING_RE.findall(text) or [path.stem]
        for timing in timings:
            catalog[timing].update(ids)
    return {name: frozenset(ids) for name, ids in catalog.items()}


def _id_key(threat_id: str) -> tuple[int, str]:
    number = threat_id.removeprefix("MCP-T")
    try:
        return (int(number), threat_id)
    except ValueError:
        return (10**9, threat_id)


def _top_severity(findings: list[Finding]) -> str:
    if not findings:
        return ""
    return max(findings, key=lambda finding: SEVERITY_WEIGHTS.get(finding.severity, 0)).severity


def build_taxonomy_coverage(
    results: list[TargetResult],
    *,
    taxonomy: dict[str, Any],
    catalog: dict[str, frozenset[str]],
) -> dict[str, Any]:
    """One row per threat ID in *taxonomy*, plus any finding ID it does not list."""
    titles = {
        str(threat["threat_id"]): str(threat.get("title", ""))
        for threat in taxonomy.get("threats", [])
        if isinstance(threat, dict) and threat.get("threat_id")
    }
    capable: dict[str, set[str]] = defaultdict(set)
    for timing, ids in catalog.items():
        for threat_id in ids:
            capable[threat_id].add(timing)

    ran: set[str] = set()
    hits: dict[str, list[Finding]] = defaultdict(list)
    for result in results:
        ran.update(result.timings)
        for finding in result.findings:
            if finding.taxonomy_id:
                hits[finding.taxonomy_id].append(finding)

    defined = sorted(titles, key=_id_key)
    rows: list[dict[str, Any]] = []
    for threat_id in defined:
        found = hits.get(threat_id, [])
        if found:
            status = "fail"
        elif capable.get(threat_id, set()) & ran:
            status = "pass"
        else:
            status = "untested"
        rows.append(
            {
                "threat_id": threat_id,
                "title": titles[threat_id],
                "status": status,
                "findings": len(found),
                "severity": _top_severity(found),
            }
        )

    unknown = sorted((threat_id for threat_id in hits if threat_id not in titles), key=_id_key)
    counts = {status: sum(1 for row in rows if row["status"] == status) for status in ("fail", "pass", "untested")}
    return {
        "schema": "v1",
        "threats": rows,
        "unknown": unknown,
        "summary": {"total": len(rows), **counts},
    }


def print_taxonomy_coverage(report: dict[str, Any], console: Any = None) -> None:
    """Render fail and untested in full. Pass is a count plus the IDs."""

    def _w(line: str = "") -> None:
        if console is not None:
            console.print(line)
        else:
            print(line)

    summary = report["summary"]
    _w()
    _w(
        f"Taxonomy coverage: {summary['fail']} fail, {summary['pass']} pass, "
        f"{summary['untested']} untested ({summary['total']} IDs)"
    )
    for status in ("fail", "untested"):
        rows = [row for row in report["threats"] if row["status"] == status]
        if not rows:
            continue
        _w(status.upper())
        for row in rows:
            extra = f"  {row['findings']} {row['severity']}" if row["findings"] else ""
            _w(f"  {row['threat_id']}  {row['title']}{extra}")
    passed = [row["threat_id"] for row in report["threats"] if row["status"] == "pass"]
    if passed:
        _w("PASS  " + " ".join(passed))
    if report["unknown"]:
        _w("UNKNOWN  " + " ".join(report["unknown"]))
