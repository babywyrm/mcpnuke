"""Pass, fail, or untested for each vendored threat ID.

fail: a finding in this scan carries the ID.
pass: a check that can attribute the ID has a timing, and none of them fired.
untested: no such check ran. An ID with no check in the tree is untested
until a finding attributes it anyway.

ponytail: an ID attaches to the time_check calls in the same function.
Two checks in one function still share IDs. Split the function to separate them.
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


def _constants(text: str) -> dict[str, str]:
    return {name: value for name, value in _CONST_RE.findall(text)}


def _ids_in(text: str, constants: dict[str, str]) -> set[str]:
    ids = set(_LITERAL_RE.findall(text))
    for name, value in constants.items():
        if re.search(rf"taxonomy_id\s*=\s*{name}\b", text):
            ids.add(value)
    return ids


_CALL_RE: re.Pattern[str] = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def check_taxonomy_catalog() -> dict[str, frozenset[str]]:
    """Map each timing name to the threat IDs that check can attribute.

    An ID counts when it is written in the same function as the
    ``time_check``, or in a same-file helper that function calls and that
    helper has no ``time_check`` of its own.
    """
    catalog: dict[str, set[str]] = defaultdict(set)
    for path in sorted(_CHECKS_DIR.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        constants = _constants(text)
        chunks = re.split(r"(?m)^def ", text)[1:]
        records: list[dict[str, Any]] = []
        for chunk in chunks:
            name_match = re.match(r"(\w+)", chunk)
            records.append(
                {
                    "name": name_match.group(1) if name_match else "",
                    "ids": _ids_in(chunk, constants),
                    "timings": _TIMING_RE.findall(chunk),
                    "calls": set(_CALL_RE.findall(chunk)),
                }
            )
        by_name = {str(record["name"]): record for record in records}
        for record in records:
            timings = record["timings"]
            if not timings:
                continue
            ids = set(record["ids"])
            for called in record["calls"]:
                helper = by_name.get(called)
                if helper and not helper["timings"]:
                    ids.update(helper["ids"])
            for timing in timings:
                catalog[str(timing)].update(ids)
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
