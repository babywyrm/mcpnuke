"""Per-lane grouping + reporting for scan findings.

Implements the `--by-lane` CLI flag per
mcpnuke/docs/specs/2026-04-26-by-lane-reporting.md.

Groups a list of TargetResult findings by agentic-identity lane
(1..5) and surfaces a per-lane severity tally plus the transports
each lane actually hit during the scan. Findings with `lane=None`
report under an "Uncategorized" bucket.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from mcpnuke.core.models import Finding, TargetResult

# Canonical lane vocabulary — must match camazotz /api/lanes schema v1
# and agentic-sec/docs/identity-flows.md.
LANE_SLUGS: dict[int, str] = {
    1: "human-direct",
    2: "delegated",
    3: "machine",
    4: "chain",
    5: "anonymous",
}
LANE_NAMES: dict[int, str] = {
    1: "Human Direct",
    2: "Delegated",
    3: "Machine Identity",
    4: "Agent → Agent",
    5: "Anonymous",
}
VALID_LANES: frozenset[int] = frozenset(LANE_SLUGS)


def _tally(findings: Iterable[Finding]) -> dict[str, int]:
    """Count severities across a flat list of findings."""
    c: Counter[str] = Counter()
    for f in findings:
        c[f.severity] += 1
    # Return in canonical order, even when counts are zero, so consumers
    # can rely on the shape.
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    return {k: c.get(k, 0) for k in order if c.get(k, 0) > 0} | {
        k: 0 for k in order if c.get(k, 0) == 0
    }


def _order_severities(tally: dict[str, int]) -> dict[str, int]:
    """Return tally in canonical severity order, hiding zero entries."""
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    return {k: tally[k] for k in order if tally.get(k, 0) > 0}


def build_by_lane(results: list[TargetResult]) -> dict[str, Any]:
    """Group findings from all targets by lane.

    Returns a versioned dict:

        {
          "schema": "v1",
          "by_lane": {
            "1": {"slug": "human-direct", "name": "Human Direct",
                  "transports_hit": ["A", "B"], "findings": [...],
                  "severity_tally": {"CRITICAL": 2, "HIGH": 1}},
            ...,
            "uncategorized": {"findings": [...], "severity_tally": {...}},
          },
          "total_findings": int,
        }
    """
    by_lane: dict[int, list[Finding]] = defaultdict(list)
    uncategorized: list[Finding] = []
    transports_per_lane: dict[int, set[str]] = defaultdict(set)

    for r in results:
        for f in r.findings:
            if f.lane in VALID_LANES:
                by_lane[f.lane].append(f)
                if f.transport:
                    transports_per_lane[f.lane].add(f.transport)
            else:
                uncategorized.append(f)

    out: dict[str, Any] = {"schema": "v1", "by_lane": {}}
    total = 0
    for lane_id in sorted(VALID_LANES):
        findings = by_lane.get(lane_id, [])
        total += len(findings)
        out["by_lane"][str(lane_id)] = {
            "slug": LANE_SLUGS[lane_id],
            "name": LANE_NAMES[lane_id],
            "transports_hit": sorted(transports_per_lane.get(lane_id, set())),
            "finding_count": len(findings),
            "severity_tally": _order_severities(_tally(findings)),
            "findings": [
                {
                    "target": f.target,
                    "check": f.check,
                    "severity": f.severity,
                    "title": f.title,
                    "transport": f.transport,
                }
                for f in findings
            ],
        }
    if uncategorized:
        out["by_lane"]["uncategorized"] = {
            "finding_count": len(uncategorized),
            "severity_tally": _order_severities(_tally(uncategorized)),
            "findings": [
                {
                    "target": f.target,
                    "check": f.check,
                    "severity": f.severity,
                    "title": f.title,
                }
                for f in uncategorized
            ],
        }
        total += len(uncategorized)
    out["total_findings"] = total
    return out


def print_by_lane(results: list[TargetResult], console=None) -> None:
    """Render the by-lane report to a Rich console (or stdout)."""
    from mcpnuke.core.constants import SEV_COLOR

    report = build_by_lane(results)
    total = report["total_findings"]

    def _write(line: str = "") -> None:
        if console is not None:
            console.print(line)
        else:
            print(line)

    _write()
    _write(f"[bold]── Findings grouped by identity lane "
           f"({total} total) ──[/bold]" if console else
           f"── Findings grouped by identity lane ({total} total) ──")

    for lane_id in (1, 2, 3, 4, 5):
        key = str(lane_id)
        block = report["by_lane"].get(key, {})
        count = block.get("finding_count", 0)
        name = block.get("name", LANE_NAMES[lane_id])
        transports = block.get("transports_hit", [])
        transport_s = "+".join(transports) if transports else "-"
        if console is not None:
            header = (
                f"\n[bold cyan]Lane {lane_id} — {name}[/] "
                f"(slug={LANE_SLUGS[lane_id]}, transport={transport_s})"
            )
            _write(header)
        else:
            _write(f"\nLane {lane_id} — {name} (slug={LANE_SLUGS[lane_id]}, transport={transport_s})")

        if count == 0:
            _write("  (no findings fired)")
            continue
        tally = block.get("severity_tally", {})
        tally_s = ", ".join(f"{s}={n}" for s, n in tally.items())
        _write(f"  {count} finding(s): {tally_s}")
        for f in block["findings"][:20]:
            sev = f["severity"]
            if console is not None:
                color = SEV_COLOR.get(sev, "dim")
                _write(f"    [{color}]{sev:8s}[/] {f['check']:25s} {f['title']}")
            else:
                _write(f"    {sev:8s} {f['check']:25s} {f['title']}")
        if len(block["findings"]) > 20:
            _write(f"    ... and {len(block['findings']) - 20} more")

    uncat = report["by_lane"].get("uncategorized")
    if uncat:
        _write()
        if console is not None:
            _write(f"[bold]Uncategorized[/] (no lane scope — {uncat['finding_count']} finding(s))")
        else:
            _write(f"Uncategorized (no lane scope — {uncat['finding_count']} finding(s))")
        for f in uncat["findings"][:10]:
            _write(f"    {f['severity']:8s} {f['check']:25s} {f['title']}")
