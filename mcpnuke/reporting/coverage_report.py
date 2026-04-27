"""Cross-project coverage report consuming camazotz /api/lanes schema v1.

Implements the `--coverage-report <url>` CLI flag per
mcpnuke/docs/specs/2026-04-26-by-lane-reporting.md.

Fetches a target camazotz instance's lane taxonomy, intersects it with
mcpnuke's scan findings on that target, and emits a cross-project
report that names every lane the target camazotz declares, whether
mcpnuke's checks fired on it, and the widest coverage gaps.

The schema v1 contract comes from camazotz; any schema drift fails
loudly with clear update guidance.
"""

from __future__ import annotations

from typing import Any

import httpx

from mcpnuke.core.models import TargetResult
from mcpnuke.reporting.by_lane import build_by_lane, LANE_NAMES, LANE_SLUGS


SUPPORTED_SCHEMA = "v1"


class SchemaMismatchError(RuntimeError):
    """Raised when camazotz /api/lanes returns a schema this build doesn't know."""


def fetch_lane_taxonomy(camazotz_url: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """GET <camazotz_url>/api/lanes and validate schema version.

    Raises SchemaMismatchError if the response's `schema` field is not
    a supported version. Raises httpx.HTTPError on network failure.
    """
    base = camazotz_url.rstrip("/")
    endpoint = f"{base}/api/lanes"
    resp = httpx.get(endpoint, timeout=timeout)
    resp.raise_for_status()
    payload = resp.json()
    schema = payload.get("schema")
    if schema != SUPPORTED_SCHEMA:
        raise SchemaMismatchError(
            f"camazotz /api/lanes schema {schema!r} incompatible; "
            f"mcpnuke supports {SUPPORTED_SCHEMA!r}. Update one side."
        )
    return payload


def build_coverage_report(
    results: list[TargetResult],
    taxonomy: dict[str, Any],
) -> dict[str, Any]:
    """Intersect a scan's by-lane findings with a camazotz taxonomy.

    Output shape (schema v1):

        {
          "schema": "v1",
          "camazotz_lanes": 5,
          "camazotz_labs": int,
          "lanes": {
            "1": {
              "slug": "human-direct",
              "name": "Human Direct",
              "camazotz": {
                "primary_count": int,
                "secondary_count": int,
                "transports_present": [...],
                "gaps": [...],
              },
              "mcpnuke": {
                "checks_fired": int,
                "severity_tally": {...},
                "transports_hit": [...],
              },
              "alignment_note": str,  # human-readable gap summary
            },
            ...
          },
          "summary": {
            "lanes_covered_by_mcpnuke": int,
            "lanes_covered_by_camazotz": int,
            "lanes_both": int,
            "widest_gap": str | None,
          },
        }
    """
    by_lane = build_by_lane(results)["by_lane"]
    camazotz_lanes = taxonomy.get("lanes", [])
    camazotz_cov = taxonomy.get("coverage", {})
    labs = taxonomy.get("labs", [])

    out: dict[str, Any] = {
        "schema": "v1",
        "camazotz_lanes": len(camazotz_lanes),
        "camazotz_labs": len(labs),
        "lanes": {},
    }

    lanes_both = 0
    lanes_by_mcpnuke = 0
    lanes_by_camazotz = 0
    widest_gap_id: int | None = None
    widest_gap_size = -1

    for lane in camazotz_lanes:
        lane_id = lane.get("id")
        if lane_id not in (1, 2, 3, 4, 5):
            continue
        cov = camazotz_cov.get(str(lane_id), {})
        mcpnuke_block = by_lane.get(str(lane_id), {})

        primary = cov.get("primary_count", 0)
        fired = mcpnuke_block.get("finding_count", 0)
        if primary:
            lanes_by_camazotz += 1
        if fired:
            lanes_by_mcpnuke += 1
        if primary and fired:
            lanes_both += 1

        # Alignment heuristic: widest gap = lane where camazotz has the
        # most primary labs but mcpnuke fired zero findings.
        if primary and fired == 0 and primary > widest_gap_size:
            widest_gap_size = primary
            widest_gap_id = lane_id

        note_parts: list[str] = []
        if primary == 0 and fired == 0:
            note_parts.append("lane unused by both camazotz and mcpnuke (anonymous lane, by design)" if lane_id == 5 else "lane unused by this target")
        elif primary > 0 and fired == 0:
            note_parts.append(f"camazotz declares {primary} primary lab(s); mcpnuke fired zero findings — check may not exist or is dormant")
        elif primary == 0 and fired > 0:
            note_parts.append("mcpnuke fired findings on a lane camazotz does not cover — scanner ahead of target corpus")
        else:
            cov_gaps = cov.get("gaps", [])
            if cov_gaps:
                note_parts.append(f"target camazotz flags: {', '.join(cov_gaps)}")
            else:
                note_parts.append(f"{primary} lab(s) covered, {fired} finding(s) fired — aligned")

        out["lanes"][str(lane_id)] = {
            "slug": lane.get("slug", LANE_SLUGS.get(lane_id, "")),
            "name": lane.get("name", LANE_NAMES.get(lane_id, "")),
            "camazotz": {
                "primary_count": primary,
                "secondary_count": cov.get("secondary_count", 0),
                "transports_present": cov.get("transports_present", []),
                "gaps": cov.get("gaps", []),
            },
            "mcpnuke": {
                "checks_fired": fired,
                "severity_tally": mcpnuke_block.get("severity_tally", {}),
                "transports_hit": mcpnuke_block.get("transports_hit", []),
            },
            "alignment_note": " · ".join(note_parts),
        }

    out["summary"] = {
        "lanes_covered_by_mcpnuke": lanes_by_mcpnuke,
        "lanes_covered_by_camazotz": lanes_by_camazotz,
        "lanes_both": lanes_both,
        "widest_gap": (
            f"Lane {widest_gap_id} ({LANE_SLUGS.get(widest_gap_id, '')})"
            if widest_gap_id is not None else None
        ),
    }
    return out


def print_coverage_report(report: dict[str, Any], console=None) -> None:
    """Render the coverage report to console."""
    def _w(line: str = "") -> None:
        if console is not None:
            console.print(line)
        else:
            print(line)

    summary = report.get("summary", {})
    _w()
    _w("[bold]── Cross-project coverage report (vs camazotz) ──[/bold]" if console else
       "── Cross-project coverage report (vs camazotz) ──")
    _w(f"  camazotz: {report['camazotz_labs']} labs across {report['camazotz_lanes']} lanes")
    _w(f"  mcpnuke covered {summary['lanes_covered_by_mcpnuke']}/5 lanes on this scan")
    if summary.get("widest_gap"):
        if console is not None:
            _w(f"  [yellow]widest gap: {summary['widest_gap']} — camazotz declares labs, mcpnuke fired none[/yellow]")
        else:
            _w(f"  widest gap: {summary['widest_gap']} — camazotz declares labs, mcpnuke fired none")

    for lane_id in (1, 2, 3, 4, 5):
        key = str(lane_id)
        block = report.get("lanes", {}).get(key)
        if not block:
            continue
        _w()
        header = f"Lane {lane_id} — {block['name']}"
        if console is not None:
            _w(f"[bold cyan]{header}[/]")
        else:
            _w(header)
        cz = block["camazotz"]
        mn = block["mcpnuke"]
        _w(f"  camazotz: {cz['primary_count']} primary lab(s), transports "
           f"[{', '.join(cz['transports_present']) or '-'}]"
           + (f", gaps: {', '.join(cz['gaps'])}" if cz['gaps'] else ""))
        tally = mn["severity_tally"]
        tally_s = ", ".join(f"{s}={n}" for s, n in tally.items()) if tally else "none"
        _w(f"  mcpnuke:  {mn['checks_fired']} finding(s) fired ({tally_s})"
           + (f", transports [{', '.join(mn['transports_hit'])}]" if mn['transports_hit'] else ""))
        if console is not None:
            _w(f"  [dim]{block['alignment_note']}[/]")
        else:
            _w(f"  {block['alignment_note']}")
