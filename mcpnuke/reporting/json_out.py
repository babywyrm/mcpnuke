"""JSON report output."""

import json
from datetime import datetime, timezone
from collections import Counter

from mcpnuke.core.models import TargetResult
from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS


def _build_target_dict(r: TargetResult) -> dict:
    tools_total = r.tools_total if r.tools_total > 0 else len(r.tools)
    tools_scanned = len(r.tools)
    d = {
        "url": r.url,
        "transport": r.transport,
        "risk_score": r.risk_score(),
        "auth_context": r.auth_context,
        "tools_total": tools_total,
        "tools_scanned": tools_scanned,
        "tools_scanned_names": [t.get("name") for t in r.tools],
        "tools_unscanned_count": max(0, tools_total - tools_scanned),
        "timings": r.timings,
        "findings": [
            {
                "check": f.check,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "lane": f.lane,
                "transport": f.transport,
                "taxonomy_id": getattr(f, "taxonomy_id", ""),
                "mitre_id": getattr(f, "mitre_id", ""),
            }
            for f in r.findings
        ],
        "attack_chains": [
            {
                "source": c.source,
                "target": c.target,
                "evidence_tools": c.evidence_tools,
            }
            for c in r.attack_chains
        ],
    }
    if r.scan_diff is not None:
        diff = r.scan_diff
        d["diff"] = {
            "new": [
                {"check": f.check, "severity": f.severity, "title": f.title}
                for f in diff.new_findings
            ],
            "resolved": [
                {"check": f.check, "severity": f.severity, "title": f.title}
                for f in diff.resolved_findings
            ],
            "severity_changes": diff.severity_changes,
            "unchanged_count": diff.unchanged_count,
        }
    return d


def build_report(results: list[TargetResult], *, include_k8s: bool = True) -> dict:
    """Assemble the full JSON report as a plain dict.

    This is the in-memory counterpart to :func:`write_json` — same schema,
    no file I/O — so embedders (e.g. the mcpnuke-runner service) can return
    structured results over an API without touching disk.
    """
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "targets": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "severity_counts": dict(
                Counter(
                    f.severity for r in results for f in r.findings
                )
            ),
        },
        "targets": [_build_target_dict(r) for r in results],
    }
    if include_k8s:
        report["k8s_findings"] = [
            {
                "check": f.check,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
            }
            for f in GLOBAL_K8S_FINDINGS
        ]
    return report


def write_json(results: list[TargetResult], path: str, console=None):
    report = build_report(results)
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    if console:
        console.print(f"\n[green]JSON report written → {path}[/green]")
