"""JSON report output."""

import json
from datetime import datetime, timezone
from collections import Counter

from mcpnuke.core.models import TargetResult
from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS


def _build_target_dict(r: TargetResult) -> dict:
    return {
        "url": r.url,
        "transport": r.transport,
        "risk_score": r.risk_score(),
        "tools": [t.get("name") for t in r.tools],
        "timings": r.timings,
        "findings": [
            {
                "check": f.check,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
            }
            for f in r.findings
        ],
        "attack_chains": [
            {"source": c.source, "target": c.target} for c in r.attack_chains
        ],
    }


def write_json(results: list[TargetResult], path: str, console=None):
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
        "k8s_findings": [
            {
                "check": f.check,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
            }
            for f in GLOBAL_K8S_FINDINGS
        ],
    }
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)
    if console:
        console.print(f"\n[green]JSON report written → {path}[/green]")
