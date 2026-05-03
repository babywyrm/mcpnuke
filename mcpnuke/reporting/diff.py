"""Scan diff engine: compare two TargetResult or two JSON scan files."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcpnuke.core.models import Finding, TargetResult


@dataclass
class ScanDiffResult:
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    severity_changes: list[dict[str, Any]] = field(default_factory=list)
    unchanged_count: int = 0


def _finding_key(f: Finding) -> str:
    """Canonical key for deduplication across scans."""
    return f"{f.check}:{f.title}"


def compare_scans(before: TargetResult, after: TargetResult) -> ScanDiffResult:
    """Diff two in-memory TargetResult objects."""
    before_map: dict[str, Finding] = {_finding_key(f): f for f in before.findings}
    after_map: dict[str, Finding] = {_finding_key(f): f for f in after.findings}

    new_findings: list[Finding] = []
    resolved_findings: list[Finding] = []
    severity_changes: list[dict[str, Any]] = []
    unchanged_count = 0

    for key, f in after_map.items():
        if key not in before_map:
            new_findings.append(f)
        else:
            prev = before_map[key]
            if prev.severity != f.severity:
                severity_changes.append({
                    "title": f.title,
                    "check": f.check,
                    "before": prev.severity,
                    "after": f.severity,
                })
            else:
                unchanged_count += 1

    for key, f in before_map.items():
        if key not in after_map:
            resolved_findings.append(f)

    return ScanDiffResult(
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        severity_changes=severity_changes,
        unchanged_count=unchanged_count,
    )


def _load_target_from_json(path: str) -> TargetResult:
    """Load the first target from an mcpnuke JSON output file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Scan file not found: {path}")
    data = json.loads(p.read_text())
    targets = data.get("targets", [])
    if not targets:
        return TargetResult(url="unknown")
    t = targets[0]
    result = TargetResult(
        url=t.get("url", "unknown"),
        transport=t.get("transport", "unknown"),
    )
    for fd in t.get("findings", []):
        result.findings.append(Finding(
            target=result.url,
            check=fd.get("check", ""),
            severity=fd.get("severity", "MEDIUM"),
            title=fd.get("title", ""),
            detail=fd.get("detail", ""),
            evidence=fd.get("evidence", ""),
            lane=fd.get("lane"),
            transport=fd.get("transport"),
            taxonomy_id=fd.get("taxonomy_id", ""),
            mitre_id=fd.get("mitre_id", ""),
        ))
    return result


def compare_json_files(before_path: str, after_path: str) -> ScanDiffResult:
    """Diff two mcpnuke JSON output files."""
    before = _load_target_from_json(before_path)
    after = _load_target_from_json(after_path)
    return compare_scans(before, after)


def format_diff_terminal(diff: ScanDiffResult) -> str:
    """Format a ScanDiffResult as a human-readable terminal string."""
    lines: list[str] = []

    if diff.new_findings:
        lines.append(f"NEW ({len(diff.new_findings)}):")
        for f in diff.new_findings:
            lines.append(f"  + [{f.severity}] {f.title} ({f.check})")
    else:
        lines.append("No new findings.")

    if diff.resolved_findings:
        lines.append(f"\nRESOLVED ({len(diff.resolved_findings)}):")
        for f in diff.resolved_findings:
            lines.append(f"  - [{f.severity}] {f.title} ({f.check})")

    if diff.severity_changes:
        lines.append(f"\nSEVERITY CHANGES ({len(diff.severity_changes)}):")
        for sc in diff.severity_changes:
            lines.append(f"  ~ {sc['title']}: {sc['before']} -> {sc['after']}")

    if diff.unchanged_count:
        lines.append(f"\n{diff.unchanged_count} unchanged finding(s) carried over.")

    return "\n".join(lines)
