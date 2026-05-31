"""SARIF 2.1.0 export for GitHub Code Scanning and IDE integration."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from mcpnuke import __version__
from mcpnuke.core.models import TargetResult

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_SECURITY_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
}


def _make_rule(check: str, title: str, severity: str, detail: str, taxonomy_id: str, mitre_id: str) -> dict[str, Any]:
    tags: list[str] = ["security", "mcp"]
    if taxonomy_id:
        tags.append(taxonomy_id)
    if mitre_id:
        tags.append(mitre_id)
    return {
        "id": check,
        "name": check.replace("_", " ").title().replace(" ", ""),
        "shortDescription": {"text": title},
        "fullDescription": {"text": detail or title},
        "defaultConfiguration": {
            "level": _SEVERITY_MAP.get(severity.upper(), "warning"),
        },
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY_MAP.get(severity.upper(), "5.0"),
        },
        "helpUri": f"https://github.com/babywyrm/mcpnuke/blob/main/mcpnuke/checks/{check}.py",
    }


def build_sarif(results: list[TargetResult]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from scan results."""
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for target in results:
        for finding in target.findings:
            rule_id = finding.check
            if rule_id not in rules:
                rules[rule_id] = _make_rule(
                    check=rule_id,
                    title=finding.title,
                    severity=finding.severity,
                    detail=finding.detail,
                    taxonomy_id=getattr(finding, "taxonomy_id", ""),
                    mitre_id=getattr(finding, "mitre_id", ""),
                )

            message_parts = [finding.detail or finding.title]
            if finding.evidence:
                message_parts.append(f"Evidence: {finding.evidence}")
            if getattr(finding, "taxonomy_id", ""):
                message_parts.append(f"Taxonomy: {finding.taxonomy_id}")

            sarif_results.append({
                "ruleId": rule_id,
                "level": _SEVERITY_MAP.get(finding.severity.upper(), "warning"),
                "message": {"text": " | ".join(message_parts)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target.url,
                                "uriBaseId": "%SRCROOT%",
                            },
                        },
                        "logicalLocations": [
                            {
                                "name": target.url,
                                "kind": "module",
                            }
                        ],
                    }
                ],
                "properties": {
                    "severity": finding.severity,
                    "transport": finding.transport or target.transport,
                    "lane": finding.lane,
                    "taxonomy_id": getattr(finding, "taxonomy_id", ""),
                    "mitre_id": getattr(finding, "mitre_id", ""),
                },
            })

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpnuke",
                        "version": __version__,
                        "informationUri": "https://github.com/babywyrm/mcpnuke",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }


def write_sarif(results: list[TargetResult], path: str, console=None) -> None:
    """Write SARIF 2.1.0 report to path."""
    sarif = build_sarif(results)
    with open(path, "w") as fh:
        json.dump(sarif, fh, indent=2)
    if console:
        console.print(f"\n[green]SARIF report written → {path}[/green]")
