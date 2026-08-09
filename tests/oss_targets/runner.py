"""Launch a pinned target, scan it with the real pipeline, normalize the result."""

from __future__ import annotations

import shutil

from mcpnuke.scanner import scan_stdio_target
from tests.oss_targets.targets import Target


def launcher_available(launcher: str) -> bool:
    return shutil.which(launcher) is not None


def scan_target(target: Target, timeout: float = 60.0) -> list[dict]:
    """Scan *target* and return its normalized finding set.

    Calls scan_stdio_target — the same function --stdio uses — rather than
    reassembling the pipeline. A harness that drives a private path measures
    that path, not the product: the HTTP fixture made exactly that mistake by
    omitting the auth_context the CLI always sets, and fabricated three
    findings.
    """
    result = scan_stdio_target(target.command, timeout=timeout)
    return normalize_findings(result.findings)


def normalize_findings(findings: list) -> list[dict]:
    """Reduce findings to the fields that are stable across runs.

    Elapsed times, temp paths and PIDs vary every run; a snapshot containing
    them would never match twice. Evidence blobs are dropped entirely — they
    are large, and they carry both.
    """
    rows = [
        {"check": f.check, "severity": f.severity, "title": f.title} for f in findings
    ]
    rows.sort(key=lambda r: (r["check"], r["severity"], r["title"]))
    return rows
