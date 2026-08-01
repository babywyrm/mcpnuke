"""Data models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    target: str
    check: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""
    # Agentic identity lane (1..5) and transport surface (A|B|C) this
    # finding is scoped to. None = not lane-scoped (e.g. generic TLS hygiene).
    # Vocabulary source: camazotz/frontend/lane_taxonomy.py::LANES (schema v1)
    # via agentic-sec/docs/identity-flows.md. See also:
    # mcpnuke/docs/specs/2026-04-26-by-lane-reporting.md
    lane: int | None = None
    transport: str | None = None
    taxonomy_id: str = ""
    mitre_id: str = ""


@dataclass
class AttackChain:
    source: str
    target: str
    evidence_tools: list[str] = field(default_factory=list)


@dataclass
class TargetResult:
    url: str
    transport: str = "unknown"
    protocol_mode: str = "unknown"
    server_info: dict[str, Any] = field(default_factory=dict)
    auth_context: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    error: str = ""
    tools_total: int = 0
    scan_diff: object | None = None

    def add(
        self,
        check: str,
        severity: str,
        title: str,
        detail: str = "",
        evidence: str = "",
        skip_transports: list[str] | None = None,
        *,
        lane: int | None = None,
        transport: str | None = None,
        taxonomy_id: str = "",
        mitre_id: str = "",
    ) -> Finding | None:
        if skip_transports and self.transport in skip_transports:
            return None
        f = Finding(
            self.url, check, severity, title, detail, evidence,
            lane=lane, transport=transport,
            taxonomy_id=taxonomy_id, mitre_id=mitre_id,
        )
        self.findings.append(f)
        return f

    def note_error(self, msg: str) -> None:
        """Record a non-fatal error, keeping ``error`` a flat semicolon-joined str.

        Callers that hit a recoverable failure mid-scan use this instead of
        assigning ``error`` directly, so one probe's failure cannot discard an
        earlier one. ``error`` stays a string because reporting and scoring
        read it as one.
        """
        self.error = f"{self.error}; {msg}" if self.error else msg

    def risk_score(self) -> int:
        from mcpnuke.core.constants import SEVERITY_WEIGHTS
        return sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in self.findings)
