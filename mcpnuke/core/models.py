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


@dataclass
class AttackChain:
    source: str
    target: str
    evidence_tools: list[str] = field(default_factory=list)


@dataclass
class TargetResult:
    url: str
    transport: str = "unknown"
    server_info: dict[str, Any] = field(default_factory=dict)
    auth_context: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    error: str = ""

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
    ) -> Finding | None:
        if skip_transports and self.transport in skip_transports:
            return None
        f = Finding(
            self.url, check, severity, title, detail, evidence,
            lane=lane, transport=transport,
        )
        self.findings.append(f)
        return f

    def risk_score(self) -> int:
        from mcpnuke.core.constants import SEVERITY_WEIGHTS
        return sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in self.findings)
