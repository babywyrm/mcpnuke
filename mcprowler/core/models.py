"""Data models for scan results."""

from dataclasses import dataclass, field

from mcprowler.core.constants import SEV_COLOR


@dataclass
class Finding:
    target: str
    check: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""


@dataclass
class TargetResult:
    url: str
    transport: str = "unknown"
    server_info: dict = field(default_factory=dict)
    tools: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    prompts: list = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    error: str = ""

    def add(
        self,
        check: str,
        severity: str,
        title: str,
        detail: str = "",
        evidence: str = "",
    ) -> Finding:
        f = Finding(self.url, check, severity, title, detail, evidence)
        self.findings.append(f)
        return f

    def risk_score(self) -> int:
        from mcprowler.core.constants import SEVERITY_WEIGHTS
        return sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in self.findings)
