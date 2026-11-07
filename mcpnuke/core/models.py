"""Data models for scan results."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypedDict

from mcpnuke.patterns.credentials import redact_credentials

if TYPE_CHECKING:
    # Import-only: reporting.diff imports this module, so a runtime import
    # here would be circular.
    from mcpnuke.core.oast import CanaryListener
    from mcpnuke.profile import ProfileData
    from mcpnuke.reporting.diff import ScanDiffResult


class ProbeOpts(TypedDict, total=False):
    """Scan options every check receives. A plain dict at runtime.

    Typed so a misspelled key or a wrong value type fails mypy instead of
    reading as None and silently switching a probe off.
    """

    # Built from the CLI by cli_steps._base_probe_opts.
    no_invoke: bool
    safe_mode: bool
    probe_calls: bool
    max_pages: int
    protocol_mode: str
    jwt_max_ttl: int
    tool_names_file: str | None
    claude: bool
    chain_replay: bool
    chain_replay_retries: int
    cross_server: bool
    claude_model: str
    claude_max_tools: int
    claude_phase2_workers: int
    ollama_analysis: str | None
    ollama_model: str
    ollama_ensemble: str | None
    fast: bool
    coverage_n: int
    probe_workers: int
    deterministic: bool
    tls_verify: bool
    extra_headers: dict[str, str] | None
    inference_host: str | None
    inference_scan: bool
    inference_baseline: str | None
    save_inference_baseline: str | None
    error_reflection: str
    # Added by the scan entry points.
    trust_sets: list[list[str]]
    target_count: int
    auth_context_summary: dict[str, Any]
    profile: ProfileData | None
    oast: CanaryListener
    oast_wait: float
    # Set during run_all_checks and shared between checks.
    _log: Callable[[str], None]
    _response_cache: dict[str, str]
    # Test seam for protected_resource_metadata.
    get_json: Callable[[str], dict[str, Any] | None]


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
    # mcpnuke/docs/superpowers/specs/2026-04-26-by-lane-reporting.md
    lane: int | None = None
    transport: str | None = None
    taxonomy_id: str = ""
    mitre_id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.evidence, str):
            self.evidence = redact_credentials(self.evidence)
        if self.taxonomy_id and (self.lane is None or self.transport is None):
            try:
                from mcpnuke.core.taxonomy import threat_metadata
                meta = threat_metadata(self.taxonomy_id)
                if meta:
                    if self.lane is None and "lane" in meta:
                        self.lane = meta["lane"]
                    if self.transport is None and "transport" in meta:
                        self.transport = meta["transport"]
            except Exception:
                pass



@dataclass
class AttackChain:
    source: str
    target: str
    evidence_tools: list[str] = field(default_factory=list)
    # Tools implicated by both ends. Non-empty is the one case where the two
    # findings are known to meet; empty means either no shared tool or a
    # target-scoped finding that names none, which `linkage` distinguishes.
    shared_tools: list[str] = field(default_factory=list)
    linkage: str = "co-occurrence"


@dataclass
class TargetResult:
    url: str
    transport: str = "unknown"
    protocol_mode: str = "unknown"
    server_info: dict[str, Any] = field(default_factory=dict)
    auth_context: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    # Full tools/list surface. ``tools`` becomes the --fast/--coverage sample
    # after run_all_checks; inventory, --save-baseline, and --baseline hash this.
    tools_enumerated: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    list_cache: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    error: str = ""
    tools_total: int = 0
    # Only ever a reporting.diff.ScanDiffResult. Typed as object it forced
    # every reader to guess, and json_out reached for four attributes mypy
    # could not confirm existed.
    scan_diff: ScanDiffResult | None = None

    def catalog_tools(self) -> list[dict[str, Any]]:
        """Enumerated tool surface, even when ``tools`` is a coverage sample."""
        return self.tools_enumerated if self.tools_enumerated else self.tools

    def scanned_anonymously(self) -> bool:
        """True when this scan carried no credential of any kind.

        Any finding phrased as "unauthenticated X succeeded" must gate on this.
        Reporting that a server accepts anonymous access when the scanner in
        fact authenticated tells an operator their access control is broken when
        it is working, and the report gives them no way to tell otherwise.
        """
        auth = self.auth_context or {}
        if auth.get("_raw_token") or auth.get("jwt_claims_summary"):
            return False
        return not (auth.get("oidc_url") or auth.get("introspection_active"))

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
