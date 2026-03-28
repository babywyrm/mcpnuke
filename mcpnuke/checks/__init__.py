"""Security check registry and runner."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from mcpnuke.core.models import TargetResult

_log_internal = logging.getLogger("mcpnuke.checks")
from mcpnuke.checks.injection import (
    check_prompt_injection,
    check_tool_poisoning,
    check_indirect_injection,
)
from mcpnuke.checks.permissions import (
    check_excessive_permissions,
    check_schema_risks,
)
from mcpnuke.checks.behavioral import (
    check_rug_pull,
    check_deep_rug_pull,
    check_state_mutation,
    check_notification_abuse,
    check_protocol_robustness,
)
from mcpnuke.checks.theft import check_token_theft
from mcpnuke.checks.execution import (
    check_code_execution,
    check_remote_access,
)
from mcpnuke.checks.chaining import (
    check_tool_shadowing,
    check_multi_vector,
    check_attack_chains,
)
from mcpnuke.checks.transport import check_sse_security
from mcpnuke.checks.rate_limit import check_rate_limit
from mcpnuke.checks.prompt_leakage import check_prompt_leakage
from mcpnuke.checks.supply_chain import check_supply_chain
from mcpnuke.checks.tool_probes import (
    check_tool_response_injection,
    check_input_sanitization,
    check_error_leakage,
    check_temporal_consistency,
    check_resource_poisoning,
)
from mcpnuke.checks.response_credentials import check_response_credentials
from mcpnuke.checks.config_tampering import check_config_tampering
from mcpnuke.checks.webhook_persistence import check_webhook_persistence
from mcpnuke.checks.credential_in_schema import check_credential_in_schema
from mcpnuke.checks.exfil_flow import check_exfil_flow
from mcpnuke.checks.ssrf_probe import check_ssrf_probe
from mcpnuke.checks.actuator_probe import check_actuator_probe

# Checks that --fast mode skips (heavy, LLM-backed, or slow)
FAST_SKIP_CHECKS = {
    "input_sanitization",
    "error_leakage",
    "temporal_consistency",
    "ssrf_probe",
}


def _emit_duration_estimate(
    n_tools: int,
    session,
    no_invoke: bool,
    fast_mode: bool,
    probe_workers: int,
    _log,
):
    """Print a rough scan-time estimate so operators know what to expect."""
    stdio = hasattr(session, "_proc") if session else False
    avg_per_tool = 8.0 if stdio else 3.0
    static_secs = 2.0
    behavioral_secs = 3.0 if not no_invoke else 0.0

    if no_invoke:
        deep_secs = 0.0
    else:
        deep_checks = 10
        if fast_mode:
            deep_checks -= len(FAST_SKIP_CHECKS)
        deep_secs = deep_checks * n_tools * avg_per_tool
        if probe_workers > 1:
            deep_secs /= min(probe_workers, n_tools or 1)

    total_secs = static_secs + behavioral_secs + deep_secs
    if total_secs < 60:
        est = f"~{int(total_secs)}s"
    else:
        est = f"~{total_secs / 60:.0f}min"

    transport = "stdio" if stdio else "HTTP"
    mode = "fast" if fast_mode else "deep"
    _log(f"  [bold]Estimated scan time: {est} ({n_tools} tools, {mode} mode, {transport} transport)[/bold]")


def run_all_checks(
    session,
    result: TargetResult,
    all_results: list[TargetResult],
    base: str = "",
    sse_path: str = "",
    verbose: bool = False,
    probe_opts: dict | None = None,
    log=None,
):
    """Run all security checks against a target result.

    Ordering: static checks first (fast, no side-effects), then behavioral
    probes that actively interact with the server.

    probe_opts keys:
      no_invoke     (bool) — skip all tool-calling checks
      safe_mode     (bool) — skip invoking dangerous tools
      probe_calls   (int)  — invocations per tool for deep rug pull (default 6)
      fast          (bool) — sample top 5 tools, skip heavy probes
      probe_workers (int)  — parallel deep behavioral probe threads (default 1)
    """
    from mcpnuke.core.constants import SEV_COLOR

    opts = probe_opts or {}
    no_invoke = opts.get("no_invoke", False)
    fast_mode = opts.get("fast", False)
    probe_workers = opts.get("probe_workers", 1)
    _log = log or (lambda msg: None)
    if verbose:
        opts["_log"] = _log

    # In fast mode: cap tools to top 5 security-relevant, force probe_workers=2 max
    if fast_mode:
        _original_tools = result.tools
        result.tools = _pick_security_relevant(result.tools, 5)
        if verbose:
            _log(f"  [yellow]--fast: sampled {len(result.tools)}/{len(_original_tools)} security-relevant tools[/yellow]")
        probe_workers = min(probe_workers or 2, 2)

    if verbose:
        _emit_duration_estimate(
            len(result.tools), session, no_invoke, fast_mode, probe_workers, _log,
        )

    check_num = 0
    total_checks = 0
    _findings_lock = threading.Lock()

    def _run(name, fn, *args, **kwargs):
        nonlocal check_num
        with _findings_lock:
            check_num += 1
            num = check_num
        before_count = len(result.findings)
        if verbose:
            _log(f"  [dim]  [{num}/{total_checks}][/dim] [white]▸ {name}[/white]")
        t0 = time.time()
        fn(*args, **kwargs)
        elapsed = time.time() - t0
        new_findings = result.findings[before_count:]
        if verbose and new_findings:
            for f in new_findings:
                color = SEV_COLOR.get(f.severity, "white")
                _log(f"    [{color}]  ■ {f.severity:8s}[/{color}] {f.title}")
                if f.detail:
                    _log(f"    [dim]           {f.detail[:120]}[/dim]")
        if verbose:
            status = f"[green]✓[/green] {len(new_findings)} finding(s)" if new_findings else "[dim]clean[/dim]"
            _log(f"  [dim]    └─ {status}  ({elapsed:.2f}s)[/dim]")

    # Count total checks for progress display
    total_checks = 15  # static (exfil_flow counted separately below)
    total_checks += 1  # exfil_flow
    if not no_invoke:
        deep_count = 10 if not fast_mode else (10 - len(FAST_SKIP_CHECKS))
        total_checks += 3 + deep_count  # light behavioral + deep
    if base and sse_path:
        total_checks += 1
    if base:
        total_checks += 1
    total_checks += 2  # aggregate

    # ── Static checks (metadata only — always run) ─────────────────────
    if verbose:
        _log("  [bold cyan]── Static Analysis ──[/bold cyan]")
    _run("tool_shadowing", check_tool_shadowing, all_results, result)
    _run("prompt_injection", check_prompt_injection, result)
    _run("tool_poisoning", check_tool_poisoning, result)
    _run("excessive_permissions", check_excessive_permissions, result)
    _run("token_theft", check_token_theft, result)
    _run("code_execution", check_code_execution, result)
    _run("remote_access", check_remote_access, result)
    _run("schema_risks", check_schema_risks, result)
    _run("rate_limit", check_rate_limit, result)
    _run("prompt_leakage", check_prompt_leakage, result)
    _run("supply_chain", check_supply_chain, result)
    _run("config_tampering", check_config_tampering, result)
    _run("webhook_persistence", check_webhook_persistence, result)
    _run("credential_in_schema", check_credential_in_schema, result)
    _run("exfil_flow", check_exfil_flow, result, session=session, probe_opts=opts)
    if verbose:
        static_count = len(result.findings)
        _log(f"  [bold]  Static total: {static_count} finding(s)[/bold]")

    # ── Behavioral checks (light interaction — always run unless --no-invoke)
    if not no_invoke:
        if verbose:
            _log("\n  [bold cyan]── Behavioral Probes ──[/bold cyan]")
        _run("rug_pull", check_rug_pull, session, result)
        _run("indirect_injection", check_indirect_injection, session, result)
        _run("protocol_robustness", check_protocol_robustness, session, result)

        # ── Deep behavioral probes (invoke tools, analyze responses) ───
        if verbose:
            _log("\n  [bold cyan]── Deep Behavioral Probes ──[/bold cyan]")
            if probe_workers > 1:
                _log(f"  [dim]  (running with {probe_workers} parallel probe workers)[/dim]")

        deep_checks: list[tuple[str, Callable[..., Any], tuple[Any, ...], dict[str, Any]]] = [
            ("deep_rug_pull", check_deep_rug_pull, (session, result), {"probe_opts": opts}),
            ("tool_response_injection", check_tool_response_injection, (session, result), {"probe_opts": opts}),
            ("input_sanitization", check_input_sanitization, (session, result), {"probe_opts": opts}),
            ("error_leakage", check_error_leakage, (session, result), {"probe_opts": opts}),
            ("temporal_consistency", check_temporal_consistency, (session, result), {"probe_opts": opts}),
            ("resource_poisoning", check_resource_poisoning, (session, result), {}),
            ("response_credentials", check_response_credentials, (session, result), {"probe_opts": opts}),
            ("ssrf_probe", check_ssrf_probe, (session, result), {"probe_opts": opts}),
            ("state_mutation", check_state_mutation, (session, result), {}),
            ("notification_abuse", check_notification_abuse, (session, result), {}),
        ]

        if fast_mode:
            deep_checks = [
                (name, fn, a, kw) for name, fn, a, kw in deep_checks
                if name not in FAST_SKIP_CHECKS
            ]
            if verbose:
                _log(f"  [yellow]--fast: skipping {', '.join(sorted(FAST_SKIP_CHECKS))}[/yellow]")

        if probe_workers > 1:
            with ThreadPoolExecutor(max_workers=probe_workers) as pool:
                futures = {
                    pool.submit(_run, name, fn, *a, **kw): name
                    for name, fn, a, kw in deep_checks
                }
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception as exc:
                        check_name = futures[f]
                        _log_internal.debug("Deep check %s failed: %s", check_name, exc)
        else:
            for name, fn, a, kw in deep_checks:
                _run(name, fn, *a, **kw)

        behavioral_count = len(result.findings) - static_count
        if verbose:
            _log(f"  [bold]  Behavioral total: {behavioral_count} finding(s)[/bold]")

    # ── Transport checks ───────────────────────────────────────────────
    if base and sse_path:
        if verbose:
            _log("\n  [bold cyan]── Transport Checks ──[/bold cyan]")
        _run("sse_security", check_sse_security, base, sse_path, result)

    # ── Target surface checks (probe base URL, not tools) ─────────────
    if base:
        _run("actuator_probe", check_actuator_probe, base, result, auth_token=opts.get("auth_token"))

    # ── Cross-cutting / aggregate (run last, they read other findings) ─
    if verbose:
        _log("\n  [bold cyan]── Aggregate Analysis ──[/bold cyan]")
    _run("multi_vector", check_multi_vector, result)
    _run("attack_chains", check_attack_chains, result)
    if verbose:
        _log(f"\n  [bold green]  ✓ All {check_num} checks complete: {len(result.findings)} total finding(s)[/bold green]")


def _pick_security_relevant(tools: list[dict], n: int) -> list[dict]:
    """Select the top N most security-relevant tools for fast-mode scanning."""
    ranked = sorted(tools, key=_tool_security_score, reverse=True)
    return ranked[:n]


# ---------------------------------------------------------------------------
# Tool security relevance scoring
#
# Categorises keywords by threat class and assigns differentiated weights
# so that a zero-param secrets-leaking tool always outranks a five-param
# movement helper.
# ---------------------------------------------------------------------------

# Weight applied when keyword appears in tool *name* vs *description*.
_NAME_MULTIPLIER: int = 3
_DESC_MULTIPLIER: int = 1

# Keyword categories ordered by descending security impact.
# Each tuple: (keywords frozenset, per-match weight)
_KEYWORD_TIERS: list[tuple[frozenset[str], int]] = [
    # Tier 1 — direct execution / shell access
    (frozenset({
        "exec", "execute", "eval", "shell", "bash", "spawn", "system",
    }), 10),
    # Tier 2 — sensitive data exposure
    (frozenset({
        "secret", "credential", "password", "token", "key", "config",
        "leak", "dump", "env", "private",
    }), 8),
    # Tier 3 — outbound / persistence channels
    (frozenset({
        "webhook", "callback", "notify", "hook", "subscribe",
        "fetch", "proxy", "egress", "curl", "request",
    }), 7),
    # Tier 4 — dangerous operations
    (frozenset({
        "run", "command", "cmd", "deploy", "maintenance",
        "delete", "drop", "destroy", "kill", "purge",
    }), 6),
    # Tier 5 — data movement / filesystem
    (frozenset({
        "upload", "write", "send", "transfer", "backup",
        "read", "file", "path", "query", "sql",
    }), 4),
    # Tier 6 — administrative / elevated scope
    (frozenset({
        "admin", "root", "sudo", "manage", "install",
        "email", "sms", "broadcast",
    }), 3),
]

# Parameter names that signal attack surface regardless of tool name.
_DANGEROUS_PARAM_NAMES: frozenset[str] = frozenset({
    "url", "uri", "path", "file", "filename",
    "command", "cmd", "code", "query", "script",
    "host", "address", "endpoint", "callback",
})

# Minimum score floor for tools whose names strongly indicate secrets or
# config exposure — prevents zero-param leak tools from being outranked
# by benign high-param tools.
_HIGH_VALUE_NAME_KEYWORDS: frozenset[str] = frozenset({
    "secret", "credential", "password", "token", "config",
    "leak", "dump", "env", "private", "key",
})
_HIGH_VALUE_FLOOR: int = 15


def _tool_security_score(tool: dict) -> int:
    """Score a single MCP tool definition for security relevance.

    Higher scores indicate greater likelihood of exploitable behaviour.
    The algorithm intentionally favours tool *name* signals over schema
    complexity so that a zero-param ``server-config`` outranks a
    five-param ``move-to-position``.
    """
    name: str = tool.get("name", "").lower()
    desc: str = tool.get("description", "").lower()
    props: dict = tool.get("inputSchema", {}).get("properties", {})

    score: int = 0

    # --- Keyword tier scoring ---
    for keywords, weight in _KEYWORD_TIERS:
        for kw in keywords:
            if kw in name:
                score += weight * _NAME_MULTIPLIER
            elif kw in desc:
                score += weight * _DESC_MULTIPLIER

    # --- Dangerous parameter names ---
    for pname in props:
        if pname.lower() in _DANGEROUS_PARAM_NAMES:
            score += 8

    # --- Schema complexity (capped to avoid domination by benign tools) ---
    score += min(len(props), 3)

    # --- Floor for high-value tool names ---
    if any(kw in name for kw in _HIGH_VALUE_NAME_KEYWORDS):
        score = max(score, _HIGH_VALUE_FLOOR)

    return score
