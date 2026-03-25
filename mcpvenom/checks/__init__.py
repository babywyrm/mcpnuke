"""Security check registry and runner."""

import time

from mcpvenom.core.models import TargetResult
from mcpvenom.checks.injection import (
    check_prompt_injection,
    check_tool_poisoning,
    check_indirect_injection,
)
from mcpvenom.checks.permissions import (
    check_excessive_permissions,
    check_schema_risks,
)
from mcpvenom.checks.behavioral import (
    check_rug_pull,
    check_deep_rug_pull,
    check_state_mutation,
    check_notification_abuse,
    check_protocol_robustness,
)
from mcpvenom.checks.theft import check_token_theft
from mcpvenom.checks.execution import (
    check_code_execution,
    check_remote_access,
)
from mcpvenom.checks.chaining import (
    check_tool_shadowing,
    check_multi_vector,
    check_attack_chains,
)
from mcpvenom.checks.transport import check_sse_security
from mcpvenom.checks.rate_limit import check_rate_limit
from mcpvenom.checks.prompt_leakage import check_prompt_leakage
from mcpvenom.checks.supply_chain import check_supply_chain
from mcpvenom.checks.tool_probes import (
    check_tool_response_injection,
    check_input_sanitization,
    check_error_leakage,
    check_temporal_consistency,
    check_resource_poisoning,
)
from mcpvenom.checks.response_credentials import check_response_credentials
from mcpvenom.checks.config_tampering import check_config_tampering
from mcpvenom.checks.webhook_persistence import check_webhook_persistence
from mcpvenom.checks.credential_in_schema import check_credential_in_schema
from mcpvenom.checks.exfil_flow import check_exfil_flow
from mcpvenom.checks.ssrf_probe import check_ssrf_probe
from mcpvenom.checks.actuator_probe import check_actuator_probe


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
      no_invoke  (bool)  — skip all tool-calling checks
      safe_mode  (bool)  — skip invoking dangerous tools (delete, send, exec, write)
      probe_calls (int)  — invocations per tool for deep rug pull (default 6)
    """
    from mcpvenom.core.constants import SEV_COLOR

    opts = probe_opts or {}
    no_invoke = opts.get("no_invoke", False)
    _log = log or (lambda msg: None)
    if verbose:
        opts["_log"] = _log
    check_num = 0
    total_checks = 0

    def _run(name, fn, *args, **kwargs):
        nonlocal check_num
        check_num += 1
        before = len(result.findings)
        if verbose:
            _log(f"  [dim]  [{check_num}/{total_checks}][/dim] [white]▸ {name}[/white]")
        t0 = time.time()
        fn(*args, **kwargs)
        elapsed = time.time() - t0
        new_findings = result.findings[before:]
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
    total_checks = 17  # static
    if not no_invoke:
        total_checks += 13  # behavioral + deep
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
    _run("exfil_flow", check_exfil_flow, result)
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
        _run("deep_rug_pull", check_deep_rug_pull, session, result, probe_opts=opts)
        _run("tool_response_injection", check_tool_response_injection, session, result, probe_opts=opts)
        _run("input_sanitization", check_input_sanitization, session, result, probe_opts=opts)
        _run("error_leakage", check_error_leakage, session, result, probe_opts=opts)
        _run("temporal_consistency", check_temporal_consistency, session, result, probe_opts=opts)
        _run("resource_poisoning", check_resource_poisoning, session, result)
        _run("response_credentials", check_response_credentials, session, result, probe_opts=opts)
        _run("ssrf_probe", check_ssrf_probe, session, result, probe_opts=opts)
        _run("state_mutation", check_state_mutation, session, result)
        _run("notification_abuse", check_notification_abuse, session, result)

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
