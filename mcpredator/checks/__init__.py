"""Security check registry and runner."""

import time

from mcpredator.core.models import TargetResult
from mcpredator.checks.injection import (
    check_prompt_injection,
    check_tool_poisoning,
    check_indirect_injection,
)
from mcpredator.checks.permissions import (
    check_excessive_permissions,
    check_schema_risks,
)
from mcpredator.checks.behavioral import (
    check_rug_pull,
    check_deep_rug_pull,
    check_state_mutation,
    check_notification_abuse,
    check_protocol_robustness,
)
from mcpredator.checks.theft import check_token_theft
from mcpredator.checks.execution import (
    check_code_execution,
    check_remote_access,
)
from mcpredator.checks.chaining import (
    check_tool_shadowing,
    check_multi_vector,
    check_attack_chains,
)
from mcpredator.checks.transport import check_sse_security
from mcpredator.checks.rate_limit import check_rate_limit
from mcpredator.checks.prompt_leakage import check_prompt_leakage
from mcpredator.checks.supply_chain import check_supply_chain
from mcpredator.checks.tool_probes import (
    check_tool_response_injection,
    check_input_sanitization,
    check_error_leakage,
    check_temporal_consistency,
    check_resource_poisoning,
)
from mcpredator.checks.response_credentials import check_response_credentials
from mcpredator.checks.config_tampering import check_config_tampering
from mcpredator.checks.webhook_persistence import check_webhook_persistence
from mcpredator.checks.credential_in_schema import check_credential_in_schema
from mcpredator.checks.exfil_flow import check_exfil_flow
from mcpredator.checks.ssrf_probe import check_ssrf_probe
from mcpredator.checks.actuator_probe import check_actuator_probe


def run_all_checks(
    session,
    result: TargetResult,
    all_results: list[TargetResult],
    base: str = "",
    sse_path: str = "",
    verbose: bool = False,
    probe_opts: dict | None = None,
):
    """Run all security checks against a target result.

    Ordering: static checks first (fast, no side-effects), then behavioral
    probes that actively interact with the server.

    probe_opts keys:
      no_invoke  (bool)  — skip all tool-calling checks
      safe_mode  (bool)  — skip invoking dangerous tools (delete, send, exec, write)
      probe_calls (int)  — invocations per tool for deep rug pull (default 6)
    """
    opts = probe_opts or {}
    no_invoke = opts.get("no_invoke", False)

    # ── Static checks (metadata only — always run) ─────────────────────
    check_tool_shadowing(all_results, result)
    check_prompt_injection(result)
    check_tool_poisoning(result)
    check_excessive_permissions(result)
    check_token_theft(result)
    check_code_execution(result)
    check_remote_access(result)
    check_schema_risks(result)
    check_rate_limit(result)
    check_prompt_leakage(result)
    check_supply_chain(result)
    check_config_tampering(result)
    check_webhook_persistence(result)
    check_credential_in_schema(result)
    check_exfil_flow(result)

    # ── Behavioral checks (light interaction — always run unless --no-invoke)
    if not no_invoke:
        check_rug_pull(session, result)
        check_indirect_injection(session, result)
        check_protocol_robustness(session, result)

        # ── Deep behavioral probes (invoke tools, analyze responses) ───
        check_deep_rug_pull(session, result, probe_opts=opts)
        check_tool_response_injection(session, result, probe_opts=opts)
        check_input_sanitization(session, result, probe_opts=opts)
        check_error_leakage(session, result, probe_opts=opts)
        check_temporal_consistency(session, result, probe_opts=opts)
        check_resource_poisoning(session, result)
        check_response_credentials(session, result, probe_opts=opts)
        check_ssrf_probe(session, result, probe_opts=opts)
        check_state_mutation(session, result)
        check_notification_abuse(session, result)

    # ── Transport checks ───────────────────────────────────────────────
    if base and sse_path:
        check_sse_security(base, sse_path, result)

    # ── Target surface checks (probe base URL, not tools) ─────────────
    if base:
        auth_token = opts.get("auth_token")
        check_actuator_probe(base, result, auth_token=auth_token)

    # ── Cross-cutting / aggregate (run last, they read other findings) ─
    check_multi_vector(result)
    check_attack_chains(result)
