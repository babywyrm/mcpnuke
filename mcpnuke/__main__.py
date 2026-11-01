#!/usr/bin/env python3
"""
mcpnuke — MCP Red Teaming & Security Scanner

Usage:
    mcpnuke --targets http://localhost:9090
    mcpnuke --port-range localhost:9001-9010 --verbose
    mcpnuke --targets http://target:9090 --auth-token $TOKEN --json report.json
    mcpnuke --stdio 'npx -y @modelcontextprotocol/server-everything'
    mcpnuke --targets http://target:9090 --fast --group-findings
"""

import sys
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel

from mcpnuke import __version__
from mcpnuke.cli import build_url_list, parse_args
from mcpnuke.cli_steps import (
    _base_probe_opts,
    _k8s_setup,
    _report,
    _resolve_auth,
    _should_fail,
    _start_oast,
    _validate_ai_backend,
    _watch_lanes,
)
from mcpnuke.core.auth import parse_header_kv_pairs
from mcpnuke.core.models import TargetResult
from mcpnuke.core.trust import parse_trust_sets
from mcpnuke.diff import (
    apply_diff_findings,
    diff_against_baseline,
    load_baseline,
    print_diff_report,
    save_baseline,
)
from mcpnuke.patterns.credentials import redact_credentials
from mcpnuke.scanner import run_parallel, scan_stdio_target, scan_target
from mcpnuke.subcommands import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    _run_diff_subcommand,
    _run_doctor,
    _run_lab_coverage,
)


def _main_inner() -> None:
    # Handle `mcpnuke diff a.json b.json` before full arg parse
    if len(sys.argv) >= 2 and sys.argv[1] == "diff":
        _run_diff_subcommand(sys.argv[2:])
        return

    args = parse_args()
    console = Console(no_color=args.no_color, force_terminal=not args.no_color)
    from mcpnuke.core.llm import configure_bedrock
    configure_bedrock(enabled=False)
    try:
        extra_headers = parse_header_kv_pairs(getattr(args, "header", None))
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(EXIT_ERROR)
    if args.dpop_proof:
        extra_headers["DPoP"] = args.dpop_proof

    if args.doctor:
        _run_doctor(console)
        sys.exit(EXIT_CLEAN)

    if getattr(args, "lab_coverage", None):
        _run_lab_coverage(args.lab_coverage, console, getattr(args, "json_out", None))
        sys.exit(EXIT_CLEAN)

    _validate_ai_backend(args)

    deterministic_mode: bool = bool(getattr(args, "deterministic", False))
    effective_probe_workers: int = args.probe_workers
    effective_phase2_workers: int = args.claude_phase2_workers
    if deterministic_mode:
        effective_probe_workers = 1
        effective_phase2_workers = 1

    # --stdio mode: scan a local server via stdin/stdout, then exit
    if args.stdio:
        probe_opts = _base_probe_opts(
            args,
            extra_headers=extra_headers,
            probe_workers=effective_probe_workers,
            phase2_workers=effective_phase2_workers,
            deterministic=deterministic_mode,
        )

        panel_lines = [
            f"[bold cyan]mcpnuke v{__version__}[/bold cyan]  [dim]MCP Red Teaming & Security Scanner[/dim]",
            "Mode    : stdio",
            f"Command : {args.stdio}",
            f"Fast    : {args.fast}",
            f"Workers : {effective_probe_workers} probe thread(s)",
            f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        if deterministic_mode:
            panel_lines.append("Deterministic: True")
        console.print(Panel("\n".join(panel_lines), title="mcpnuke", border_style="cyan"))

        result = scan_stdio_target(
            args.stdio,
            timeout=args.timeout,
            verbose=args.verbose,
            probe_opts=probe_opts,
        )
        _report(args, [result], console)
        if _should_fail(result.findings, getattr(args, "fail_on", "high")):
            sys.exit(EXIT_FINDINGS)
        sys.exit(EXIT_CLEAN)

    inference_only = (
        getattr(args, "inference_host", None)
        and not args.targets
        and not args.targets_file
        and not getattr(args, "public_targets", False)
        and not args.port_range
    )
    if inference_only or (
        args.k8s_discover
        and not args.targets
        and not args.targets_file
        and not getattr(args, "public_targets", False)
        and not args.port_range
    ):
        urls = []
    else:
        urls = build_url_list(args)

    try:
        trust_sets = parse_trust_sets(getattr(args, "trust_set", None), targets=urls)
    except ValueError as exc:
        console.print(f"  [red]✗[/red] {exc}")
        sys.exit(EXIT_ERROR)

    auth_token, auth_context_summary = _resolve_auth(args, urls, extra_headers, console)
    jwt_claims_summary: dict = auth_context_summary.get("jwt_claims_summary", {})

    baseline = {}
    if args.baseline:
        baseline = load_baseline(args.baseline)
        if not baseline:
            console.print(f"[yellow]Baseline empty or not found: {args.baseline}[/yellow]")

    panel_lines = [
        f"[bold cyan]mcpnuke v{__version__}[/bold cyan]  [dim]MCP Red Teaming & Security Scanner[/dim]",
        f"Targets : {len(urls)}",
        f"Workers : {args.workers}",
        f"Timeout : {args.timeout}s",
        f"Verbose : {args.verbose}  Debug: {args.debug}",
        f"Fast    : {args.fast}" if args.fast else "",
        f"Probe⌿  : {effective_probe_workers} thread(s)" if effective_probe_workers > 1 else "",
        f"Group   : {args.group_findings}" if args.group_findings else "",
        f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    panel_lines = [line for line in panel_lines if line]
    if args.baseline:
        panel_lines.append(f"Baseline: {args.baseline}")
    if args.save_baseline:
        panel_lines.append(f"Save baseline: {args.save_baseline}")
    if auth_token:
        if args.client_id:
            panel_lines.append(f"Auth: OIDC client_credentials (client={args.client_id})")
        else:
            panel_lines.append("Auth: Bearer token")
    if args.oidc_scope:
        panel_lines.append(f"OIDC scope: {args.oidc_scope}")
    if args.dpop_proof:
        panel_lines.append("DPoP: provided")
    if args.tls_verify:
        panel_lines.append("TLS verify: True")
    if extra_headers:
        panel_lines.append(f"Extra headers: {len(extra_headers)}")
    if jwt_claims_summary:
        claims_short = ", ".join(
            f"{k}={v}" for k, v in jwt_claims_summary.items() if k in {"iss", "sub", "aud", "scope", "scp"}
        )
        if claims_short:
            panel_lines.append(f"JWT claims: {claims_short[:120]}")
    if "introspection_summary" in auth_context_summary:
        active = auth_context_summary["introspection_summary"].get("active")
        panel_lines.append(f"Introspection active: {active}")
    if "jwks_summary" in auth_context_summary:
        panel_lines.append(f"JWKS keys: {auth_context_summary['jwks_summary'].get('key_count', 0)}")
    if args.claude:
        if args.bedrock:
            panel_lines.append(f"AI: Claude via Bedrock ({args.bedrock_model})")
            if args.bedrock_region:
                panel_lines.append(f"Bedrock region: {args.bedrock_region}")
            if args.bedrock_profile:
                panel_lines.append(f"Bedrock profile: {args.bedrock_profile}")
        else:
            panel_lines.append(f"AI: Claude ({args.claude_model})")
        if effective_phase2_workers > 1:
            panel_lines.append(f"AI Phase2 workers: {effective_phase2_workers}")
    elif args.ollama_analysis:
        if args.ollama_ensemble:
            models_str = args.ollama_ensemble
            panel_lines.append(f"AI: Ollama ensemble ({args.ollama_analysis})")
            panel_lines.append(f"    models: {models_str}")
        else:
            panel_lines.append(f"AI: Ollama ({args.ollama_analysis}, model={args.ollama_model})")

    if deterministic_mode:
        panel_lines.append("Deterministic: True")
    if args.k8s_api_url:
        panel_lines.append(f"K8s API: {args.k8s_api_url} (external)")
    elif not args.no_k8s:
        panel_lines.append("K8s: in-cluster (auto-detect)")

    console.print(
        Panel(
            "\n".join(panel_lines),
            title="mcpnuke",
            border_style="cyan",
        )
    )

    profile_data = None
    if getattr(args, "profile", None):
        from mcpnuke.profile import load_profile
        try:
            profile_data = load_profile(args.profile)
            console.print(f"  [green]Profile loaded:[/green] {profile_data.name} ({len(profile_data.tools)} tools)")
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"  [red]Profile error:[/red] {exc}")

    probe_opts = {
        **_base_probe_opts(
            args,
            extra_headers=extra_headers,
            probe_workers=effective_probe_workers,
            phase2_workers=effective_phase2_workers,
            deterministic=deterministic_mode,
        ),
        "trust_sets": [sorted(group) for group in trust_sets],
        "target_count": len(urls),
        "auth_context_summary": auth_context_summary,
        "profile": profile_data,
    }

    oast_listener = _start_oast(args, console)
    if oast_listener is not None:
        probe_opts["oast"] = oast_listener

    if args.no_invoke:
        console.print("  [yellow]--no-invoke: behavioral probes disabled (static-only)[/yellow]")
    elif args.safe_mode:
        console.print("  [yellow]--safe-mode: skipping dangerous tool invocations[/yellow]")
    if args.fast:
        console.print("  [yellow]--fast: sampling top 5 tools, skipping heavy probes[/yellow]")
    elif getattr(args, "coverage", None):
        console.print(
            f"  [yellow]--coverage {args.coverage}: sampling top "
            f"{args.coverage} security-relevant tools[/yellow]"
        )
    if deterministic_mode:
        console.print("  [yellow]--deterministic: stable ordering, single-threaded probes/AI phase2[/yellow]")
    if args.tls_verify:
        console.print("  [yellow]--tls-verify: TLS certificate verification enabled[/yellow]")
    if getattr(args, "inference_host", None):
        console.print(f"  [yellow]--inference-host: probing {args.inference_host}[/yellow]")
    elif getattr(args, "inference", False):
        console.print("  [yellow]--inference: auto-detecting inference backends from MCP context[/yellow]")
    if getattr(args, "inference_baseline", None):
        console.print(f"  [yellow]--inference-baseline: comparing against {args.inference_baseline}[/yellow]")
    if getattr(args, "save_inference_baseline", None):
        console.print(f"  [yellow]--save-inference-baseline: will snapshot to {args.save_inference_baseline}[/yellow]")

    _k8s_setup(args, urls, console)

    if not urls and inference_only:
        from mcpnuke.checks.inference_backend import check_inference_backend, check_model_integrity
        t0 = time.time()
        result = TargetResult(url=probe_opts["inference_host"])
        result.transport = "inference-only"
        check_inference_backend(result, probe_opts=probe_opts)
        if probe_opts.get("inference_baseline") or probe_opts.get("save_inference_baseline"):
            check_model_integrity(result, probe_opts=probe_opts)
        result.timings["total"] = time.time() - t0
        results = [result]
        _report(args, results, console)
        if probe_opts.get("save_inference_baseline"):
            console.print(f"\n  [green]✓[/green] Inference baseline saved to {probe_opts['save_inference_baseline']}")
        from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS
        if _should_fail(result.findings + GLOBAL_K8S_FINDINGS, getattr(args, "fail_on", "high")):
            sys.exit(EXIT_FINDINGS)
        sys.exit(EXIT_CLEAN)

    if not urls:
        from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS
        if GLOBAL_K8S_FINDINGS:
            console.print(f"\n[bold]── K8s-Only Report ({len(GLOBAL_K8S_FINDINGS)} findings) ──[/bold]")
            _report(args, [], console)
            if _should_fail(GLOBAL_K8S_FINDINGS, getattr(args, "fail_on", "high")):
                sys.exit(EXIT_FINDINGS)
            sys.exit(EXIT_CLEAN)
        console.print("[red]No targets specified and K8s discovery found nothing.[/red]")
        sys.exit(EXIT_ERROR)

    if len(urls) == 1:
        results = [
            scan_target(
                urls[0],
                [],
                timeout=args.timeout,
                verbose=args.verbose,
                auth_token=auth_token,
                probe_opts=probe_opts,
            )
        ]
    else:
        results = run_parallel(
            urls,
            timeout=args.timeout,
            workers=args.workers,
            verbose=args.verbose,
            auth_token=auth_token,
            probe_opts=probe_opts,
        )

    # Differential scan: compare to baseline and add findings
    diff_results = []
    if args.baseline and baseline:
        for r in results:
            base = baseline.get(r.url, {})
            if base:
                diff = diff_against_baseline(
                    r.catalog_tools(),
                    r.resources,
                    r.prompts,
                    base.get("tools", []),
                    base.get("resources", []),
                    base.get("prompts", []),
                    url=r.url,
                )
                diff_results.append(diff)
                apply_diff_findings(r, diff)
        print_diff_report(diff_results, args.baseline, console=console)

    _report(args, results, console)
    if args.save_baseline:
        save_baseline(results, args.save_baseline, console=console)

    if getattr(args, "watch", None):
        _watch_lanes(args, results, urls, auth_token, probe_opts, baseline, console)
        return

    from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS
    all_findings = [f for r in results for f in r.findings] + GLOBAL_K8S_FINDINGS
    if _should_fail(all_findings, getattr(args, "fail_on", "high")):
        sys.exit(EXIT_FINDINGS)


def main() -> None:
    try:
        _main_inner()
    except Exception as exc:
        print(f"mcpnuke: {type(exc).__name__}: {redact_credentials(str(exc))}", file=sys.stderr)
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
