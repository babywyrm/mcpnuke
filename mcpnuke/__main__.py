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
    _apply_baseline,
    _base_probe_opts,
    _k8s_setup,
    _print_mode_notices,
    _print_scan_panel,
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
    load_baseline,
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

    baseline = {}
    if args.baseline:
        baseline = load_baseline(args.baseline)
        if not baseline:
            console.print(f"[yellow]Baseline empty or not found: {args.baseline}[/yellow]")

    _print_scan_panel(
        args,
        urls,
        auth_token=auth_token,
        auth_context_summary=auth_context_summary,
        extra_headers=extra_headers,
        probe_workers=effective_probe_workers,
        phase2_workers=effective_phase2_workers,
        deterministic=deterministic_mode,
        console=console,
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

    _print_mode_notices(args, deterministic_mode, console)

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

    _apply_baseline(args, results, baseline, console)

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
