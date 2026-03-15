#!/usr/bin/env python3
"""
mcprowler — MCP Red Teaming & Security Scanner

Usage:
    mcprowler --targets http://localhost:9090
    mcprowler --port-range localhost:9001-9010 --verbose
    mcprowler --targets http://target:9090 --auth-token $TOKEN --json report.json
"""

import sys
from datetime import datetime

from mcprowler import __version__
from mcprowler.cli import parse_args, build_url_list
from mcprowler.scanner import scan_target, run_parallel, detect_cross_shadowing
from mcprowler.reporting import print_report, write_json
from mcprowler.k8s import run_k8s_checks, discover_services, fingerprint_services
from mcprowler.diff import (
    load_baseline,
    save_baseline,
    diff_against_baseline,
    print_diff_report,
)
from rich.console import Console
from rich.panel import Panel

console = Console()


def main():
    args = parse_args()
    if args.k8s_discover and not args.targets and not args.targets_file and not args.public_targets and not args.port_range:
        urls = []
    else:
        urls = build_url_list(args)

    baseline = {}
    if args.baseline:
        baseline = load_baseline(args.baseline)
        if not baseline:
            console.print(f"[yellow]Baseline empty or not found: {args.baseline}[/yellow]")

    panel_lines = [
        f"[bold cyan]mcprowler v{__version__}[/bold cyan]  [dim]MCP Red Teaming & Security Scanner[/dim]",
        f"Targets : {len(urls)}",
        f"Workers : {args.workers}",
        f"Timeout : {args.timeout}s",
        f"Verbose : {args.verbose}  Debug: {args.debug}",
        f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    if args.baseline:
        panel_lines.append(f"Baseline: {args.baseline}")
    if args.save_baseline:
        panel_lines.append(f"Save baseline: {args.save_baseline}")
    if args.auth_token:
        panel_lines.append("Auth: Bearer token")

    console.print(
        Panel(
            "\n".join(panel_lines),
            title="mcprowler",
            border_style="cyan",
        )
    )

    probe_opts = {
        "no_invoke": args.no_invoke,
        "safe_mode": args.safe_mode,
        "probe_calls": args.probe_calls,
        "tool_names_file": getattr(args, "tool_names_file", None),
    }

    if args.no_invoke:
        console.print("  [yellow]--no-invoke: behavioral probes disabled (static-only)[/yellow]")
    elif args.safe_mode:
        console.print("  [yellow]--safe-mode: skipping dangerous tool invocations[/yellow]")

    if not args.no_k8s:
        run_k8s_checks(args.k8s_namespace, console=console)

        import os
        sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if os.path.exists(sa_token_path):
            with open(sa_token_path) as _f:
                _token = _f.read().strip()
            fingerprint_services(
                args.k8s_namespace,
                _token,
                fingerprint_workers=args.k8s_discovery_workers,
                console=console,
            )

    if args.k8s_discover:
        discovered = discover_services(
            namespaces=args.k8s_discover_namespaces,
            probe=not args.k8s_no_probe,
            discovery_workers=args.k8s_discovery_workers,
            max_endpoints=args.k8s_max_endpoints,
            console=console,
        )
        if args.k8s_discover_only:
            from rich.table import Table
            table = Table(title="Discovered MCP Endpoints")
            table.add_column("Namespace", style="dim")
            table.add_column("Service", style="cyan")
            table.add_column("URL", style="green")
            table.add_column("Source", style="yellow")
            for ep in discovered:
                table.add_row(ep.namespace, ep.service_name, ep.url, ep.source)
            console.print(table)
            console.print(f"\n[bold]Total: {len(discovered)} endpoint(s)[/bold]")
            if args.json_out:
                import json
                report = {
                    "discovered": [
                        {"url": ep.url, "service": ep.service_name, "namespace": ep.namespace, "source": ep.source}
                        for ep in discovered
                    ],
                    "count": len(discovered),
                }
                from pathlib import Path
                Path(args.json_out).write_text(json.dumps(report, indent=2))
                console.print(f"[green]JSON written to {args.json_out}[/green]")
            sys.exit(0)
        for ep in discovered:
            if ep.url not in urls:
                urls.append(ep.url)
                console.print(f"  [green]+[/green] Added discovered target: {ep.url}")

    if not urls:
        from mcprowler.k8s.scanner import GLOBAL_K8S_FINDINGS
        if GLOBAL_K8S_FINDINGS:
            console.print(f"\n[bold]── K8s-Only Report ({len(GLOBAL_K8S_FINDINGS)} findings) ──[/bold]")
            from mcprowler.core.constants import SEV_COLOR
            for f in GLOBAL_K8S_FINDINGS:
                color = SEV_COLOR.get(f.severity, "dim")
                console.print(f"  [{color}]{f.severity:8s}[/] {f.title}")
                if f.detail:
                    console.print(f"           [dim]{f.detail}[/dim]")
            if args.json_out:
                import json
                report = {"k8s_findings": [
                    {"severity": f.severity, "check": f.check, "title": f.title, "detail": f.detail}
                    for f in GLOBAL_K8S_FINDINGS
                ]}
                from pathlib import Path
                Path(args.json_out).write_text(json.dumps(report, indent=2))
                console.print(f"\n[green]JSON report written to {args.json_out}[/green]")
            if any(f.severity in ("CRITICAL", "HIGH") for f in GLOBAL_K8S_FINDINGS):
                sys.exit(1)
            sys.exit(0)
        console.print("[red]No targets specified and K8s discovery found nothing.[/red]")
        sys.exit(1)

    if len(urls) == 1:
        results = [
            scan_target(
                urls[0],
                [],
                timeout=args.timeout,
                verbose=args.verbose,
                auth_token=args.auth_token,
                probe_opts=probe_opts,
            )
        ]
    else:
        results = run_parallel(
            urls,
            timeout=args.timeout,
            workers=args.workers,
            verbose=args.verbose,
            auth_token=args.auth_token,
            probe_opts=probe_opts,
        )

    detect_cross_shadowing(results)

    # Differential scan: compare to baseline and add findings
    diff_results = []
    if args.baseline and baseline:
        for r in results:
            base = baseline.get(r.url, {})
            if base:
                diff = diff_against_baseline(
                    r.tools,
                    r.resources,
                    r.prompts,
                    base.get("tools", []),
                    base.get("resources", []),
                    base.get("prompts", []),
                    url=r.url,
                )
                diff_results.append(diff)
                # Add findings for new tools (security regression)
                for t in diff.added_tools:
                    r.add(
                        "differential",
                        "MEDIUM",
                        f"Added tool: {t.get('name', '?')}",
                        "New tool since baseline — review for security impact",
                    )
        print_diff_report(diff_results, args.baseline, console=console)

    print_report(results)

    if args.save_baseline:
        save_baseline(results, args.save_baseline, console=console)

    if args.json_out:
        write_json(results, args.json_out, console=console)

    all_findings = [f for r in results for f in r.findings]
    if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
