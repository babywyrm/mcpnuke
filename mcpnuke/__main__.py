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
from datetime import datetime

from mcpnuke import __version__
from mcpnuke.cli import parse_args, build_url_list
from mcpnuke.core.auth import resolve_auth_token, detect_auth_requirements
from mcpnuke.scanner import scan_target, scan_stdio_target, run_parallel, detect_cross_shadowing
from mcpnuke.reporting import print_report, write_json
from mcpnuke.k8s import run_k8s_checks, discover_services, fingerprint_services
from mcpnuke.diff import (
    load_baseline,
    save_baseline,
    diff_against_baseline,
    print_diff_report,
)
from rich.console import Console
from rich.panel import Panel

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _run_doctor(console: Console) -> None:
    """Check installation health and report missing deps / config."""
    from mcpnuke import __version__
    import shutil

    console.print(f"\n[bold cyan]mcpnuke v{__version__} — doctor[/bold cyan]\n")
    ok_count = 0
    warn_count = 0

    def _ok(msg: str) -> None:
        nonlocal ok_count
        ok_count += 1
        console.print(f"  [green]✓[/green] {msg}")

    def _warn(msg: str, hint: str = "") -> None:
        nonlocal warn_count
        warn_count += 1
        console.print(f"  [yellow]✗[/yellow] {msg}")
        if hint:
            from rich.markup import escape
            console.print(f"    [dim]{escape(hint)}[/dim]")

    def _pkg_version(name: str) -> str:
        try:
            mod = __import__(name)
            ver = getattr(mod, "__version__", None)
            if ver:
                return ver
        except ImportError:
            return "missing"
        try:
            from importlib.metadata import version as meta_ver
            return meta_ver(name)
        except Exception:
            return "?"

    # Core deps (always installed)
    for pkg in ("httpx", "rich"):
        ver = _pkg_version(pkg)
        if ver == "missing":
            _warn(f"{pkg} not found", f"pip install {pkg}")
        else:
            _ok(f"{pkg} {ver}")

    # Optional: AI
    try:
        import anthropic
        ver = getattr(anthropic, "__version__", "?")
        _ok(f"anthropic {ver}  [dim](extra: ai)[/dim]")
    except ImportError:
        _warn("anthropic not installed — --claude disabled",
              "uv pip install 'mcpnuke[ai]'  or:  pip install anthropic")

    # Optional: K8s
    try:
        import kubernetes
        ver = getattr(kubernetes, "__version__", "?")
        _ok(f"kubernetes {ver}  [dim](extra: k8s)[/dim]")
    except ImportError:
        _warn("kubernetes not installed — K8s discovery/checks disabled",
              "uv pip install 'mcpnuke[k8s]'  or:  pip install kubernetes")

    # Env vars
    import os
    if os.environ.get("ANTHROPIC_API_KEY"):
        key = os.environ["ANTHROPIC_API_KEY"]
        _ok(f"ANTHROPIC_API_KEY set ({key[:12]}...)")
    else:
        _warn("ANTHROPIC_API_KEY not set — --claude will fail",
              "export ANTHROPIC_API_KEY=sk-ant-...")

    if os.environ.get("MCP_AUTH_TOKEN"):
        _ok("MCP_AUTH_TOKEN set")
    else:
        console.print(f"  [dim]─[/dim] MCP_AUTH_TOKEN not set  [dim](optional, for authenticated targets)[/dim]")

    # Python version
    _ok(f"Python {sys.version.split()[0]}")

    # Platform tools
    for tool in ("curl", "ssh", "tmux"):
        if shutil.which(tool):
            _ok(f"{tool} available")
        else:
            _warn(f"{tool} not found on PATH",
                  f"Install with your package manager (apt/brew install {tool})")

    console.print(f"\n  [bold]{ok_count} ok[/bold], [bold yellow]{warn_count} warning(s)[/bold yellow]\n")
    if warn_count == 0:
        console.print("  [bold green]All good — ready to scan.[/bold green]\n")
    else:
        console.print("  [dim]Fix warnings above for full functionality.[/dim]\n")


def _main_inner() -> None:
    args = parse_args()
    console = Console(no_color=args.no_color, force_terminal=not args.no_color)

    if args.doctor:
        _run_doctor(console)
        sys.exit(EXIT_CLEAN)

    if args.claude:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            print(
                "Error: --claude requires the 'anthropic' package.\n"
                "Install it with:  uv pip install mcpnuke[ai]   (or: pip install anthropic)",
                file=sys.stderr,
            )
            sys.exit(EXIT_ERROR)
        import os
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print(
                "Error: --claude requires ANTHROPIC_API_KEY environment variable.\n"
                "  export ANTHROPIC_API_KEY=sk-ant-...",
                file=sys.stderr,
            )
            sys.exit(EXIT_ERROR)

    # --stdio mode: scan a local server via stdin/stdout, then exit
    if args.stdio:
        probe_opts = {
            "no_invoke": args.no_invoke,
            "safe_mode": args.safe_mode,
            "probe_calls": args.probe_calls,
            "tool_names_file": getattr(args, "tool_names_file", None),
            "claude": args.claude,
            "claude_model": args.claude_model,
            "claude_max_tools": args.claude_max_tools,
            "fast": args.fast,
            "probe_workers": args.probe_workers,
        }

        panel_lines = [
            f"[bold cyan]mcpnuke v{__version__}[/bold cyan]  [dim]MCP Red Teaming & Security Scanner[/dim]",
            f"Mode    : stdio",
            f"Command : {args.stdio}",
            f"Fast    : {args.fast}",
            f"Workers : {args.probe_workers} probe thread(s)",
            f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ]
        console.print(Panel("\n".join(panel_lines), title="mcpnuke", border_style="cyan"))

        result = scan_stdio_target(
            args.stdio,
            timeout=args.timeout,
            verbose=args.verbose,
            probe_opts=probe_opts,
        )
        print_report([result], group_findings=args.group_findings, console=console)
        if args.json_out:
            write_json([result], args.json_out, console=console)
        if any(f.severity in ("CRITICAL", "HIGH") for f in result.findings):
            sys.exit(EXIT_FINDINGS)
        sys.exit(EXIT_CLEAN)

    if args.k8s_discover and not args.targets and not args.targets_file and not args.public_targets and not args.port_range:
        urls = []
    else:
        urls = build_url_list(args)

    # Resolve auth token (direct, OIDC client_credentials, or auto-detect)
    auth_token = args.auth_token
    if not auth_token and args.client_id and args.client_secret:
        try:
            auth_token = resolve_auth_token(args)
            console.print(f"  [green]✓[/green] Token acquired via OIDC client_credentials")
        except RuntimeError as e:
            console.print(f"  [red]✗[/red] OIDC token fetch failed: {e}")
            sys.exit(EXIT_ERROR)
    elif not auth_token and urls and args.verbose:
        info = detect_auth_requirements(urls[0])
        if info.requires_auth:
            console.print(f"  [yellow]⚠[/yellow]  Target requires auth: {info.summary()}")
            if info.token_endpoint:
                console.print(f"  [dim]  Token endpoint: {info.token_endpoint}[/dim]")
                console.print(f"  [dim]  Use: --oidc-url {info.issuer or '...'} --client-id ID --client-secret SECRET[/dim]")

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
        f"Probe⌿  : {args.probe_workers} thread(s)" if args.probe_workers > 1 else "",
        f"Group   : {args.group_findings}" if args.group_findings else "",
        f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    panel_lines = [l for l in panel_lines if l]
    if args.baseline:
        panel_lines.append(f"Baseline: {args.baseline}")
    if args.save_baseline:
        panel_lines.append(f"Save baseline: {args.save_baseline}")
    if auth_token:
        if args.client_id:
            panel_lines.append(f"Auth: OIDC client_credentials (client={args.client_id})")
        else:
            panel_lines.append("Auth: Bearer token")
    if args.claude:
        panel_lines.append(f"AI: Claude ({args.claude_model})")

    console.print(
        Panel(
            "\n".join(panel_lines),
            title="mcpnuke",
            border_style="cyan",
        )
    )

    probe_opts = {
        "no_invoke": args.no_invoke,
        "safe_mode": args.safe_mode,
        "probe_calls": args.probe_calls,
        "tool_names_file": getattr(args, "tool_names_file", None),
        "claude": args.claude,
        "claude_model": args.claude_model,
        "claude_max_tools": args.claude_max_tools,
        "fast": args.fast,
        "probe_workers": args.probe_workers,
    }

    if args.no_invoke:
        console.print("  [yellow]--no-invoke: behavioral probes disabled (static-only)[/yellow]")
    elif args.safe_mode:
        console.print("  [yellow]--safe-mode: skipping dangerous tool invocations[/yellow]")
    if args.fast:
        console.print("  [yellow]--fast: sampling top 5 tools, skipping heavy probes[/yellow]")

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
            sys.exit(EXIT_CLEAN)
        for ep in discovered:
            if ep.url not in urls:
                urls.append(ep.url)
                console.print(f"  [green]+[/green] Added discovered target: {ep.url}")

    if not urls:
        from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS
        if GLOBAL_K8S_FINDINGS:
            console.print(f"\n[bold]── K8s-Only Report ({len(GLOBAL_K8S_FINDINGS)} findings) ──[/bold]")
            from mcpnuke.core.constants import SEV_COLOR
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

    print_report(results, group_findings=args.group_findings, console=console)

    if args.save_baseline:
        save_baseline(results, args.save_baseline, console=console)

    if args.json_out:
        write_json(results, args.json_out, console=console)

    all_findings = [f for r in results for f in r.findings]
    if any(f.severity in ("CRITICAL", "HIGH") for f in all_findings):
        sys.exit(EXIT_FINDINGS)


def main() -> None:
    try:
        _main_inner()
    except Exception:
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
