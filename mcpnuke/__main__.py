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

import argparse
import sys
import time
from datetime import datetime

from rich.console import Console
from rich.panel import Panel

from mcpnuke import __version__
from mcpnuke.cli import build_url_list, parse_args
from mcpnuke.core.auth import (
    decode_jwt_claims,
    detect_auth_requirements,
    fetch_jwks,
    fetch_token_introspection,
    parse_header_kv_pairs,
    resolve_auth_token,
    summarize_introspection,
    summarize_jwks,
    summarize_jwt_claims,
)
from mcpnuke.core.models import TargetResult
from mcpnuke.diff import (
    diff_against_baseline,
    load_baseline,
    print_diff_report,
    save_baseline,
)
from mcpnuke.k8s import discover_services, fingerprint_services, run_k8s_checks
from mcpnuke.reporting import print_report, write_json, write_sarif
from mcpnuke.scanner import detect_cross_shadowing, run_parallel, scan_stdio_target, scan_target

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_SEVERITY_ORDER: list[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _should_fail(findings: list, fail_on: str) -> bool:
    """Return True if any finding meets or exceeds the --fail-on threshold."""
    if fail_on == "none":
        return False
    if fail_on == "any":
        return bool(findings)
    threshold = fail_on.upper()
    if threshold not in _SEVERITY_ORDER:
        return False
    min_idx = _SEVERITY_ORDER.index(threshold)
    return any(
        f.severity.upper() in _SEVERITY_ORDER
        and _SEVERITY_ORDER.index(f.severity.upper()) >= min_idx
        for f in findings
    )


def _run_doctor(console: Console) -> None:
    """Check installation health and report missing deps / config."""
    import shutil

    from mcpnuke import __version__

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

    # Optional: Bedrock runtime
    try:
        import boto3  # noqa: F401
        _ok("boto3 available  [dim](Bedrock runtime)[/dim]")
        try:
            session = boto3.Session()
            creds = session.get_credentials()
            if creds and creds.access_key:
                _ok("AWS credentials available for Bedrock")
            else:
                _warn(
                    "AWS credentials not found — --bedrock may fail",
                    "Configure AWS creds (env vars, profile, or instance role).",
                )
        except Exception as e:
            _warn(
                f"AWS credential check failed: {type(e).__name__}",
                "Use aws configure / profile / role, then re-run --doctor.",
            )
    except ImportError:
        _warn("boto3 not installed — --bedrock disabled", "uv pip install 'mcpnuke[ai]'  or:  pip install boto3")

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
        console.print("  [dim]─[/dim] MCP_AUTH_TOKEN not set  [dim](optional, for authenticated targets)[/dim]")

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


def _build_diff_parser() -> argparse.ArgumentParser:
    """Construct the parser for `mcpnuke diff`.

    Split out from _run_diff_subcommand for the same reason build_parser was
    split out of parse_args: the reference generator has to introspect it.
    `diff` is dispatched off sys.argv before the main parser runs, so
    build_parser() cannot see it and a hand-written section went stale
    immediately.
    """
    p = argparse.ArgumentParser(
        prog="mcpnuke diff",
        description="Compare two mcpnuke JSON scan outputs and show what changed.",
    )
    p.add_argument("before", help="Path to the baseline (older) scan JSON")
    p.add_argument("after", help="Path to the new scan JSON")
    p.add_argument("--json", metavar="FILE", help="Write diff summary as JSON to FILE")
    return p


def _run_diff_subcommand(argv: list[str]) -> None:
    """Handle: mcpnuke diff <before.json> <after.json>"""
    from mcpnuke.reporting.diff import compare_json_files, format_diff_terminal

    args = _build_diff_parser().parse_args(argv)

    try:
        diff = compare_json_files(args.before, args.after)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(format_diff_terminal(diff))

    if args.json:
        import json as _json
        from pathlib import Path as _Path
        summary = {
            "new": [
                {"check": f.check, "severity": f.severity, "title": f.title}
                for f in diff.new_findings
            ],
            "resolved": [
                {"check": f.check, "severity": f.severity, "title": f.title}
                for f in diff.resolved_findings
            ],
            "severity_changes": diff.severity_changes,
            "unchanged_count": diff.unchanged_count,
        }
        _Path(args.json).write_text(_json.dumps(summary, indent=2))
        print(f"\nDiff JSON written to {args.json}")

    if diff.new_findings:
        sys.exit(1)


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

    if args.ollama_analysis:
        # Validate Ollama is reachable before starting any scans.
        import httpx as _httpx
        try:
            _r = _httpx.get(f"{args.ollama_analysis.rstrip('/')}/api/tags", timeout=5.0)
            _r.raise_for_status()
            _models = [m["name"] for m in _r.json().get("models", [])]
            if args.ollama_model not in _models:
                print(
                    f"Warning: model '{args.ollama_model}' not found on "
                    f"{args.ollama_analysis}.\n"
                    f"  Available: {', '.join(_models[:8]) or '(none)'}",
                    file=sys.stderr,
                )
        except Exception as _exc:
            print(
                f"Error: cannot reach Ollama at {args.ollama_analysis}: {_exc}\n"
                "  Check the host/port and that Ollama is running.",
                file=sys.stderr,
            )
            sys.exit(EXIT_ERROR)

    if args.claude:
        if args.ollama_analysis:
            print("Error: --claude and --ollama-analysis are mutually exclusive.", file=sys.stderr)
            sys.exit(EXIT_ERROR)
        if args.bedrock:
            try:
                import boto3  # noqa: F401
            except ImportError:
                print(
                    "Error: --bedrock requires boto3.\n"
                    "Install it with:  uv pip install boto3",
                    file=sys.stderr,
                )
                sys.exit(EXIT_ERROR)
            configure_bedrock(
                enabled=True,
                region=args.bedrock_region,
                profile=args.bedrock_profile,
                model=args.bedrock_model,
            )
        else:
            configure_bedrock(enabled=False)
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

    deterministic_mode: bool = bool(getattr(args, "deterministic", False))
    effective_probe_workers: int = args.probe_workers
    effective_phase2_workers: int = args.claude_phase2_workers
    if deterministic_mode:
        effective_probe_workers = 1
        effective_phase2_workers = 1

    # --stdio mode: scan a local server via stdin/stdout, then exit
    if args.stdio:
        probe_opts = {
            "no_invoke": args.no_invoke,
            "safe_mode": args.safe_mode,
            "probe_calls": args.probe_calls,
            "max_pages": args.max_pages,
            "protocol_mode": args.protocol_mode,
            "jwt_max_ttl": args.jwt_max_ttl,
            "tool_names_file": getattr(args, "tool_names_file", None),
            "claude": args.claude,
            "claude_model": args.claude_model,
            "bedrock": args.bedrock,
            "bedrock_region": args.bedrock_region,
            "bedrock_profile": args.bedrock_profile,
            "bedrock_model": args.bedrock_model,
            "claude_max_tools": args.claude_max_tools,
            "claude_phase2_workers": effective_phase2_workers,
            "ollama_analysis": getattr(args, "ollama_analysis", None),
            "ollama_model": getattr(args, "ollama_model", "qwen2.5:14b"),
            "ollama_ensemble": getattr(args, "ollama_ensemble", None),
            "fast": args.fast,
            "coverage_n": getattr(args, "coverage", None) or 0,
            "probe_workers": effective_probe_workers,
            "deterministic": deterministic_mode,
            "tls_verify": args.tls_verify,
            "extra_headers": extra_headers,
            "inference_host": getattr(args, "inference_host", None),
            "inference_scan": getattr(args, "inference", False) or bool(getattr(args, "inference_host", None)),
            "inference_baseline": getattr(args, "inference_baseline", None),
            "save_inference_baseline": getattr(args, "save_inference_baseline", None),
        }

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
        print_report([result], group_findings=args.group_findings, console=console)
        if args.json_out:
            write_json([result], args.json_out, console=console)
        if getattr(args, "sarif_out", None):
            write_sarif([result], args.sarif_out, console=console)
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

    # Resolve auth token (direct, OIDC client_credentials, or auto-detect)
    auth_token = args.auth_token
    if not auth_token and args.client_id and args.client_secret:
        try:
            auth_token = resolve_auth_token(args)
            console.print("  [green]✓[/green] Token acquired via OIDC client_credentials")
        except RuntimeError as e:
            console.print(f"  [red]✗[/red] OIDC token fetch failed: {e}")
            sys.exit(EXIT_ERROR)
    elif not auth_token and urls and args.verbose:
        info = detect_auth_requirements(
            urls[0],
            verify_tls=args.tls_verify,
            extra_headers=extra_headers,
        )
        if info.requires_auth:
            console.print(f"  [yellow]⚠[/yellow]  Target requires auth: {info.summary()}")
            if info.token_endpoint:
                console.print(f"  [dim]  Token endpoint: {info.token_endpoint}[/dim]")
                console.print(
                    f"  [dim]  Use: --oidc-url {info.issuer or '...'} "
                    f"--client-id ID --client-secret SECRET[/dim]"
                )
    jwt_claims_summary: dict = {}
    auth_context_summary: dict = {}
    if auth_token:
        auth_context_summary["_raw_token"] = auth_token
        claims = decode_jwt_claims(auth_token)
        if claims:
            jwt_claims_summary = summarize_jwt_claims(claims)
            auth_context_summary["jwt_claims_summary"] = jwt_claims_summary
    if args.token_introspect_url:
        if not auth_token:
            console.print("  [yellow]⚠[/yellow] token introspection configured but no auth token resolved")
        else:
            try:
                raw_introspection = fetch_token_introspection(
                    args.token_introspect_url,
                    auth_token,
                    client_id=args.token_introspect_client_id,
                    client_secret=args.token_introspect_client_secret,
                    verify_tls=args.tls_verify,
                    extra_headers=extra_headers,
                )
                auth_context_summary["introspection_summary"] = summarize_introspection(raw_introspection)
            except RuntimeError as e:
                console.print(f"  [yellow]⚠[/yellow] token introspection failed: {e}")
    if args.jwks_url:
        try:
            jwks = fetch_jwks(
                args.jwks_url,
                verify_tls=args.tls_verify,
                extra_headers=extra_headers,
            )
            auth_context_summary["jwks_summary"] = summarize_jwks(jwks)
        except RuntimeError as e:
            console.print(f"  [yellow]⚠[/yellow] JWKS fetch failed: {e}")

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

    if args.ollama_ensemble and not args.ollama_analysis:
        print("Error: --ollama-ensemble requires --ollama-analysis.", file=sys.stderr)
        sys.exit(EXIT_ERROR)
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
        "no_invoke": args.no_invoke,
        "safe_mode": args.safe_mode,
        "probe_calls": args.probe_calls,
        "max_pages": args.max_pages,
        "protocol_mode": args.protocol_mode,
        "jwt_max_ttl": args.jwt_max_ttl,
        "tool_names_file": getattr(args, "tool_names_file", None),
        "claude": args.claude,
        "claude_model": args.claude_model,
        "bedrock": args.bedrock,
        "bedrock_region": args.bedrock_region,
        "bedrock_profile": args.bedrock_profile,
        "bedrock_model": args.bedrock_model,
        "claude_max_tools": args.claude_max_tools,
        "claude_phase2_workers": effective_phase2_workers,
        "ollama_analysis": getattr(args, "ollama_analysis", None),
        "ollama_model": getattr(args, "ollama_model", "qwen2.5:14b"),
        "ollama_ensemble": getattr(args, "ollama_ensemble", None),
        "fast": args.fast,
        "coverage_n": getattr(args, "coverage", None) or 0,
        "probe_workers": effective_probe_workers,
        "deterministic": deterministic_mode,
        "tls_verify": args.tls_verify,
        "extra_headers": extra_headers,
        "auth_context_summary": auth_context_summary,
        "inference_host": getattr(args, "inference_host", None),
        "inference_scan": getattr(args, "inference", False) or bool(getattr(args, "inference_host", None)),
        "inference_baseline": getattr(args, "inference_baseline", None),
        "save_inference_baseline": getattr(args, "save_inference_baseline", None),
        "profile": profile_data,
    }

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

    # Resolve K8s token: --k8s-token > --k8s-token-file > MCPNUKE_K8S_TOKEN env > SA file
    k8s_token: str | None = args.k8s_token
    if not k8s_token and args.k8s_token_file:
        from pathlib import Path as _P
        _tf = _P(args.k8s_token_file)
        if _tf.is_file():
            k8s_token = _tf.read_text().strip()
        else:
            console.print(f"[red]Error: --k8s-token-file not found: {args.k8s_token_file}[/red]")
            sys.exit(EXIT_ERROR)
    k8s_api_url: str | None = args.k8s_api_url

    if not args.no_k8s:
        run_k8s_checks(args.k8s_namespace, console=console, api_url=k8s_api_url, token=k8s_token)

        import os
        sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        _fp_token = k8s_token
        if not _fp_token and os.path.exists(sa_token_path):
            with open(sa_token_path) as _f:
                _fp_token = _f.read().strip()
        if _fp_token:
            fingerprint_services(
                args.k8s_namespace,
                _fp_token,
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
            api_url=k8s_api_url,
            token=k8s_token,
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
        print_report(results, group_findings=args.group_findings, console=console)
        if probe_opts.get("save_inference_baseline"):
            console.print(f"\n  [green]✓[/green] Inference baseline saved to {probe_opts['save_inference_baseline']}")
        if args.json_out:
            write_json(results, args.json_out, console=console)
        if getattr(args, "sarif_out", None):
            write_sarif(results, args.sarif_out, console=console)
        if _should_fail(result.findings, getattr(args, "fail_on", "high")):
            sys.exit(EXIT_FINDINGS)
        sys.exit(EXIT_CLEAN)

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

    if getattr(args, "sarif_out", None):
        write_sarif(results, args.sarif_out, console=console)

    if getattr(args, "diff_baseline", None):
        from mcpnuke.reporting.diff import compare_json_files, format_diff_terminal
        if args.json_out:
            try:
                # Not `diff`: that name already holds a DiffResult from the
                # inventory comparison above, an unrelated type.
                scan_diff = compare_json_files(args.diff_baseline, args.json_out)
                for result in results:
                    result.scan_diff = scan_diff
                console.print("\n[bold cyan]── Diff vs baseline ──[/bold cyan]")
                console.print(format_diff_terminal(scan_diff))
                # Re-write JSON with diff block attached
                write_json(results, args.json_out, console=None)
            except FileNotFoundError as exc:
                console.print(f"[yellow]--diff-baseline: {exc}[/yellow]")
        else:
            console.print(
                "[yellow]--diff-baseline requires --json to write current scan results first.[/yellow]"
            )

    if getattr(args, "policy_out", None):
        from pathlib import Path as _PolicyPath

        from mcpnuke.policy import generate_policy, serialize_policy
        rules = generate_policy(results)

        def _kv_pairs(items: list[str], flag: str) -> dict[str, str]:
            out: dict[str, str] = {}
            for item in items:
                if "=" not in item:
                    raise SystemExit(
                        f"{flag} expects KEY=VALUE, got {item!r}"
                    )
                key, _, value = item.partition("=")
                key, value = key.strip(), value.strip()
                if not key:
                    raise SystemExit(f"{flag} key may not be empty: {item!r}")
                out[key] = value
            return out

        selector = _kv_pairs(
            getattr(args, "policy_selector", []) or [], "--policy-selector"
        )
        meta_labels = _kv_pairs(
            getattr(args, "policy_labels", []) or [], "--policy-labels"
        )
        yaml_str = serialize_policy(
            rules,
            name=getattr(args, "policy_name", "mcpnuke-recommended"),
            namespace=getattr(args, "policy_namespace", "") or "",
            selector_labels=selector,
            metadata_labels=meta_labels,
        )
        _PolicyPath(args.policy_out).write_text(yaml_str)
        scope = (
            f"selector={selector}" if selector else "selector=ALL pods (broad)"
        )
        console.print(
            f"\n[green]nullfield policy written to {args.policy_out} "
            f"({len(rules)} rules, {scope})[/green]"
        )

    if getattr(args, "by_lane", False):
        from mcpnuke.reporting import print_by_lane
        print_by_lane(results, console=console)

    if getattr(args, "coverage_report", None):
        import httpx as _httpx

        from mcpnuke.reporting import (
            SchemaMismatchError,
            build_coverage_report,
            fetch_lane_taxonomy,
            print_coverage_report,
        )
        try:
            taxonomy = fetch_lane_taxonomy(args.coverage_report)
            report = build_coverage_report(results, taxonomy)
            print_coverage_report(report, console=console)
        except SchemaMismatchError as exc:
            console.print(f"\n[red]coverage-report: {exc}[/red]")
        except _httpx.HTTPError as exc:
            console.print(
                f"\n[red]coverage-report: failed to fetch /api/lanes from "
                f"{args.coverage_report}: {exc}[/red]"
            )

    # Taxonomy validation — checks that every finding's taxonomy_id is known
    # to the agentic-sec threat taxonomy (default: vendored lanes.yaml).
    # Surfaces silent vocabulary drift between checks and the canonical list.
    if getattr(args, "taxonomy", None) is not None or any(
        f.taxonomy_id for r in results for f in r.findings
    ):
        from mcpnuke.core.taxonomy import load_taxonomy
        from mcpnuke.core.taxonomy import threat_ids as _tids
        try:
            tax = load_taxonomy(args.taxonomy)
            valid = _tids(tax)
            unknowns: dict[str, int] = {}
            for r in results:
                for f in r.findings:
                    if f.taxonomy_id and f.taxonomy_id not in valid:
                        unknowns[f.taxonomy_id] = unknowns.get(f.taxonomy_id, 0) + 1
            source = args.taxonomy if args.taxonomy else "vendored lanes.yaml"
            console.print(
                f"\n[dim]Taxonomy: {len(valid)} threat IDs loaded from {source}[/dim]"
            )
            if unknowns:
                console.print(
                    "[yellow]Findings reference threat IDs not in the taxonomy:[/yellow]"
                )
                for tid, count in sorted(unknowns.items()):
                    console.print(f"  [yellow]{tid}[/yellow]  ({count} finding(s))")
        except FileNotFoundError as exc:
            console.print(f"\n[red]--taxonomy: {exc}[/red]")
        except Exception as exc:  # noqa: BLE001 - surface any taxonomy load issue clearly
            console.print(f"\n[red]--taxonomy: failed to load: {exc}[/red]")

    all_findings = [f for r in results for f in r.findings]
    if _should_fail(all_findings, getattr(args, "fail_on", "high")):
        sys.exit(EXIT_FINDINGS)


def main() -> None:
    try:
        _main_inner()
    except Exception:
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
