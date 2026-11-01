"""Scan-path steps that `mcpnuke.__main__._main_inner` runs in order."""

import argparse
import sys
import time
from typing import TYPE_CHECKING

from rich.console import Console

from mcpnuke.core.auth import (
    decode_jwt_claims,
    detect_auth_requirements,
    fetch_jwks,
    fetch_token_introspection,
    load_auth_secret_files,
    resolve_auth_token,
    summarize_introspection,
    summarize_jwks,
    summarize_jwt_claims,
)
from mcpnuke.core.models import TargetResult
from mcpnuke.diff import (
    apply_diff_findings,
    diff_against_baseline,
)
from mcpnuke.k8s import discover_services, fingerprint_services, run_k8s_checks
from mcpnuke.reporting import print_report, write_json, write_sarif
from mcpnuke.reporting.files import write_private
from mcpnuke.scanner import run_parallel, scan_target
from mcpnuke.subcommands import (
    EXIT_CLEAN,
    EXIT_ERROR,
)

if TYPE_CHECKING:
    from mcpnuke.core.oast import CanaryListener

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




def _start_oast(args: argparse.Namespace, console: Console) -> "CanaryListener | None":
    """Bring up the callback listener when --oast is set.

    Returns None when the flag is off or the socket cannot be bound. A listener
    that fails to start must not abort the scan: every other check still works,
    and the exfil finding simply keeps its weaker, honest wording.
    """
    if not getattr(args, "oast", False):
        return None

    from mcpnuke.core.oast import CanaryListener

    try:
        listener = CanaryListener(
            port=int(getattr(args, "oast_port", 0) or 0),
            advertised_host=getattr(args, "oast_host", None),
        ).start()
    except OSError as exc:
        console.print(f"  [red]--oast: could not bind listener: {exc}[/red]")
        return None

    console.print(
        f"  [yellow]--oast: callback listener on {listener.base_url} — "
        "the target must be able to reach this address[/yellow]"
    )
    return listener


def _emit_taxonomy_coverage(
    args: argparse.Namespace,
    results: list[TargetResult],
    console: Console,
) -> dict | None:
    """Print the per-ID report when asked. None leaves the JSON unchanged."""
    if not getattr(args, "taxonomy_coverage", False):
        return None
    from mcpnuke.core.taxonomy import get_taxonomy
    from mcpnuke.reporting.taxonomy_coverage import (
        build_taxonomy_coverage,
        check_taxonomy_catalog,
        print_taxonomy_coverage,
    )

    report = build_taxonomy_coverage(
        results, taxonomy=get_taxonomy(), catalog=check_taxonomy_catalog()
    )
    print_taxonomy_coverage(report, console=console)
    return report


def _watch_lanes(
    args: argparse.Namespace,
    results: list[TargetResult],
    urls: list[str],
    auth_token: str | None,
    probe_opts: dict,
    baseline: dict,
    console: Console,
) -> None:
    """Re-scan until interrupted. Print only the lane delta each pass."""
    from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS
    from mcpnuke.reporting.by_lane import build_by_lane, format_lane_delta

    previous = build_by_lane(results)
    console.print(f"\n[dim]Watching every {args.watch}s. Interrupt to stop.[/dim]")
    try:
        while True:
            time.sleep(args.watch)
            # The k8s scanner appends to a process global. A repeat scan
            # would otherwise stack the same findings forever.
            GLOBAL_K8S_FINDINGS.clear()
            if len(urls) == 1:
                scanned = [
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
                scanned = run_parallel(
                    urls,
                    timeout=args.timeout,
                    workers=args.workers,
                    verbose=args.verbose,
                    auth_token=auth_token,
                    probe_opts=probe_opts,
                )
            if args.baseline and baseline:
                for result in scanned:
                    base = baseline.get(result.url, {})
                    if not base:
                        continue
                    diff = diff_against_baseline(
                        result.catalog_tools(),
                        result.resources,
                        result.prompts,
                        base.get("tools", []),
                        base.get("resources", []),
                        base.get("prompts", []),
                        url=result.url,
                    )
                    apply_diff_findings(result, diff)
            current = build_by_lane(scanned)
            console.print(format_lane_delta(previous, current))
            previous = current
    except KeyboardInterrupt:
        console.print("\n[dim]Watch stopped.[/dim]")


def _k8s_setup(args: argparse.Namespace, urls: list[str], console: Console) -> None:
    """Run the cluster checks and add discovered MCP endpoints to ``urls``.

    Token order: --k8s-token or its MCPNUKE_K8S_TOKEN default, then
    --k8s-token-file, then the pod's service-account token.
    """
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
                write_private(args.json_out, json.dumps(report, indent=2))
                console.print(f"[green]JSON written to {args.json_out}[/green]")
            sys.exit(EXIT_CLEAN)
        for ep in discovered:
            if ep.url not in urls:
                urls.append(ep.url)
                console.print(f"  [green]+[/green] Added discovered target: {ep.url}")


def _validate_ai_backend(args: argparse.Namespace) -> None:
    """Fail fast on AI flags that cannot work, before any scan or network call."""
    from mcpnuke.core.llm import configure_bedrock

    if args.claude and args.ollama_analysis:
        print("Error: --claude and --ollama-analysis are mutually exclusive.", file=sys.stderr)
        sys.exit(EXIT_ERROR)
    if args.ollama_ensemble and not args.ollama_analysis:
        print("Error: --ollama-ensemble requires --ollama-analysis.", file=sys.stderr)
        sys.exit(EXIT_ERROR)

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


def _resolve_auth(
    args: argparse.Namespace,
    urls: list[str],
    extra_headers: dict[str, str],
    console: Console,
) -> tuple[str | None, dict]:
    """Resolve the bearer (flag, file, OIDC, or none) and the auth context checks read.

    The context holds the raw token under ``_raw_token``; JSON output redacts it.
    """
    try:
        load_auth_secret_files(args)
    except RuntimeError as e:
        console.print(f"  [red]✗[/red] {e}")
        sys.exit(EXIT_ERROR)
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
    auth_context_summary: dict = {}
    if auth_token:
        auth_context_summary["_raw_token"] = auth_token
        claims = decode_jwt_claims(auth_token)
        if claims:
            auth_context_summary["jwt_claims_summary"] = summarize_jwt_claims(claims)
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
    return auth_token, auth_context_summary


def _base_probe_opts(
    args: argparse.Namespace,
    *,
    extra_headers: dict[str, str],
    probe_workers: int,
    phase2_workers: int,
    deterministic: bool,
) -> dict:
    """Probe options every scan mode shares, read straight from the CLI."""
    return {
        "no_invoke": args.no_invoke,
        "safe_mode": args.safe_mode,
        "probe_calls": args.probe_calls,
        "max_pages": args.max_pages,
        "protocol_mode": args.protocol_mode,
        "jwt_max_ttl": args.jwt_max_ttl,
        "tool_names_file": getattr(args, "tool_names_file", None),
        "claude": args.claude,
        "chain_replay": getattr(args, "chain_replay", False),
        "chain_replay_retries": getattr(args, "chain_replay_retries", 1),
        "cross_server": getattr(args, "cross_server", False),
        "claude_model": args.claude_model,
        "bedrock": args.bedrock,
        "bedrock_region": args.bedrock_region,
        "bedrock_profile": args.bedrock_profile,
        "bedrock_model": args.bedrock_model,
        "claude_max_tools": args.claude_max_tools,
        "claude_phase2_workers": phase2_workers,
        "ollama_analysis": getattr(args, "ollama_analysis", None),
        "ollama_model": getattr(args, "ollama_model", "qwen2.5:14b"),
        "ollama_ensemble": getattr(args, "ollama_ensemble", None),
        "fast": args.fast,
        "coverage_n": getattr(args, "coverage", None) or 0,
        "probe_workers": probe_workers,
        "deterministic": deterministic,
        "tls_verify": args.tls_verify,
        "extra_headers": extra_headers,
        "inference_host": getattr(args, "inference_host", None),
        "inference_scan": getattr(args, "inference", False) or bool(getattr(args, "inference_host", None)),
        "inference_baseline": getattr(args, "inference_baseline", None),
        "save_inference_baseline": getattr(args, "save_inference_baseline", None),
        "error_reflection": getattr(args, "error_reflection", "downgrade"),
    }


def _report(args: argparse.Namespace, results: list[TargetResult], console: Console) -> None:
    """Print and write every requested report. Shared by all scan modes."""
    print_report(results, group_findings=args.group_findings, console=console)

    taxonomy_coverage = _emit_taxonomy_coverage(args, results, console)
    if args.json_out:
        write_json(results, args.json_out, console=console, taxonomy_coverage=taxonomy_coverage)

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
                write_json(results, args.json_out, console=None, taxonomy_coverage=taxonomy_coverage)
            except FileNotFoundError as exc:
                console.print(f"[yellow]--diff-baseline: {exc}[/yellow]")
        else:
            console.print(
                "[yellow]--diff-baseline requires --json to write current scan results first.[/yellow]"
            )

    if getattr(args, "policy_out", None):

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
        write_private(args.policy_out, yaml_str)
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

    if getattr(args, "owasp", False):
        from mcpnuke.reporting import print_owasp
        print_owasp(results, console=console)

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

