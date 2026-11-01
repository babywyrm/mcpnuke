"""CLI modes that never scan: --doctor, --lab-coverage, and `mcpnuke diff`.

Kept apart from __main__ so the scan path stays readable. The exit codes
live here because these modes use them and __main__ imports this module.
"""

import argparse
import sys

from rich.console import Console

from mcpnuke import __version__
from mcpnuke.reporting.files import write_private

EXIT_CLEAN: int = 0
EXIT_FINDINGS: int = 1
EXIT_ERROR: int = 2


def _run_lab_coverage(path: str, console: Console, json_out: str | None) -> None:
    """Print which labs in a profile have a check. No scan, no target."""
    import json
    from pathlib import Path

    from mcpnuke.reporting.lab_coverage import build_lab_coverage, print_lab_coverage
    from mcpnuke.reporting.taxonomy_coverage import check_taxonomy_catalog

    profile_path = Path(path)
    if not profile_path.is_file():
        console.print(f"[red]lab-coverage: file not found: {profile_path}[/red]")
        sys.exit(EXIT_ERROR)
    try:
        profile = json.loads(profile_path.read_text())
    except json.JSONDecodeError as exc:
        console.print(f"[red]lab-coverage: {profile_path} is not JSON: {exc}[/red]")
        sys.exit(EXIT_ERROR)
    if not isinstance(profile, dict):
        console.print(f"[red]lab-coverage: {profile_path} must be an object[/red]")
        sys.exit(EXIT_ERROR)
    report = build_lab_coverage(profile, check_taxonomy_catalog())
    print_lab_coverage(report, console=console)
    if json_out:
        write_private(json_out, json.dumps(report, indent=2))
        console.print(f"\n[green]JSON report written → {json_out}[/green]")


def _run_doctor(console: Console) -> None:
    """Check installation health and report missing deps / config."""
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
            if isinstance(ver, str) and ver:
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
        write_private(args.json, _json.dumps(summary, indent=2))
        print(f"\nDiff JSON written to {args.json}")

    if diff.new_findings:
        sys.exit(1)
