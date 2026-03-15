"""Rich console reporting."""

from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

from mcprowler.core.models import TargetResult
from mcprowler.core.constants import SEV_COLOR
from mcprowler.k8s.scanner import GLOBAL_K8S_FINDINGS

console = Console()


def print_report(results: list[TargetResult]):
    all_findings = (
        [f for r in results for f in r.findings] + GLOBAL_K8S_FINDINGS
    )

    if not all_findings:
        console.print("[green]  No vulnerabilities found.[/green]")
        return

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f = sorted(
        all_findings, key=lambda f: sev_order.get(f.severity, 5)
    )

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Target", style="cyan", no_wrap=True)
    table.add_column("Check", style="white")
    table.add_column("Sev", style="bold", no_wrap=True, width=8)
    table.add_column("Finding", style="white")

    for f in sorted_f:
        color = SEV_COLOR.get(f.severity, "white")
        table.add_row(
            f.target.replace("http://", ""),
            f.check,
            Text(f.severity, style=color),
            f.title,
        )
    console.print(table)

    console.print("\n[bold]Per-Target Summary[/bold]")
    ranked = sorted(results, key=lambda r: r.risk_score(), reverse=True)
    pt = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    pt.add_column("Target", style="cyan")
    pt.add_column("Transport")
    pt.add_column("Tools", justify="right")
    pt.add_column("Findings", justify="right")
    pt.add_column("Score", justify="right", style="bold")
    pt.add_column("Time", justify="right")

    for r in ranked:
        score = r.risk_score()
        color = (
            "bold red"
            if score >= 20
            else "red"
            if score >= 10
            else "yellow"
            if score >= 5
            else "green"
        )
        pt.add_row(
            r.url.replace("http://", ""),
            r.transport,
            str(len(r.tools)),
            str(len(r.findings)),
            Text(str(score), style=color),
            f"{r.timings.get('total', 0):.1f}s",
        )
    console.print(pt)

    counts = Counter(f.severity for f in all_findings)
    console.print(
        f"\n  [bold red]CRITICAL: {counts.get('CRITICAL', 0)}[/bold red]  |  "
        f"[red]HIGH: {counts.get('HIGH', 0)}[/red]  |  "
        f"[yellow]MEDIUM: {counts.get('MEDIUM', 0)}[/yellow]  |  "
        f"[cyan]LOW: {counts.get('LOW', 0)}[/cyan]"
    )

    chain_findings = [f for f in all_findings if f.check == "attack_chain"]
    if chain_findings:
        console.print("\n[bold red]Attack Chains Detected:[/bold red]")
        for f in chain_findings:
            console.print(
                f"  [bold red]⚠[/bold red]  {f.title} ({f.target})"
            )
