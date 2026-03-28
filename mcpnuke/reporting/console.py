"""Rich console reporting with optional grouped findings."""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

from mcpnuke.core.models import TargetResult, Finding
from mcpnuke.core.constants import SEV_COLOR
from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS

_default_console = Console()

_TOOL_NAME_RE = re.compile(r"'([^']+)'")


def _short_target(url: str, max_len: int = 45) -> str:
    """Truncate a target URL for table display."""
    url = url.replace("http://", "")
    if len(url) <= max_len:
        return url
    return url[:max_len - 1] + "\u2026"


def _group_findings(findings: list[Finding]) -> list[dict]:
    """Collapse similar findings by (check, severity) into compact grouped rows.

    Returns dicts with keys: check, severity, title, count, tools.
    """
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.check, f.severity)].append(f)

    rows = []
    for (check, severity), group in groups.items():
        tools: list[str] = []
        for f in group:
            m = _TOOL_NAME_RE.search(f.title)
            if m:
                tools.append(m.group(1))

        title = group[0].title
        if len(group) > 1:
            if tools:
                unique_tools = sorted(set(tools))
                title = f"{check}: {len(group)} findings across {len(unique_tools)} tool(s)"
            else:
                title = f"{check}: {len(group)} findings"

        rows.append({
            "check": check,
            "severity": severity,
            "title": title,
            "count": len(group),
            "tools": sorted(set(tools)),
            "target": group[0].target,
        })
    return rows


def print_report(
    results: list[TargetResult],
    group_findings: bool = False,
    console: Console | None = None,
) -> None:
    console = console or _default_console
    all_findings = (
        [f for r in results for f in r.findings] + GLOBAL_K8S_FINDINGS
    )

    if not all_findings:
        console.print("[green]  No vulnerabilities found.[/green]")
        return

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    if group_findings:
        rows = _group_findings(all_findings)
        rows.sort(key=lambda r: sev_order.get(r["severity"], 5))

        table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("Check", style="white")
        table.add_column("Sev", style="bold", no_wrap=True, width=8)
        table.add_column("#", justify="right", width=4)
        table.add_column("Finding", style="white")
        table.add_column("Affected Tools", style="dim")

        for r in rows:
            color = SEV_COLOR.get(r["severity"], "white")
            tool_str = ", ".join(r["tools"][:6])
            if len(r["tools"]) > 6:
                tool_str += f" +{len(r['tools']) - 6}"
            table.add_row(
                _short_target(r["target"]),
                r["check"],
                Text(r["severity"], style=color),
                str(r["count"]),
                r["title"],
                tool_str,
            )
        console.print(table)
    else:
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
                _short_target(f.target),
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
            _short_target(r.url),
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
