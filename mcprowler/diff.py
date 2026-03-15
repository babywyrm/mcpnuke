"""Differential scanning: compare current scan to baseline."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class DiffResult:
    """Result of diffing current scan against baseline."""

    url: str
    added_tools: list[dict] = field(default_factory=list)
    removed_tools: list[dict] = field(default_factory=list)
    modified_tools: list[tuple[dict, dict]] = field(default_factory=list)
    added_resources: list[dict] = field(default_factory=list)
    removed_resources: list[dict] = field(default_factory=list)
    added_prompts: list[dict] = field(default_factory=list)
    removed_prompts: list[dict] = field(default_factory=list)

    def has_changes(self) -> bool:
        return bool(
            self.added_tools
            or self.removed_tools
            or self.modified_tools
            or self.added_resources
            or self.removed_resources
            or self.added_prompts
            or self.removed_prompts
        )


def _tool_key(t: dict) -> str:
    return t.get("name", "")


def _resource_key(r: dict) -> str:
    return r.get("uri", r.get("name", ""))


def _prompt_key(p: dict) -> str:
    return p.get("name", "")


def _tools_equal(a: dict, b: dict) -> bool:
    """Compare two tool definitions (name, description, inputSchema)."""
    return (
        a.get("name") == b.get("name")
        and a.get("description", "") == b.get("description", "")
        and json.dumps(a.get("inputSchema", {}), sort_keys=True)
        == json.dumps(b.get("inputSchema", {}), sort_keys=True)
    )


def diff_against_baseline(
    current_tools: list[dict],
    current_resources: list[dict],
    current_prompts: list[dict],
    baseline_tools: list[dict],
    baseline_resources: list[dict],
    baseline_prompts: list[dict],
    url: str = "",
) -> DiffResult:
    """Compare current enumeration to baseline. Returns DiffResult."""
    result = DiffResult(url=url)

    # Tools
    base_tool_map = {_tool_key(t): t for t in baseline_tools}
    curr_tool_map = {_tool_key(t): t for t in current_tools}

    for name, t in curr_tool_map.items():
        if name not in base_tool_map:
            result.added_tools.append(t)
        elif not _tools_equal(t, base_tool_map[name]):
            result.modified_tools.append((base_tool_map[name], t))

    for name, t in base_tool_map.items():
        if name not in curr_tool_map:
            result.removed_tools.append(t)

    # Resources
    base_res_map = {_resource_key(r): r for r in baseline_resources}
    curr_res_map = {_resource_key(r): r for r in current_resources}

    for key, r in curr_res_map.items():
        if key not in base_res_map:
            result.added_resources.append(r)
    for key, r in base_res_map.items():
        if key not in curr_res_map:
            result.removed_resources.append(r)

    # Prompts
    base_prompt_map = {_prompt_key(p): p for p in baseline_prompts}
    curr_prompt_map = {_prompt_key(p): p for p in current_prompts}

    for key, p in curr_prompt_map.items():
        if key not in base_prompt_map:
            result.added_prompts.append(p)
    for key, p in base_prompt_map.items():
        if key not in curr_prompt_map:
            result.removed_prompts.append(p)

    return result


def load_baseline(path: str | Path) -> dict[str, dict]:
    """Load baseline from JSON. Returns dict[url, {tools, resources, prompts}]. """
    p = Path(path)
    if not p.is_file():
        return {}
    data = json.loads(p.read_text())
    # Format: { "targets": { url: { tools, resources, prompts } } }
    targets = data.get("targets", data)
    if isinstance(targets, dict):
        return targets
    # Legacy: list of {url, tools, resources, prompts}
    return {t["url"]: t for t in targets if isinstance(t, dict) and "url" in t}


def save_baseline(results: list, path: str | Path, console=None):
    """Save current scan results as baseline JSON."""
    from mcprowler.core.models import TargetResult

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    targets = {}
    for r in results:
        if not isinstance(r, TargetResult):
            continue
        targets[r.url] = {
            "url": r.url,
            "tools": r.tools,
            "resources": r.resources,
            "prompts": r.prompts,
        }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline": True,
        "targets": targets,
    }
    p.write_text(json.dumps(report, indent=2))
    if console:
        console.print(f"\n[green]Baseline saved → {path}[/green]")


def print_diff_report(diff_results: list["DiffResult"], baseline_path: str, console=None):
    """Print differential scan report to console."""
    if not console:
        from rich.console import Console
        console = Console()

    any_changes = any(d.has_changes() for d in diff_results)
    if not any_changes:
        console.print("\n[green]No changes since baseline.[/green]")
        return

    console.print(f"\n[bold cyan]Differential Scan[/bold cyan] (baseline: {baseline_path})")
    for d in diff_results:
        if not d.has_changes():
            continue
        console.print(f"\n  [bold]{d.url.replace('http://', '')}[/bold]")
        if d.added_tools:
            for t in d.added_tools:
                console.print(f"    [green]+ ADDED tool:[/green] {t.get('name', '?')}")
        if d.removed_tools:
            for t in d.removed_tools:
                console.print(f"    [red]- REMOVED tool:[/red] {t.get('name', '?')}")
        if d.modified_tools:
            for _base, curr in d.modified_tools:
                console.print(f"    [yellow]~ MODIFIED tool:[/yellow] {curr.get('name', '?')}")
        if d.added_resources:
            for r in d.added_resources:
                uri = r.get("uri", r.get("name", "?"))
                console.print(f"    [green]+ ADDED resource:[/green] {uri}")
        if d.removed_resources:
            for r in d.removed_resources:
                uri = r.get("uri", r.get("name", "?"))
                console.print(f"    [red]- REMOVED resource:[/red] {uri}")
        if d.added_prompts:
            for p in d.added_prompts:
                console.print(f"    [green]+ ADDED prompt:[/green] {p.get('name', '?')}")
        if d.removed_prompts:
            for p in d.removed_prompts:
                console.print(f"    [red]- REMOVED prompt:[/red] {p.get('name', '?')}")
