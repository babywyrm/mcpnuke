"""Scan orchestration and cross-target analysis."""

import threading
import time
from collections import defaultdict
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from mcpnuke.core.models import TargetResult
from mcpnuke.core.session import detect_transport, StdioSession, ToolServerSession
from mcpnuke.core.enumerator import enumerate_server
from mcpnuke.checks import run_all_checks

console = Console()


def _stdio_short_label(cmd: str) -> str:
    """Extract a compact label from a stdio command string.

    'npx -y github:yuniko-software/minecraft-mcp-server --host ...'
      -> 'stdio://minecraft-mcp-server'
    """
    import re
    parts = cmd.split()
    for p in reversed(parts):
        if p.startswith("-"):
            continue
        name = p.rsplit("/", 1)[-1]
        name = re.sub(r"^@[^/]+/", "", name)
        if name and name not in ("npx", "node", "python", "python3", "uv", "-y"):
            return f"stdio://{name}"
    return f"stdio://{parts[-1]}" if parts else "stdio://unknown"


def scan_stdio_target(
    cmd: str,
    timeout: float = 25.0,
    verbose: bool = False,
    probe_opts: dict | None = None,
) -> TargetResult:
    """Scan a local MCP server launched via stdin/stdout."""
    label = _stdio_short_label(cmd)
    result = TargetResult(url=label)
    t_start = time.time()

    opts = probe_opts or {}
    _log = console.print if verbose else lambda msg: None

    console.print(f"\n[bold cyan]▶ {label}[/bold cyan]")
    console.print(f"  [dim]Launching subprocess: {cmd}[/dim]")

    try:
        session = StdioSession(cmd, timeout=timeout)
    except Exception as e:
        console.print(f"  [red]✗[/red] Failed to launch: {e}")
        result.transport = "stdio-error"
        result.error = str(e)
        result.timings["total"] = time.time() - t_start
        return result

    if not session.wait_ready(timeout=10.0):
        console.print(f"  [red]✗[/red] Subprocess not ready (exited or timed out)")
        result.transport = "stdio-error"
        result.error = "Process not ready"
        session.close()
        result.timings["total"] = time.time() - t_start
        return result

    result.transport = "stdio"
    console.print(f"  [green]✓[/green] Transport=stdio  pid={session._proc.pid}")

    enumerate_server(session, result, verbose=verbose, log=_log)

    if result.server_info:
        si = result.server_info.get("serverInfo", {})
        if si:
            console.print(
                f"  [dim]Server: {si.get('name', '?')} v{si.get('version', '?')}[/dim]"
            )

    console.print(
        f"  [dim]Tools={len(result.tools)} "
        f"Resources={len(result.resources)} "
        f"Prompts={len(result.prompts)}[/dim]"
    )

    run_all_checks(
        session,
        result,
        [],
        verbose=verbose,
        probe_opts=opts,
        log=_log,
    )

    if opts.get("claude"):
        from mcpnuke.checks.llm_analysis import run_llm_analysis
        run_llm_analysis(
            session, result,
            probe_opts=opts,
            model=opts.get("claude_model", "claude-sonnet-4-20250514"),
            console=console,
        )

    session.close()
    result.timings["total"] = time.time() - t_start
    console.print(
        f"  [dim]Done in {result.timings['total']:.1f}s  "
        f"findings={len(result.findings)}  score={result.risk_score()}[/dim]"
    )
    return result


def detect_cross_shadowing(results: list[TargetResult]):
    """Detect tool name collisions across servers."""
    tool_map: dict[str, list[str]] = defaultdict(list)
    for r in results:
        for t in r.tools:
            tool_map[t["name"]].append(r.url)
    for name, servers in tool_map.items():
        if len(servers) > 1:
            for r in results:
                if r.url in servers:
                    r.add(
                        "cross_shadowing",
                        "MEDIUM",
                        f"Tool '{name}' exists on {len(servers)} servers",
                        f"Servers: {servers}",
                    )


def scan_target(
    url: str,
    all_results: list[TargetResult],
    timeout: float = 25.0,
    verbose: bool = False,
    auth_token: str | None = None,
    probe_opts: dict | None = None,
) -> TargetResult:
    result = TargetResult(url=url)
    t_start = time.time()
    console.print(f"\n[bold cyan]▶ {url}[/bold cyan]")

    opts = probe_opts or {}
    _log = console.print if verbose else lambda msg: None
    session = detect_transport(
        url, connect_timeout=timeout, verbose=verbose, auth_token=auth_token,
        tool_names_file=opts.get("tool_names_file"),
        log=_log,
    )

    if not session:
        console.print(f"  [red]✗[/red] No MCP transport found on {url}")
        result.transport = "none"
        result.add(
            "transport",
            "HIGH",
            "No MCP endpoint found",
            "Tried SSE + HTTP POST + ToolServer on common paths",
        )
        result.timings["total"] = time.time() - t_start
        return result

    if isinstance(session, ToolServerSession):
        transport_label = "ToolServer"
        fp = session.fingerprint
        if fp:
            fp_parts = []
            if fp.get("framework"):
                fp_parts.append(f"framework={fp['framework']}")
            if fp.get("server_header"):
                fp_parts.append(f"server={fp['server_header']}")
            if fp_parts:
                transport_label += f" ({', '.join(fp_parts)})"
    elif hasattr(session, "sse_url") and session.sse_url:
        transport_label = "SSE"
    else:
        transport_label = "HTTP"
    result.transport = transport_label
    console.print(
        f"  [green]✓[/green] Transport={transport_label}"
        f"  post_url={session.post_url}"
    )

    base = ""
    sse_path = ""
    if hasattr(session, "sse_url") and session.sse_url:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        sse_path = urlparse(session.sse_url).path

    enumerate_server(session, result, verbose=verbose, log=_log)

    # Print server info if available
    if result.server_info:
        si = result.server_info.get("serverInfo", {})
        if si:
            console.print(
                f"  [dim]Server: {si.get('name', '?')} v{si.get('version', '?')}[/dim]"
            )

    console.print(
        f"  [dim]Tools={len(result.tools)} "
        f"Resources={len(result.resources)} "
        f"Prompts={len(result.prompts)}[/dim]"
    )

    run_all_checks(
        session,
        result,
        all_results,
        base=base,
        sse_path=sse_path,
        verbose=verbose,
        probe_opts=probe_opts or {},
        log=_log,
    )

    # AI-powered analysis (optional, runs after deterministic checks)
    if opts.get("claude"):
        from mcpnuke.checks.llm_analysis import run_llm_analysis
        claude_model = opts.get("claude_model", "claude-sonnet-4-20250514")
        run_llm_analysis(
            session, result,
            probe_opts=probe_opts or {},
            model=claude_model,
            console=console,
        )

    session.close()
    result.timings["total"] = time.time() - t_start
    console.print(
        f"  [dim]Done in {result.timings['total']:.1f}s  "
        f"findings={len(result.findings)}  score={result.risk_score()}[/dim]"
    )
    return result


def run_parallel(
    urls: list[str],
    timeout: float = 25.0,
    workers: int = 4,
    verbose: bool = False,
    auth_token: str | None = None,
    probe_opts: dict | None = None,
) -> list[TargetResult]:
    results: list[TargetResult] = []
    lock = threading.Lock()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
    task = progress.add_task(
        f"Scanning {len(urls)} target(s)", total=len(urls)
    )

    with progress:

        def worker(url: str):
            with lock:
                snapshot = list(results)
            r = scan_target(
                url, snapshot, timeout=timeout, verbose=verbose,
                auth_token=auth_token, probe_opts=probe_opts,
            )
            with lock:
                results.append(r)
            progress.advance(task)

        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(worker, u) for u in urls]
            concurrent.futures.wait(futures)

    return results
