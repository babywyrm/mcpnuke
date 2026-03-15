"""MCP server enumeration: initialize, tools, resources, prompts."""

import json
import time

from mcpredator.core.constants import MCP_INIT_PARAMS
from mcpredator.core.models import TargetResult


def enumerate_server(session, result: TargetResult, verbose: bool = False, log=None):
    """Enumerate an MCP server: initialize, list tools/resources/prompts.
    
    When verbose=True and log is provided, emits detailed progress.
    """
    _log = log or (lambda msg: None)
    t0 = time.time()

    if verbose:
        _log(f"  [dim]Sending initialize...[/dim]")

    resp = session.call("initialize", MCP_INIT_PARAMS, retries=3)

    if not resp or "result" not in resp:
        result.add(
            "init",
            "HIGH",
            "No response to MCP initialize",
            "Server did not respond to initialize handshake",
        )
        result.timings["enumerate"] = time.time() - t0
        return

    r = resp["result"]
    result.server_info = r
    info = r.get("serverInfo", {})
    caps = r.get("capabilities", {})

    if verbose:
        server_name = info.get("name", "?")
        server_version = info.get("version", "?")
        proto = r.get("protocolVersion", "?")
        _log(f"  [dim]Server: {server_name} v{server_version}  protocol={proto}[/dim]")
        cap_list = list(caps.keys()) if caps else ["none"]
        _log(f"  [dim]Capabilities: {', '.join(cap_list)}[/dim]")

    result.add(
        "auth",
        "HIGH",
        "Unauthenticated MCP initialize accepted",
        f"Server '{info.get('name','?')}' v{info.get('version','?')} "
        f"accepted initialize with no credentials",
        evidence=json.dumps(r, indent=2)[:500],
    )

    session.notify("notifications/initialized")
    time.sleep(0.5)

    if verbose:
        _log(f"  [dim]Enumerating tools...[/dim]")

    for attempt in range(3):
        tr = session.call("tools/list", timeout=15, retries=2)
        if tr and "result" in tr:
            result.tools = tr["result"].get("tools", [])
            break
        time.sleep(1)

    if verbose and result.tools:
        _log(f"  [dim]Tools ({len(result.tools)}):[/dim]")
        for t in result.tools:
            desc = t.get("description", "")[:60]
            _log(f"  [dim]    {t['name']}: {desc}[/dim]")

    if verbose:
        _log(f"  [dim]Enumerating resources...[/dim]")

    rr = session.call("resources/list", timeout=15, retries=2)
    if rr and "result" in rr:
        result.resources = rr["result"].get("resources", [])

    if verbose and result.resources:
        _log(f"  [dim]Resources ({len(result.resources)}):[/dim]")
        for r_item in result.resources[:10]:
            _log(f"  [dim]    {r_item.get('uri', r_item.get('name', '?'))}[/dim]")

    if verbose:
        _log(f"  [dim]Enumerating prompts...[/dim]")

    pr = session.call("prompts/list", timeout=15, retries=2)
    if pr and "result" in pr:
        result.prompts = pr["result"].get("prompts", [])

    if verbose and result.prompts:
        _log(f"  [dim]Prompts ({len(result.prompts)}):[/dim]")
        for p in result.prompts[:10]:
            _log(f"  [dim]    {p.get('name', '?')}[/dim]")

    result.timings["enumerate"] = time.time() - t0
    if verbose:
        _log(f"  [dim]Enumeration done in {result.timings['enumerate']:.1f}s[/dim]")
