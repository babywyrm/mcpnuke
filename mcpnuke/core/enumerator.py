"""MCP server enumeration: initialize, tools, resources, prompts."""

import json
import time

from mcpnuke.core.constants import MCP_INIT_PARAMS
from mcpnuke.core.models import TargetResult

DEFAULT_MAX_PAGES: int = 20

_LIST_ITEM_KEYS: dict[str, str] = {
    "tools/list": "tools",
    "resources/list": "resources",
    "prompts/list": "prompts",
}


def _paginated_list(
    session,
    method: str,
    max_pages: int = DEFAULT_MAX_PAGES,
    timeout: float = 15,
    retries: int = 2,
) -> tuple[list[dict], bool]:
    """Fetch a paginated MCP list, following nextCursor up to *max_pages*.

    Returns (items, truncated) where truncated is True when the page cap
    was reached before the server stopped returning cursors.
    """
    item_key = _LIST_ITEM_KEYS.get(method, method.split("/")[0])
    all_items: list[dict] = []
    cursor: str | None = None
    truncated = False

    for page in range(max_pages):
        params: dict = {}
        if cursor:
            params["cursor"] = cursor

        resp = session.call(method, params or None, timeout=timeout, retries=retries)
        if not resp or "result" not in resp:
            break

        result = resp["result"]
        items = result.get(item_key, [])
        all_items.extend(items)

        cursor = result.get("nextCursor") or result.get("cursor")
        if not cursor:
            break

        if page == max_pages - 1:
            truncated = True

    return all_items, truncated


def enumerate_server(
    session,
    result: TargetResult,
    verbose: bool = False,
    log=None,
    max_pages: int = DEFAULT_MAX_PAGES,
):
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
        skip_transports=["stdio"],
    )

    session.notify("notifications/initialized")
    time.sleep(0.5)

    if verbose:
        _log(f"  [dim]Enumerating tools...[/dim]")

    for attempt in range(3):
        tools, tools_truncated = _paginated_list(
            session, "tools/list", max_pages=max_pages, timeout=15,
        )
        if tools is not None:
            result.tools = tools
            break
        time.sleep(1)

    if tools_truncated:
        result.add(
            "enumeration",
            "LOW",
            "Tool enumeration truncated at page cap",
            f"Server returned nextCursor beyond {max_pages}-page limit — "
            f"reported {len(result.tools)} tools but more may exist",
        )

    if verbose and result.tools:
        _log(f"  [dim]Tools ({len(result.tools)}):[/dim]")
        for t in result.tools:
            desc = t.get("description", "")[:60]
            _log(f"  [dim]    {t['name']}: {desc}[/dim]")

    if verbose:
        _log(f"  [dim]Enumerating resources...[/dim]")

    resources, res_truncated = _paginated_list(
        session, "resources/list", max_pages=max_pages, timeout=15,
    )
    result.resources = resources

    if res_truncated:
        result.add(
            "enumeration",
            "LOW",
            "Resource enumeration truncated at page cap",
            f"Server returned nextCursor beyond {max_pages}-page limit — "
            f"reported {len(result.resources)} resources but more may exist",
        )

    if verbose and result.resources:
        _log(f"  [dim]Resources ({len(result.resources)}):[/dim]")
        for r_item in result.resources[:10]:
            _log(f"  [dim]    {r_item.get('uri', r_item.get('name', '?'))}[/dim]")

    if verbose:
        _log(f"  [dim]Enumerating prompts...[/dim]")

    prompts, prompts_truncated = _paginated_list(
        session, "prompts/list", max_pages=max_pages, timeout=15,
    )
    result.prompts = prompts

    if prompts_truncated:
        result.add(
            "enumeration",
            "LOW",
            "Prompt enumeration truncated at page cap",
            f"Server returned nextCursor beyond {max_pages}-page limit — "
            f"reported {len(result.prompts)} prompts but more may exist",
        )

    if verbose and result.prompts:
        _log(f"  [dim]Prompts ({len(result.prompts)}):[/dim]")
        for p in result.prompts[:10]:
            _log(f"  [dim]    {p.get('name', '?')}[/dim]")

    result.timings["enumerate"] = time.time() - t0
    if verbose:
        _log(f"  [dim]Enumeration done in {result.timings['enumerate']:.1f}s[/dim]")
