"""MCP server enumeration: initialize, tools, resources, prompts."""

import json
import time

from mcpnuke.core.constants import MCP_INIT_PARAMS
from mcpnuke.core.models import TargetResult
from mcpnuke.core.protocol import AUTO, LEGACY, STATELESS

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


def negotiate_protocol(
    session,
    result: TargetResult,
    mode: str = AUTO,
    verbose: bool = False,
    log=None,
) -> str:
    """Determine whether *session* speaks the legacy or stateless protocol.

    Probes ``initialize`` (legacy handshake), then ``server/discover``, then a
    bare ``tools/list`` (both stateless). Returns the winning mode, or ``""``
    when the server answered none of them. Sets ``result.protocol_mode`` and
    ``session.protocol_mode`` as a side effect.
    """
    _log = log or (lambda msg: None)

    if mode in (AUTO, LEGACY):
        if verbose:
            _log("  [dim]Sending initialize...[/dim]")
        resp = session.call("initialize", MCP_INIT_PARAMS, retries=3)
        if resp and "result" in resp:
            result.server_info = resp["result"]
            result.protocol_mode = LEGACY
            session.protocol_mode = LEGACY
            return LEGACY
        if mode == LEGACY:
            return ""

    # Stateless: capabilities are optional, so a failed discover is not fatal.
    session.protocol_mode = STATELESS

    if verbose:
        _log("  [dim]Trying stateless server/discover...[/dim]")
    resp = session.call("server/discover", None, retries=2)
    if resp and "result" in resp:
        result.server_info = resp["result"]
        result.protocol_mode = STATELESS
        info = resp["result"].get("serverInfo", {})
        result.add(
            "auth",
            "HIGH",
            "Unauthenticated MCP server/discover accepted",
            f"Server '{info.get('name','?')}' v{info.get('version','?')} "
            f"disclosed capabilities to an anonymous caller via server/discover",
            evidence=json.dumps(resp["result"], indent=2)[:500],
            skip_transports=["stdio"],
            lane=5,
            transport="A",
        )
        return STATELESS

    if verbose:
        _log("  [dim]Trying stateless tools/list without discovery...[/dim]")
    resp = session.call("tools/list", None, retries=2)
    if resp and "result" in resp:
        result.protocol_mode = STATELESS
        return STATELESS

    session.protocol_mode = LEGACY
    return ""


def enumerate_server(
    session,
    result: TargetResult,
    verbose: bool = False,
    log=None,
    max_pages: int = DEFAULT_MAX_PAGES,
    protocol_mode: str = AUTO,
):
    """Enumerate an MCP server: initialize, list tools/resources/prompts.

    When verbose=True and log is provided, emits detailed progress.
    """
    _log = log or (lambda msg: None)
    t0 = time.time()

    mode = negotiate_protocol(session, result, protocol_mode, verbose=verbose, log=log)

    if not mode:
        result.add(
            "init",
            "HIGH",
            "No response to MCP initialize",
            "Server did not respond to initialize, server/discover, or tools/list",
        )
        result.timings["enumerate"] = time.time() - t0
        return

    r = result.server_info
    info = r.get("serverInfo", {})
    caps = r.get("capabilities", {})

    if verbose:
        server_name = info.get("name", "?")
        server_version = info.get("version", "?")
        proto = r.get("protocolVersion", "?")
        _log(f"  [dim]Server: {server_name} v{server_version}  protocol={proto} mode={mode}[/dim]")
        cap_list = list(caps.keys()) if caps else ["none"]
        _log(f"  [dim]Capabilities: {', '.join(cap_list)}[/dim]")

    if mode == LEGACY:
        result.add(
            "auth",
            "HIGH",
            "Unauthenticated MCP initialize accepted",
            f"Server '{info.get('name','?')}' v{info.get('version','?')} "
            f"accepted initialize with no credentials",
            evidence=json.dumps(r, indent=2)[:500],
            skip_transports=["stdio"],
            # The "anybody can initialize" failure is a Lane 5 (anonymous)
            # finding: it describes what a pre-auth caller can do.
            lane=5,
            transport="A",
        )

        session.notify("notifications/initialized")
        time.sleep(0.5)

    if verbose:
        _log("  [dim]Enumerating tools...[/dim]")

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
        _log("  [dim]Enumerating resources...[/dim]")

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
        _log("  [dim]Enumerating prompts...[/dim]")

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
