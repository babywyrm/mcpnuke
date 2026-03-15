"""MCP server enumeration: initialize, tools, resources, prompts."""

import json
import time

from mcprowler.core.constants import MCP_INIT_PARAMS
from mcprowler.core.models import TargetResult


def enumerate_server(session, result: TargetResult, verbose: bool = False):
    t0 = time.time()
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

    for attempt in range(3):
        tr = session.call("tools/list", timeout=15, retries=2)
        if tr and "result" in tr:
            result.tools = tr["result"].get("tools", [])
            break
        time.sleep(1)

    rr = session.call("resources/list", timeout=15, retries=2)
    if rr and "result" in rr:
        result.resources = rr["result"].get("resources", [])

    pr = session.call("prompts/list", timeout=15, retries=2)
    if pr and "result" in pr:
        result.prompts = pr["result"].get("prompts", [])

    result.timings["enumerate"] = time.time() - t0
