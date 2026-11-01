"""Transport detection: probe a URL and open the session that answers.

The four session classes live in ``mcpnuke.core.transports``.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx

from mcpnuke.core.constants import MCP_INIT_PARAMS, POST_PATHS, SSE_PATHS
from mcpnuke.core.constants import build_jsonrpc_request as _jrpc
from mcpnuke.core.transports.http import HTTPSession, _auth_headers, _mcp_headers, _parse_sse_json
from mcpnuke.core.transports.sse import MCPSession
from mcpnuke.core.transports.stdio import StdioSession
from mcpnuke.core.transports.toolserver import (
    ToolServerSession,
    _fingerprint_tool_server,
)

# Re-exported: checks, the scanner, and tests import these from here.
__all__ = [
    "HTTPSession",
    "MCPSession",
    "StdioSession",
    "ToolServerSession",
    "_auth_headers",
    "_mcp_headers",
    "_parse_sse_json",
    "detect_transport",
]


def _probe_sse_path(
    base: str,
    path: str,
    timeout: float = 6.0,
    auth_token: str | None = None,
    verify_tls: bool = False,
    extra_headers: dict | None = None,
) -> bool:
    url = base + path
    result: list[bool] = [False]
    done = threading.Event()
    headers = _auth_headers(auth_token, extra_headers)

    def _try() -> None:
        try:
            with httpx.Client(
                verify=verify_tls, timeout=httpx.Timeout(timeout, connect=4.0)
            ) as c, c.stream(
                "GET", url, headers=headers
            ) as resp:
                ct = resp.headers.get("content-type", "")
                if resp.status_code == 200 and "text/event-stream" in ct:
                    result[0] = True
                done.set()
                for _ in zip(resp.iter_bytes(chunk_size=64), range(3), strict=False):
                    pass
        except Exception:
            pass
        finally:
            done.set()

    t = threading.Thread(target=_try, daemon=True)
    t.start()
    done.wait(timeout=timeout + 1)
    return result[0]



TOOL_SERVER_PROBES = [
    {"tool": "get_cluster_health"},
    {"tool": "list_tools"},
    {"tool": "health"},
    {"tool": "help"},
    {"tool": "status"},
    {"tool": ""},
]


TOOL_EXECUTE_PATHS = [
    "/execute", "/tools/execute", "/api/execute", "/run",
    "/api/run", "/invoke", "/api/invoke", "/tools/run",
    "/tool", "/api/tool", "/v1/execute", "/v1/run",
    "/v1/invoke", "/v1/tool", "/rpc/execute",
    "/action", "/api/action", "/command", "/api/command",
]


def _detect_tool_server(
    base: str,
    hint: str | None,
    timeout: float,
    auth_token: str | None,
    verify_tls: bool,
    extra_headers: dict | None,
    tool_names_file: str | None = None,
) -> ToolServerSession | None:
    """Try to detect a custom tool-execute API (non-MCP).

    Probes the hint path first, then TOOL_EXECUTE_PATHS. Uses 404 vs 400/200
    to distinguish "path exists but wrong payload" from "path doesn't exist."
    """
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    if extra_headers:
        headers.update(extra_headers)

    paths_to_try: list[str] = []
    if hint:
        paths_to_try.append(hint)
    paths_to_try.extend(TOOL_EXECUTE_PATHS)

    seen: set[str] = set()
    client = httpx.Client(verify=verify_tls, timeout=5, follow_redirects=True)

    try:
        for path in paths_to_try:
            if path in seen:
                continue
            seen.add(path)
            url = base + path

            # Quick 404 check: if GET returns 404, skip this path entirely
            try:
                get_r = client.get(url, headers={"Accept": "application/json"})
                if get_r.status_code == 404:
                    continue
            except Exception:
                pass

            for probe in TOOL_SERVER_PROBES:
                try:
                    r = client.post(url, json=probe, headers=headers)
                    body = r.text.lower()
                    resp_headers = dict(r.headers)

                    is_tool_server = False

                    if r.status_code == 200:
                        try:
                            r.json()
                            is_tool_server = True
                        except Exception:
                            pass

                    if r.status_code in (400, 403, 422) and (
                        "unknown tool" in body
                        or ("tool" in body and "error" in body)
                        or "invalid tool" in body
                        or "not found" in body and "tool" in body
                        or "required" in body and ("tool" in body or "name" in body)
                    ):
                        is_tool_server = True

                    # 405 Method Not Allowed on GET but path accepts POST = likely tool server
                    if r.status_code == 405:
                        is_tool_server = False

                    if is_tool_server:
                        fp = _fingerprint_tool_server(resp_headers, r.text)
                        return ToolServerSession(
                            base, url, timeout=timeout, headers=headers,
                            tool_names_file=tool_names_file, fingerprint=fp,
                            verify_tls=verify_tls,
                        )

                except Exception:
                    pass
    finally:
        client.close()

    return None


def detect_transport(
    url: str,
    connect_timeout: float = 25.0,
    verbose: bool = False,
    auth_token: str | None = None,
    verify_tls: bool = False,
    extra_headers: dict | None = None,
    log: Callable[[str], None] | None = None,
    **kwargs: Any,
) -> MCPSession | HTTPSession | ToolServerSession | None:
    """Detect MCP transport at the given URL.

    Tries SSE, HTTP POST (Streamable HTTP), SSE+POST combos, and custom tool servers.
    When verbose=True and log is provided, emits detailed probe status.
    """
    _log = log or (lambda msg: None)
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    hint = parsed.path.rstrip("/") or None

    seen_paths: set[str] = set()
    ordered_paths: list[str] = []
    for p in ([hint] if hint else []) + SSE_PATHS:
        if p is not None and p not in seen_paths:
            seen_paths.add(p)
            ordered_paths.append(p)

    if verbose:
        _log(f"  [dim]Probing {len(ordered_paths)} SSE path(s) on {base}[/dim]")

    for sse_path in ordered_paths:
        if verbose:
            _log(f"  [dim]  SSE probe: {base}{sse_path}[/dim]")
        if not _probe_sse_path(
            base,
            sse_path,
            timeout=6.0,
            auth_token=auth_token,
            verify_tls=verify_tls,
            extra_headers=extra_headers,
        ):
            continue

        if verbose:
            _log(f"  [dim]  SSE stream found at {sse_path}, waiting for endpoint...[/dim]")
        session = MCPSession(
            base,
            sse_path,
            timeout=connect_timeout,
            auth_token=auth_token,
            verify_tls=verify_tls,
            extra_headers=extra_headers,
        )

        if session.wait_ready(timeout=12.0) and session.post_url:
            if verbose:
                _log(f"  [dim]  SSE ready: post_url={session.post_url}[/dim]")
            return session

        session.close()

    client = httpx.Client(verify=verify_tls, timeout=8, follow_redirects=True)

    seen_post: set[str] = set()
    ordered_post: list[str] = []
    for p in ([hint] if hint else []) + POST_PATHS:
        if p is not None and p not in seen_post:
            seen_post.add(p)
            ordered_post.append(p)

    if verbose:
        _log(f"  [dim]Probing {len(ordered_post)} HTTP POST path(s) on {base}[/dim]")

    mcp_headers = _mcp_headers(auth_token, extra_headers)
    for path in ordered_post:
        post_url = base + path
        try:
            if verbose:
                _log(f"  [dim]  POST probe: {post_url}[/dim]")
            r = client.post(
                post_url,
                json=_jrpc("initialize", MCP_INIT_PARAMS),
                headers=mcp_headers,
                timeout=5,
            )
            if verbose:
                _log(f"  [dim]  → HTTP {r.status_code} ({r.headers.get('content-type', 'no ct')})[/dim]")

            if r.status_code in (401, 403):
                www_auth = r.headers.get("www-authenticate", "")
                if verbose:
                    hint_msg = f" ({www_auth})" if www_auth else ""
                    _log(f"  [yellow]  Auth required: HTTP {r.status_code} at {path}{hint_msg}[/yellow]")
                # Auth failure on an MCP endpoint means transport EXISTS but needs auth
                # Still return the session — the caller can handle auth
                if "jsonrpc" in r.text or "Bearer" in (www_auth or "") or "token" in r.text.lower():
                    client.close()
                    if verbose:
                        _log(f"  [yellow]  MCP endpoint found at {path} but requires authentication[/yellow]")
                    return HTTPSession(
                        base,
                        post_url,
                        timeout=connect_timeout,
                        headers=mcp_headers,
                        verify_tls=verify_tls,
                    )

            is_jsonrpc_body = "jsonrpc" in r.text or "JSON-RPC" in r.text
            is_jsonrpc_error = r.status_code in (400, 422) and (
                is_jsonrpc_body
                or "method" in r.text
            )
            if (
                (r.status_code in (200, 202) and is_jsonrpc_body)
                or (r.status_code == 200 and "text/event-stream" in r.headers.get("content-type", ""))
                or is_jsonrpc_error
            ):
                if verbose:
                    _log(f"  [dim]  HTTP MCP endpoint confirmed at {path}[/dim]")
                client.close()
                return HTTPSession(
                    base,
                    post_url,
                    timeout=connect_timeout,
                    headers=mcp_headers,
                    verify_tls=verify_tls,
                )
        except httpx.ConnectError:
            if verbose:
                _log("  [dim]  → Connection refused[/dim]")
        except httpx.TimeoutException:
            if verbose:
                _log("  [dim]  → Timeout[/dim]")
        except Exception:
            pass

    if verbose:
        _log("  [dim]Trying SSE+POST combinations...[/dim]")

    for sse_path in ["/sse", ""]:
        for post_path in ["/messages", "/message", "/mcp"]:
            post_url = base + post_path
            try:
                r = client.post(
                    post_url,
                    json=_jrpc("initialize", MCP_INIT_PARAMS),
                    headers=mcp_headers,
                    timeout=4,
                )
                if r.status_code in (400, 404, 422):
                    session = MCPSession(
                        base,
                        sse_path,
                        timeout=connect_timeout,
                        auth_token=auth_token,
                        verify_tls=verify_tls,
                        extra_headers=extra_headers,
                    )
                    if session.wait_ready(timeout=10.0) and session.post_url:
                        client.close()
                        return session
                    session.close()
            except Exception:
                pass

    client.close()

    if verbose:
        _log("  [dim]Trying ToolServer detection...[/dim]")

    tool_session = _detect_tool_server(
        base, hint, connect_timeout, auth_token, verify_tls, extra_headers,
        tool_names_file=kwargs.get("tool_names_file"),
    )
    if tool_session:
        if verbose:
            fp = tool_session.fingerprint
            fw = fp.get("framework", "unknown")
            _log(f"  [dim]  ToolServer detected (framework={fw})[/dim]")
        return tool_session

    return None
