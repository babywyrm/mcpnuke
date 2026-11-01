"""ToolServer transport: plain REST tool-execution endpoints that speak no JSON-RPC."""

from __future__ import annotations

import contextlib
import json
import re
import time
from pathlib import Path

import httpx

from mcpnuke.core.protocol import LEGACY

_DEFAULT_TOOL_NAMES_FILE = Path(__file__).parent.parent.parent / "data" / "tool_names.txt"

_TOOL_SERVER_FRAMEWORKS: dict[str, list[tuple[str | None, str | None]]] = {
    "Flask": [("Server", "Werkzeug"), ("Server", "Python")],
    "FastAPI": [("Server", "uvicorn"), (None, '"detail"')],
    "Express": [("X-Powered-By", "Express")],
    "Spring Boot": [("X-Application-Context", None)],
    "Django": [("X-Frame-Options", "DENY")],
    "Go net/http": [("Content-Type", "text/plain; charset=utf-8")],
    "ASP.NET": [("X-Powered-By", "ASP.NET")],
}


def _load_tool_names(extra_file: str | None = None) -> list[str]:
    """Load tool names from default wordlist + optional custom file."""
    names: list[str] = []
    seen: set[str] = set()

    for path in [_DEFAULT_TOOL_NAMES_FILE, extra_file]:
        if path is None:
            continue
        p = Path(path)
        if not p.is_file():
            continue
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line not in seen:
                    seen.add(line)
                    names.append(line)

    if not names:
        names = [
            "get_cluster_health", "get_pod_status", "get_node_metrics",
            "restart_service", "cluster_diagnostics", "list_tools",
            "health", "status", "help", "execute", "run_command",
            "get_logs", "get_config", "deploy", "rollback", "scale",
        ]
    return names


def _fingerprint_tool_server(headers: dict, body: str) -> dict:
    """Fingerprint a tool server from HTTP response metadata."""
    info: dict = {}

    for fw, sigs in _TOOL_SERVER_FRAMEWORKS.items():
        for header_key, match_val in sigs:
            if header_key:
                for k, v in headers.items():
                    if k.lower() == header_key.lower() and (
                        match_val is None or match_val.lower() in v.lower()
                    ):
                        info["framework"] = fw
                        break
            elif match_val and match_val.lower() in body.lower():
                info["framework"] = fw
            if "framework" in info:
                break
        if "framework" in info:
            break

    server = headers.get("Server", headers.get("server", ""))
    if server:
        info["server_header"] = server

    for h in ("X-Request-Id", "X-Trace-Id", "X-Correlation-Id"):
        for k in headers:
            if k.lower() == h.lower():
                info["has_request_tracing"] = True
                break

    ct = headers.get("Content-Type", headers.get("content-type", ""))
    if ct:
        info["content_type"] = ct

    return info


class ToolServerSession:
    """Session for custom tool-execute APIs (e.g. POST /execute with {"tool": "...", ...}).

    Wraps the non-MCP tool server so the scanner can enumerate tools and run checks
    using the same interface as MCPSession/HTTPSession.
    """

    def __init__(
        self,
        base: str,
        post_url: str,
        timeout: float = 25.0,
        headers: dict | None = None,
        tool_names_file: str | None = None,
        fingerprint: dict | None = None,
        verify_tls: bool = False,
    ):
        self.base = base
        self.sse_url = ""
        self.post_url = post_url
        self.timeout = timeout
        # Negotiated by enumerator.negotiate_protocol. Only HTTPSession
        # varies its framing on this today; the rest carry it so the
        # negotiated mode is readable from any transport.
        self.protocol_mode = LEGACY
        self._headers = headers or {"Content-Type": "application/json"}
        self._client = httpx.Client(verify=verify_tls, timeout=timeout, follow_redirects=True)
        self._discovered_tools: list[dict] = []
        self._tool_names_file = tool_names_file
        self.fingerprint: dict = fingerprint or {}

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return True

    def post_raw(
        self,
        payload: dict,
        extra_headers: dict | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """POST *payload* to the tool endpoint, returning the raw response.

        See HTTPSession.post_raw. This transport speaks its own wire format
        rather than JSON-RPC, but DPoP is enforced at the HTTP layer above the
        body, so header probes still apply.
        """
        headers = dict(self._headers)
        if extra_headers:
            headers.update(extra_headers)
        return self._client.post(
            self.post_url,
            json=payload,
            headers=headers,
            timeout=timeout or self.timeout,
        )

    def enumerate_tools(self) -> list[dict]:
        """Probe tool names from wordlist and return the ones the server recognizes."""
        names = _load_tool_names(self._tool_names_file)
        tools = []
        seen = set()
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            try:
                r = self._client.post(
                    self.post_url,
                    json={"tool": name},
                    headers=self._headers,
                    timeout=5,
                )
                body = r.text.lower()
                if r.status_code == 200 or r.status_code in (400, 403, 422) and "unknown tool" not in body:
                    tool_def = self._build_tool_def(name, r)
                    tools.append(tool_def)
            except Exception:
                pass
        self._discovered_tools = tools
        return tools

    def _build_tool_def(self, name: str, r: httpx.Response) -> dict:
        """Build a tool definition from a probe response."""
        tool_def: dict = {
            "name": name,
            "description": f"Tool server endpoint (status {r.status_code})",
            "inputSchema": {"type": "object", "properties": {}},
        }
        try:
            data = r.json()
            if isinstance(data, dict):
                tool_def["description"] = f"Returns: {', '.join(data.keys())}"

                # Infer params from error messages like "service_name is required"
                err = data.get("error", "")
                if isinstance(err, str):
                    req_match = re.search(r"(\w+)\s+is\s+required", err, re.IGNORECASE)
                    if req_match:
                        param = req_match.group(1)
                        tool_def["inputSchema"]["properties"][param] = {
                            "type": "string", "description": f"Required: {param}"
                        }
                        tool_def["inputSchema"].setdefault("required", []).append(param)

                # Detect query/command params from response keys or known tool names
                exec_indicators = ("query", "command", "cmd", "expression", "code", "script")
                name_lower = name.lower()
                has_exec_hint = any(kw in name_lower for kw in (
                    "diagnostic", "execute", "run", "shell", "eval", "command", "query",
                ))
                response_keys = str(data.keys()).lower()
                if has_exec_hint or any(k in response_keys for k in exec_indicators):
                    for param in exec_indicators:
                        if param in response_keys or (has_exec_hint and param == "query"):
                            if param not in tool_def["inputSchema"]["properties"]:
                                tool_def["inputSchema"]["properties"][param] = {
                                    "type": "string", "description": f"{param.title()} to execute"
                                }
                                tool_def["inputSchema"].setdefault("required", []).append(param)
                            break
        except Exception:
            pass
        return tool_def

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        """Translate MCP-style calls to tool-server /execute calls."""
        params = params or {}

        if method == "initialize":
            fw = self.fingerprint.get("framework", "unknown")
            server_hdr = self.fingerprint.get("server_header", "")
            name = f"tool-server ({fw})" if fw != "unknown" else "tool-server"
            version = server_hdr or "unknown"
            return {"jsonrpc": "2.0", "id": 1, "result": {
                "protocolVersion": "custom-tool-server",
                "serverInfo": {"name": name, "version": version},
                "capabilities": {"tools": {}},
                "_fingerprint": self.fingerprint,
            }}

        if method == "tools/list":
            tools = self._discovered_tools or self.enumerate_tools()
            return {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}

        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": 1, "result": {"resources": []}}

        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": 1, "result": {"prompts": []}}

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            payload = {"tool": tool_name, **arguments}
            for attempt in range(retries + 1):
                try:
                    r = self._client.post(
                        self.post_url,
                        json=payload,
                        headers=self._headers,
                        timeout=timeout or self.timeout,
                    )
                    try:
                        data = r.json()
                    except Exception:
                        data = {"text": r.text}
                    return {"jsonrpc": "2.0", "id": 1, "result": {
                        "content": [{"type": "text", "text": json.dumps(data)}],
                        "isError": r.status_code >= 400,
                        "_status_code": r.status_code,
                    }}
                except Exception:
                    if attempt < retries:
                        time.sleep(0.5)
            return None

        return None

    def notify(self, method: str, params: dict | None = None) -> None:
        pass

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._client.close()

