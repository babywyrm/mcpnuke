"""MCP session handling: SSE, HTTP, Stdio, and ToolServer transport detection."""

import json
import queue
import re
import shlex
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from mcpnuke.core.constants import MCP_INIT_PARAMS, SSE_PATHS, POST_PATHS, build_jsonrpc_request as _jrpc


def _auth_headers(auth_token: str | None, extra_headers: dict | None = None) -> dict:
    """Build headers with optional Authorization Bearer."""
    h = {"Accept": "text/event-stream"}
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    if extra_headers:
        h.update(extra_headers)
    return h


def _mcp_headers(auth_token: str | None, extra_headers: dict | None = None) -> dict:
    """Build MCP request headers with optional Authorization Bearer."""
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    if extra_headers:
        h.update(extra_headers)
    return h


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

    def _try():
        try:
            with httpx.Client(
                verify=verify_tls, timeout=httpx.Timeout(timeout, connect=4.0)
            ) as c:
                with c.stream(
                    "GET", url, headers=headers
                ) as resp:
                    ct = resp.headers.get("content-type", "")
                    if resp.status_code == 200 and "text/event-stream" in ct:
                        result[0] = True
                    done.set()
                    for _ in zip(resp.iter_bytes(chunk_size=64), range(3)):
                        pass
        except Exception:
            pass
        finally:
            done.set()

    t = threading.Thread(target=_try, daemon=True)
    t.start()
    done.wait(timeout=timeout + 1)
    return result[0]


class MCPSession:
    """SSE-based MCP session."""

    def __init__(
        self,
        base: str,
        sse_path: str,
        timeout: float = 25.0,
        auth_token: str | None = None,
        verify_tls: bool = False,
        extra_headers: dict | None = None,
    ):
        self.base = base
        self.sse_url = base + sse_path
        self.post_url: str = ""
        self.timeout = timeout
        self._auth_token = auth_token
        self._verify_tls = verify_tls
        self._extra_headers = extra_headers or {}
        self._req_id = 0
        self._session_id: str | None = None
        self._q: queue.Queue[dict] = queue.Queue()
        self._stop = threading.Event()
        self._endpoint_ready = threading.Event()
        self._client = httpx.Client(
            verify=verify_tls, timeout=timeout, follow_redirects=True
        )
        self._listener = threading.Thread(
            target=self._listen, daemon=True, name=f"sse-{base}"
        )
        self._listener.start()

    def _listen(self):
        headers = _auth_headers(self._auth_token, self._extra_headers)
        headers["Accept"] = "text/event-stream"
        try:
            with self._client.stream(
                "GET",
                self.sse_url,
                headers=headers,
            ) as resp:
                for k, v in resp.headers.items():
                    if k.lower() == "mcp-session-id" and v:
                        self._session_id = v
                        break
                event_type = "message"
                for raw in resp.iter_lines():
                    if self._stop.is_set():
                        break
                    line = raw.strip()
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data = line[5:].strip()
                        if event_type == "endpoint" and data:
                            self.post_url = (
                                data
                                if data.startswith("http")
                                else self.base + data
                            )
                            self._endpoint_ready.set()
                        elif event_type != "endpoint" and data:
                            try:
                                msg = json.loads(data)
                                self._q.put(msg)
                            except json.JSONDecodeError:
                                pass
                        event_type = "message"
        except Exception:
            pass
        finally:
            self._endpoint_ready.set()

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return self._endpoint_ready.wait(timeout=timeout)

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        wait = timeout or self.timeout
        for attempt in range(retries + 1):
            self._req_id += 1
            payload = _jrpc(method, params, self._req_id)
            headers = _mcp_headers(self._auth_token, self._extra_headers)
            if self._session_id:
                headers["Mcp-Session-Id"] = self._session_id
            try:
                r = self._client.post(
                    self.post_url,
                    json=payload,
                    headers=headers,
                    timeout=10,
                )
                if r.status_code not in (200, 202, 204):
                    if attempt < retries:
                        time.sleep(0.5)
                        continue
                    return None
            except Exception:
                if attempt < retries:
                    time.sleep(0.5)
                    continue
                return None

            deadline = time.time() + wait
            pending: list[dict] = []
            while time.time() < deadline:
                try:
                    msg = self._q.get(timeout=0.3)
                    if isinstance(msg, dict) and msg.get("id") == self._req_id:
                        for m in pending:
                            self._q.put(m)
                        return msg
                    pending.append(msg)
                except queue.Empty:
                    pass
            for m in pending:
                self._q.put(m)
            if attempt < retries:
                time.sleep(1.0)
        return None

    def notify(self, method: str, params: dict | None = None):
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        headers = _mcp_headers(self._auth_token, self._extra_headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        try:
            self._client.post(
                self.post_url,
                json=payload,
                headers=headers,
                timeout=5,
            )
        except Exception:
            pass

    def close(self):
        self._stop.set()
        try:
            self._client.close()
        except Exception:
            pass


def _parse_sse_json(text: str, req_id: int | None = None) -> dict | None:
    """Extract JSON-RPC response from SSE body (event: message / data: {...})."""
    for line in text.splitlines():
        if line.startswith("data:"):
            data = line[5:].strip()
            if data:
                try:
                    msg = json.loads(data)
                    if req_id is None or msg.get("id") == req_id:
                        return msg
                except json.JSONDecodeError:
                    pass
    return None


class HTTPSession:
    """Plain HTTP POST fallback (no SSE). Handles both application/json and text/event-stream responses."""

    def __init__(
        self,
        base: str,
        post_url: str,
        timeout: float = 25.0,
        headers: dict | None = None,
        verify_tls: bool = False,
    ):
        self.base = base
        self.sse_url = ""
        self.post_url = post_url
        self.timeout = timeout
        self._req_id = 0
        self._session_id: str | None = None
        self._headers = headers or {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        self._client = httpx.Client(
            verify=verify_tls, timeout=timeout, follow_redirects=True
        )

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return True

    def _request_headers(self) -> dict:
        h = dict(self._headers)
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    def _capture_session_id(self, resp_headers) -> None:
        for k, v in resp_headers.items():
            if k.lower() == "mcp-session-id" and v:
                self._session_id = v
                break

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        for attempt in range(retries + 1):
            self._req_id += 1
            try:
                r = self._client.post(
                    self.post_url,
                    json=_jrpc(method, params, self._req_id),
                    headers=self._request_headers(),
                    timeout=timeout or self.timeout,
                )
                self._capture_session_id(r.headers)
                if r.status_code in (200, 202):
                    ct = r.headers.get("content-type", "")
                    if "application/json" in ct:
                        return r.json()
                    if "text/event-stream" in ct or "jsonrpc" in r.text:
                        parsed = _parse_sse_json(r.text, self._req_id)
                        if parsed:
                            return parsed
                        try:
                            return r.json()
                        except Exception:
                            pass
            except Exception:
                if attempt < retries:
                    time.sleep(0.5)
        return None

    def notify(self, method: str, params: dict | None = None):
        try:
            self._client.post(
                self.post_url,
                json={
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params or {},
                },
                headers=self._request_headers(),
                timeout=5,
            )
        except Exception:
            pass

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


TOOL_SERVER_PROBES = [
    {"tool": "get_cluster_health"},
    {"tool": "list_tools"},
    {"tool": "health"},
    {"tool": "help"},
    {"tool": "status"},
    {"tool": ""},
]

_DEFAULT_TOOL_NAMES_FILE = Path(__file__).parent.parent / "data" / "tool_names.txt"

TOOL_EXECUTE_PATHS = [
    "/execute", "/tools/execute", "/api/execute", "/run",
    "/api/run", "/invoke", "/api/invoke", "/tools/run",
    "/tool", "/api/tool", "/v1/execute", "/v1/run",
    "/v1/invoke", "/v1/tool", "/rpc/execute",
    "/action", "/api/action", "/command", "/api/command",
]

_TOOL_SERVER_FRAMEWORKS = {
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
                    if k.lower() == header_key.lower():
                        if match_val is None or match_val.lower() in v.lower():
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
        self._headers = headers or {"Content-Type": "application/json"}
        self._client = httpx.Client(verify=verify_tls, timeout=timeout, follow_redirects=True)
        self._discovered_tools: list[dict] = []
        self._tool_names_file = tool_names_file
        self.fingerprint: dict = fingerprint or {}

    def wait_ready(self, timeout: float = 10.0) -> bool:
        return True

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
                if r.status_code == 200:
                    tool_def = self._build_tool_def(name, r)
                    tools.append(tool_def)
                elif r.status_code in (400, 403, 422) and "unknown tool" not in body:
                    tool_def = self._build_tool_def(name, r)
                    tools.append(tool_def)
            except Exception:
                pass
        self._discovered_tools = tools
        return tools

    def _build_tool_def(self, name: str, r) -> dict:
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

    def notify(self, method: str, params: dict | None = None):
        pass

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass


class StdioSession:
    """JSON-RPC over stdin/stdout for local MCP servers (npm, npx, python, etc.).

    Launches a subprocess with the given command and communicates via
    newline-delimited JSON-RPC over the process's stdin/stdout.
    """

    def __init__(self, cmd: str | list[str], timeout: float = 25.0, env: dict | None = None):
        if isinstance(cmd, str):
            self.cmd = shlex.split(cmd)
        else:
            self.cmd = list(cmd)
        self.timeout = timeout
        self.post_url = f"stdio://{' '.join(self.cmd)}"
        self.sse_url = ""
        self._req_id = 0
        self._q: queue.Queue[dict] = queue.Queue()
        self._stop = threading.Event()

        proc_env = None
        if env:
            import os
            proc_env = {**os.environ, **env}

        self._proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=proc_env,
        )
        self._reader = threading.Thread(
            target=self._read_stdout, daemon=True, name="stdio-reader"
        )
        self._reader.start()

    def _read_stdout(self):
        assert self._proc.stdout is not None
        for raw in self._proc.stdout:
            if self._stop.is_set():
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                self._q.put(msg)
            except json.JSONDecodeError:
                pass

    def wait_ready(self, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                return False
            time.sleep(0.1)
            if self._proc.stdout and self._proc.stdout.readable():
                return True
        return self._proc.poll() is None

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        retries: int = 2,
    ) -> dict | None:
        wait = timeout or self.timeout
        for attempt in range(retries + 1):
            self._req_id += 1
            payload = _jrpc(method, params, self._req_id)
            try:
                assert self._proc.stdin is not None
                line = json.dumps(payload) + "\n"
                self._proc.stdin.write(line.encode("utf-8"))
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError):
                if attempt < retries:
                    time.sleep(0.5)
                    continue
                return None

            deadline = time.time() + wait
            pending: list[dict] = []
            while time.time() < deadline:
                try:
                    msg = self._q.get(timeout=0.3)
                    if isinstance(msg, dict) and msg.get("id") == self._req_id:
                        for m in pending:
                            self._q.put(m)
                        return msg
                    pending.append(msg)
                except queue.Empty:
                    pass
            for m in pending:
                self._q.put(m)
            if attempt < retries:
                time.sleep(0.5)
        return None

    def notify(self, method: str, params: dict | None = None):
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        try:
            assert self._proc.stdin is not None
            line = json.dumps(payload) + "\n"
            self._proc.stdin.write(line.encode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def close(self):
        self._stop.set()
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass


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
    log=None,
    **kwargs,
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
                _log(f"  [dim]  → Connection refused[/dim]")
        except httpx.TimeoutException:
            if verbose:
                _log(f"  [dim]  → Timeout[/dim]")
        except Exception:
            pass

    if verbose:
        _log(f"  [dim]Trying SSE+POST combinations...[/dim]")

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
        _log(f"  [dim]Trying ToolServer detection...[/dim]")

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
