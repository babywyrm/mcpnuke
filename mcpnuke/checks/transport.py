"""SSE/transport security checks."""

from __future__ import annotations

import httpx

from mcpnuke.core.models import TargetResult
from mcpnuke.core.constants import MCP_INIT_PARAMS, build_jsonrpc_request as _jrpc
from mcpnuke.checks.base import time_check


def check_sse_security(base: str, sse_path: str, result: TargetResult):
    with time_check("sse_security", result):
        client = httpx.Client(verify=False, timeout=8)
        try:
            with client.stream(
                "GET",
                base + sse_path,
                headers={"Accept": "text/event-stream"},
                timeout=httpx.Timeout(6.0, connect=3.0),
            ) as r:
                ct = r.headers.get("content-type", "")
                if "text/event-stream" in ct:
                    result.add(
                        "sse_security",
                        "HIGH",
                        "SSE stream accessible without authentication",
                        f"GET {sse_path} returned event-stream with no credentials",
                    )
        except Exception:
            pass

        try:
            with client.stream(
                "GET",
                base + sse_path,
                headers={
                    "Accept": "text/event-stream",
                    "Origin": "https://evil.example.com",
                },
                timeout=httpx.Timeout(6.0, connect=3.0),
            ) as r:
                acao = r.headers.get("access-control-allow-origin", "")
                if acao in ("*", "https://evil.example.com"):
                    result.add(
                        "sse_security",
                        "HIGH",
                        f"SSE CORS misconfiguration: ACAO={acao}",
                    )
        except Exception:
            pass

        try:
            r = client.post(
                base + "/messages",
                json=_jrpc("initialize", MCP_INIT_PARAMS),
                headers={
                    "Content-Type": "application/json",
                    "Origin": "https://evil.example.com",
                },
                follow_redirects=False,
                timeout=5,
            )
            if r.status_code in (200, 202, 307):
                result.add(
                    "sse_security",
                    "MEDIUM",
                    "MCP messages endpoint accepts cross-origin POST",
                    f"Status {r.status_code} with evil Origin header",
                )
        except Exception:
            pass

        client.close()
