"""Scan tool and resource response content for leaked credentials (MCP-T07)."""

import re

from mcpvenom.core.models import TargetResult
from mcpvenom.checks.base import time_check
from mcpvenom.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke
from mcpvenom.patterns.probes import CREDENTIAL_CONTENT_PATTERNS


def _scan_text_for_creds(text: str, source: str, result: TargetResult):
    """Scan a text blob for credential patterns, adding findings."""
    for pat, cred_type in CREDENTIAL_CONTENT_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            result.add(
                "response_credentials",
                "CRITICAL",
                f"Credential leak in {source}: {cred_type}",
                f"Response contains what appears to be a live {cred_type}",
                evidence=m.group()[:200],
            )
            break


def check_response_credentials(session, result: TargetResult, probe_opts: dict | None = None):
    """Scan tool responses and resource content for credential patterns.

    Goes beyond error_leakage by checking ALL responses (success and error)
    for secrets like API keys, connection strings, private keys, and passwords
    that slip through incomplete server-side redaction.
    """
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    cache = opts.get("_response_cache", {})
    with time_check("response_credentials", result):
        invokable = [t for t in result.tools if _should_invoke(t, opts)]
        _log(f"    [dim]    scanning {len(invokable)} tool responses for credentials[/dim]")
        if cache:
            _log(f"    [dim]    ({len(cache)} cached responses available, skipping re-invocation)[/dim]")
        tool_idx = 0
        for tool in result.tools:
            if not _should_invoke(tool, opts):
                continue
            tool_idx += 1
            name = tool.get("name", "")
            _log(f"    [dim]    [{tool_idx}/{len(invokable)}] {name}[/dim]")
            text = cache.get(name)
            if text is None:
                args = _build_safe_args(tool)
                resp = _call_tool(session, name, args)
                text = _response_text(resp)
            if text:
                _scan_text_for_creds(text, f"tool '{name}' response", result)

        # Scan resource contents
        for resource in result.resources:
            uri = resource.get("uri", "")
            try:
                resp = session.call("resources/read", {"uri": uri}, timeout=15)
                if not resp or "result" not in resp:
                    continue
                for content in resp["result"].get("contents", []):
                    text = content.get("text", "") or content.get("blob", "")
                    if text:
                        _scan_text_for_creds(text, f"resource '{uri}'", result)
            except Exception:
                pass

        # Scan server_info from initialize (may contain leaked config)
        if result.server_info:
            import json
            info_text = json.dumps(result.server_info, default=str)
            _scan_text_for_creds(info_text, "server initialize response", result)
