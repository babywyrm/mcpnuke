"""Detect tools that leak infrastructure configuration and secrets (MCP-T07).

Goes beyond response_credentials by identifying tools whose *purpose*
is to expose internal service topology, environment variables, or secret
paths — even when individual credential patterns don't match.
"""

import re

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke

CONFIG_TOOL_NAMES = re.compile(
    r"(config|settings|env|environment|status|info|diagnostics|debug|healthz|metadata|describe|inspect)",
    re.IGNORECASE,
)

INFRA_LEAK_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}", "MEDIUM", "Internal IP:port"),
    (r"\w+\.(?:svc\.cluster\.local|internal|local)\b", "HIGH", "Kubernetes/internal DNS name"),
    (r"KUBERNETES_SERVICE_(?:HOST|PORT)", "HIGH", "Kubernetes service env var"),
    (r"(?:RCON|ADMIN|API|SECRET|AUTH)[_-](?:PASSWORD|KEY|TOKEN|SECRET)\b", "HIGH", "Secret env var name"),
    (r"/var/run/secrets/kubernetes", "HIGH", "Kubernetes SA token path"),
    (r"/etc/[\w/.-]*(?:secret|key|cert|pem|credential)", "HIGH", "Secret file path"),
    (r"-----BEGIN (?:\w+ )?PRIVATE KEY-----", "CRITICAL", "Private key in response"),
    (r"\[file:[^\]]+\]", "MEDIUM", "File path reference"),
    (r"(?:ollama|redis|postgres|mysql|mongodb|rabbitmq|elasticsearch)\S*:\d{2,5}", "MEDIUM", "Internal service endpoint"),
    (r"(?:guardrail|safety|evaluator|ai)[_\s]*[:=]", "MEDIUM", "AI safety config exposure"),
]


def check_config_dump(session, result: TargetResult, probe_opts: dict | None = None):
    """Detect tools that dump internal configuration, service topology, or secret paths."""
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    cache = opts.get("_response_cache", {})

    with time_check("config_dump", result):
        config_tools = [
            t for t in result.tools
            if _should_invoke(t, opts) and (
                CONFIG_TOOL_NAMES.search(t.get("name", ""))
                or CONFIG_TOOL_NAMES.search(t.get("description", ""))
            )
        ]

        if not config_tools:
            return

        _log(f"    [dim]    scanning {len(config_tools)} config-like tool(s) for infra leaks[/dim]")

        for tool in config_tools:
            name = tool.get("name", "")
            text = cache.get(name)
            if text is None:
                args = _build_safe_args(tool)
                resp = _call_tool(session, name, args)
                text = _response_text(resp)
            if not text:
                continue

            findings_for_tool: list[str] = []
            max_severity = "MEDIUM"

            for pattern, severity, label in INFRA_LEAK_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    findings_for_tool.append(f"{label} ({len(matches)}x)")
                    if severity == "CRITICAL" or (severity == "HIGH" and max_severity != "CRITICAL"):
                        max_severity = severity

            if findings_for_tool:
                result.add(
                    "config_dump",
                    max_severity,
                    f"Tool '{name}' leaks infrastructure config",
                    f"Exposed: {', '.join(findings_for_tool[:6])}",
                    evidence=text[:500],
                )
