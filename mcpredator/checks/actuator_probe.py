"""Debug and actuator endpoint discovery (MCP-T07).

Probes the target's base URL for exposed debug/admin endpoints
that leak configuration, credentials, or internal state.
"""

import re

import httpx

from mcpredator.core.models import TargetResult
from mcpredator.checks.base import time_check

DEBUG_ENDPOINTS = [
    ("/actuator/env", "CRITICAL", "Spring Boot actuator env — may expose secrets and config"),
    ("/actuator/beans", "HIGH", "Spring Boot actuator beans — application context"),
    ("/actuator/configprops", "HIGH", "Spring Boot config properties"),
    ("/actuator/health", "MEDIUM", "Spring Boot health endpoint"),
    ("/actuator/info", "MEDIUM", "Spring Boot info endpoint"),
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


def check_actuator_probe(base_url: str, result: TargetResult, auth_token: str | None = None):
    """Probe for exposed debug/admin endpoints on the target's base URL."""
    with time_check("actuator_probe", result):
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        client = httpx.Client(verify=False, timeout=5, follow_redirects=True)
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
                except Exception:
                    pass
        finally:
            client.close()
