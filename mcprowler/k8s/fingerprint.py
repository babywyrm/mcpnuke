"""Internal service fingerprinting for non-MCP endpoints.

Probes cluster services to identify frameworks, exposed debug endpoints,
and unauthenticated admin interfaces. Complements MCP-specific discovery
by mapping the broader internal attack surface.

Supports parallel probing for clusters with many services.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from mcprowler.core.models import Finding

_ACTUATOR_PATHS = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
    "/actuator/configprops", "/actuator/mappings", "/actuator/info",
]

_DEBUG_PATHS = [
    "/metrics", "/debug/pprof", "/debug/vars",
    "/_cluster/health", "/_cat/indices",
    "/server-info", "/server-status",
    "/.well-known/openid-configuration",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
    "/graphql", "/graphiql",
    "/console", "/admin", "/dashboard",
]

_FRAMEWORK_SIGNATURES = {
    "Spring Boot": [("X-Application-Context", None), (None, "Whitelabel Error Page")],
    "Express": [("X-Powered-By", "Express")],
    "FastAPI": [(None, '"openapi"'), (None, "FastAPI")],
    "Flask": [("Server", "Werkzeug")],
    "Django": [("X-Frame-Options", "DENY"), (None, "Django")],
    "ASP.NET": [("X-Powered-By", "ASP.NET"), ("X-AspNet-Version", None)],
    "Go net/http": [("Content-Type", "text/plain; charset=utf-8")],
    "Nginx": [("Server", "nginx")],
    "Envoy": [("Server", "envoy"), ("x-envoy-upstream-service-time", None)],
}


@dataclass
class ServiceFingerprint:
    service_name: str
    namespace: str
    port: int
    framework: str = ""
    exposed_paths: list[str] | None = None
    findings: list[Finding] | None = None

    def __post_init__(self):
        if self.exposed_paths is None:
            self.exposed_paths = []
        if self.findings is None:
            self.findings = []


def _http_probe(url: str, timeout: float = 3.0) -> tuple[int, dict, str]:
    """Quick HTTP GET, returns (status, headers_dict, body_snippet)."""
    import httpx
    try:
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as c:
            r = c.get(url)
            headers = dict(r.headers)
            body = r.text[:2048]
            return r.status_code, headers, body
    except Exception:
        return 0, {}, ""


def _detect_framework(headers: dict, body: str) -> str:
    """Match response against known framework signatures."""
    for framework, sigs in _FRAMEWORK_SIGNATURES.items():
        for header_key, match_val in sigs:
            if header_key and header_key.lower() in {k.lower() for k in headers}:
                if match_val is None:
                    return framework
                actual = headers.get(header_key, "")
                for k, v in headers.items():
                    if k.lower() == header_key.lower():
                        actual = v
                        break
                if match_val.lower() in actual.lower():
                    return framework
            if header_key is None and match_val and match_val.lower() in body.lower():
                return framework
    return ""


def _fingerprint_one_service(
    name: str,
    namespace: str,
    port: int,
    base_url: str,
) -> tuple[ServiceFingerprint, list[Finding]]:
    """Fingerprint a single service:port. Returns (fp, findings). Thread-safe."""
    dns = f"{name}.{namespace}"
    status, headers, body = _http_probe(base_url)
    if status == 0:
        return (ServiceFingerprint(service_name=name, namespace=namespace, port=port), [])

    fp = ServiceFingerprint(service_name=name, namespace=namespace, port=port)
    fp.framework = _detect_framework(headers, body)

    sensitive_paths = _ACTUATOR_PATHS + _DEBUG_PATHS
    for path in sensitive_paths:
        url = f"{base_url}{path}"
        s, h, b = _http_probe(url, timeout=2.0)
        if s in (200, 301, 302) and len(b) > 10:
            fp.exposed_paths.append(path)

    findings: list[Finding] = []
    if fp.exposed_paths:
        actuator_exposed = [p for p in fp.exposed_paths if "actuator" in p]
        debug_exposed = [p for p in fp.exposed_paths if p not in actuator_exposed]

        if actuator_exposed:
            sev = "HIGH" if any(p in ("/actuator/env", "/actuator/configprops") for p in actuator_exposed) else "MEDIUM"
            f = Finding(
                target="k8s", check="service_fingerprint", severity=sev,
                title=f"Spring Actuator exposed on {dns}:{port}",
                detail=f"Paths: {', '.join(actuator_exposed[:8])}",
            )
            fp.findings.append(f)
            findings.append(f)

        if any(p in ("/debug/pprof", "/debug/vars") for p in debug_exposed):
            f = Finding(
                target="k8s", check="service_fingerprint", severity="MEDIUM",
                title=f"Debug profiling endpoint on {dns}:{port}",
                detail=f"Paths: {', '.join(p for p in debug_exposed if 'debug' in p)}",
            )
            fp.findings.append(f)
            findings.append(f)

        if any(p in ("/swagger-ui.html", "/swagger-ui/", "/api-docs",
                     "/openapi.json", "/graphiql") for p in debug_exposed):
            f = Finding(
                target="k8s", check="service_fingerprint", severity="LOW",
                title=f"API documentation exposed on {dns}:{port}",
                detail=f"Paths: {', '.join(p for p in debug_exposed if any(s in p for s in ('swagger', 'api-doc', 'openapi', 'graphi')))}",
            )
            fp.findings.append(f)
            findings.append(f)

    return (fp, findings)


def fingerprint_services(
    namespace: str,
    token: str,
    fingerprint_workers: int = 10,
    console=None,
) -> list[ServiceFingerprint]:
    """Fingerprint all services in a namespace for frameworks and exposed endpoints.

    Args:
        namespace: Namespace to scan.
        token: K8s API token.
        fingerprint_workers: Max concurrent service probes (for many-service clusters).
        console: Rich console for output (optional).
    """
    from mcprowler.k8s.scanner import _k8s_get, GLOBAL_K8S_FINDINGS

    svc_data = _k8s_get(f"/api/v1/namespaces/{namespace}/services", token)
    if not svc_data:
        return []

    candidates: list[tuple[str, str, int, str]] = []
    for svc in svc_data.get("items", []):
        name = svc.get("metadata", {}).get("name", "")
        spec = svc.get("spec", {})
        cluster_ip = spec.get("clusterIP", "")
        if not cluster_ip or cluster_ip == "None":
            continue
        for sp in spec.get("ports", []):
            port = sp.get("port", 0)
            if not port:
                continue
            dns = f"{name}.{namespace}"
            base_url = f"http://{dns}:{port}"
            candidates.append((name, namespace, port, base_url))

    if not candidates:
        return []

    if console:
        console.print(f"\n[bold]── Service Fingerprinting (ns={namespace}) ──[/bold]")
        if fingerprint_workers > 1:
            console.print(f"  [dim]Probing {len(candidates)} service(s) with {fingerprint_workers} workers[/dim]")

    results: list[ServiceFingerprint] = []
    workers = min(fingerprint_workers, len(candidates))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_fingerprint_one_service, name, ns, port, base_url): (name, ns, port)
            for (name, ns, port, base_url) in candidates
        }
        for fut in as_completed(futures):
            name, ns, port = futures[fut]
            try:
                fp, findings = fut.result()
                GLOBAL_K8S_FINDINGS.extend(findings)
                if fp.framework or fp.exposed_paths:
                    results.append(fp)
                    if console:
                        dns = f"{name}.{ns}"
                        if fp.framework:
                            console.print(f"  [cyan]•[/] {dns}:{port} → {fp.framework}")
                        for f in fp.findings:
                            from mcprowler.core.constants import SEV_COLOR
                            color = SEV_COLOR.get(f.severity, "dim")
                            console.print(f"    [{color}]{f.severity}[/] {f.title}")
            except Exception:
                if console:
                    console.print(f"  [dim]  {name}.{ns}:{port} -- fingerprint failed[/dim]")

    if console:
        console.print(f"  [bold]Fingerprinted {len(results)} service(s)[/bold]")

    return results
