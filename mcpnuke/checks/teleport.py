"""Teleport infrastructure security checks for MCP environments.

Detects and probes Teleport proxy/auth services alongside MCP servers.
All checks are safe to run when Teleport is not present — they gracefully
skip and produce no findings.
"""

from __future__ import annotations

import json
import ssl
import urllib.request
from urllib.error import URLError

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check


def _probe_url(url: str, timeout: float = 3.0) -> dict | None:
    """GET a URL with TLS verification disabled, return parsed JSON or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def check_teleport_proxy_discovery(base: str, result: TargetResult):
    """Probe for Teleport proxy endpoints on the target host.

    Discovers version, cluster name, and auth configuration. A publicly
    accessible /webapi/ping endpoint reveals cluster metadata that aids
    reconnaissance.
    """
    from urllib.parse import urlparse

    with time_check("teleport_proxy_discovery", result):
        parsed = urlparse(base)
        host = parsed.hostname or ""
        if not host:
            return

        candidates = []
        for port in (443, 3080, 30136, 30443):
            candidates.append(f"https://{host}:{port}/webapi/ping")

        for url in candidates:
            data = _probe_url(url)
            if data and "server_version" in data:
                cluster = data.get("cluster_name", "unknown")
                version = data.get("server_version", "unknown")
                auth_type = data.get("auth", {}).get("type", "unknown")
                result.add(
                    "teleport_proxy_discovery",
                    "MEDIUM",
                    f"Teleport proxy discovered: {cluster} v{version}",
                    f"Endpoint {url} exposes cluster metadata. "
                    f"Auth type: {auth_type}. Consider restricting /webapi/ping.",
                    evidence=json.dumps(data, indent=2)[:500],
                )
                return


def check_teleport_cert_validation(base: str, result: TargetResult):
    """Test if the Teleport proxy uses self-signed certificates.

    Self-signed certs in production mean clients must use --insecure,
    disabling TLS verification and enabling MITM attacks.
    """
    from urllib.parse import urlparse

    with time_check("teleport_cert_validation", result):
        parsed = urlparse(base)
        host = parsed.hostname or ""
        if not host:
            return

        for port in (443, 3080, 30136, 30443):
            url = f"https://{host}:{port}/webapi/ping"

            strict_ctx = ssl.create_default_context()
            req = urllib.request.Request(url)
            try:
                urllib.request.urlopen(req, timeout=3, context=strict_ctx)
            except ssl.SSLCertVerificationError:
                insecure_data = _probe_url(url)
                if insecure_data and "server_version" in insecure_data:
                    result.add(
                        "teleport_cert_validation",
                        "HIGH",
                        f"Teleport proxy uses self-signed certificate on port {port}",
                        "The proxy's TLS certificate is not trusted by system CAs. "
                        "Clients must use --insecure to connect, disabling MITM protection. "
                        "Use cert-manager or a trusted CA for production deployments.",
                    )
                    return
            except Exception:
                continue


def check_teleport_app_enumeration(base: str, result: TargetResult):
    """Attempt to enumerate MCP applications registered in Teleport.

    Misconfigured Teleport clusters may expose the application list to
    unauthenticated callers via /webapi/apps or /v1/webapi/apps.
    """
    from urllib.parse import urlparse

    with time_check("teleport_app_enumeration", result):
        parsed = urlparse(base)
        host = parsed.hostname or ""
        if not host:
            return

        for port in (443, 3080, 30136, 30443):
            for path in ("/v1/webapi/apps", "/webapi/apps"):
                url = f"https://{host}:{port}{path}"
                data = _probe_url(url)
                if data and isinstance(data, (dict, list)):
                    apps = data if isinstance(data, list) else data.get("apps", [])
                    if apps:
                        app_names = [a.get("name", "?") for a in apps[:10]]
                        result.add(
                            "teleport_app_enumeration",
                            "HIGH",
                            f"Teleport application list accessible without auth ({len(apps)} apps)",
                            f"Unauthenticated access to {url} reveals registered MCP applications: "
                            f"{', '.join(app_names)}. This aids reconnaissance and targeting.",
                            evidence=json.dumps(app_names),
                        )
                        return


def check_tbot_credential_exposure(result: TargetResult):
    """Check for tbot credential secrets exposed in Kubernetes.

    When running in-cluster, scans for tbot output secrets (tbot-out,
    tbot-kube) and checks if they are mounted into non-tbot pods,
    which would indicate credential over-sharing.
    """
    import os

    with time_check("tbot_credential_exposure", result):
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if not os.path.exists(token_path):
            return

        try:
            with open(token_path) as f:
                token = f.read().strip()
        except Exception:
            return

        k8s_host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
        k8s_port = os.environ.get("KUBERNETES_SERVICE_PORT", "")
        if not k8s_host:
            return

        api_base = f"https://{k8s_host}:{k8s_port}"
        ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        try:
            with open(ns_path) as f:
                namespace = f.read().strip()
        except Exception:
            namespace = "default"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        tbot_secret_names = ["tbot-out", "tbot-kube", "tbot"]
        for secret_name in tbot_secret_names:
            url = f"{api_base}/api/v1/namespaces/{namespace}/secrets/{secret_name}"
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            })
            try:
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    secret_data = json.loads(resp.read())
                    keys = list(secret_data.get("data", {}).keys())
                    if "identity" in keys or "kubeconfig.yaml" in keys or "tlscert" in keys:
                        result.add(
                            "tbot_credential_exposure",
                            "HIGH",
                            f"tbot credential secret '{secret_name}' readable from scan pod",
                            f"Secret contains sensitive keys: {keys}. "
                            "Ensure tbot output secrets are scoped to specific pods via RBAC. "
                            "Any pod in this namespace can extract the bot's identity.",
                            evidence=f"namespace={namespace} keys={keys}",
                        )
            except Exception:
                continue


def check_teleport_bot_overprivilege(result: TargetResult):
    """Check if Teleport bot service accounts have excessive K8s RBAC.

    Scans ClusterRoleBindings for service accounts matching tbot patterns
    and flags any with more than 'view' access.
    """
    import os

    with time_check("teleport_bot_overprivilege", result):
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if not os.path.exists(token_path):
            return

        try:
            with open(token_path) as f:
                token = f.read().strip()
        except Exception:
            return

        k8s_host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
        k8s_port = os.environ.get("KUBERNETES_SERVICE_PORT", "")
        if not k8s_host:
            return

        api_base = f"https://{k8s_host}:{k8s_port}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"{api_base}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                data = json.loads(resp.read())
        except Exception:
            return

        privileged_roles = {"cluster-admin", "admin", "edit"}
        for binding in data.get("items", []):
            role_ref = binding.get("roleRef", {}).get("name", "")
            if role_ref not in privileged_roles:
                continue
            for subject in binding.get("subjects", []):
                sa_name = subject.get("name", "")
                if "tbot" in sa_name or "teleport" in sa_name.lower():
                    result.add(
                        "teleport_bot_overprivilege",
                        "HIGH",
                        f"Teleport bot SA '{sa_name}' bound to privileged role '{role_ref}'",
                        f"ClusterRoleBinding '{binding['metadata']['name']}' grants "
                        f"'{role_ref}' to service account '{sa_name}'. "
                        "Bot service accounts should use 'view' or a custom least-privilege role.",
                    )
