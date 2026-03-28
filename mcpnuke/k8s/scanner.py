"""Kubernetes RBAC, Helm secrets, and pod security scanning."""

import base64
import gzip
import json
import os
from typing import Any

from mcpnuke.core.models import Finding

GLOBAL_K8S_FINDINGS: list[Finding] = []

_SENSITIVE_VALUE_PATTERNS = ["password", "secret", "token", "apikey", "api_key",
                             "private_key", "privatekey", "credential", "passphrase"]

_DANGEROUS_CAPABILITIES = {"NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN",
                           "SYS_MODULE", "DAC_OVERRIDE", "SETUID", "SETGID"}


def _k8s_get(path: str, token: str) -> dict | None:
    import ssl
    import urllib.request

    req = urllib.request.Request(
        f"https://kubernetes.default{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return json.loads(r.read())
    except Exception:
        return None


def _scan_helm(sname: str, obj: Any, path: str):
    if isinstance(obj, dict):
        for k, v in obj.items():
            np = f"{path}.{k}" if path else k
            if isinstance(v, str):
                if "PRIVATE KEY" in v:
                    GLOBAL_K8S_FINDINGS.append(
                        Finding(
                            target="k8s",
                            check="helm_secrets",
                            severity="CRITICAL",
                            title=f"Private key in Helm values: {sname} → {np}",
                        )
                    )
                elif any(s in k.lower() for s in _SENSITIVE_VALUE_PATTERNS):
                    GLOBAL_K8S_FINDINGS.append(
                        Finding(
                            target="k8s",
                            check="helm_secrets",
                            severity="HIGH",
                            title=f"Credential in Helm values: {sname} → {np}",
                        )
                    )
            else:
                _scan_helm(sname, v, np)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _scan_helm(sname, item, f"{path}[{i}]")


def _check_pod_security(pod: dict, namespace: str):
    """Analyze a pod spec for security misconfigurations."""
    meta = pod.get("metadata", {})
    pod_name = meta.get("name", "?")
    spec = pod.get("spec", {})

    if spec.get("hostNetwork"):
        GLOBAL_K8S_FINDINGS.append(Finding(
            target="k8s", check="pod_security", severity="HIGH",
            title=f"Pod {pod_name} uses hostNetwork",
            detail="Host networking bypasses network policies and exposes host interfaces",
        ))

    if spec.get("hostPID"):
        GLOBAL_K8S_FINDINGS.append(Finding(
            target="k8s", check="pod_security", severity="HIGH",
            title=f"Pod {pod_name} uses hostPID",
            detail="Host PID namespace allows process inspection and ptrace attacks",
        ))

    for c in spec.get("containers", []) + spec.get("initContainers", []):
        cname = c.get("name", "?")
        sc = c.get("securityContext", {})

        if sc.get("privileged"):
            GLOBAL_K8S_FINDINGS.append(Finding(
                target="k8s", check="pod_security", severity="CRITICAL",
                title=f"Privileged container: {pod_name}/{cname}",
                detail="Privileged containers have full host access",
            ))

        if sc.get("runAsUser") == 0 or sc.get("runAsGroup") == 0:
            GLOBAL_K8S_FINDINGS.append(Finding(
                target="k8s", check="pod_security", severity="MEDIUM",
                title=f"Container runs as root: {pod_name}/{cname}",
            ))

        caps = sc.get("capabilities", {})
        added = set(caps.get("add", []))
        dangerous = added & _DANGEROUS_CAPABILITIES
        if dangerous:
            GLOBAL_K8S_FINDINGS.append(Finding(
                target="k8s", check="pod_security", severity="HIGH",
                title=f"Dangerous capabilities on {pod_name}/{cname}: {dangerous}",
            ))

        for vm in c.get("volumeMounts", []):
            if vm.get("mountPath", "").startswith("/var/run/secrets"):
                continue
            mount_name = vm.get("name", "")
            for vol in spec.get("volumes", []):
                if vol.get("name") == mount_name and vol.get("hostPath"):
                    hp = vol["hostPath"].get("path", "")
                    GLOBAL_K8S_FINDINGS.append(Finding(
                        target="k8s", check="pod_security", severity="HIGH",
                        title=f"hostPath mount on {pod_name}/{cname}: {hp}",
                        detail=f"Volume {mount_name} mounts host path {hp}",
                    ))

        resources = c.get("resources", {})
        if not resources.get("limits"):
            GLOBAL_K8S_FINDINGS.append(Finding(
                target="k8s", check="pod_security", severity="LOW",
                title=f"No resource limits on {pod_name}/{cname}",
                detail="Missing limits can lead to resource exhaustion",
            ))


def _check_configmap_leaks(cm: dict, namespace: str):
    """Scan ConfigMap data for leaked secrets."""
    name = cm.get("metadata", {}).get("name", "?")
    for key, value in cm.get("data", {}).items():
        if not isinstance(value, str):
            continue
        if "PRIVATE KEY" in value:
            GLOBAL_K8S_FINDINGS.append(Finding(
                target="k8s", check="configmap_secrets", severity="CRITICAL",
                title=f"Private key in ConfigMap: {name}/{key}",
            ))
        if any(s in key.lower() for s in _SENSITIVE_VALUE_PATTERNS):
            GLOBAL_K8S_FINDINGS.append(Finding(
                target="k8s", check="configmap_secrets", severity="MEDIUM",
                title=f"Possible credential in ConfigMap: {name}/{key}",
            ))


def _check_sa_blast_radius(namespace: str, token: str, console=None):
    """Map effective permissions for each ServiceAccount in the namespace.

    Uses SelfSubjectRulesReview to enumerate what each SA can do, then
    flags overprivileged accounts (secret access, pod exec, wildcard verbs).
    """
    sa_data = _k8s_get(f"/api/v1/namespaces/{namespace}/serviceaccounts", token)
    if not sa_data:
        return

    pods_data = _k8s_get(f"/api/v1/namespaces/{namespace}/pods", token)
    sa_to_pods: dict[str, list[str]] = {}
    if pods_data:
        for pod in pods_data.get("items", []):
            sa = pod.get("spec", {}).get("serviceAccountName", "default")
            pod_name = pod.get("metadata", {}).get("name", "?")
            sa_to_pods.setdefault(sa, []).append(pod_name)

    if console:
        console.print(f"\n[bold]── SA Blast Radius (ns={namespace}) ──[/bold]")

    dangerous_verbs = {"create", "delete", "patch", "update", "*"}
    sensitive_resources = {"secrets", "pods/exec", "serviceaccounts/token",
                          "roles", "rolebindings", "clusterroles",
                          "clusterrolebindings", "daemonsets", "deployments"}

    for sa in sa_data.get("items", []):
        sa_name = sa.get("metadata", {}).get("name", "?")

        review_body = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectRulesReview",
            "spec": {"namespace": namespace},
        }
        import ssl
        import urllib.request
        req = urllib.request.Request(
            "https://kubernetes.default/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            data=json.dumps(review_body).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Impersonate-User": f"system:serviceaccount:{namespace}:{sa_name}",
            },
            method="POST",
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        rules = []
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                result = json.loads(r.read())
                rules = result.get("status", {}).get("resourceRules", [])
        except Exception:
            pass

        if not rules:
            continue

        pods_using = sa_to_pods.get(sa_name, [])
        pod_label = f" (pods: {', '.join(pods_using[:3])}{'...' if len(pods_using) > 3 else ''})" if pods_using else " (unused)"

        permissions: list[str] = []
        risk_flags: list[str] = []

        for rule in rules:
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))

            for res in resources:
                verb_str = ",".join(sorted(verbs))
                permissions.append(f"{res}:[{verb_str}]")

                if res in sensitive_resources and verbs & dangerous_verbs:
                    risk_flags.append(f"can {','.join(verbs & dangerous_verbs)} {res}")
                if res == "secrets" and verbs & {"get", "list", "*"}:
                    risk_flags.append("can read secrets")
                if res == "pods/exec" and verbs & {"create", "*"}:
                    risk_flags.append("can exec into pods")
                if "*" in verbs and "*" in resources:
                    risk_flags.append("wildcard access (cluster-admin equivalent)")

        if risk_flags:
            unique_flags = sorted(set(risk_flags))
            sev = "CRITICAL" if "wildcard access" in " ".join(unique_flags) else "HIGH"
            GLOBAL_K8S_FINDINGS.append(Finding(
                target="k8s", check="sa_blast_radius", severity=sev,
                title=f"SA {sa_name} is overprivileged{pod_label}",
                detail="; ".join(unique_flags),
                evidence=", ".join(permissions[:15]),
            ))
            if console:
                console.print(f"  [red]![/] {sa_name}{pod_label}: {'; '.join(unique_flags)}")
        else:
            if console:
                perm_count = len(permissions)
                console.print(f"  [dim]  {sa_name}{pod_label}: {perm_count} rules, no elevated risk[/dim]")


def _check_helm_version_drift(namespace: str, token: str, console=None):
    """Compare Helm release versions to find credentials removed in newer releases.

    When operators rotate secrets and upgrade a Helm release, the old release
    objects (v1, v2, ...) remain in the cluster. Secrets removed from current
    values are still recoverable from prior versions.
    """
    secrets_data = _k8s_get(f"/api/v1/namespaces/{namespace}/secrets", token)
    if not secrets_data:
        return

    import re
    releases: dict[str, list[tuple[int, dict]]] = {}
    for secret in secrets_data.get("items", []):
        if secret.get("type") != "helm.sh/release.v1":
            continue
        sname = secret["metadata"]["name"]
        m = re.match(r"^sh\.helm\.release\.v1\.(.+)\.v(\d+)$", sname)
        if not m:
            continue
        release_name, version = m.group(1), int(m.group(2))
        b64 = secret.get("data", {}).get("release", "")
        if not b64:
            continue
        try:
            decoded = gzip.decompress(base64.b64decode(base64.b64decode(b64)))
            values = json.loads(decoded).get("chart", {}).get("values", {})
            releases.setdefault(release_name, []).append((version, values))
        except Exception:
            pass

    if console and releases:
        console.print(f"\n[bold]── Helm Release Version Drift ──[/bold]")

    for release_name, versions in releases.items():
        if len(versions) < 2:
            continue
        versions.sort(key=lambda x: x[0])

        latest_ver, latest_vals = versions[-1]
        latest_flat = _flatten_values(latest_vals)

        for ver, vals in versions[:-1]:
            old_flat = _flatten_values(vals)
            removed_keys = set(old_flat.keys()) - set(latest_flat.keys())

            for key in removed_keys:
                old_val = old_flat[key]
                if not isinstance(old_val, str):
                    continue
                if "PRIVATE KEY" in old_val:
                    GLOBAL_K8S_FINDINGS.append(Finding(
                        target="k8s", check="helm_version_drift", severity="CRITICAL",
                        title=f"Removed private key still in Helm v{ver}: {release_name} → {key}",
                        detail=f"Key was in v{ver} but removed by v{latest_ver}. "
                               f"Old release secret still exists in cluster.",
                    ))
                    if console:
                        console.print(f"  [red]![/] {release_name} v{ver}→v{latest_ver}: "
                                      f"private key removed from {key} but old release persists")
                elif any(s in key.lower() for s in _SENSITIVE_VALUE_PATTERNS):
                    GLOBAL_K8S_FINDINGS.append(Finding(
                        target="k8s", check="helm_version_drift", severity="HIGH",
                        title=f"Removed credential still in Helm v{ver}: {release_name} → {key}",
                        detail=f"Credential key '{key}' was in v{ver} but removed by v{latest_ver}.",
                    ))
                    if console:
                        console.print(f"  [yellow]![/] {release_name} v{ver}→v{latest_ver}: "
                                      f"credential '{key}' removed but old release persists")

            changed_secrets = set()
            for key in set(old_flat.keys()) & set(latest_flat.keys()):
                old_v = old_flat[key]
                new_v = latest_flat[key]
                if old_v != new_v and isinstance(old_v, str):
                    if "PRIVATE KEY" in old_v or any(s in key.lower() for s in _SENSITIVE_VALUE_PATTERNS):
                        changed_secrets.add(key)

            if changed_secrets:
                GLOBAL_K8S_FINDINGS.append(Finding(
                    target="k8s", check="helm_version_drift", severity="MEDIUM",
                    title=f"Rotated credentials in old Helm v{ver}: {release_name}",
                    detail=f"Old values for {', '.join(sorted(changed_secrets)[:5])} "
                           f"still recoverable from v{ver}.",
                ))


def _flatten_values(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict into dot-notation keys."""
    flat: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                flat.update(_flatten_values(v, new_key))
            else:
                flat[new_key] = v
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(item, (dict, list)):
                flat.update(_flatten_values(item, key))
            else:
                flat[key] = item
    return flat


def _check_network_policies(namespace: str, token: str):
    """Check if network policies exist in the namespace."""
    data = _k8s_get(
        f"/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies",
        token,
    )
    if data is None:
        return
    policies = data.get("items", [])
    if not policies:
        GLOBAL_K8S_FINDINGS.append(Finding(
            target="k8s", check="network_policy", severity="MEDIUM",
            title=f"No NetworkPolicies in namespace {namespace}",
            detail="All pod-to-pod traffic is unrestricted without network policies",
        ))
    else:
        GLOBAL_K8S_FINDINGS.append(Finding(
            target="k8s", check="network_policy", severity="INFO",
            title=f"{len(policies)} NetworkPolicy(ies) in {namespace}",
        ))


def run_k8s_checks(namespace: str, console=None):
    """Run K8s internal checks (requires running inside a pod)."""
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    if not os.path.exists(token_path):
        if console:
            console.print("[dim]  No SA token — skipping K8s checks[/dim]")
        return

    with open(token_path) as f:
        token = f.read().strip()

    if console:
        console.print(f"\n[bold]── K8s Internal Checks (ns={namespace}) ──[/bold]")

    # RBAC enumeration
    for name, path in [
        ("secrets", f"/api/v1/namespaces/{namespace}/secrets"),
        ("configmaps", f"/api/v1/namespaces/{namespace}/configmaps"),
        ("pods", f"/api/v1/namespaces/{namespace}/pods"),
    ]:
        data = _k8s_get(path, token)
        if data:
            count = len(data.get("items", []))
            sev = "HIGH" if name == "secrets" else "INFO"
            GLOBAL_K8S_FINDINGS.append(
                Finding(
                    target="k8s",
                    check="rbac",
                    severity=sev,
                    title=f"SA can read {name} ({count} items) in {namespace}",
                )
            )
            if console:
                tag = "[red]!" if name == "secrets" else "[dim]*"
                console.print(f"  {tag}[/] SA can list {name}: {count} items")

    # Helm release secret scanning
    secrets_data = _k8s_get(
        f"/api/v1/namespaces/{namespace}/secrets", token
    )
    if secrets_data:
        for secret in secrets_data.get("items", []):
            if secret.get("type") != "helm.sh/release.v1":
                continue
            sname = secret["metadata"]["name"]
            b64 = secret.get("data", {}).get("release", "")
            if not b64:
                continue
            try:
                decoded = gzip.decompress(
                    base64.b64decode(base64.b64decode(b64))
                )
                _scan_helm(
                    sname,
                    json.loads(decoded).get("chart", {}).get("values", {}),
                    "",
                )
            except Exception:
                pass

    # Pod security checks
    pods_data = _k8s_get(f"/api/v1/namespaces/{namespace}/pods", token)
    if pods_data:
        for pod in pods_data.get("items", []):
            _check_pod_security(pod, namespace)

    # ConfigMap leak scanning
    cm_data = _k8s_get(f"/api/v1/namespaces/{namespace}/configmaps", token)
    if cm_data:
        for cm in cm_data.get("items", []):
            _check_configmap_leaks(cm, namespace)

    # SA blast radius mapping
    _check_sa_blast_radius(namespace, token, console=console)

    # Helm release version drift
    _check_helm_version_drift(namespace, token, console=console)

    # Network policy checks
    _check_network_policies(namespace, token)

    if console:
        sev_counts = {}
        for f in GLOBAL_K8S_FINDINGS:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        console.print(f"  [bold]K8s findings: {len(GLOBAL_K8S_FINDINGS)}[/bold] "
                      f"({', '.join(f'{s}={c}' for s, c in sorted(sev_counts.items()))})")
