# Kubernetes Deployment

Deploy mcpnuke as a K8s Job to scan cluster-internal MCP services and
audit the Kubernetes posture from inside.

## Clusters with many MCPs

When a cluster has many services (dozens or hundreds of potential MCP endpoints):

- **Parallel discovery** — MCP probes run with `--k8s-discovery-workers` (default 10).
  Increase for faster discovery: `--k8s-discovery-workers 20`.
- **Cap endpoints** — Limit how many MCPs are scanned: `--k8s-max-endpoints 50`.
  Annotation-sourced endpoints are kept first; then probed; then port-match.
- **Discover-only triage** — List endpoints without running full MCP scans:
  `mcpnuke --k8s-discover --k8s-discover-only --json endpoints.json`
  to export a URL list for triage or splitting across jobs.
- **Service fingerprinting** — Uses the same worker count for parallel HTTP
  probes when enumerating frameworks and exposed actuator/debug paths.

> **Note:** Use `mcpnuke` (not `./scan`) in K8s manifests — inside the
> container the package is installed globally.

## Quick deploy

```bash
# Build the image
docker build -f mcpnuke/k8s/Dockerfile -t mcpnuke:latest .

# Deploy (read-only cluster access)
kubectl apply -k mcpnuke/k8s/manifests/

# Optional: enable full RBAC auditing (SA blast radius mapping)
kubectl apply -f mcpnuke/k8s/manifests/rbac-impersonate.yaml

# Check results
kubectl logs -n mcpnuke -l app.kubernetes.io/name=mcpnuke
```

> **Note:** The base deployment grants read-only access to services, pods,
> secrets, configmaps, and network policies. The optional
> `rbac-impersonate.yaml` adds ServiceAccount impersonation, which lets the
> scanner enumerate effective permissions for every SA in the target
> namespace. This is an elevated privilege -- apply it only if you want
> complete RBAC auditing. The scanner degrades gracefully without it.

## What it checks in-cluster

| Check | What It Finds |
|-------|--------------|
| **RBAC enumeration** | Which resources the scanner's SA can access (secrets, configmaps, pods) |
| **SA blast radius** | Maps effective permissions for every ServiceAccount; flags overprivileged accounts |
| **Helm secret scanning** | Decodes Helm release secrets (base64→base64→gzip) and scans values for private keys and credentials |
| **Helm version drift** | Compares release versions to find credentials removed in newer releases but still recoverable from old ones |
| **Pod security** | Privileged containers, hostNetwork/PID, dangerous capabilities, hostPath mounts, root UID, missing resource limits |
| **ConfigMap leaks** | Scans ConfigMap data for private keys and credential-named fields |
| **NetworkPolicy audit** | Flags namespaces with no network policies |
| **Service fingerprinting** | Identifies frameworks (Spring Boot, Flask, Express, etc.) and probes for exposed actuator, debug, swagger, and admin endpoints |
| **MCP discovery** | Auto-discovers MCP servers via annotations (`mcp.io/enabled`) and well-known port probing |
| **Tool server detection** | Detects non-MCP tool-execute APIs (`POST /execute`) by probing with tool-style payloads |
| **hostNetwork loopback bridge** | Flags hostNetwork pods that can reach loopback-only services on the node (MCP-T58) |
| **Session token exposure** | Execs into pods to check well-known paths for cached session/token files (MCP-T57) |

## Recurring scans

Use the CronJob manifest for periodic auditing:

```bash
kubectl apply -f mcpnuke/k8s/manifests/cronjob.yaml
```

Default schedule: every 6 hours. Edit the `spec.schedule` field to change.

## Customization

Edit `mcpnuke/k8s/manifests/job.yaml` args to target specific namespaces:

```yaml
args:
  - "--k8s-discover"
  - "--k8s-discover-namespaces"
  - "my-namespace"
  - "--k8s-namespace"
  - "my-namespace"
  - "--verbose"
  - "--json"
  - "/reports/scan.json"
```
