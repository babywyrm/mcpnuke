# mcprowler

**MCP Red Teaming & Security Scanner**

Security scanner for [Model Context Protocol](https://modelcontextprotocol.io)
servers. Combines **static metadata analysis** with **active behavioral
probing** — connects to MCP servers, enumerates tools/resources/prompts,
calls tools with safe payloads, and analyzes what comes back.

Works against standard MCP (SSE, Streamable HTTP), non-standard tool servers
(`POST /execute`), and Kubernetes-internal MCP deployments.

Use with [DVMCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
for training, or point at any MCP server in dev/staging/prod.

**See [CHANGELOG.md](CHANGELOG.md) for recent changes and planned work.**

---

## Install

**uv (recommended):**
```bash
uv pip install -e .
mcprowler --targets http://localhost:9090
```

**pip:**
```bash
pip install -e .
mcprowler --targets http://localhost:9090
```

**No install (run as module):**
```bash
python -m mcprowler --targets http://localhost:9090
```

**From PyPI** (coming soon):
```bash
uv pip install mcprowler
```

---

## Quick Start

```bash
# Single target
mcprowler --targets http://localhost:2266

# DVMCP challenges 1–10
mcprowler --port-range localhost:9001-9010 --verbose

# Authenticated endpoint (JWT, PAT, etc.)
mcprowler --targets https://api.githubcopilot.com/mcp/ --auth-token ghp_xxx

# JSON report for CI
mcprowler --port-range localhost:9001-9010 --json report.json

# Differential scan (compare to baseline)
mcprowler --targets http://localhost:9001 --baseline baseline.json
```

All commands also work as `mcprowler` or `python3 -m mcprowler`.

---

## How It Works

```
1. CONNECT        Detect transport (SSE, Streamable HTTP, or custom tool server)
2. ENUMERATE      initialize → tools/list → resources/list → prompts/list
                  (or probe tool names for non-MCP /execute APIs)
3. STATIC CHECKS  Pattern-match metadata (names, descriptions, schemas)
4. PROBE          Call tools with safe payloads, read resources
5. ANALYZE        Scan responses for injection, exfil, leakage, drift
6. AGGREGATE      Detect attack chains across findings
7. REPORT         Console table + optional JSON
```

### Scan Phases

The scanner runs checks in a deliberate order:

| Phase | Checks | What Happens |
|-------|--------|-------------|
| **Static** | prompt_injection, tool_poisoning, excessive_permissions, token_theft, code_execution, remote_access, schema_risks, rate_limit, prompt_leakage, supply_chain, tool_shadowing | Pattern-match on tool names, descriptions, schemas. No server interaction beyond enumeration. |
| **Behavioral** | rug_pull, indirect_injection, protocol_robustness | Light interaction: re-list tools, read resources, send invalid methods. |
| **Deep Probes** | deep_rug_pull, tool_response_injection, input_sanitization, error_leakage, temporal_consistency, resource_poisoning, state_mutation, notification_abuse | Active tool invocation with safe payloads. Analyze responses for threats. |
| **Transport** | sse_security | CORS, unauthenticated SSE, cross-origin POST. |
| **Aggregate** | multi_vector, attack_chains | Cross-reference all prior findings to detect compound threats. |

---

## Security Checks Reference

### Static Checks (metadata only)

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `prompt_injection` | CRITICAL | Injection payloads in tool/resource/prompt descriptions |
| `tool_poisoning` | CRITICAL | Hidden instructions, invisible Unicode in tool descriptions |
| `excessive_permissions` | CRITICAL–MEDIUM | Dangerous capabilities (shell, filesystem, network, DB, cloud) |
| `code_execution` | CRITICAL–HIGH | Tools with exec/eval/shell parameters or descriptions |
| `remote_access` | CRITICAL–HIGH | Reverse shells, C2 beacons, port forwarding, data exfil |
| `token_theft` | CRITICAL–HIGH | Tools that accept or forward credentials as parameters |
| `supply_chain` | CRITICAL | Dynamic package install from user-controlled URLs |
| `schema_risk` | CRITICAL–MEDIUM | Command params, unbounded strings, freeform objects |
| `tool_shadowing` | HIGH–MEDIUM | Tool names that collide with common tools or other servers |
| `prompt_leakage` | HIGH | Tools that may echo, log, or expose internal prompts |
| `rate_limit` | MEDIUM | Descriptions suggesting unbounded/unthrottled usage |

### Behavioral Checks (active server interaction)

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `rug_pull` | CRITICAL–HIGH | Tool list changes between two `tools/list` calls |
| `deep_rug_pull` | CRITICAL | Tool list/schema changes **after invoking tools** — catches state-dependent rug pulls that the shallow check misses |
| `tool_response_injection` | CRITICAL–HIGH | Injection payloads, exfil URLs, hidden content, invisible Unicode, or base64-encoded attacks in tool **responses** |
| `cross_tool_manipulation` | HIGH | Tool output that directs the LLM to invoke a different tool |
| `input_sanitization` | CRITICAL–HIGH | Path traversal, command injection, template injection, SQL injection probes reflected unsanitized |
| `error_leakage` | HIGH–MEDIUM | Stack traces, internal paths, connection strings, or secrets in error responses |
| `temporal_consistency` | CRITICAL–MEDIUM | Escalating injection, wildly inconsistent responses, or new threats across repeated identical calls |
| `resource_poisoning` | CRITICAL–HIGH | Base64-encoded injection, data URIs, steganographic Unicode, CSS-hidden HTML, or markdown image exfiltration in resource content |
| `state_mutation` | HIGH–MEDIUM | Resources that appear, disappear, or change content after tool invocations |
| `notification_abuse` | CRITICAL–MEDIUM | Unsolicited `sampling/createMessage`, `roots/list`, or other server-initiated requests |
| `indirect_injection` | CRITICAL–HIGH | Injection/poison patterns and exfil URLs in resource content |

### Transport & Aggregate Checks

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `auth` | HIGH | Unauthenticated MCP/tool-server initialize accepted |
| `sse_security` | HIGH–MEDIUM | Unauthenticated SSE stream, CORS misconfiguration, cross-origin POST |
| `multi_vector` | CRITICAL | 2+ dangerous vulnerability categories active on one server |
| `attack_chain` | CRITICAL | Linked vulnerability pairs (e.g. `input_sanitization → code_execution`) |

---

## Behavioral Probing Methodology

The deep probe checks **call tools on the target server** using safe,
non-destructive payloads. Here's how it works:

### Safe Argument Generation

For each tool, the scanner reads the `inputSchema` and generates minimal
arguments using context-aware safe values:

| Parameter Pattern | Safe Value |
|------------------|-----------|
| `path`, `file`, `dir` | `/tmp/mcp_probe_MCP_PROBE_8f4c2a` |
| `command`, `exec` | `echo hello` |
| `expression`, `code` | `1+1` |
| `url`, `endpoint` | `http://example.com/test` |
| `username`, `name` | `probe_user` |
| `password`, `token` | `MCP_PROBE_8f4c2a` (canary) |
| Enum params | First enum value |
| Everything else | `test` |

Only **required** parameters are filled. Optional params are skipped to
minimize side effects.

### Injection Probes

For `input_sanitization`, the scanner sends targeted probes based on
parameter semantics:

| Param Type | Probe Examples |
|-----------|---------------|
| File/path params | `../../../tmp/MCP_PROBE_8f4c2a`, path null bytes |
| Command params | `test; echo MCP_PROBE_8f4c2a`, pipe/backtick variants |
| Query/SQL params | `' OR '1'='1`, `UNION SELECT` |
| Other strings | `{{7*7}}`, `${7*7}`, ERB/Jinja templates |

The canary string `MCP_PROBE_8f4c2a` is embedded in probes. If it appears
in the response, the tool reflected input without sanitization.

### Response Analysis

Every tool response is scanned for:

- **Injection payloads** — "ignore previous instructions", role overrides, system prompt markers
- **Exfiltration URLs** — webhook, ngrok, burp, requestbin, pipedream, interactsh
- **Hidden content** — HTML comments, `<hidden>` blocks, `<script>` tags
- **Invisible Unicode** — zero-width chars, bidi overrides, invisible formatters
- **Base64-encoded attacks** — decoded and re-scanned for injection patterns
- **Cross-tool references** — "call tool X", "invoke function Y"

---

## CLI Reference

```
mcprowler [OPTIONS]

Target Selection:
  --targets URL [URL ...]     One or more MCP target URLs
  --port-range HOST:START-END Scan a port range (e.g. localhost:9001-9010)
  --targets-file FILE         Read URLs from file (one per line, # comments)
  --public-targets            Use built-in public targets list

Authentication:
  --auth-token TOKEN          Bearer token for authenticated endpoints
                              (or set MCP_AUTH_TOKEN env var)

Scan Options:
  --timeout SEC               Per-target connection timeout (default: 25)
  --workers N                 Parallel scan workers (default: 4)

Safety Controls:
  --no-invoke                 Static-only: skip all behavioral probes (safe for production)
  --safe-mode                 Skip dangerous tools (delete/send/exec/write), probe read-only
  --probe-calls N             Invocations per tool for deep rug pull (default: 6)

Tool Server:
  --tool-names-file FILE      Custom wordlist for ToolServer enumeration (supplements built-in)

Output:
  --json FILE                 Write JSON report to FILE
  --verbose, -v               Verbose output
  --debug                     Debug output (very noisy)

Differential:
  --baseline FILE             Compare against baseline
  --save-baseline FILE        Save scan as baseline

Kubernetes:
  --k8s-namespace NS          Namespace for internal checks (default: default)
  --no-k8s                    Skip Kubernetes checks
  --k8s-discover              Auto-discover MCP targets via K8s service discovery
  --k8s-discover-namespaces   Namespaces to scan for MCP services
  --k8s-no-probe              Skip active probing during discovery (port match only)
  --k8s-discovery-workers N   Concurrent MCP probes during discovery (default: 10)
  --k8s-max-endpoints N       Cap number of MCP endpoints to scan (no limit by default)
  --k8s-discover-only         List discovered endpoints only; skip MCP scanning
```

### Scan Modes

| Mode | Flag | What Runs | Use Case |
|------|------|-----------|----------|
| **Full** | (default) | Static + all behavioral probes | Dev/staging, DVMCP, CTFs |
| **Safe** | `--safe-mode` | Static + probes on read-only tools only | Prod servers with mixed tool risk |
| **Static** | `--no-invoke` | Static checks only, no tool calls | Prod servers, zero side-effect risk |

Tools are classified as **dangerous** if their name contains keywords like
`delete`, `execute`, `send`, `write`, `deploy`, `kill`, `transfer`, etc.
In `--safe-mode`, these are skipped while read-only tools (`get`, `list`,
`search`, `check`, `verify`, etc.) are still probed.

---

## Quickstart Scenarios

### Scan DVMCP (all 10 challenges)

```bash
# Terminal 1: start challenge servers
./tests/dvmcp_reset.sh --setup-only

# Terminal 2: scan
mcprowler --port-range localhost:9001-9010 --verbose
```

### Custom tool server (non-MCP /execute API)

```bash
# Servers that use POST /execute with {"tool": "...", "query": "..."} instead of MCP
mcprowler --targets http://localhost:5000/execute --verbose

# With custom tool names wordlist for a specific engagement
mcprowler --targets http://localhost:5000/execute --tool-names-file my_tools.txt
```

The scanner auto-detects non-MCP tool servers by probing 20+ common
execute/invoke paths and fingerprints the framework (Flask, FastAPI, Express,
Spring Boot, etc.) from response headers. Tools are enumerated from a
built-in wordlist (`data/tool_names.txt`, 84 names) supplemented by any
custom wordlist. All static + behavioral checks run against discovered tools.

### Authenticated endpoint (GitHub MCP)

```bash
mcprowler --targets https://api.githubcopilot.com/mcp/ --auth-token ghp_xxx

# Or via env var
export MCP_AUTH_TOKEN=ghp_xxx
mcprowler --targets https://api.githubcopilot.com/mcp/
```

### Remote public MCP (DeepWiki)

```bash
mcprowler --targets https://mcp.deepwiki.com/mcp
```

Use `/mcp` (Streamable HTTP), not `/sse`.

### Differential scan

```bash
# Save baseline
mcprowler --targets http://localhost:9001 --save-baseline baseline.json

# Later: detect regressions
mcprowler --targets http://localhost:9001 --baseline baseline.json
```

Reports added/removed/modified tools, resources, prompts. New tools
flagged as MEDIUM for review.

### JSON report for CI

```bash
mcprowler --port-range localhost:9001-9010 --json report.json
```

Exit code is 1 if any CRITICAL or HIGH findings; 0 otherwise. Use in
CI pipelines to gate deployments.

### Run tests

```bash
uv run pytest
# or
python -m pytest tests/ -v
```

---

## Kubernetes Deployment

Deploy mcprowler as a K8s Job to scan cluster-internal MCP services and
audit the Kubernetes posture from inside.

### Clusters with many MCPs

When a cluster has many services (dozens or hundreds of potential MCP endpoints):

- **Parallel discovery** — MCP probes run with `--k8s-discovery-workers` (default 10).
  Increase for faster discovery: `--k8s-discovery-workers 20`.
- **Cap endpoints** — Limit how many MCPs are scanned: `--k8s-max-endpoints 50`.
  Annotation-sourced endpoints are kept first; then probed; then port-match.
- **Discover-only triage** — List endpoints without running full MCP scans:
  `mcprowler --k8s-discover --k8s-discover-only --json endpoints.json`
  to export a URL list for triage or splitting across jobs.
- **Service fingerprinting** — Uses the same worker count for parallel HTTP
  probes when enumerating frameworks and exposed actuator/debug paths.

### Quick deploy

```bash
# Build the image
docker build -f mcprowler/k8s/Dockerfile -t mcprowler:latest .

# Deploy (read-only cluster access)
kubectl apply -k mcprowler/k8s/manifests/

# Optional: enable full RBAC auditing (SA blast radius mapping)
kubectl apply -f mcprowler/k8s/manifests/rbac-impersonate.yaml

# Check results
kubectl logs -n mcprowler -l app.kubernetes.io/name=mcprowler
```

> **Note:** The base deployment grants read-only access to services, pods,
> secrets, configmaps, and network policies. The optional
> `rbac-impersonate.yaml` adds ServiceAccount impersonation, which lets the
> scanner enumerate effective permissions for every SA in the target
> namespace. This is an elevated privilege -- apply it only if you want
> complete RBAC auditing. The scanner degrades gracefully without it.

### What it checks in-cluster

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
| **Tool server detection** | Detects non-MCP tool-execute APIs (`POST /execute`) by probing with tool-style payloads; enumerates available tools by name |

### Recurring scans

Use the CronJob manifest for periodic auditing:

```bash
kubectl apply -f mcprowler/k8s/manifests/cronjob.yaml
```

Default schedule: every 6 hours. Edit the `spec.schedule` field to change.

### Customization

Edit `k8s/manifests/job.yaml` args to target specific namespaces:

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

---

## Project Structure

```
mcprowler/                     # repo root
├── mcprowler/                 # Python package
│   ├── __init__.py            # Version, package docstring
│   ├── __main__.py            # Entry point (python -m mcprowler)
│   ├── cli.py                 # Argument parsing
│   ├── scanner.py             # Scan orchestration, parallel execution, cross-target analysis
│   ├── diff.py                # Differential scanning (baseline save/load/compare)
│   ├── core/
│   │   ├── constants.py       # Protocol versions, severity weights, attack chain patterns
│   │   ├── enumerator.py      # MCP handshake: initialize → list tools/resources/prompts
│   │   ├── models.py          # Finding, TargetResult dataclasses
│   │   └── session.py         # SSE + HTTP + ToolServer transport detection and sessions
│   ├── patterns/
│   │   ├── rules.py           # Static regex patterns (injection, poison, theft, exec, etc.)
│   │   └── probes.py          # Behavioral probe payloads, canary strings, response analysis
│   ├── checks/
│   │   ├── __init__.py        # Check registry and run_all_checks() orchestrator
│   │   ├── injection.py       # prompt_injection, tool_poisoning, indirect_injection
│   │   ├── permissions.py     # excessive_permissions, schema_risks
│   │   ├── behavioral.py      # rug_pull, deep_rug_pull, state_mutation, notification_abuse
│   │   ├── tool_probes.py     # response_injection, input_sanitization, error_leakage
│   │   ├── theft.py           # token_theft
│   │   ├── execution.py       # code_execution, remote_access
│   │   ├── chaining.py        # tool_shadowing, multi_vector, attack_chains
│   │   ├── transport.py       # sse_security (CORS, unauth SSE, cross-origin POST)
│   │   ├── rate_limit.py      # rate_limit
│   │   ├── prompt_leakage.py  # prompt_leakage
│   │   └── supply_chain.py    # supply_chain
│   ├── data/
│   │   ├── public_targets.txt # Built-in target URLs (DVMCP, public MCP servers)
│   │   └── tool_names.txt     # Wordlist for ToolServer tool enumeration
│   ├── k8s/
│   │   ├── scanner.py         # RBAC, Helm secrets, pod security, SA blast radius
│   │   ├── discovery.py       # MCP auto-discovery via annotations + port probing
│   │   ├── fingerprint.py     # Framework detection + exposed endpoint probing
│   │   ├── Dockerfile         # Multi-stage Python 3.12-slim image
│   │   └── manifests/         # Kustomize-ready K8s deployment manifests
│   └── reporting/
│       ├── console.py         # Rich table output
│       └── json_out.py        # JSON report writer
├── tests/                     # Pytest suite
├── pyproject.toml             # Project metadata, dependencies, entry points
├── CHANGELOG.md
└── README.md
```

---

## Risk Scoring

```
Score = SUM(finding_weights)

  CRITICAL  →  10 points
  HIGH      →   7 points
  MEDIUM    →   4 points
  LOW       →   1 point

Rating:
  ≥ 20  →  CRITICAL
  ≥ 10  →  HIGH
  ≥  5  →  MEDIUM
  ≥  1  →  LOW
     0  →  CLEAN
```

---

## Attack Chain Detection

After all individual checks run, the scanner looks for **linked
vulnerability pairs** that combine into compound attack paths:

| Chain | Risk |
|-------|------|
| `prompt_injection → code_execution` | Injection leads to RCE |
| `prompt_injection → token_theft` | Injection leads to credential exfil |
| `code_execution → token_theft` | RCE used to steal credentials |
| `code_execution → remote_access` | RCE to persistent access |
| `indirect_injection → token_theft` | Poisoned data exfils creds |
| `tool_response_injection → cross_tool_manipulation` | Output hijacks tool flow |
| `deep_rug_pull → tool_poisoning` | Post-trust tool mutation |
| `input_sanitization → code_execution` | Unsanitized input to RCE |
| `resource_poisoning → tool_response_injection` | Poisoned resource feeds tool |
| `cross_tool_manipulation → token_theft` | Tool chaining steals creds |

Chains are reported as CRITICAL and appear in the "Attack Chains Detected"
section of the scan output.

---

## Testing with DVMCP

[DVMCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server) provides
10 deliberately vulnerable MCP servers for testing:

| Challenge | Port | Vulnerability |
|-----------|------|--------------|
| 1. Basic Prompt Injection | 9001 | Sensitive credentials in resources |
| 2. Tool Poisoning | 9002 | `execute_command` with `shell=True` |
| 3. Excessive Permissions | 9003 | `file_manager` with read/write/delete |
| 4. Rug Pull Attack | 9004 | Tool behavior changes after N calls |
| 5. Tool Shadowing | 9005 | Tool name conflicts |
| 6. Indirect Prompt Injection | 9006 | Injection via data sources |
| 7. Token Theft | 9007 | Passwords/tokens as parameters |
| 8. Code Execution | 9008 | `eval()` on user input |
| 9. Remote Access Control | 9009 | Command injection via `remote_access` |
| 10. Multi-Vector Attack | 9010 | Chained vulnerabilities |

```bash
# One-time setup
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git \
    tests/test_targets/DVMCP

# Reset to baseline + start servers + scan (recommended)
./tests/dvmcp_reset.sh --scan

# Or step by step:
./tests/dvmcp_reset.sh                  # reset + start servers
mcprowler --port-range localhost:9001-9010 --verbose

# Scan specific challenges
mcprowler --targets http://localhost:9002 http://localhost:9008

# Deeper rug pull probing (more calls per tool)
mcprowler --port-range localhost:9001-9010 --probe-calls 10

# Static-only scan (no tool calls)
mcprowler --port-range localhost:9001-9010 --no-invoke

# Kill servers + clean state
./tests/dvmcp_reset.sh --kill-only
```

---

## Exit Code

Exits **1** if any CRITICAL or HIGH findings; **0** otherwise.
