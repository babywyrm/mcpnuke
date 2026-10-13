# mcpnuke Quickstart

Recipe-first guide to **mcpnuke**. Every block below is copy-pasteable.
Pitch and install: [`README.md`](README.md). Full flags:
[`docs/cli-reference.md`](docs/cli-reference.md). Scan modes:
[`docs/scan-modes.md`](docs/scan-modes.md).

> **Mental model:** point mcpnuke at an MCP server you are allowed to
> scan, pick a goal (triage, prove, policy, CI), run the matching
> command, then read the priority actions. Exit `1` means findings at
> the `--fail-on` threshold (default `high`), not a crashed scan.

---

## 1. Launch

From a clone, `uv sync --all-extras`, then prefix commands with
`uv run`. An installed copy is just `mcpnuke`.

```bash
uv run mcpnuke --doctor
uv run mcpnuke --targets http://<mcp-host>/mcp --no-invoke --verbose
```

`--doctor` checks the install and does not scan. `--no-invoke` reads
the catalog and does not call tools. Replace `<mcp-host>` with a
server you own. A host with no MCP endpoint still finishes: the
finding is "No MCP endpoint found" and the exit is `1`. DVMCP's lab
ports are in [section 8](#8-dvmcp-challenge-scan), after those servers
are started. Later goals are in section 3.

---

## 2. Choose how hard to press

The same target takes any of these. `--fast` still reads the full
catalog; it only samples invoke probes.

| Goal | Flags |
|------|-------|
| Catalog only | `--no-invoke` |
| Quick triage | `--fast` |
| Prod, mixed tools | `--safe-mode` |
| Full probes | (default) |
| AI on top | `--claude` or `--ollama-analysis URL` |

AI phases, including chain replay, are in
[`docs/ai-analysis.md`](docs/ai-analysis.md).

---

## 3. Recipes by goal

### "Is this server quiet enough to look at?"

```bash
mcpnuke --targets http://<mcp-host>/mcp --no-invoke --verbose --json triage.json
```

Static checks only. Use this on a production endpoint before any tool
call. Add `--safe-mode` when a later pass may invoke tools and some of
them write, send, or fetch.

### "What did the tools actually do?"

```bash
mcpnuke --targets http://<mcp-host>/mcp --verbose --json probe.json
```

Calls tools with the scanner's payloads and grades the responses.
`--fast` keeps that to the top five security-relevant tools.

### "Do these servers compose?"

```bash
A=http://<mcp-host>/sse
B=http://<other-host>/sse
mcpnuke --targets "$A" "$B" \
  --trust-set "$A,$B" \
  --chain-replay --cross-server --chain-replay-retries 1 \
  --ollama-analysis http://<ollama-host>:11434 --ollama-model qwen2.5:14b \
  --verbose --json replay.json
```

`--claude` is the same four phases when you are not on a local model.
A step may name the other server with `target`. The transcript names
that server. A chain is reproduced only when an earlier output lands
in a parameter the later tool declares. Exit `1` here is the fail-on
threshold.

### "Turn a proved chain into a policy"

```bash
mcpnuke --targets http://<mcp-host>/mcp --generate-policy fix.yaml
```

A proved chain becomes **DENY on the sink** and **HOLD on earlier
sources**. Edit the YAML before you apply it. The full loop, including
the example policy, is in [section 4](#4-generate-nullfield-policy-from-findings).

### "Gate a pipeline on the result"

```bash
mcpnuke --targets http://<mcp-host>/mcp --json report.json --fail-on high
```

`0` is clean at that threshold, `1` is findings, `2` is a scan that
did not finish. `--coverage-report` does not change the exit code.

### "Did the tool surface change?"

```bash
mcpnuke --targets http://<mcp-host>/mcp --save-baseline baseline.json
mcpnuke --targets http://<mcp-host>/mcp --baseline baseline.json
```

Description or schema drift on a tool that was already approved is
CRITICAL. A tool added or removed is MEDIUM.

### "The server is a local process"

```bash
mcpnuke --stdio 'npx -y @modelcontextprotocol/server-everything'
```

No URL and no proxy. Auth-shaped findings that need an HTTP boundary
are not reported on stdio.

### "The server wants a token"

```bash
mcpnuke --targets https://mcp.example.com/mcp --auth-token-file ./token --tls-verify
```

The token stays in the file, not in the process list. OIDC, DPoP, and
JWKS are in [section 10](#10-oauthjwt-validation).

### "I just want the right defaults for a known host"

```bash
mcpnuke --targets https://mcp.example.com/mcp --scan-profile cursor-mcp
```

`--scan-profile` applies a named set of defaults: `cursor-mcp` and
`claude-desktop` turn on safe-mode and fast, `stdio` turns on safe-mode.
Any flag you pass explicitly still wins over the profile.

---

## Lab scenarios

The blocks above are the goals. The numbered sections are the longer
lab notes (Camazotz, DVMCP, Teleport, Kubernetes) those goals came from.

## 0) Setup

```bash
git clone https://github.com/babywyrm/mcpnuke.git
cd mcpnuke
./quickstart.sh
```

---

## 1) Basic Scan (Local Camazotz)

Catalog only. `--no-invoke` does not call tools, and `--fast` does not
shrink that catalog. The top-five sample applies when probes run.

```bash
mcpnuke --targets http://localhost:8080/mcp --fast --no-invoke --verbose
```

On Camazotz this still reports the static set: prompt injection, code
execution, webhook persistence, and credential exposure.

## 2) Full Scan (Invoke Tools)

Remove `--no-invoke` to actually call tools and analyze responses:

```bash
mcpnuke --targets http://localhost:8080/mcp --fast --verbose
```

This adds behavioral probes: rug-pull detection, response injection, input
sanitization, temporal consistency, SSRF probes, and the Teleport lab exploit
chains.

## 3) Scan K8s-Deployed Target (K3s / Cluster)

When camazotz runs behind nullfield on Kubernetes:

```bash
# Via NodePort (from outside the cluster)
mcpnuke --targets http://<cluster-node>:30080/mcp --fast --no-invoke --verbose

# Via ClusterIP (from inside the cluster)
mcpnuke --targets http://<cluster-ip>:8080/mcp --fast --no-invoke --verbose
```

nullfield intercepts the scan — unregistered tools return `-32003`. The scan
still finds findings in registered tools' schemas and metadata.

---

## 4) Generate nullfield Policy from Findings

**This is the feedback loop.** Scan → generate policy → apply → re-scan.

Proved multi-hop findings (out-of-band / chain reproduced / live exfil
confirmed) become **DENY on the sink** and **HOLD on earlier sources** so you
can cut egress without hard-blocking every reader. Edit the YAML before apply
if you want stricter or looser rules.

```bash
# Step 1: Scan and generate policy
mcpnuke --targets http://localhost:8080/mcp \
  --fast --no-invoke \
  --generate-policy fix.yaml

# Step 2: Review the generated policy
cat fix.yaml
```

Example output (`fix.yaml`):

```yaml
# Generated by mcpnuke --generate-policy
apiVersion: nullfield.io/v1alpha1
kind: NullfieldPolicy
metadata:
  name: mcpnuke-recommended
spec:
  selector:
    matchLabels: {}
  rules:
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["net.send"]
      reason: "mcpnuke: proved chain sink (out-of-band)"
    - action: HOLD
      mcpMethod: tools/call
      toolNames: ["vault.read"]
      reason: "mcpnuke: proved chain source (out-of-band)"
      hold:
        timeout: 5m
        onTimeout: DENY
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["hallucination.execute_plan"]
      reason: "mcpnuke: remote access capability"
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["shadow.register_webhook"]
      reason: "mcpnuke: webhook persistence vector"
    - action: SCOPE
      mcpMethod: tools/call
      toolNames: ["relay.execute_with_context"]
      reason: "mcpnuke: credential parameter exposure"
      scope:
        response:
          redactPatterns: ["password", "secret", "token", "api_key", "credential"]
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
      reason: "mcpnuke: default deny"
```

```bash
# Step 3: Apply to nullfield (Kubernetes CRD)
kubectl apply -f deploy/crds/           # one-time: install CRDs
kubectl apply -f fix.yaml               # apply the generated policy

# Step 3 alt: Apply to nullfield (Docker Compose)
cp fix.yaml examples/policy.yaml
docker compose restart nullfield

# Step 4: Re-scan to validate
mcpnuke --targets http://localhost:8080/mcp --fast --no-invoke --verbose
# Findings that are now blocked by nullfield will return -32000 or -32003
```

The mapping logic:
- `code_execution` → **HOLD** (timeout 5m, onTimeout DENY)
- `remote_access` → **DENY**
- `webhook_persistence` / `exfil_flow` → **DENY**
- `credential_in_schema` / `response_credentials` → **SCOPE** (redact)
- `rate_limit` → **ALLOW + budget** (per-identity call limits)

---

## 5) Teleport Infrastructure Checks

When Teleport is deployed alongside your MCP servers, mcpnuke probes for
infrastructure misconfigurations. Use the node IP so the checks probe the
right host:

```bash
mcpnuke --targets http://<cluster-node>:30080/mcp --fast --no-invoke --verbose
```

Teleport-specific findings you may see:

| Check | What It Finds |
|-------|--------------|
| `teleport_proxy_discovery` | Teleport proxy exposed, version + auth config leaked |
| `teleport_cert_validation` | Self-signed cert on proxy (MITM risk) |
| `teleport_app_enumeration` | MCP app list accessible without auth |
| `tbot_credential_exposure` | tbot secrets readable by non-tbot pods |
| `teleport_bot_overprivilege` | Bot service account bound to cluster-admin |

## 6) Teleport Lab Exploit Chains

Run the full scan (with `--invoke`) against camazotz to exercise the Teleport
lab attack sequences:

```bash
mcpnuke --targets http://localhost:8080/mcp --verbose
```

Three automated exploit chains:

**Bot identity theft** (`teleport_lab_bot_theft`):
```
read_tbot_secret → extract cert_serial → replay_identity → capture flag
                                        → check_session_binding → defense report
```

**Role escalation** (`teleport_lab_role_escalation`):
```
get_current_roles → request_role (social engineer justification)
                  → privileged_operation → capture flag
```

**Certificate replay** (`teleport_lab_cert_replay`):
```
get_expired_cert → replay_cert (within grace window) → capture flag
                 → check_replay_detection → defense report
```

On easy difficulty, attacks succeed (CRITICAL findings). On hard difficulty,
defenses hold (INFO findings).

---

## 7) Camazotz with AI Analysis

Add Claude reasoning for deeper finding analysis:

```bash
mcpnuke --targets http://localhost:8080/mcp \
  --fast --claude \
  --probe-calls 5 \
  --claude-max-tools 8 \
  --verbose \
  --json report.json
```

For deterministic benchmarking (stable ordering, single-threaded):

```bash
mcpnuke --targets http://localhost:8080/mcp \
  --fast --claude \
  --deterministic \
  --verbose \
  --json benchmark.json
```

## 8) DVMCP Challenge Scan

Scan the Damn Vulnerable MCP Server (10 challenge servers):

```bash
# Terminal 1: start challenge servers
./tests/dvmcp_reset.sh --setup-only

# Terminal 2: scan
./scan --port-range localhost:9001-9010 --verbose
```

## 9) Static-Only Safety Pass (Production)

For production endpoints where invoking tools is not acceptable:

```bash
mcpnuke --targets https://mcp.internal.example.com/mcp \
  --no-invoke \
  --auth-token "$MCP_TOKEN" \
  --tls-verify \
  --verbose \
  --json production-audit.json \
  --generate-policy recommended-policy.yaml
```

## 10) OAuth/JWT Validation

Validate scoped client-credentials and JWT hardening:

```bash
mcpnuke --targets https://mcp.example.com/mcp \
  --oidc-url https://auth.example.com/realms/agentic \
  --client-id scanner \
  --client-secret-file ./client-secret \
  --oidc-scope "mcp.read mcp.invoke" \
  --oidc-resource https://mcp.example.com/mcp \
  --tls-verify --verbose \
  --json jwt-audit.json
```

Add DPoP proof-binding, token introspection, and JWKS metadata checks when the
authorization server supports them:

```bash
mcpnuke --targets https://mcp.example.com/mcp \
  --auth-token "$ACCESS_TOKEN" \
  --dpop-proof "$DPOP_PROOF_JWT" \
  --token-introspect-url "https://auth.example.com/oauth2/introspect" \
  --token-introspect-client-id scanner \
  --token-introspect-client-secret "$CLIENT_SECRET" \
  --jwks-url "https://auth.example.com/.well-known/jwks.json" \
  --tls-verify \
  --json auth-flow-report.json
```

When `--auth-token` looks like a JWT, mcpnuke decodes it (without signature
validation) and includes a safe claim summary in JSON output under
`auth_context.jwt_claims_summary` to help validate agentic auth wiring.
Token introspection and JWKS fetch summaries likewise land under
`auth_context`; when those flags are not set they do not affect scan behavior.

## 11) K8s Discovery Scan

Auto-discover MCP servers in a Kubernetes cluster:

```bash
# Via kubectl proxy
kubectl proxy --port=8001 &
mcpnuke --k8s-api-url http://localhost:8001 \
  --k8s-discover \
  --k8s-discover-namespaces camazotz hammerhand \
  --verbose

# Via direct API
mcpnuke --k8s-api-url https://<cluster-node>:6443 \
  --k8s-token-file /tmp/tbot-kubeconfig.yaml \
  --k8s-discover --verbose
```

## 12) Per-Lane Reporting and Coverage

Group findings by agentic-identity lane (1–5) and intersect with a running
camazotz instance's lane corpus. Vocabulary follows
[ADR 0001](https://github.com/babywyrm/camazotz/blob/main/docs/adr/0001-five-transport-taxonomy.md)
(transports A–E).

```bash
# Group this scan's findings by lane and print per-lane severity tally
mcpnuke --targets http://<cluster-node>:30080/mcp \
  --auth-token "$FORGED_RO_TOKEN" \
  --fast --no-invoke \
  --by-lane
```

Example output snippet (live cluster scan with a forged read-only token —
Lane 1 jumped from 0 to 2 findings once the new MCP-T04 JWT checks
landed):

```
── Findings grouped by identity lane (168 total) ──

Lane 1 — Human Direct (slug=human-direct, transport=A)
  2 finding(s): HIGH=2
    HIGH     jwt_audience_target_match JWT aud claim does not match the MCP endpoint
    HIGH     jwt_cross_role_replay     Read-only token sees write/admin tools in tools/list

Lane 2 — Delegated (slug=delegated, transport=A)
  ...
```

Cross-project coverage report against a live camazotz instance:

```bash
mcpnuke --targets http://<cluster-node>:30080/mcp \
  --fast --no-invoke \
  --coverage-report http://<cluster-node>:3000
```

Example output snippet:

```
── Cross-project coverage report (vs camazotz) ──
  camazotz: 35 labs across 5 lanes
  mcpnuke covered 5/5 lanes on this scan

Lane 1 — Human Direct
  camazotz: 6 primary lab(s), transports [A, B]
  mcpnuke:  2 finding(s) fired (HIGH=2), transports [A]
  6 lab(s) covered, 2 finding(s) fired — aligned
...
```

`--coverage-report` is purely diagnostic — it does **not** alter the
scanner's exit code. The scan still exits `0` / `1` / `2` based on
findings (see README "Exit Code"). Schema mismatches and HTTP errors are
printed in red but do not abort the scan.

You can also generate a single-line nullfield policy from any scan, lane
report or not:

```bash
mcpnuke --targets http://localhost:8080/mcp --fast --no-invoke --generate-policy fix.yaml
```

(See section 4 above for the full feedback-loop walkthrough.)

---

## 13) Baseline and Regression

Save a scan as a baseline, then compare future scans:

```bash
# Save baseline
mcpnuke --targets http://localhost:8080/mcp \
  --fast --no-invoke \
  --save-baseline baseline.json

# Compare (after deploying fixes)
mcpnuke --targets http://localhost:8080/mcp \
  --fast --no-invoke \
  --baseline baseline.json
```

This compares the catalog. Description or schema drift on a tool that
was in the baseline is CRITICAL. A tool added or removed is MEDIUM.
`--diff-baseline` is the finding diff.

---

## 14) Stateless Servers (MCP spec 2026-07-28)

The 2026-07-28 spec retires the `initialize` handshake and the `Mcp-Session-Id`
header. mcpnuke auto-detects which protocol a server speaks, so no flag is
normally needed:

```bash
mcpnuke --targets https://server.example.com/mcp --verbose
```

Verbose output reports the negotiated protocol, e.g.
`Server: camazotz-brain-gateway v0.2.0  protocol=2025-03-26 mode=legacy`.

Force a mode when auto-detection is undesirable — for example when a gateway
rejects the legacy handshake outright:

```bash
# Skip the initialize probe entirely
mcpnuke --targets https://server.example.com/mcp --protocol-mode stateless --verbose

# Force legacy-only (never send Mcp-Method/Mcp-Name routing headers)
mcpnuke --targets http://localhost:8080/mcp --protocol-mode legacy --verbose
```

---

## 15) Custom tool server (non-MCP /execute API)

```bash
# Servers that use POST /execute with {"tool": "...", "query": "..."} instead of MCP
./scan --targets http://localhost:5000/execute --verbose

# With custom tool names wordlist for a specific engagement
./scan --targets http://localhost:5000/execute --tool-names-file my_tools.txt
```

The scanner auto-detects non-MCP tool servers by probing 20+ common
execute/invoke paths and fingerprints the framework (Flask, FastAPI, Express,
Spring Boot, etc.) from response headers. Tools are enumerated from a
built-in wordlist (`data/tool_names.txt`, 84 names) supplemented by any
custom wordlist. All static + behavioral checks run against discovered tools.

## 16) Authenticated endpoint (GitHub MCP)

```bash
./scan --targets https://api.githubcopilot.com/mcp/ --auth-token-file ./token

# Or via env var
export MCP_AUTH_TOKEN=ghp_xxx
./scan --targets https://api.githubcopilot.com/mcp/
```

## 17) Remote public MCP (DeepWiki)

```bash
./scan --targets https://mcp.deepwiki.com/mcp
```

Use `/mcp` (Streamable HTTP), not `/sse`.

## 18) Differential scan

```bash
# Save baseline
./scan --targets http://localhost:9001 --save-baseline baseline.json

# Later: detect regressions
./scan --targets http://localhost:9001 --baseline baseline.json
```

Reports added, removed, and modified tools, resources, and prompts.
Description or schema drift is CRITICAL. A tool added or removed is
MEDIUM.

## 19) JSON report for CI

```bash
./scan --port-range localhost:9001-9010 --json report.json
```

Exit `0` means nothing at or above `--fail-on` (default `high`), so a
report that is only LOW or MEDIUM still exits `0`. Exit `1` means a
finding at that threshold. Exit `2` means the scan did not finish.
`--fail-on none` always exits `0`.

## 20) Run tests

```bash
# Full suite
uv run pytest tests/ -v

# DVMCP challenges only
uv run pytest tests/test_dvmcp.py -v

# Stop on first failure
uv run pytest tests/ -v -x
```

CI runs three gates on every push and pull request, and a change has to clear
all of them:

```bash
uv run ruff check .      # must be zero
uv run mypy mcpnuke/     # must stay at or below the ceiling in the workflow
uv run pytest tests/     # 900+ passed, 0 failed, on Python 3.12 and 3.13
```

The mypy ceiling is a ratchet: it only ever moves down, so new code cannot add
untyped surface. `mcpnuke/core/` is stricter still — `disallow_untyped_defs` is
enforced there, so every function in it needs annotations.

Dependencies are pinned in `uv.lock` and CI installs with `--frozen`. If you
change `pyproject.toml`, run `uv lock` and commit the result, or the
`uv lock --check` step will fail on the drift.
