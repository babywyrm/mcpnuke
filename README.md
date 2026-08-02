# mcpnuke

**MCP Red Teaming & Security Scanner**

Security scanner for [Model Context Protocol](https://modelcontextprotocol.io)
servers. Combines **static metadata analysis** with **active behavioral
probing** — connects to MCP servers, enumerates tools/resources/prompts,
calls tools with safe payloads, and analyzes what comes back.

Works against standard MCP (SSE, Streamable HTTP), **local stdio servers**
(`npx`, `python`, etc.), non-standard tool servers (`POST /execute`), and
Kubernetes-internal MCP deployments.

Use with [DVMCP](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
for training, or point at any MCP server in dev/staging/prod.

**See [CHANGELOG.md](CHANGELOG.md) for recent changes and planned work.**

---

## Install

**Quickstart (recommended):**
```bash
git clone https://github.com/babywyrm/mcpnuke.git && cd mcpnuke
./quickstart.sh
```

This creates a `.venv`, installs all extras (dev, ai, k8s), runs tests, and
prints usage. After that, `./scan` and `uv run mcpnuke` just work — no
activation needed.

**uv (manual):**
```bash
uv sync --all-extras
uv run mcpnuke --help
```

No `source .venv/bin/activate` needed — `uv run` finds the project venv automatically.

Optional extras: `dev` (testing/linting), `ai` (Claude analysis), `k8s` (Kubernetes checks), `all` (everything).

**pip (manual):**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[all,dev]"
```

**From PyPI** (coming soon):
```bash
uv pip install 'mcpnuke[all]'
```

**Verify your install:**
```bash
mcpnuke --doctor
```

---

## Quick Start

**New to mcpnuke?** Try the **[DVMCP Walkthrough](walkthrough/README.md)** --
a hands-on guide that scans 10 vulnerable MCP servers and explains every finding.
Or run `./walkthrough/demo.sh` for the fully automated version.
For command recipes across camazotz, DVMCP, deterministic benchmarking, and
Bedrock variations, see **[QUICKSTART.md](QUICKSTART.md)**.

```bash
# Single target
./scan --targets http://localhost:2266

# DVMCP challenges 1–10
./scan --port-range localhost:9001-9010 --verbose

# Authenticated endpoint (JWT, PAT, etc.)
./scan --targets https://api.githubcopilot.com/mcp/ --auth-token ghp_xxx

# OIDC auto-token (Keycloak, etc.)
./scan --targets http://localhost:9090/mcp \
  --oidc-url http://keycloak:8080/realms/myapp \
  --client-id myapp --client-secret SECRET

# OIDC with explicit scope, extra headers, and TLS verification
./scan --targets https://target.example/mcp \
  --oidc-url https://auth.example/realms/agentic \
  --client-id scanner --client-secret SECRET \
  --oidc-scope "mcp.read mcp.invoke" \
  --header "X-Tenant: blue" \
  --header "X-Agent-Flow: planner" \
  --tls-verify

# Optional: DPoP + token introspection + JWKS metadata checks
./scan --targets https://target.example/mcp \
  --auth-token "$ACCESS_TOKEN" \
  --dpop-proof "$DPOP_PROOF_JWT" \
  --token-introspect-url "https://auth.example/oauth2/introspect" \
  --token-introspect-client-id scanner \
  --token-introspect-client-secret SECRET \
  --jwks-url "https://auth.example/.well-known/jwks.json" \
  --tls-verify \
  --json auth-flow-report.json

# JSON report for CI
./scan --port-range localhost:9001-9010 --json report.json

# Differential scan (compare to baseline)
./scan --targets http://localhost:9001 --baseline baseline.json

# Scan a local MCP server via stdin/stdout (no proxy needed)
./scan --stdio 'npx -y @modelcontextprotocol/server-everything'

# Fast scan (~2min vs ~30min) — samples top 5 security-relevant tools, skips heavy probes
./scan --targets http://localhost:9090 --fast --verbose

# Grouped findings (compact report)
./scan --targets http://localhost:9090 --group-findings

# Parallel deep probes (faster behavioral phase)
./scan --targets http://localhost:9090 --probe-workers 4

# AI-powered analysis (requires ANTHROPIC_API_KEY)
./scan --targets http://localhost:9002/sse --claude --verbose
./scan --targets http://localhost:9002/sse --claude --claude-model claude-opus-4-20250514
./scan --targets http://localhost:9002/sse --claude --claude-max-tools 25 --claude-phase2-workers 3

# AI-powered analysis via AWS Bedrock Claude (optional)
./scan --targets http://localhost:9002/sse --claude --bedrock --bedrock-region us-east-1

# AI-powered analysis via local Ollama (no API key required)
./scan --targets http://localhost:9002/sse --ollama-analysis http://<ollama-host>:11434
./scan --targets http://localhost:9002/sse --ollama-analysis http://<ollama-host>:11434 --ollama-ensemble qwen2.5:14b,qwen2.5:7b

# Run tests
uv run pytest tests/ -v
```

All `./scan` commands also work as `uv run mcpnuke` (no activation needed),
`mcpnuke` (with venv activated), or `.venv/bin/mcpnuke`.

When `--auth-token` looks like a JWT, mcpnuke decodes it (without signature
validation) and includes a safe claim summary in JSON output under
`auth_context.jwt_claims_summary` to help validate agentic auth wiring.
If configured, token introspection and JWKS fetch summaries are also included
under `auth_context` without affecting scan behavior when disabled.

**Exit codes:** `0` — no findings (clean); `1` — findings at or above the
`--fail-on` threshold (default: `high`); `2` — scan error (connection failure,
invalid args, etc.). Use `1` vs `2` in CI to distinguish “vulns found” from
“scanner failed.” Use `--fail-on none` to always exit 0 (informational scans).

**SARIF output:** Use `--sarif results.sarif` to emit a SARIF 2.1.0 report
for GitHub Code Scanning, VS Code, and IDE integration. Findings map as:
CRITICAL/HIGH — `error`, MEDIUM — `warning`, LOW — `note`.

See [CI/CD Integration Guide](docs/ci-cd-guide.md) for GitHub Actions, GitLab CI,
and mcpnuke-runner setup.

---

## How It Works

```
1. CONNECT        Detect transport (SSE, Streamable HTTP, stdio, or custom tool server)
2. ENUMERATE      initialize → tools/list → resources/list → prompts/list
                  (or probe tool names for non-MCP /execute APIs)
3. STATIC CHECKS  Pattern-match metadata (names, descriptions, schemas)
4. PROBE          Call tools with safe payloads, read resources
5. ANALYZE        Scan responses for injection, exfil, leakage, drift
6. AGGREGATE      Detect attack chains across findings
7. REPORT         Console table (or --group-findings) + optional JSON
```

### Scan Phases

The scanner runs checks in a deliberate order:

| Phase | What Happens |
|-------|-------------|
| **Static** | Pattern-match on tool names, descriptions, schemas. No server interaction beyond enumeration. |
| **Behavioral** | Light interaction: re-list tools, read resources, send invalid methods. |
| **Deep Probes** | Active tool invocation with safe payloads. Analyze responses for threats. |
| **Transport** | CORS, unauthenticated SSE, cross-origin POST. |
| **Aggregate** | Cross-reference all prior findings to detect compound threats. |
| **AI** (optional) | Claude reads definitions, tool output, and all findings to identify subtle risks and multi-step attack chains. Requires `--claude`. |

Which checks run in each phase, and under what conditions, is in
**[docs/checks.md](docs/checks.md)**.

---

## Security Checks

mcpnuke runs 83 checks across static, behavioral, infrastructure and aggregate
phases. See **[docs/checks.md](docs/checks.md)** for the full inventory with
severities and detection notes.

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

### Response Caching

When `tool_response_injection` calls a tool, the response is cached in
`probe_opts["_response_cache"]`. Downstream checks like `response_credentials`
reuse the cache instead of re-invoking the same tools, eliminating redundant
calls and reducing scan time.

### Response Analysis

Every tool response is scanned for:

- **Injection payloads** — "ignore previous instructions", role overrides, system prompt markers
- **Semantic injection** — mode switches, secrecy directives, credential requests, XML/delimiter tool-call injection
- **Exfiltration URLs** — webhook, ngrok, burp, requestbin, pipedream, interactsh
- **Hidden content** — HTML comments, `<hidden>` blocks, `<script>` tags
- **Invisible Unicode** — zero-width chars, bidi overrides, invisible formatters
- **Base64-encoded attacks** — decoded and re-scanned for injection patterns
- **Cross-tool references** — "call tool X", "invoke function Y"
- **LLM classification** (with `--claude`) — ambiguous responses sent to Claude for malicious/benign classification

---

## Identity Lanes & Transports

mcpnuke labels every lane-scoped finding with two ecosystem-shared dimensions
sourced from the agentic-identity Identity Flow Framework and frozen by
[ADR 0001 — Five-Transport Taxonomy](https://github.com/babywyrm/camazotz/blob/main/docs/adr/0001-five-transport-taxonomy.md):

**Identity lanes** (the *who* — request initiator):

| Lane | Slug | Description |
|------|------|-------------|
| 1 | `human-direct` | Human authenticates directly to the MCP server |
| 2 | `delegated` | Human → agent token exchange (OAuth on-behalf-of) |
| 3 | `machine` | Workload identity (SPIFFE, SA tokens, bot certs) |
| 4 | `chain` | Agent → agent / chained delegation |
| 5 | `anonymous` | Pre-auth or unauthenticated surface |

**Transports** (the *how* — wire / process surface, codes A through E per
ADR 0001):

| Code | Name | Notes |
|------|------|-------|
| A | MCP JSON-RPC | The protocol most of this scanner exercises directly |
| B | Direct wire API | REST / gRPC / GraphQL the agent calls outside MCP |
| C | In-process SDK / library | Python imports, in-process function calls |
| D | Subprocess / native binary | Agent spawns `kubectl`, `terraform`, etc.; credentials cross the fork boundary |
| E | Native LLM function-calling | OpenAI tools, Anthropic `tool_use`, Gemini function-calling — no MCP wire involved |

The Finding dataclass carries `lane: int | None` and `transport: str | None`;
`--by-lane` groups by lane, `--coverage-report` intersects with camazotz's
schema-v1 lane corpus. Findings that are not lane-scoped (rate limit, TLS
hygiene, generic HTTP surface) keep `lane=None` and report under
"Uncategorized."

> Transports D and E currently appear in the taxonomy and `--by-lane`
> output for camazotz-side coverage tracking; in mcpnuke's own check
> emissions, lane-tagged findings are predominantly Transport A (MCP
> JSON-RPC) since that is the wire mcpnuke speaks. D / E coverage shows
> up via `--coverage-report` against a camazotz target that exercises
> those surfaces.

---

## CLI Reference

```
./scan [OPTIONS]

Target Selection:
  --targets URL [URL ...]     One or more MCP target URLs
  --port-range HOST:START-END Scan a port range (e.g. localhost:9001-9010)
  --targets-file FILE         Read URLs from file (one per line, # comments)
  --public-targets            Use built-in public targets list

Authentication:
  --auth-token TOKEN          Bearer token for authenticated endpoints
                              (or set MCP_AUTH_TOKEN env var)
  --dpop-proof JWT            Optional static DPoP header value
  --header KEY:VALUE          Extra HTTP header (repeatable)
  --tls-verify                Enable TLS certificate verification
  --oidc-scope SCOPE          Optional OAuth2 scope for client_credentials
  --token-introspect-url URL  Optional OAuth2 token introspection endpoint
  --token-introspect-client-id ID
  --token-introspect-client-secret SECRET
  --jwks-url URL              Optional JWKS endpoint for keyset metadata

Scan Options:
  --timeout SEC               Per-target connection timeout (default: 25)
  --workers N                 Parallel scan workers (default: 4)
  --max-pages N               Max pages to follow via nextCursor when enumerating
                              tools/resources/prompts (default: 20)
  --protocol-mode MODE        MCP protocol mode: auto|legacy|stateless (default: auto).
                              'legacy' uses the initialize/initialized handshake;
                              'stateless' uses the 2026-07-28 spec with
                              Mcp-Method/Mcp-Name headers and no session;
                              'auto' probes for whichever the server speaks.

Stdio Transport:
  --stdio CMD                 Scan a local MCP server via stdin/stdout JSON-RPC
                              (e.g. --stdio 'npx -y @modelcontextprotocol/server-everything')

Safety Controls:
  --no-invoke                 Static-only: skip all behavioral probes (safe for production)
  --safe-mode                 Skip dangerous tools (delete/send/exec/write), probe read-only
  --probe-calls N             Invocations per tool for deep rug pull (default: 10)

Performance:
  --fast                      Sample top 5 security-relevant tools, skip heavy probes
  --probe-workers N           Parallel deep behavioral probe threads (default: 1)
  --deterministic             Stable ordering + single-thread probes/AI Phase 2 for repeatable benchmarking
  --claude-phase2-workers N   Parallel Claude workers for AI Phase 2 (default: 1)
  --bedrock                   Route Claude calls through AWS Bedrock runtime
  --bedrock-region REGION     Bedrock region (e.g. us-east-1)
  --bedrock-profile PROFILE   AWS profile for Bedrock credentials
  --bedrock-model MODEL_ID    Bedrock model ID (default: anthropic.claude-3-5-sonnet-20241022-v2:0)
  --ollama-analysis URL       Use a local/networked Ollama instance as the AI
                              analysis backend instead of Claude. No API key
                              required. Example: --ollama-analysis http://<ollama-host>:11434
  --ollama-model MODEL        Ollama model to use (default: qwen2.5:14b). Larger
                              models produce more thorough analysis.
  --ollama-ensemble MODELS    Run analysis with multiple Ollama models and surface
                              consensus findings. Comma-separated.
                              Example: --ollama-ensemble qwen2.5:14b,qwen2.5:7b,qwen3:4b

Tool Server:
  --tool-names-file FILE      Custom wordlist for ToolServer enumeration (supplements built-in)

Output:
  --json FILE                 Write JSON report to FILE
  --group-findings            Collapse similar findings into compact grouped rows
  --no-color                  Disable colored output (respects NO_COLOR env var)
  --verbose, -v               Verbose output
  --debug                     Debug output (very noisy)

Lane Reporting & Cross-Project Coverage:
  --by-lane                   Group findings by agentic-identity lane (1..5),
                              print per-lane severity tally, and emit the
                              same structure into --json when both are set.
  --coverage-report URL       Fetch GET <URL>/api/lanes (schema v1) from a
                              running camazotz instance and print a
                              cross-project coverage report intersecting this
                              scan's findings with camazotz's lane corpus.
                              Diagnostic only — does NOT change the scanner's
                              exit code; failures (HTTP/schema mismatch) are
                              printed in red and the scan still exits based
                              on findings (see Exit Codes table).
  --generate-policy FILE      Generate a nullfield NullfieldPolicy YAML from
                              this scan's findings and write to FILE. Maps
                              code_execution / remote_access → DENY,
                              webhook_persistence → DENY, response_credentials
                              → SCOPE redact, etc. Pairs naturally with
                              --no-invoke for safe production audits.
  --policy-name NAME          metadata.name for the generated policy
                              (default: mcpnuke-recommended).
  --policy-namespace NS       metadata.namespace for the generated policy.
                              Empty means cluster-scoped or set at apply time.
  --policy-selector K=V       spec.selector.matchLabels entry, repeatable.
                              Without it the selector is empty and matches
                              every pod — typically too broad for a real
                              cluster. For the camazotz reference deployment:
                              --policy-selector app=brain-gateway
  --policy-labels K=V         metadata.labels entry, repeatable. Useful for
                              tagging by lane/transport so dashboards group it.
                              Example: --policy-labels nullfield.io/lane=machine

Differential:
  --baseline FILE             Compare against baseline
  --save-baseline FILE        Save scan as baseline

Inference Backend:
  --inference                 Auto-detect LLM backends from MCP server context
  --inference-host URL        Explicit inference backend URL (implies --inference)
  --inference-baseline FILE   Compare model digests against a known-good baseline (MCP-T55)
  --save-inference-baseline FILE  Snapshot current model state to FILE for later comparison

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
| **Fast** | `--fast` | Static + top-5 tools (tiered scoring), skip heavy probes (risk-aware: retains `input_sanitization` when dangerous params detected), cap workers at 2 | Quick triage, large tool sets |
| **Safe** | `--safe-mode` | Static + probes on read-only tools only | Prod servers with mixed tool risk |
| **Static** | `--no-invoke` | Static checks only, no tool calls | Prod servers, zero side-effect risk |
| **AI** | `--claude` | All checks + Claude analysis | Deep analysis, subtle vuln hunting |

### Fast Mode Scoring

In `--fast` mode, mcpnuke ranks all discovered tools using a tiered weighted
scoring algorithm (`_tool_security_score`) and selects the top 5. The scorer
considers:

| Factor | How It Works |
|--------|-------------|
| **Keyword tiers** (6 levels) | Exec/eval/shell keywords score highest (10), followed by secret/credential (8), webhook/callback (7), run/command (6), upload/write/file (4), admin/root (3) |
| **Name vs description** | Keywords in the tool *name* get 3x the weight of keywords in the description |
| **Dangerous parameters** | Params named `url`, `command`, `code`, `query`, `script`, `host`, etc. add +8 each |
| **Schema complexity** | Number of input properties (capped at 3) adds a small bonus |
| **High-value floor** | Tools with names containing `secret`, `credential`, `password`, `token`, `config`, etc. get a minimum score of 15, even if other signals are weak |

This ensures zero-parameter tools like `server-config` and `secrets.leak_config`
rank above benign tools like `smelt-item` or `move-to-position`, and that tools
with dangerous parameter surfaces (`run-maintenance`, `admin-webhook`, `fetch-skin`)
are consistently selected.

### AI-Powered Analysis (Claude)

Add `--claude` to any scan to layer LLM reasoning on top of deterministic checks.
Requires the `anthropic` package and `ANTHROPIC_API_KEY` env var.
By default, mcpnuke uses direct Claude API calls; Bedrock is opt-in via `--bedrock`.

**Setup:**
```bash
# If installed via quickstart.sh or uv sync --all-extras, anthropic is included.
# Otherwise install the AI extra:
uv pip install -e ".[ai]"    # or: pip install anthropic

export ANTHROPIC_API_KEY=sk-ant-...
```

For Bedrock mode, the same `ai` extra includes `boto3`; configure AWS credentials
and pass `--bedrock` (plus optional region/profile/model flags).

**`--claude` fails loud — no key, no run.** If `--claude` is set but the
`anthropic` package is missing or `ANTHROPIC_API_KEY` is unset, mcpnuke
exits immediately (exit code `2`) with a clear error message *before* any
scanning begins. There is no silent fallback to a stub responder. This is
deliberate: a missing key would otherwise downgrade an "AI scan" to a
deterministic-only scan with the same flag set, masking the regression.
(Camazotz's brain takes the opposite trade-off and degrades to a
`[cloud-stub]` responder when its key is missing — useful for live demos,
but unsafe for security tooling.)

**Usage:**
```bash
# Sonnet (fast, default)
./scan --targets http://localhost:9002/sse --claude --verbose

# Opus (deepest reasoning)
./scan --targets http://localhost:9002/sse --claude --claude-model claude-opus-4-20250514

# Fast mode + Claude (deterministic fast scan, then AI analysis)
./scan --targets http://localhost:9090 --fast --claude --verbose

# Faster Claude Phase 2 on medium/large toolsets
./scan --targets http://localhost:9090 --fast --claude --claude-max-tools 25 --claude-phase2-workers 3

# Repeatable benchmarking mode (recommended for run-to-run comparisons)
./scan --targets http://localhost:9090 --fast --claude --deterministic --verbose

# Claude via Bedrock (no ANTHROPIC_API_KEY required)
./scan --targets http://localhost:9090 --fast --claude --bedrock --bedrock-region us-east-1
```

**`--claude-phase2-workers` guidance:**
- Default is `1` (serial). This is safe and works out of the box.
- Use `2-4` to reduce wall-clock time when Phase 2 dominates runtime.
- Keep `1` if your key is rate-limited or target/network is unstable.
- This flag is optional; scans run normally without it.

**`--deterministic` guidance:**
- Forces stable tool ordering and single-threaded deep probes/AI Phase 2.
- Use this for benchmarking and CI drift checks when you need tighter run-to-run consistency.
- This does not remove model/target nondeterminism entirely, but it reduces scanner-side variance.

mcpnuke uses a three-layer analysis architecture. Each layer catches what
the previous one can't:

```
Layer 1: Deterministic (regex patterns)     — what tools SAY
Layer 2: Behavioral (call tools, probe)     — what tools DO
Layer 3: Claude AI (read, reason, chain)    — what tools MEAN
```

Claude runs three phases after deterministic + behavioral checks:

| Phase | What it does | Example finding |
|-------|-------------|----------------|
| **Tool analysis** | Reads definitions for subtle poisoning, social engineering, logical risks | "These tools chain into a privilege escalation path" |
| **Response analysis** | Reads actual tool output for manipulation, hidden intent, credential leakage | "Tool response is a fake paywall — social engineering the LLM" |
| **Chain reasoning** | Connects all findings into multi-step attack scenarios | "Unauthenticated access → command injection → lateral movement → persistence" |

Real example from DVMCP Challenge 4 (Rug Pull):

| Layer | Findings | Score |
|-------|----------|-------|
| Deterministic only | 5 (schema_risk, auth, SSE) | 26 |
| + Behavioral probes | 6 (+ deep_rug_pull) | 36 |
| + Claude Opus | 10 (+ social engineering, attack chains) | 64 |

AI findings are prefixed with `[AI]` and include taxonomy IDs (e.g. `[AI] [MCP-T03]`).
They appear alongside deterministic findings in the same report.

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
./scan --port-range localhost:9001-9010 --verbose
```

### Custom tool server (non-MCP /execute API)

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

### Authenticated endpoint (GitHub MCP)

```bash
./scan --targets https://api.githubcopilot.com/mcp/ --auth-token ghp_xxx

# Or via env var
export MCP_AUTH_TOKEN=ghp_xxx
./scan --targets https://api.githubcopilot.com/mcp/
```

### Remote public MCP (DeepWiki)

```bash
./scan --targets https://mcp.deepwiki.com/mcp
```

Use `/mcp` (Streamable HTTP), not `/sse`.

### Differential scan

```bash
# Save baseline
./scan --targets http://localhost:9001 --save-baseline baseline.json

# Later: detect regressions
./scan --targets http://localhost:9001 --baseline baseline.json
```

Reports added/removed/modified tools, resources, prompts. New tools
flagged as MEDIUM for review.

### JSON report for CI

```bash
./scan --port-range localhost:9001-9010 --json report.json
```

Exit code is `1` if the scan completes and reports findings, `0` if clean,
and `2` on scan errors. Use in CI pipelines to gate deployments and to
separate “findings” from “scanner failure.”

### Run tests

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

---

## Kubernetes Deployment

Deploy mcpnuke as a K8s Job to scan cluster-internal MCP services and
audit the Kubernetes posture from inside.

### Clusters with many MCPs

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

### Quick deploy

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
kubectl apply -f mcpnuke/k8s/manifests/cronjob.yaml
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
.
├── quickstart.sh              # One-command setup (venv + install + tests)
├── scan                       # Zero-config runner (no venv activation needed)
├── mcpnuke/                # Python package
│   ├── __init__.py            # Version, package docstring
│   ├── __main__.py            # Entry point (python -m mcpnuke)
│   ├── cli.py                 # Argument parsing
│   ├── scanner.py             # Scan orchestration, parallel execution, cross-target analysis
│   ├── diff.py                # Differential scanning (baseline save/load/compare)
│   ├── core/
│   │   ├── constants.py       # Protocol versions, severity weights, attack chain patterns
│   │   ├── enumerator.py      # Protocol negotiation + list tools/resources/prompts
│   │   ├── protocol.py        # Legacy vs stateless framing (MCP 2026-07-28 spec)
│   │   ├── models.py          # Finding, TargetResult dataclasses
│   │   ├── auth.py            # OIDC/OAuth discovery and token resolution
│   │   ├── llm.py             # Claude / Bedrock analysis backends
│   │   ├── llm_ollama.py      # Local Ollama analysis, single and ensemble
│   │   ├── taxonomy.py        # agentic-sec taxonomy loading (MCP-T01–T56)
│   │   ├── session.py         # SSE + HTTP + Stdio + ToolServer detection and sessions
│   │   └── transports/
│   │       └── base.py        # MCPSessionProtocol, HTTPCapableSession contracts
│   ├── patterns/
│   │   ├── rules.py           # Static regex patterns (injection, poison, theft, exec, etc.)
│   │   ├── probes.py          # Behavioral probe payloads, canary strings, response analysis
│   │   └── credentials.py     # The only credential regexes, tiered by false-positive risk
│   ├── checks/                # 43 modules; a representative selection below
│   │   ├── __init__.py        # Check registry and run_all_checks() orchestrator
│   │   ├── injection.py       # prompt_injection, tool_poisoning, indirect_injection, active_prompt_injection
│   │   ├── permissions.py     # excessive_permissions, schema_risks
│   │   ├── behavioral.py      # rug_pull, deep_rug_pull, state_mutation, notification_abuse
│   │   ├── tool_probes.py     # response_injection, input_sanitization, error_leakage
│   │   ├── theft.py           # token_theft
│   │   ├── execution.py       # code_execution, remote_access
│   │   ├── chaining.py        # tool_shadowing, multi_vector, attack_chains
│   │   ├── transport.py       # sse_security (CORS, unauth SSE, cross-origin POST)
│   │   ├── rate_limit.py      # rate_limit
│   │   ├── prompt_leakage.py  # prompt_leakage
│   │   ├── supply_chain.py    # supply_chain
│   │   ├── webhook_persistence.py  # webhook_persistence (name + param detection)
│   │   ├── credential_in_schema.py # credential_in_schema
│   │   ├── config_tampering.py     # config_tampering
│   │   ├── exfil_flow.py           # exfil_flow (source→sink with live verification)
│   │   ├── response_credentials.py # response_credentials (cached response reuse)
│   │   ├── dpop_enforcement.py     # RFC 9449 proof enforcement, validation, binding
│   │   ├── inference_backend.py    # Backend fingerprint, model integrity, guardrail variance
│   │   └── ...                     # See docs/checks.md for the full inventory
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
│       ├── json_out.py        # JSON report writer
│       ├── sarif.py           # SARIF 2.1.0 for code-scanning upload
│       ├── diff.py            # Scan-to-scan comparison against a baseline
│       ├── by_lane.py         # Per-lane finding breakdown
│       └── coverage_report.py # Check coverage against a target's declared labs
├── tests/                     # Pytest suite (900+ tests, incl. DVMCP challenges)
│   ├── test_dvmcp.py          # DVMCP challenges 1-10 (offline + optional live)
│   ├── test_cli.py            # CLI argument parsing
│   ├── test_diff.py           # Differential scanning
│   ├── test_k8s.py            # Kubernetes checks
│   ├── test_fast_sampling.py  # _tool_security_score + _pick_security_relevant
│   ├── test_webhook_persistence.py
│   ├── test_response_credentials.py
│   ├── test_exfil_flow.py
│   ├── test_config_tampering.py
│   ├── test_credential_in_schema.py
│   └── ...
├── walkthrough/               # Hands-on DVMCP guide + automated demo
│   ├── README.md              # Progressive walkthrough with annotated findings
│   └── demo.sh                # Zero-to-findings automated demo script
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
| `webhook_persistence → tool_response_injection` | Persistent callback feeds poisoned responses |
| `webhook_persistence → token_theft` | Webhook exfils credentials |
| `config_tampering → code_execution` | Config rewrite enables RCE |
| `config_tampering → webhook_persistence` | Config rewrite installs persistent callback |
| `response_credentials → token_theft` | Leaked creds enable further theft |
| `response_credentials → remote_access` | Leaked creds enable lateral movement |
| `exfil_flow → token_theft` | Source→sink pipeline steals creds |
| `exfil_flow → remote_access` | Source→sink pipeline enables remote access |

Chains are reported as CRITICAL with evidence-based tool names (e.g.
`input_sanitization → code_execution (execute_command)`) and appear in the
"Attack Chains Detected" section of the scan output.

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
# Run offline DVMCP challenge tests (no servers needed)
.venv/bin/pytest tests/test_dvmcp.py -v

# One-time setup for live testing
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git \
    tests/test_targets/DVMCP

# Reset to baseline + start servers + scan (recommended)
./tests/dvmcp_reset.sh --scan

# Or step by step:
./tests/dvmcp_reset.sh                  # reset + start servers
./scan --port-range localhost:9001-9010 --verbose

# Scan specific challenges
./scan --targets http://localhost:9002 http://localhost:9008

# Deeper rug pull probing (more calls per tool, default is 10)
./scan --port-range localhost:9001-9010 --probe-calls 15

# Static-only scan (no tool calls)
./scan --port-range localhost:9001-9010 --no-invoke

# Run live DVMCP tests
DVMCP_LIVE=1 .venv/bin/pytest tests/test_dvmcp.py -v

# Kill servers + clean state
./tests/dvmcp_reset.sh --kill-only
```

---

## Exit Code

| Code | Meaning |
|------|---------|
| **0** | Clean — scan finished with no findings |
| **1** | Findings — at least one finding was reported |
| **2** | Error — scan did not complete successfully (e.g. unreachable target, bad flags) |

## Documentation Hub

For ecosystem architecture, walkthroughs, and cross-project guides:
**[agentic-sec](https://github.com/babywyrm/agentic-sec)** — the central documentation for camazotz + nullfield + mcpnuke.
