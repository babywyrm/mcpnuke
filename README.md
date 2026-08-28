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

## Contents

**On this page**

- [Install](#install)
  - [To use mcpnuke](#to-use-mcpnuke)
  - [To work on mcpnuke](#to-work-on-mcpnuke)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Security Checks](#security-checks)
- [Identity Lanes & Transports](#identity-lanes--transports)
- [CLI Reference](#cli-reference)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Exit Code](#exit-code)
- [Authorized Use](#authorized-use)
- [Contributing](#contributing)
- [License](#license)

**Reference**

| Document | Contents |
|----------|----------|
| [docs/cli-reference.md](docs/cli-reference.md) | Every flag, generated from the parser |
| [docs/checks.md](docs/checks.md) | Full check inventory with severities |
| [docs/scan-modes.md](docs/scan-modes.md) | Scan modes and fast-mode scoring |
| [docs/ai-analysis.md](docs/ai-analysis.md) | Claude, Bedrock and Ollama analysis |
| [docs/kubernetes.md](docs/kubernetes.md) | In-cluster deployment and posture checks |
| [docs/methodology.md](docs/methodology.md) | Probing methodology, risk scoring, attack chains |
| [docs/spec-surface.md](docs/spec-surface.md) | MCP 2026-08-22 roadmap: what we speak, scan, and can probe next |
| [QUICKSTART.md](QUICKSTART.md) | End-to-end scenarios |
| [docs/ci-cd-guide.md](docs/ci-cd-guide.md) | Integrating scans into your pipeline |
| [walkthrough/README.md](walkthrough/README.md) | Guided DVMCP scan, finding by finding |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup, check-authoring recipe, test invariants |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and authorized-use guidance |

**Ecosystem**

[agentic-sec](https://github.com/babywyrm/agentic-sec) — architecture,
walkthroughs and cross-project guides for camazotz + nullfield + mcpnuke.

---

## Install

### To use mcpnuke

**One-liner:**
```bash
curl -LsSf https://raw.githubusercontent.com/babywyrm/mcpnuke/main/install.sh | bash
```

Picks `uv tool`, `pipx` or `pip --user`, whichever you have. All three install
mcpnuke into its own environment, so its dependency pins cannot disturb the
rest of your Python. Pass `--extras all` for the optional features, or
`--dry-run` to see the plan first.

**Or install it yourself:**
```bash
uv tool install mcpnuke          # recommended
pipx install mcpnuke
pip install --user mcpnuke
```

**Verify:**
```bash
mcpnuke --doctor
```

Optional extras: `ai` (Claude analysis), `k8s` (Kubernetes checks), `server`
(the `mcpnuke-runner` HTTP job API), `all` (everything). The scanner itself
needs none of them — `uv tool install 'mcpnuke[all]'` if you want the lot.

### To work on mcpnuke

```bash
git clone https://github.com/babywyrm/mcpnuke.git && cd mcpnuke
./quickstart.sh
```

Creates a `.venv`, installs every extra including `dev`, runs the test suite
and prints usage. After that `./scan` and `uv run mcpnuke` both work with no
activation, because `uv run` finds the project venv on its own.

Manual equivalents:
```bash
uv sync --all-extras                              # uv
python3 -m venv .venv && source .venv/bin/activate && pip install -e ".[all,dev]"
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

# JSON report for CI (includes proof-ranked priority_actions + impact/fix/verify)
./scan --port-range localhost:9001-9010 --json report.json

# Suggest a NullfieldPolicy from findings (proved chains → DENY sink + HOLD sources)
./scan --targets http://localhost:8080/mcp --generate-policy fix.yaml

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
./scan --targets http://localhost:9002/sse --claude --claude-model claude-opus-5
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

**Exit codes:** `0` — nothing at or above the `--fail-on` threshold
(default: `high`); `1` — findings at or above it; `2` — scan error (connection
failure, invalid args, etc.). Use `1` vs `2` in CI to distinguish “vulns found”
from “scanner failed.” Use `--fail-on none` to always exit 0 (informational
scans). Full table under [Exit Code](#exit-code).

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
7. REPORT         Priority actions (fix first) + console/JSON (+ optional policy)
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

How the probes are built, how findings are scored and chained, and how to test
all of it against DVMCP, is in **[docs/methodology.md](docs/methodology.md)**.

---

## Security Checks

mcpnuke runs 88 checks across static, behavioral, infrastructure and aggregate
phases. See **[docs/checks.md](docs/checks.md)** for the full inventory with
severities and detection notes.

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

Every flag, its argument group, and the environment variable that backs it:
**[docs/cli-reference.md](docs/cli-reference.md)**, generated from the parser
so it cannot drift.

- Scan modes (`--fast`, `--safe-mode`, `--no-invoke`) and how `--fast` picks
  which tools to sample: **[docs/scan-modes.md](docs/scan-modes.md)**
- `--claude`, `--bedrock` and `--ollama-analysis`, and what the AI layer adds
  over the deterministic checks: **[docs/ai-analysis.md](docs/ai-analysis.md)**

---

## Kubernetes Deployment

mcpnuke also deploys as a K8s Job to scan cluster-internal MCP services and
audit the Kubernetes posture from inside. Manifests, RBAC, the in-cluster check
list and CronJob scheduling: **[docs/kubernetes.md](docs/kubernetes.md)**.

---

## Exit Code

The exit code reports the `--fail-on` threshold, not the raw finding count.
A scan that reports only LOW findings exits `0` under the default threshold.

| Code | Meaning |
|------|---------|
| **0** | Clean — nothing at or above the `--fail-on` threshold (default: `high`) |
| **1** | Findings — at least one finding at or above that threshold |
| **2** | Error — scan did not complete successfully (e.g. unreachable target, bad flags) |

`--fail-on any` exits `1` on any finding at all; `--fail-on none` always exits
`0`, for informational scans.

---

## Authorized Use

mcpnuke actively probes targets. By default it calls tools, sends injection and
SSRF payloads, and attempts multi-step chains — which on a real server can
create data, trigger outbound requests, or move data between systems.

**Only scan systems you own or have written authorization to test.**

Against anything you do not control, start with `--no-invoke` (static-only, never
calls a tool), then `--safe-mode` (skips tools classified dangerous) once you
know the blast radius. Full guidance, plus how to handle the sensitive output a
scan produces, is in **[SECURITY.md](SECURITY.md)**.

---

## Contributing

Bug reports about **detection quality — false positives and false negatives —
are the most valuable contribution**, because operator trust in the output is
what makes the tool worth running.

Setup, the check-authoring recipe, severity calibration, and the invariants the
test suite guards: **[CONTRIBUTING.md](CONTRIBUTING.md)**.

To report a vulnerability *in mcpnuke itself*, use private reporting as described
in [SECURITY.md](SECURITY.md) rather than a public issue.

---

## License

[MIT](LICENSE) © babywyrm
