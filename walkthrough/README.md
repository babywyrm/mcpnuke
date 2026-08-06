# mcpnuke DVMCP Walkthrough

A hands-on guide to MCP security scanning using mcpnuke against the
[Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) (DVMCP).

DVMCP provides 10 deliberately vulnerable MCP servers, each demonstrating a
different attack class. This walkthrough scans them all and explains every
finding in terms of what an attacker could actually do.

---

## Quick Start

**Automated (recommended):**

```bash
# Standard demo — deterministic checks, no API key needed
./walkthrough/demo.sh

# AI demo — adds Claude reasoning (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
./walkthrough/demo_ai.sh           # Sonnet (fast)
./walkthrough/demo_ai.sh --opus    # Opus (deepest analysis)
```

`demo.sh` handles everything: installs mcpnuke, starts DVMCP via Docker,
runs progressive scans with annotations, and offers cleanup at the end.
`demo_ai.sh` does the same but adds Claude analysis — showing the difference
between deterministic and AI-powered findings side by side.

**Manual setup:**

```bash
# 1. Install mcpnuke
./quickstart.sh --skip-tests

# 2. Start DVMCP (Docker required)
git clone --depth 1 https://github.com/harishsg993010/damn-vulnerable-MCP-server.git \
    tests/test_targets/DVMCP
cd tests/test_targets/DVMCP && docker build -t dvmcp . && cd ../../..
docker run -d --name dvmcp -p 9001-9010:9001-9010 dvmcp

# 3. Scan
./scan --port-range localhost:9001-9010 --verbose --no-invoke
```

---

## Prerequisites

- **uv** -- [install](https://docs.astral.sh/uv/getting-started/installation/)
- **Docker** -- with daemon running
- **Python 3.11+** -- uv handles this automatically

---

## Understanding Scan Modes

mcpnuke has three scan modes. This walkthrough starts with the safest and
progresses to more active probing.

| Mode | Flag | What it does | When to use |
|------|------|-------------|-------------|
| **Static** | `--no-invoke` | Analyzes tool metadata only. Never calls tools. | Production, first look |
| **Safe** | `--safe-mode` | Calls read-only tools, skips dangerous ones | Staging, dev |
| **Full** | (default) | Calls all tools with safe payloads | DVMCP, lab environments |

---

## Step 1: Your First Scan — Challenge 1 (Prompt Injection)

Challenge 1 runs a basic MCP server with a `get_user_info` tool and an
`internal://credentials` resource.

```bash
./scan --targets http://localhost:9001/sse --no-invoke
```

### What mcpnuke finds

| Check | Severity | What it means |
|-------|----------|--------------|
| `auth` | HIGH | Server accepted MCP `initialize` with no credentials. Anyone on the network can connect, enumerate tools, and start calling them. |
| `sse_security` | HIGH | The SSE event stream is open without authentication. An attacker can subscribe and observe all server-sent events. |
| `schema_risk` | MEDIUM | The `username` parameter has no `maxLength` constraint. Unbounded strings are injection surfaces -- an attacker can send arbitrarily long payloads. |
| `actuator_probe` | MEDIUM | `/openapi.json` is accessible, giving attackers a complete map of the API. |

### Risk score: 26

```
Score = (2 x HIGH=7) + (3 x MEDIUM=4) = 26
Rating: HIGH (score >= 10)
```

### Taxonomy mapping

Challenge 1 maps to **MCP-T01 (Direct Prompt Injection)**. The `get_user_info`
tool accepts user-controlled input that reaches the LLM context without
sanitization.

---

## Step 2: Dangerous Tools — Challenges 2-3

Challenge 2 exposes `execute_command` and `read_file`. Challenge 3 exposes
`file_manager` with read/write/delete capabilities.

```bash
./scan --targets http://localhost:9002/sse http://localhost:9003/sse --no-invoke
```

### Key findings

**`excessive_permissions` CRITICAL** -- Tools named `execute_command` and
`read_file` match dangerous capability patterns. These tools have more power
than any MCP client should have.

**`code_execution` CRITICAL** -- The `execute_command` tool has a parameter
literally named `command` and its description mentions execution. This is a
textbook RCE surface.

**`schema_risk` CRITICAL** -- A parameter named `command` in the input schema.
The server is advertising arbitrary code execution as a feature.

### Static checks catch what tools SAY they can do

These findings come from analyzing tool names, descriptions, and schemas --
mcpnuke never called the tools. Static analysis is fast, safe, and catches
the most obvious issues.

### Taxonomy mapping

- Challenge 2: **MCP-T02 (Tool Poisoning)** -- hidden malicious capabilities
- Challenge 3: **MCP-T03 (Confused Deputy)** -- excessive permissions

---

## Step 3: Behavioral Probes — Challenges 4, 8

Switch from `--no-invoke` to `--safe-mode` to let mcpnuke actually call
tools (skipping dangerous ones like `execute_command`).

```bash
./scan --targets http://localhost:9004/sse http://localhost:9008/sse --safe-mode
```

### What behavioral probes find that static misses

**`deep_rug_pull`** -- mcpnuke snapshots the tool list, calls each tool
multiple times, then re-snapshots. If the tool list, descriptions, or schemas
changed, it's a rug pull. Challenge 4 changes tool behavior after N calls.

**`input_sanitization`** -- mcpnuke sends injection probes through string
parameters: path traversal (`../../../etc/hostname`), command injection
(`test; echo CANARY`), template injection (`{{1333*7}}`), and interpreter
bypass (`perl -e 'print "CANARY"'`). If the canary appears in the response,
the tool reflected input without sanitization.

**`temporal_consistency`** -- The same tool called 3 times with identical
input should return consistent results. Escalating injection indicators or
wildly different response lengths suggest the server is behaving differently
based on call count.

### Behavioral checks test what tools ACTUALLY do

Static analysis tells you what a tool claims. Behavioral probing tells you
what it really does when you interact with it. The gap between the two is
where vulnerabilities hide.

### Taxonomy mapping

- Challenge 4: **MCP-T05 (Cross-Tool Context Poisoning)** -- rug pull
- Challenge 8: **MCP-T06 (Code Execution)** -- eval on user input

---

## Step 3b: AI Response Analysis — Challenge 4 with Claude

This is where the three layers stack. Add `--claude` to a behavioral scan
and Claude analyzes the actual tool responses — catching things no regex
pattern would ever flag.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./scan --targets http://localhost:9004/sse --safe-mode --claude --claude-model claude-opus-5 --verbose
```

### The three analysis layers

```
Layer 1: Deterministic checks (regex patterns)
  → schema_risk, auth, sse_security
  → Fast, free, catches obvious issues

Layer 2: Behavioral probes (call tools, analyze responses)
  → deep_rug_pull: tool output changed after repeated calls
  → input_sanitization: canary reflected unsanitized
  → tool_response_injection: input echoed in responses
  → Catches runtime behavior static analysis misses

Layer 3: Claude AI reasoning (reads everything, reasons about chains)
  → Phase 1: Analyzes tool definitions for subtle risks
  → Phase 2: Reads actual tool responses for social engineering
  → Phase 3: Chains all findings into multi-step attack paths
  → Catches meaning, intent, and logical chains
```

### What Claude found in Challenge 4 that nothing else caught

**`llm_response_analysis` MEDIUM — "Social engineering attempt through fake
paywall"**

Claude read the actual `get_weather` response and noticed it claims an API
rate limit and asks for payment for a "premium plan." This is the rug pull
in action — the tool starts returning fake paywall messages after repeated
calls, trying to manipulate the LLM into believing it needs to pay.

No regex pattern would flag this. It's a natural-language social engineering
attack embedded in a tool response, and Claude caught it by *reading and
reasoning about* what the tool returned.

**`llm_chain_reasoning` CRITICAL — "Cross-Origin MCP Hijacking Attack Chain"**

Claude chained together: unauthenticated access + CORS misconfiguration +
SSE stream access = a full cross-origin attack where a malicious website
can invoke MCP tools on behalf of a visitor.

### Score comparison across layers

| Layer | Findings | Score | What it caught |
|-------|----------|-------|---------------|
| Static only (`--no-invoke`) | 5 | 26 | Schema risks, auth, SSE |
| + Behavioral (`--safe-mode`) | 6 | 36 | Rug pull detection |
| + Claude Opus (`--claude`) | 10 | 64 | Paywall social engineering, attack chains |

Each layer catches what the previous one can't. Together they provide
comprehensive coverage.

---

## Step 4: Credential Theft — Challenges 5, 7

```bash
./scan --targets http://localhost:9005/sse http://localhost:9007/sse --no-invoke
```

### Key findings

**`token_theft` CRITICAL** -- The `authenticate` tool accepts a `password`
parameter. If an attacker can inject instructions into the LLM context,
they can trick the agent into passing real user credentials through this tool.

**`token_theft` HIGH** -- `verify_token` accepts a `token` parameter. Combined
with prompt injection, an attacker could exfiltrate active session tokens.

### The credential theft attack chain

```
1. Attacker plants injection payload in content the agent reads
2. Agent processes poisoned content
3. Injected instructions tell agent: "verify the user's token using verify_token"
4. Agent passes the real session token to the tool
5. Tool output (containing the token) is visible to the attacker
```

This is why `token_theft` findings matter even when the tool itself is
"legitimate" -- the risk is in how it can be misused through the agent.

### Taxonomy mapping

- Challenge 5: **MCP-T05 (Tool Shadowing)** -- name collisions
- Challenge 7: **MCP-T07 (Secrets in Tool Output)** -- credential parameters

---

## Step 5: Attack Chains — Challenges 9-10

```bash
./scan --targets http://localhost:9009/sse http://localhost:9010/sse --no-invoke
```

### Key findings

**`multi_vector` CRITICAL** -- Multiple dangerous vulnerability categories
active on the same server. Port 9009 has code execution AND token theft AND
remote access -- an attacker has multiple entry points and can pivot.

**`attack_chain` CRITICAL** -- Linked vulnerability pairs:
- `code_execution → token_theft`: RCE used to steal credentials
- `code_execution → remote_access`: RCE to persistent access
- `actuator_probe → token_theft`: leaked config enables token forgery

### Why chains matter

A single `schema_risk MEDIUM` finding on one server is low priority.
But `code_execution` + `token_theft` + `remote_access` on the same server
is a complete kill chain: get in, steal creds, establish persistence.

Port 9009 scores **134** -- 5x higher than port 9001 (26). Attack chains
multiply severity because each finding enables the next.

### Taxonomy mapping

- Challenge 9: **MCP-T06 (SSRF/RCE)** -- command injection via `remote_access`
- Challenge 10: **Multi-vector** -- chained MCP-T01 + MCP-T06 + MCP-T07

---

## Step 6: Full Sweep

Scan all 10 challenges at once and export a JSON report:

```bash
./scan --port-range localhost:9001-9010 --no-invoke --json walkthrough/report.json
```

### Reading the summary table

The per-target summary shows findings and risk scores ranked by severity.
Servers with attack chains and multi-vector findings always score highest.

### JSON report

The JSON output at `walkthrough/report.json` contains structured data for
every finding: target, check name, severity, title, detail, and evidence.
Use it for:

- **CI pipelines**: exit code 1 on CRITICAL/HIGH findings
- **Dashboards**: parse and visualize findings over time
- **Differential scanning**: save as baseline, compare later with `--baseline`

### Differential scanning

```bash
# Save today's scan as baseline
./scan --port-range localhost:9001-9010 --save-baseline baseline.json

# Tomorrow: detect changes
./scan --port-range localhost:9001-9010 --baseline baseline.json
```

New tools, removed tools, and schema changes are flagged as regressions.

---

## MCP Threat Taxonomy Reference

Each DVMCP challenge maps to the
[MCP Red Team Playbook](https://github.com/babywyrm/sysadmin/tree/master/mcp/redteam)
threat taxonomy:

| Challenge | Port | Taxonomy ID | Category | mcpnuke Checks |
|-----------|------|-------------|----------|----------------|
| 1 | 9001 | MCP-T01 | Direct Prompt Injection | `prompt_injection`, `schema_risk` |
| 2 | 9002 | MCP-T02 | Tool Poisoning | `tool_poisoning`, `excessive_permissions`, `code_execution` |
| 3 | 9003 | MCP-T03 | Confused Deputy | `excessive_permissions`, `schema_risk` |
| 4 | 9004 | MCP-T05 | Rug Pull / Context Poisoning | `deep_rug_pull`, `temporal_consistency` |
| 5 | 9005 | MCP-T05 | Tool Shadowing | `tool_shadowing` |
| 6 | 9006 | MCP-T02 | Indirect Prompt Injection | `indirect_injection`, `resource_poisoning` |
| 7 | 9007 | MCP-T07 | Token Theft | `token_theft`, `response_credentials` |
| 8 | 9008 | MCP-T06 | Code Execution | `code_execution`, `input_sanitization` |
| 9 | 9009 | MCP-T06 | Remote Access / SSRF | `remote_access`, `ssrf_probe`, `code_execution` |
| 10 | 9010 | Multi | Multi-Vector Attack | `multi_vector`, `attack_chain` |

### Full taxonomy (MCP-T01 through MCP-T14)

| ID | Category | Covered by mcpnuke |
|----|----------|-------------------|
| MCP-T01 | Direct Prompt Injection | `prompt_injection` |
| MCP-T02 | Indirect Prompt Injection | `indirect_injection`, `tool_poisoning`, `resource_poisoning` |
| MCP-T03 | Confused Deputy | `excessive_permissions` |
| MCP-T04 | Token Audience Bypass | `jwt_boundary` |
| MCP-T05 | Cross-Tool Context Poisoning | `tool_shadowing`, `deep_rug_pull`, `cross_tool_manipulation` |
| MCP-T06 | SSRF via Tool | `ssrf_probe`, `remote_access`, `code_execution` |
| MCP-T07 | Secrets in Tool Output | `response_credentials`, `credential_in_schema`, `error_leakage`, `actuator_probe` |
| MCP-T08 | Supply Chain via Content | `supply_chain` |
| MCP-T09 | Agent Config Tampering | `config_tampering` |
| MCP-T10 | Hallucination-Driven Destruction | Planned (requires LLM target) |
| MCP-T11 | Cross-Tenant Memory Leak | Planned (requires vector DB) |
| MCP-T12 | Exfiltration via Chaining | `exfil_flow` |
| MCP-T13 | Audit Log Evasion | Planned |
| MCP-T14 | Persistence via Webhook | `webhook_persistence` |

**Current coverage: 13/14 taxonomy IDs.**

---

## Bonus: AI-Powered Analysis

Add `--claude` to any scan to layer Claude's reasoning on top of the
deterministic checks. This catches subtle issues that regex patterns miss:
social engineering in descriptions, logical attack chains, and
context-dependent risks.

```bash
export ANTHROPIC_API_KEY=sk-ant-...

# Sonnet (fast, good for iteration)
./scan --targets http://localhost:9002/sse --no-invoke --claude --verbose

# Opus (deepest reasoning — catches lateral movement, privilege escalation chains)
./scan --targets http://localhost:9009/sse --no-invoke --claude --claude-model claude-opus-5 --verbose
```

AI findings are prefixed with `[AI]` in the output. In our testing against
DVMCP Challenge 9, Opus increased the risk score from 134 to 206 by
identifying lateral movement paths and privilege escalation chains that
the deterministic scanner couldn't reason about.

Install the AI dependency: `uv pip install -e ".[ai]"`

---

## Next Steps

- **Scan your own MCP servers**: `./scan --targets http://your-server:port/mcp -v`
- **AI-powered deep scan**: `./scan --targets URL --claude --claude-model claude-opus-5`
- **Authenticated targets**: `./scan --targets URL --oidc-url KEYCLOAK_URL --client-id ID --client-secret SECRET`
- **Add to CI**: `./scan --targets URL --json report.json` (exits 1 on CRITICAL/HIGH)
- **Run the test suite**: `uv run pytest tests/ -v`
- **Contribute new checks**: see `.cursor/skills/mcpnuke-add-check/`

---

## Cleanup

```bash
docker stop dvmcp && docker rm dvmcp
```
