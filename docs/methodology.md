# Methodology

How the scanner probes a server, how it scores what it finds, and how to
exercise the whole pipeline against a known-vulnerable target.

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
vulnerability pairs** that combine into compound attack paths.

Every pair in `ATTACK_CHAIN_PATTERNS` (`mcpnuke/core/constants.py`) is listed
below, in that list's own order.
`tests/test_docs_current.py::TestAttackChainsDocumented` fails when the two
sets diverge — this table sat sixteen chains behind the code before it had a
guard. The risk column is prose and is not derived from anything.

| Chain | Risk |
|-------|------|
| `prompt_injection → code_execution` | Injection leads to RCE |
| `prompt_injection → token_theft` | Injection leads to credential exfil |
| `code_execution → token_theft` | RCE used to steal credentials |
| `code_execution → remote_access` | RCE to persistent access |
| `indirect_injection → token_theft` | Poisoned data exfils creds |
| `indirect_injection → remote_access` | Poisoned data opens a persistent channel |
| `tool_poisoning → token_theft` | Hidden tool instructions exfil creds |
| `tool_response_injection → cross_tool_manipulation` | Output hijacks tool flow |
| `tool_response_injection → token_theft` | Poisoned output exfils creds |
| `deep_rug_pull → tool_poisoning` | Post-trust tool mutation |
| `deep_rug_pull → tool_response_injection` | The mutated tool starts poisoning its own output |
| `input_sanitization → code_execution` | Unsanitized input to RCE |
| `resource_poisoning → tool_response_injection` | Poisoned resource feeds tool |
| `state_mutation → deep_rug_pull` | Server-side state change drives the tool mutation |
| `notification_abuse → token_theft` | Server-initiated request harvests credentials |
| `cross_tool_manipulation → code_execution` | Tool chaining reaches an exec-capable tool |
| `cross_tool_manipulation → token_theft` | Tool chaining steals creds |
| `response_credentials → token_theft` | Leaked creds enable further theft |
| `response_credentials → remote_access` | Leaked creds enable lateral movement |
| `config_tampering → code_execution` | Config rewrite enables RCE |
| `config_tampering → tool_poisoning` | Config rewrite plants poisoned tool descriptions |
| `webhook_persistence → tool_response_injection` | Persistent callback feeds poisoned responses |
| `webhook_persistence → token_theft` | Webhook exfils credentials |
| `credential_in_schema → token_theft` | A credential in the schema is stealable from `tools/list` alone |
| `execution_context_forgery → token_theft` | A forged execution principal is a stolen identity |
| `sidecar_credential_tamper → token_theft` | A sidecar or broker write is a stolen credential |
| `ssrf_probe → token_theft` | Server-side fetch reaches a metadata credential endpoint |
| `ssrf_probe → remote_access` | Server-side fetch pivots into the internal network |
| `actuator_probe → response_credentials` | Exposed actuator dumps config holding secrets |
| `actuator_probe → token_theft` | Actuator-exposed secrets become stolen tokens |
| `exfil_flow → token_theft` | Source→sink pipeline steals creds |
| `exfil_flow → remote_access` | Source→sink pipeline enables remote access |
| `config_tampering → webhook_persistence` | Config rewrite installs persistent callback |
| `jwt_algorithm → token_theft` | A forgeable signature mints a token for any identity |
| `jwt_weak_key → token_theft` | A guessable HMAC key mints a forged token |
| `jwt_ttl → token_theft` | A long-lived token stays usable long after it is stolen |

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
