<!-- GENERATED FILE — do not edit by hand.
     Regenerate: uv run python -m mcpnuke._docsgen
     Source: mcpnuke/cli.py -->

# CLI Reference

Every option `mcpnuke` accepts, grouped as `--help` groups them.
Generated from the parser, so it cannot fall behind the code.

## Target Selection

| Option | Description |
|---|---|
| `--targets URL [URL ...]` | One or more MCP target URLs |
| `--targets-file FILE` | Read target URLs from file (one per line, # comments ignored) |
| `--port-range HOST:START-END` | Scan a port range, e.g. localhost:9001-9010 |
| `--public-targets` | Use built-in public targets list (DVMCP, demo servers) |

## Authentication

| Option | Description |
|---|---|
| `--auth-token TOKEN` | Bearer token for authenticated MCP endpoints (JWT, PAT, etc.). Or set MCP_AUTH_TOKEN env var. |
| `--header KEY:VALUE` | Extra HTTP header (repeatable). Example: --header 'X-Tenant: blue' |
| `--tls-verify` | Enable TLS certificate verification for outbound HTTP calls. Default is disabled for lab/self-signed targets. |
| `--oidc-url URL` | OIDC issuer URL for token fetch (e.g. http://keycloak:8080/realms/myapp). Used with --client-id and --client-secret for automatic token acquisition. |
| `--oidc-scope SCOPE` | Optional OAuth2 scope for client_credentials token requests. |
| `--client-id ID` | OAuth2 client ID for client_credentials grant. Or set MCP_CLIENT_ID env var. |
| `--client-secret SECRET` | OAuth2 client secret for client_credentials grant. Or set MCP_CLIENT_SECRET env var. |
| `--token-introspect-url URL` | Optional OAuth2 token introspection endpoint URL. |
| `--token-introspect-client-id ID` | Optional client ID for token introspection requests. |
| `--token-introspect-client-secret SECRET` | Optional client secret for token introspection requests. |
| `--jwks-url URL` | Optional JWKS endpoint URL for keyset metadata checks. |
| `--dpop-proof JWT` | Static DPoP proof JWT header value to send as DPoP. Optional and independent from bearer auth. |
| `--jwt-max-ttl SEC` | Maximum acceptable JWT TTL in seconds before flagging (default: 14400 = 4h). Or set MCPNUKE_JWT_MAX_TTL env var. |

## Scan Options

| Option | Description |
|---|---|
| `--timeout SEC` | Per-target connection timeout (default: 25) |
| `--workers N` | Parallel scan workers (default: 4) |
| `--max-pages N` | Maximum pages to follow when enumerating tools/resources/prompts via nextCursor pagination (default: 20). |
| `--protocol-mode {auto,legacy,stateless}` | MCP protocol mode (default: auto). 'legacy' uses the initialize/initialized handshake; 'stateless' uses the 2026-07-28 spec with Mcp-Method/Mcp-Name headers and no session; 'auto' probes for whichever the server speaks. |

## Stdio Transport

| Option | Description |
|---|---|
| `--stdio CMD` | Scan a local MCP server via stdin/stdout JSON-RPC. Launch CMD as a subprocess and communicate over stdio. E.g. --stdio 'npx -y @modelcontextprotocol/server-everything' |

## Safety Controls

| Option | Description |
|---|---|
| `--chain-replay` | After AI chain reasoning, propose executable multi-step chains and replay them against the target. Graded: out-of-band egress or proven data movement is CRITICAL; callable-but-unproven is MEDIUM; halted chains stay silent. Implies tool invocation; ignored under --no-invoke. Requires --claude (or another AI backend). |
| `--chain-replay-retries N` | When a replayed chain halts, feed the failing transcript back to the model and retry up to N times (default: 1). 0 disables revision. Each revise/retry attempt is logged under --verbose. |
| `--oast` | Run a callback listener and plant a per-probe URL in exfiltration payloads (and in chain-replay {{oast.url}} steps). A request for that URL proves egress: data left the target, rather than the sink merely accepting it. Chain replay awaits a short grace period for queued callbacks before grading. Off by default because it opens a listening socket and induces the target to send data outward. |
| `--oast-host HOST` | Host to advertise in callback URLs, when the address the target can reach differs from the one bound. A container cannot reach the scanner's loopback (try host.docker.internal), and a remote target cannot route to a private address. Defaults to this machine's outbound address. |
| `--oast-port PORT` | Port for the callback listener (default: an ephemeral port). Set a fixed port when the callback has to traverse a firewall rule. |
| `--no-invoke` | Static-only mode: skip all behavioral probes that call tools. Safe for production servers where tool invocation could have side effects. |
| `--safe-mode` | Skip invoking tools classified as dangerous (delete, send, exec, write, webhook, egress, exfil, …). Namespaced names like shellwrap.exec and shadow.register_webhook count too. Behavioral probes still run on read-only / low-risk tools. |
| `--probe-calls N` | Number of tool invocations per tool for deep rug pull detection (default: 10) |

## Performance

| Option | Description |
|---|---|
| `--fast` | Fast scan: sample top 5 security-relevant tools, skip heavy probes (input_sanitization, error_leakage, temporal_consistency, ssrf_probe, sdk_cache_poisoning), cap probe workers at 2. Cuts LLM-backed scan time from ~30min to ~2min. Alias for --coverage 5. |
| `--coverage N` | Sample the top N most security-relevant tools (by keyword risk score). 0 = scan all tools. --fast is an alias for --coverage 5. Example: --coverage 20 scans ~20% of a 100-tool server in fast-mode time. |
| `--probe-workers N` | Parallel deep behavioral probe threads (default: 1). Higher values speed up deep probes but increase server load. |
| `--deterministic` | Deterministic scan mode: enforce stable tool ordering and single-threaded AI Phase 2/probe execution for more repeatable benchmarking. |

## AI Analysis

| Option | Description |
|---|---|
| `--claude` | Enable AI-powered analysis using Claude. Requires ANTHROPIC_API_KEY env var. Layers LLM reasoning on top of deterministic checks to catch subtle issues. |
| `--claude-max-tools N` | Max tools for Claude AI response analysis (default: 10). Higher = more thorough but slower and costs more. |
| `--claude-model MODEL` | Claude model to use for AI analysis (default: claude-sonnet-5). Use an opus model for deepest analysis. |
| `--claude-phase2-workers N` | Parallel Claude workers for Phase 2 response analysis (default: 1). Use 2-4 to reduce wall time on fast targets. |
| `--bedrock` | Use AWS Bedrock runtime for Claude API calls instead of direct Anthropic API. Requires boto3 and AWS credentials. |
| `--bedrock-model MODEL_ID` | Bedrock inference profile to invoke when --bedrock is enabled (default: us.anthropic.claude-sonnet-4-5-20250929-v1:0). Current Anthropic models on Bedrock are inference-profile only; outside the US substitute the eu./apac./global. prefix for your region. |
| `--bedrock-profile PROFILE` | AWS profile name for Bedrock credentials resolution. |
| `--bedrock-region REGION` | AWS region for Bedrock Runtime (e.g. us-east-1). Defaults to AWS_REGION/AWS_DEFAULT_REGION if unset. |
| `--ollama-analysis URL` | Use a local/networked Ollama instance as the AI analysis backend instead of Claude. No API key required. Example: --ollama-analysis http://<ollama-host>:11434. Enables the same 3-phase analysis (tool schemas, responses, chain reasoning) at zero cloud cost. Compare results with --claude to benchmark local vs cloud quality. |
| `--ollama-ensemble MODELS` | Run AI analysis with multiple Ollama models and surface consensus findings. Comma-separated model list, e.g. --ollama-ensemble qwen2.5:14b,qwen2.5:7b,qwen3:4b. Requires --ollama-analysis. Findings where 2+ models independently flag the same taxonomy ID are tagged [CONSENSUS Nx] (high confidence); single-model findings are tagged [CANDIDATE]. Use this to validate AI findings without relying on one model. |
| `--ollama-model MODEL` | Ollama model to use when --ollama-analysis is set (default: qwen2.5:14b). Larger models produce more thorough analysis; smaller models are faster. |

## Tool Server

| Option | Description |
|---|---|
| `--tool-names-file FILE` | Custom wordlist of tool names for ToolServer enumeration (one per line, # comments). Supplements the built-in list. |

## Output

| Option | Description |
|---|---|
| `--json FILE` | Write JSON report to FILE |
| `--sarif FILE` | Write SARIF 2.1.0 report to FILE (for GitHub Code Scanning, VS Code, and CI integration) |
| `--verbose, -v` | Enable verbose output |
| `--debug` | Enable debug output (very noisy) |
| `--no-color` | Disable colored output. Respects the NO_COLOR env var (https://no-color.org). |
| `--group-findings` | Collapse similar findings by check/severity into compact rows with affected-tool lists and counts. |
| `--fail-on SEVERITY` | Exit 1 when findings at or above this severity are found. Choices: critical, high (default), medium, low, any, none. 'none' always exits 0 (useful in CI for informational scans). |

## Policy Generation

| Option | Description |
|---|---|
| `--generate-policy FILE` | Generate nullfield policy YAML from findings and write to FILE |
| `--policy-name NAME` | metadata.name for the generated NullfieldPolicy |
| `--policy-namespace NAMESPACE` | metadata.namespace for the generated NullfieldPolicy |
| `--policy-labels KEY=VALUE` | metadata.labels entry, repeatable. Example: --policy-labels nullfield.io/lane=machine |
| `--policy-selector KEY=VALUE` | spec.selector.matchLabels entry, repeatable. Without it, the selector matches every pod, which is typically too broad. Example: --policy-selector app=brain-gateway |

## Lane Reporting & Cross-Project Coverage

| Option | Description |
|---|---|
| `--by-lane` | Group scan findings by agentic-identity lane (1..5) and print a per-lane severity tally. Also emitted to --json when both are set. |
| `--coverage-report CAMAZOTZ_URL` | Fetch camazotz /api/lanes (schema v1) from CAMAZOTZ_URL, intersect with this scan's findings, and print a cross-project coverage report. Example: --coverage-report http://localhost:3000 |
| `--taxonomy PATH_OR_URL` | Override the vendored agentic-sec threat taxonomy (mcpnuke/data/taxonomy/lanes.yaml). Accepts a filesystem path or http(s) URL. Used to validate finding threat_ids and to surface lane/transport metadata. The vendored copy is used when not set. |
| `--profile FILE` | Path to a target profile JSON (maps tool names to lane, transport, threat ID, and notes). Enriches AI prompts and finding attribution. Bundled profiles: profiles/camazotz.json, profiles/dvmcp.json. |

## Differential

| Option | Description |
|---|---|
| `--baseline FILE` | Compare against baseline (differential scan) |
| `--diff-baseline FILE` | Path to a previous mcpnuke JSON output to diff against. The scan result will include a 'diff' block showing new, resolved, and severity-changed findings. |
| `--save-baseline FILE` | Save current scan as baseline for future differential scans |

## Inference Backend

| Option | Description |
|---|---|
| `--inference` | Enable inference backend scanning — auto-detect LLM backends (Ollama, vLLM, LocalAI, llama.cpp, TGI) from MCP server context and probe for unauthenticated access. Off by default. |
| `--inference-host URL` | Explicit inference backend URL to probe (e.g. http://gpu-box:11434). Implies --inference. Supports Ollama, vLLM, LocalAI, llama.cpp, and TGI. |
| `--inference-baseline FILE` | Path to a model integrity manifest (JSON). Compares current model digests against this baseline to detect tampering, removal, or injection. Generate with --save-inference-baseline. |
| `--save-inference-baseline FILE` | Snapshot current model state to FILE as a known-good baseline. Use with --inference-host to capture digests for later integrity checks. |

## Kubernetes

| Option | Description |
|---|---|
| `--k8s-api-url URL` | Kubernetes API server URL for external scanning (e.g. http://localhost:8001 for kubectl proxy). Or set MCPNUKE_K8S_API_URL env var. |
| `--k8s-discover` | Auto-discover MCP targets via K8s service discovery (requires running inside a pod with service list permissions) |
| `--k8s-discover-namespaces NS [NS ...]` | Namespaces to scan for MCP services (default: current namespace). Use with --k8s-discover. |
| `--k8s-discover-only` | Run K8s discovery and print endpoint list only; skip MCP scanning. Use with --json to export URLs. |
| `--k8s-discovery-workers N` | Concurrent probes during K8s MCP discovery (default: 10). Use higher for clusters with many services. |
| `--k8s-max-endpoints N` | Cap number of MCP endpoints to scan (default: no limit). Useful for large clusters. |
| `--k8s-namespace NS` | Kubernetes namespace for internal checks (default: default) |
| `--k8s-no-probe` | Skip active probing during K8s discovery (use port matching only) |
| `--k8s-token TOKEN` | K8s bearer token for external API access. Or set MCPNUKE_K8S_TOKEN env var. Prefer --k8s-token-file to avoid ps(1) exposure. |
| `--k8s-token-file FILE` | Read K8s bearer token from FILE (avoids ps aux exposure). |
| `--no-k8s` | Skip Kubernetes internal checks |

## Diagnostics

| Option | Description |
|---|---|
| `--doctor` | Check installation health: core deps, optional extras, env vars, connectivity. |

## Environment Variables

Each variable supplies the default for one flag; passing the flag wins. Only names are listed here — a value is a credential.

| Variable | Flag |
|---|---|
| `MCPNUKE_JWT_MAX_TTL` | `--jwt-max-ttl` |
| `MCPNUKE_K8S_API_URL` | `--k8s-api-url` |
| `MCPNUKE_K8S_TOKEN` | `--k8s-token` |
| `MCP_AUTH_TOKEN` | `--auth-token` |
| `MCP_CLIENT_ID` | `--client-id` |
| `MCP_CLIENT_SECRET` | `--client-secret` |
| `MCP_DPOP_PROOF` | `--dpop-proof` |
| `MCP_INTROSPECT_CLIENT_ID` | `--token-introspect-client-id` |
| `MCP_INTROSPECT_CLIENT_SECRET` | `--token-introspect-client-secret` |
| `MCP_INTROSPECT_URL` | `--token-introspect-url` |
| `MCP_JWKS_URL` | `--jwks-url` |
| `MCP_OIDC_SCOPE` | `--oidc-scope` |
| `MCP_OIDC_URL` | `--oidc-url` |
| `NO_COLOR` | `--no-color` |

## Subcommand: `mcpnuke diff`

Compares two saved scan reports. `diff` is dispatched off `sys.argv` before the main parser runs, so it takes its own arguments and none of the options above.

```bash
mcpnuke diff OLD.json NEW.json
```

| Argument | Description |
|---|---|
| `before` | Path to the baseline (older) scan JSON |
| `after` | Path to the new scan JSON |
| `--json FILE` | Write diff summary as JSON to FILE |

Exits 1 when the newer report contains findings the baseline did not, so it can gate a CI job.
