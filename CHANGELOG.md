# mcprowler Changelog

All notable changes to this submodule are documented here.

## [Unreleased] - 2026-03

### Added

- **Kubernetes deployment and in-cluster scanning** — Run mcprowler as a K8s Job with full cluster posture auditing:
  - `k8s/discovery.py` — Auto-discover MCP endpoints via service annotations (`mcp.io/enabled`, `mcp.io/transport`, `mcp.io/path`), well-known port matching, and active MCP protocol probing
  - `k8s/scanner.py` — Enhanced with pod security checks (privileged containers, hostNetwork/PID, dangerous capabilities, hostPath mounts, missing resource limits), ConfigMap secret scanning, and NetworkPolicy auditing
  - `k8s/fingerprint.py` — Internal service fingerprinting: detects Spring Boot, Flask, Express, FastAPI, Django, Go, Envoy, Nginx, ASP.NET; probes for exposed actuator, debug/pprof, swagger/openapi, graphiql, and admin endpoints
  - SA blast radius mapping — Enumerates effective permissions for each ServiceAccount via SelfSubjectRulesReview impersonation, flags overprivileged accounts (secret access, pod exec, wildcard verbs)
  - Helm release version diffing — Compares decoded values across release versions (v1, v2, ...) to find credentials removed in newer releases that remain recoverable from old release secrets
  - `k8s/Dockerfile` — Multi-stage Python 3.12-slim image, runs as non-root
  - `k8s/manifests/` — Kustomize-ready manifests: Namespace, ServiceAccount, ClusterRole/Binding (read-only), Job, CronJob (6h schedule), all with pod security hardening (non-root, read-only rootfs, drop all caps, seccomp)
  - CLI: `--k8s-discover`, `--k8s-discover-namespaces NS [NS ...]`, `--k8s-no-probe`
  - K8s-only report mode: prints findings and writes JSON even when no MCP targets are discovered
  - **Many-MCP clusters:** Parallel K8s discovery and fingerprinting:
    - `discover_services()` runs MCP probes in parallel (`ThreadPoolExecutor`, default 10 workers); deduplicates by URL; optional `max_endpoints` cap.
    - `fingerprint_services()` runs per-service HTTP probes in parallel (same worker count).
    - CLI: `--k8s-discovery-workers N`, `--k8s-max-endpoints N`, `--k8s-discover-only` (list endpoints only, no MCP scan). See README "Clusters with many MCPs".

- **Custom tool-server detection (`ToolServerSession`)** — Scans non-MCP tool-execute APIs (e.g. `POST /execute` with `{"tool": "...", "query": "..."}`):
  - Auto-detects tool servers by probing `/execute`, `/tools/execute`, `/api/execute`, `/run` with tool-style payloads; recognizes servers from 200+JSON or 400 "unknown tool" responses
  - Enumerates available tools from a built-in wordlist of 84 tool names (`data/tool_names.txt`), supplemented by optional `--tool-names-file`
  - Translates MCP-style `tools/call` into tool-server POST requests so all existing static and behavioral checks run natively
  - Fallback in `detect_transport`: tried after SSE and HTTP JSON-RPC detection fail
  - Tightened JSON-RPC error detection: removed overly broad `"error" in body` match that falsely classified custom APIs as MCP
  - Added `/execute` and `/health` to K8s discovery `PROBE_PATHS`
  - Scanner labels ToolServer transport type distinctly from SSE/HTTP
  - **Tool server fingerprinting** — Detects framework (Flask, FastAPI, Express, Spring Boot, Django, Go, ASP.NET) from response headers (`Server`, `X-Powered-By`, etc.). Displayed in transport label: `ToolServer (framework=Flask, server=Werkzeug/3.0.1)`
  - **Expanded tool name enumeration** — ~90 tool names loaded from `data/tool_names.txt` (cluster ops, diagnostics, CRUD, auth, file, network, AI). Custom wordlists via `--tool-names-file FILE` (supplements built-in list)
  - **Expanded path detection** — 20+ execute/invoke paths probed (`/execute`, `/invoke`, `/api/execute`, `/v1/run`, `/command`, `/action`, etc.). Uses GET 404 pre-check to skip non-existent paths quickly
  - **Parameter inference from errors** — When a tool returns `"X is required"`, the parameter is automatically added to the inferred schema with correct `required` constraint
  - CLI: `--tool-names-file FILE` for custom tool name wordlists

- **Behavioral probe engine** — 9 new checks that actively call tools and analyze responses, moving beyond static metadata analysis:
  - `check_tool_response_injection` — Calls each tool with safe inputs, scans responses for injection payloads, hidden instructions, exfiltration URLs, invisible Unicode, and base64-encoded attacks
  - `check_input_sanitization` — Sends context-aware probes (path traversal, command injection, template injection, SQL injection) and detects unsanitized reflection. Uses a canary string (`MCP_PROBE_8f4c2a`) to confirm reflection.
  - `check_error_leakage` — Sends empty, wrong-type, and prototype-pollution inputs; checks for stack traces, internal paths, connection strings, secrets in error responses
  - `check_temporal_consistency` — Calls the same tool 3x with identical input; detects escalating injection, wildly inconsistent responses, or new threats appearing in later calls
  - `check_resource_poisoning` — Deep resource content analysis: base64-encoded injection payloads, data URIs, steganographic invisible Unicode, CSS-hidden HTML, markdown image exfiltration
  - `check_cross_tool_manipulation` — Detects when a tool's output contains instructions directing the LLM to invoke other tools (cross-tool orchestration attacks)
  - `check_deep_rug_pull` — Snapshots tools → invokes each tool multiple times → re-snapshots. Catches rug pulls that only trigger after N tool invocations (e.g. DVMCP challenge 4), including schema mutations
  - `check_state_mutation` — Snapshots resource contents before and after tool invocations; detects silent server state changes, new/disappeared resources
  - `check_notification_abuse` — Monitors SSE message queue for unsolicited `sampling/createMessage`, `roots/list`, or other server-initiated requests that abuse MCP's bidirectional protocol

- **Probe payload library** (`patterns/probes.py`)
  - Canary string system for detecting unsanitized reflection
  - Context-aware safe argument generation from tool schemas
  - Injection probe sets: path traversal (4), command injection (5), template injection (5), SQL injection (3)
  - Response analysis patterns: injection (12), exfiltration (3), cross-tool (3), hidden content (5), error leakage (9)
  - Steganographic Unicode detection (zero-width, bidi, invisible formatters)
  - CSS-hidden HTML and markdown image exfiltration detection

- **Attack chain patterns** — 10 new behavioral chain combinations:
  - `tool_response_injection → cross_tool_manipulation`
  - `tool_response_injection → token_theft`
  - `deep_rug_pull → tool_poisoning`
  - `deep_rug_pull → tool_response_injection`
  - `input_sanitization → code_execution`
  - `resource_poisoning → tool_response_injection`
  - `state_mutation → deep_rug_pull`
  - `notification_abuse → token_theft`
  - `cross_tool_manipulation → code_execution`
  - `cross_tool_manipulation → token_theft`

- **Check execution ordering** — `run_all_checks()` now runs in deliberate phases: static → behavioral → deep probes → transport → aggregate. Aggregate checks (multi_vector, attack_chains) run last so they see all prior findings.

- **Production safety controls**
  - `--no-invoke` — Static-only mode: skips all behavioral probes that call tools. Safe for production servers where tool invocation could have side effects.
  - `--safe-mode` — Skips invoking tools classified as dangerous (delete, send, exec, write, deploy, etc.) while still probing read-only tools.
  - `--probe-calls N` — Configurable invocations per tool for deep rug pull detection (default: 6). Increase for stubborn thresholds.

- **Tool danger classification** — Tools are classified as dangerous based on name keywords (delete, execute, send, write, deploy, kill, etc.) and description signals. `--safe-mode` uses this to skip dangerous invocations while still probing read-only tools.

- **Credential content detection** — `check_resource_poisoning` now scans resource text for 11 patterns of actual secrets: passwords, API keys (OpenAI `sk-`, GitHub `ghp_`, AWS `AKIA`), bearer tokens, connection strings, private keys.

- **Input reflection detection** — `check_tool_response_injection` sends a distinctive probe through each string parameter and flags tools that echo user input verbatim in responses — identifying indirect injection conduits.

- **Response-content rug pull** — `check_deep_rug_pull` now compares first vs last tool responses (not just metadata). Detects paywall/degradation rug pulls where tool output shifts but descriptions stay identical. 22 shift keywords including injection indicators.

- **DVMCP reset script** (`tests/dvmcp_reset.sh`) — Kill servers, wipe `/tmp` state, recreate test data, restart all 10 with readiness polling. `--scan` flag runs sweep immediately. `--kill-only` for cleanup.

### Changed

- `checks/__init__.py` — Reorganized check execution into clear phases with comments; all behavioral checks gated on `probe_opts`
- `checks/behavioral.py` — Refactored tool-list diffing into shared `_diff_tool_lists()` helper; deep rug pull uses configurable `probe_calls`
- `checks/tool_probes.py` — All probe checks accept `probe_opts` and respect `--no-invoke` / `--safe-mode`; `_build_safe_args()` now respects `minimum`/`maximum` constraints, schema defaults, pattern fields, and all JSON schema types
- `patterns/probes.py` — Template injection probes use `1333*7=9331` instead of `7*7=49` to avoid false positives
- `scanner.py` — `probe_opts` flows from CLI through `scan_target` and `run_parallel` into `run_all_checks`

---

## [4.1] - 2026-02

### Added

- **Bearer token auth** — `--auth-token TOKEN` for authenticated MCP endpoints (JWT, PAT, etc.). Env var `MCP_AUTH_TOKEN` supported. Enables scanning GitHub MCP (`https://api.githubcopilot.com/mcp/`), internal services, etc.

- **Differential scanning**
  - `--baseline FILE` — Compare current scan to saved baseline
  - `--save-baseline FILE` — Save current scan as baseline for future comparison
  - Reports added/removed/modified tools, resources, prompts
  - New tools flagged as MEDIUM findings for security review
  - `mcprowler/diff.py` — `load_baseline`, `save_baseline`, `diff_against_baseline`, `print_diff_report`

- **New security checks**
  - `check_rate_limit` — Flags tools that suggest unbounded or unthrottled usage (e.g. "unlimited requests", "no rate limit")
  - `check_prompt_leakage` — Flags tools that may echo, log, or expose user prompts or internal instructions
  - `check_supply_chain` — Flags tools that install packages from user-controlled or dynamic URLs (e.g. `curl | bash`, "user-provided URL")

- **New pattern sets**
  - `RATE_LIMIT_PATTERNS` — 5 patterns for rate-limit abuse
  - `PROMPT_LEAKAGE_PATTERNS` — 8 patterns for prompt exposure
  - `SUPPLY_CHAIN_PATTERNS` — 9 patterns for supply-chain risks

- **CLI options**
  - `--targets-file FILE` — Read target URLs from file (one per line, `#` comments ignored)
  - `--public-targets` — Use built-in list in `data/public_targets.txt` (DVMCP localhost URLs)

- **Data**
  - `data/public_targets.txt` — Built-in targets for DVMCP (localhost:9001–9010) and public MCP servers

- **Test suite**
  - `tests/` — Pytest suite (38 tests) for checks, CLI, patterns, diff, and integration

### Changed

- `parse_args()` now accepts optional `args` for testability
- **Streamable HTTP support** — Scanner now handles MCP servers using Streamable HTTP (e.g. DeepWiki at `https://mcp.deepwiki.com/mcp`). Accepts `application/json` and `text/event-stream` responses; parses SSE-formatted POST responses.

---

## Planned

### Quick wins

- **DVMCP scoreboard** — Auto-run all 10 DVMCP challenges, report pass/fail per challenge, optional JSON output
- **Batch scan** — `scan_mcp url1 url2` or `scan_mcp_batch urls.txt` from main Agent Smith

### Medium effort

- ~~**Differential MCP scanning**~~ — ✓ Done. `--baseline` and `--save-baseline`
- ~~**Fuzzing / live probing**~~ — ✓ Done. Behavioral probe engine with safe tool invocation
- **AI-powered MCP description analysis** — Use Claude to detect subtle tool poisoning, hidden instructions, misleading descriptions
- **SARIF export** — Export findings as SARIF for IDE/CI (VS Code, GitHub Code Scanning)

### Larger investments

- ~~**Docker image**~~ — ✓ Done. `k8s/Dockerfile` with multi-stage Python 3.12-slim build
- ~~**Kubernetes deployment**~~ — ✓ Done. Job, CronJob, RBAC, Kustomize manifests with full pod security hardening
- **Metrics endpoint** — Prometheus `/metrics` for request counts, scan latency, tool usage
- ~~**Attack chain profiling**~~ — ✓ Done. 17 attack chain patterns with aggregate detection
- **MCP registry** — Curated list of public MCP servers for periodic scanning
- **Active exploitation mode** — Controlled, opt-in exploit verification (beyond safe probing)
