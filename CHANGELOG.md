# mcpnuke Changelog

All notable changes to this submodule are documented here.

## [6.2.0] - 2026-03

### Added

- **`config_dump` check** — New deep probe that identifies tools whose purpose
  is to expose internal config (names matching `config`, `env`, `status`,
  `diagnostics`, etc.), calls them, and scans responses for infrastructure
  leaks: internal IPs, Kubernetes DNS, secret env vars, SA token paths, private
  keys, and AI safety config exposure. 10 leak patterns, severity-escalating.

- **`behavioral_rate_limit` check** — Active probe that fires 10 rapid calls
  to a safe tool and flags when all succeed with no throttling or 429 response.
  Complements the existing static `rate_limit` check.

- **23 credential content patterns** — Expanded `CREDENTIAL_CONTENT_PATTERNS`
  to catch RCON passwords, admin API keys, Anthropic/OpenAI/GitHub/GitLab/Slack
  keys, file path references to secrets (`[file:...]`), Kubernetes SA token
  paths, internal service endpoints, and key-value password formats in JSON/env
  dumps.

### Fixed

- **SSRF probe early exit** — `check_ssrf_probe` no longer returns after the
  first CRITICAL or HIGH finding. All URL-accepting parameters across all tools
  are now fully probed, surfacing the complete SSRF attack surface.

- **Claude AI analysis silent failures** — `run_llm_analysis` now checks for
  `ANTHROPIC_API_KEY` and the `anthropic` package up front, logging clear
  warnings instead of silently skipping. Exception messages include the
  exception type for easier diagnosis.

- **`--doctor` flag** — Verifies installation health: core deps, optional
  extras (`ai`, `k8s`), env vars (`ANTHROPIC_API_KEY`, `MCP_AUTH_TOKEN`),
  Python version, and platform tools (`curl`, `ssh`, `tmux`). Run
  `mcpnuke --doctor` to diagnose setup issues before scanning.

- **`all` optional extra** — `uv pip install 'mcpnuke[all]'` installs both
  `ai` and `k8s` extras in one shot.

### Changed

- Check count increased from 30 to 33 (`config_dump`, `behavioral_rate_limit`,
  plus existing Claude AI phases now properly counted).
- Install hints across CLI and checks now consistently reference
  `mcpnuke[ai]` / `mcpnuke[k8s]` extras.

## [6.1.0] - 2026-03

### Fixed

- **Client version drift** — `MCP_INIT_PARAMS.clientInfo.version` now reads
  `__version__` from `mcpnuke/__init__.py` (was hardcoded as `"4.1"`).
  Single source of truth for version strings.

- **Swallowed exceptions in parallel probes** — `ThreadPoolExecutor` deep
  checks now log failures via `logging.debug` instead of bare `except: pass`.
  Enables post-hoc diagnosis of intermittent probe failures.

- **Incorrect `callable` type annotation** — `deep_checks` list in
  `checks/__init__.py` now uses `Callable[..., Any]` from `collections.abc`
  instead of the non-generic builtin `callable`.

- **Unused imports across 7 source modules** — Removed dead imports:
  `SEV_COLOR` in `models.py`, `MCP_INIT_PARAMS` in `behavioral.py`,
  `defaultdict` in `chaining.py`, `json` in `exfil_flow.py`, `field` in
  `auth.py`, `TargetResult` in `k8s/scanner.py`, `Panel` in `scanner.py`,
  `__version__` in `cli.py`.

- **Duplicate `_jrpc` helper** — Extracted `build_jsonrpc_request()` into
  `core/constants.py` as the single JSON-RPC envelope builder. `session.py`
  and `transport.py` now import from there instead of each defining their own.

### Added

- **`--no-color` flag** — Disables Rich color/markup output for terminals
  without color support, accessibility needs, or piped output. Also respects
  the `NO_COLOR` environment variable (https://no-color.org). Console instance
  flows through `print_report()` to ensure all output respects the setting.

- **`py.typed` PEP 561 marker** — Downstream consumers and IDEs now
  recognize `mcpnuke` as a typed package for improved type-checking support.

- **`from __future__ import annotations`** — Added to `constants.py`,
  `models.py`, `checks/__init__.py`, `transport.py`, and
  `reporting/console.py` for forward-compatible type annotations.

- **Properly typed `TargetResult` fields** — `tools`, `resources`, `prompts`
  now typed as `list[dict[str, Any]]` and `server_info` as `dict[str, Any]`
  (was bare `list`/`dict`).

---

## [6.0.0] - 2026-03

### Added

- **Stdio transport (`--stdio CMD`)** — Scan local MCP servers via stdin/stdout JSON-RPC.
  Launches the command as a subprocess, communicates over newline-delimited JSON-RPC.
  Eliminates the need for a proxy when scanning npm/npx/python-based MCP servers.
  E.g. `--stdio 'npx -y @modelcontextprotocol/server-everything'`

- **Fast mode (`--fast`)** — Samples top 5 security-relevant tools via a tiered
  weighted scoring algorithm, skips heavy probes (input_sanitization,
  error_leakage, temporal_consistency, ssrf_probe), caps probe workers at 2. Cuts
  LLM-backed scan time from ~30min to ~2min.

- **Grouped findings (`--group-findings`)** — Collapses similar findings by check/severity
  into compact rows with affected-tool lists and counts. Cleaner reports for servers
  with many tools generating similar findings.

- **Parallel probe workers (`--probe-workers N`)** — Deep behavioral probes run
  concurrently via ThreadPoolExecutor with thread-safe finding accumulation.
  Default: 1 (sequential). Set higher for faster scans at the cost of more
  server load.

- **Adaptive backoff in `_call_tool`** — Per-tool latency tracking, exponential retry
  with jitter, progressive timeouts up to 30s. Reduces timeouts on slow servers
  and avoids hammering overloaded endpoints.

- **9 encoding bypass probe types** in `input_sanitization` — base64, hex, double-URL,
  homoglyph, null byte, CRLF, fullwidth, concatenation, variable expansion. Each
  technique commonly defeats blocklists that only filter raw payloads.

- **Live exfil flow verification** — `check_exfil_flow` now performs source→sink tool
  calls with canary data when a session is available, confirming reachability of
  theoretical exfiltration paths (not just static classification).

- **SSE+POST fallback fix** — Added `/message` to `POST_PATHS` and the SSE+POST
  fallback combo loop for supergateway compatibility.

- **Tiered tool security scoring (`_tool_security_score`)** — Replaced the flat
  keyword-count heuristic in `_pick_security_relevant` with a weighted, multi-tier
  scoring algorithm for fast-mode tool sampling:
  - 6 keyword tiers (exec=10, secret/credential=8, webhook/callback=7,
    run/command=6, upload/write/file=4, admin/root=3)
  - Name keywords get 3× the weight of description keywords
  - Dangerous parameter names (`url`, `command`, `code`, `query`, `script`,
    `host`, `endpoint`, `callback`, etc.) add +8 per match
  - Schema complexity capped at +3
  - High-value floor of 15 for tool names containing `secret`, `credential`,
    `password`, `token`, `config`, `leak`, `dump`, `env`, `private`, `key`
  - Ensures zero-parameter tools like `server-config` rank above benign tools

- **Response caching across checks** — `tool_response_injection` now caches tool
  responses in `probe_opts["_response_cache"]`. Downstream checks
  (`response_credentials`) reuse cached responses, eliminating redundant tool
  invocations.

- **Webhook name-based detection** — `webhook_persistence` now checks if
  "webhook", "hook", "callback", "subscribe", "notify", or "listener" appear
  in the tool *name* itself (not just parameter names/descriptions) when a URL
  parameter is present. Catches tools like `admin-webhook` that were previously
  missed when parameter names were generic.

- **Fail-fast for `--claude`** — If `--claude` is specified but `anthropic` is not
  installed or `ANTHROPIC_API_KEY` is not set, mcpnuke exits immediately with a
  clear error message instead of running the full deterministic scan and failing
  at the AI phase.

- **`uv`-first quickstart** — `quickstart.sh` now prioritizes `uv` over `pip`,
  uses `uv sync --all-extras` to install all optional dependencies (dev, ai, k8s),
  and creates the venv via `uv venv` when available.

- **Scan duration estimates** — The scanner now prints an estimated scan time at
  the start (based on tool count, mode, and transport type).

- **Stdio-aware adaptive backoff** — Stdio transport uses shorter initial timeouts
  (1s vs 3s) and smaller retry caps appropriate for local subprocess latency.

- **Truncated target labels** — Long URLs in console output are shortened to
  host:port for readability.

- **Self-referencing exfil exclusion** — `exfil_flow` no longer flags a tool as
  both source and sink of its own data.

- **Single-pass `tool_response_injection`** — Merged the reflection-detection pass
  into the main response scan loop, reducing per-tool overhead.

### Tests

- **17 new tests for fast-mode scoring** (`tests/test_fast_sampling.py`):
  9 `TestToolSecurityScore` tests validating keyword tier weights, name vs
  description multipliers, dangerous parameter bonuses, and high-value floor;
  8 `TestPickSecurityRelevant` tests validating top-5 selection, benign tool
  exclusion, edge cases (empty list, n > count), and Camazotz tool ranking.
- Total test suite: **163 passed, 36 skipped** (199 collected).

## [5.0.0] - 2026-03

### Added

- **Three new static security checks (MCP-T07, MCP-T09, MCP-T14):**
  - `config_tampering` (MCP-T09) — Flags tools that can modify agent config, system prompt, or tool registry
  - `webhook_persistence` (MCP-T14) — Flags callback/webhook params enabling persistent re-injection
  - `credential_in_schema` (MCP-T07) — Detects hardcoded credentials in tool schema definitions

- **Rename: mcprowler → mcpnuke** — Full project rename across all source, tests, docs, K8s manifests, and Dockerfile.

- **Verbose mode (`-v`)** — Now emits real output throughout the scan pipeline:
  - Transport detection: shows each SSE/HTTP path probed, HTTP status codes, content types
  - Server info: prints server name, version, protocol version, capabilities
  - Enumeration: lists every discovered tool, resource, and prompt with descriptions
  - Timing: shows per-phase duration

- **OIDC client_credentials auth** — Automatic token acquisition from Keycloak or any OIDC provider:
  - `--oidc-url URL` — OIDC issuer URL (e.g. `http://keycloak:8080/realms/myapp`)
  - `--client-id ID` / `--client-secret SECRET` — OAuth2 client credentials
  - Env vars: `MCP_OIDC_URL`, `MCP_CLIENT_ID`, `MCP_CLIENT_SECRET`
  - Auto-discovers token endpoint via `.well-known/openid-configuration`
  - Falls back to standard Keycloak path if discovery fails
  - `mcpnuke/core/auth.py` — `AuthInfo`, `detect_auth_requirements`, `fetch_client_credentials_token`, `resolve_auth_token`

- **Auth-aware transport detection** — Distinguishes "server needs auth" from "no transport found":
  - Detects 401/403 during transport probing and surfaces `WWW-Authenticate` header
  - Returns a valid session for auth-required endpoints (so auth can be resolved separately)
  - In verbose mode, auto-probes first target and suggests the right `--oidc-url` to use

- **DVMCP challenge test suite** (`tests/test_dvmcp.py`) — 44 offline tests covering all 10 DVMCP challenges:
  - Ch1: Prompt injection (5 tests), Ch2: Tool poisoning (5), Ch3: Permissions (5), Ch4: Rug pull (2), Ch5: Token theft (5), Ch6: Code execution (4), Ch7: Remote access (4), Ch8: Rate limit + prompt leakage (4), Ch9: Supply chain (4), Ch10: Multi-vector (4), Full pipeline integration (2)
  - 30 optional live tests (`DVMCP_LIVE=1`) for transport, tools, and findings per port 9001-9010

- **Quickstart script** (`quickstart.sh`) — One-command setup: detects uv/pip, creates venv, installs deps, runs tests
  - `--skip-tests` and `--with-dvmcp` flags
  - `./scan` wrapper for zero-config execution without venv activation

- **Kubernetes deployment and in-cluster scanning** — Run mcpnuke as a K8s Job with full cluster posture auditing:
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
  - `mcpnuke/diff.py` — `load_baseline`, `save_baseline`, `diff_against_baseline`, `print_diff_report`

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

_Roadmap aligned with [MCP Red Team Playbook](https://github.com/babywyrm/sysadmin/tree/master/mcp/redteam) threat taxonomy (MCP-T01–T14)._

### Quick wins

- ~~**DVMCP scoreboard**~~ — ✓ Done. `tests/test_dvmcp.py` with offline + live tests
- **DVMCP scoreboard CLI** — `./scan --dvmcp-scoreboard` to auto-run all 10 challenges, report pass/fail per challenge, optional JSON
- **SARIF export** — Export findings as SARIF for IDE/CI (VS Code, GitHub Code Scanning)
- ~~**Encoding bypass probes**~~ — ✓ Done. 9 techniques (base64, hex, double-URL, homoglyph, null byte, CRLF, fullwidth, concatenation, variable expansion)

### Medium effort — new checks from playbook taxonomy + internal testing

_Gaps identified from [MCP Red Team Playbook](https://github.com/babywyrm/sysadmin/tree/master/mcp/redteam) and testing against internal MCP targets with Keycloak, K8s, and LLM integration._

- **JWT audience validation** (MCP-T04) — Decode JWT tokens, verify `aud` claim matches the target MCP endpoint, detect cross-tool token replay. Flag servers with `verify_aud: False`.
- **Cross-role token replay** (MCP-T04) — If a token is provided, attempt `tools/list` and `tools/call` for tools outside the token's role to detect role-only isolation gaps (e.g. same OIDC realm for users and agents).
- ~~**Response credential scanning**~~ (MCP-T07) — ✓ Done. `response_credentials` check with cached response reuse.
- **LLM-mediated response detection** — Detect when tool responses are LLM-generated (hallucination risk, context bleed). Flag tools whose output shows LLM patterns (Ollama/OpenAI formatting, system prompt leakage through tool output).
- **AI prompt injection via tool parameters** — Detect when user-controlled tool parameters are passed into LLM prompts, creating an injection surface through tool args rather than tool descriptions.
- **Active SSRF probing** (MCP-T06) — Beyond pattern matching: probe tools with IMDS URLs (169.254.169.254), internal K8s API, RFC1918 ranges, DNS rebinding detection, IP encoding bypasses (decimal, hex, octal, IPv6-mapped).
- **Interpreter blocklist bypass** — Input sanitization probes should try multiple interpreters beyond bash/python: `perl`, `lua`, `awk`, `ruby`, `php`, `node`. Real-world blocklists often miss less common shells.
- **Actuator/debug endpoint probing** — Probe scan targets for exposed Spring Boot actuator (`/actuator/env`, `/actuator/beans`), Flask debug, pprof, Swagger, and GraphiQL. Actuator endpoints commonly leak signing keys and credentials.
- **DPoP token support** (RFC 9449) — `--dpop-key FILE` flag to sign DPoP proofs with `htm`/`htu` claims for RFC 9449-protected MCP gateways.
- **Confused deputy detection** (MCP-T03) — Check if tool calls propagate user identity vs agent SA; detect privilege gaps between caller and tool permissions.
- ~~**Exfiltration flow analysis**~~ (MCP-T12) — ✓ Done. `exfil_flow` check with live source→sink canary verification.
- **Audit log evasion** (MCP-T13) — Verify that downstream audit logs attribute actions to the originating user, not just the agent service account.
- ~~**AI-powered description analysis**~~ — ✓ Done. `--claude` with three-phase analysis (tool definitions, tool responses, chain reasoning).

### Larger investments — campaign framework

- **Multi-stage campaign runner** (playbook Section 5) — Chain individual checks into named attack scenarios (CONTENT-TO-INFRA, COMMS-TO-CLUSTER, CODE-TO-PROD, etc.) with stage-gating and blast radius tracking
- **Purple team mode** — `--purple-team`: timestamp every attack, measure MTTD/MTTR, generate detection scorecard, SIEM alert correlation
- **LLM-as-proxy detection** — Detect when an LLM sits between the user and dangerous tools (e.g. chat endpoint → LLM → shell exec tool). Map the indirect execution path and flag the amplified blast radius.
- ~~**Agent config tampering**~~ (MCP-T09) — ✓ Done. `config_tampering` check detects tools that modify agent config, system prompt, or tool registry.
- **Hallucination-driven destruction** (MCP-T10) — Send ambiguous instructions to tool-calling endpoints, verify confirmation gates and dry-run behavior before destructive ops
- **Cross-tenant memory leak** (MCP-T11) — Plant canary strings via one session, probe retrieval from another; test vector DB tenant isolation
- ~~**Webhook/callback persistence**~~ (MCP-T14) — ✓ Done. `webhook_persistence` with name-based + parameter-based detection.
- **Metrics endpoint** — Prometheus `/metrics` for scan counts, finding rates, tool coverage
- **Active exploitation mode** — Controlled, opt-in exploit verification (beyond safe probing)
- **MCP registry** — Curated list of public MCP servers for periodic scanning

### Done (previously planned)

- ~~**Stdio transport**~~ — ✓ `--stdio CMD` for local MCP servers via stdin/stdout
- ~~**Fast mode**~~ — ✓ `--fast` samples top 5 tools via tiered scoring, skips heavy probes
- ~~**Grouped findings**~~ — ✓ `--group-findings` collapses similar findings
- ~~**Parallel probes**~~ — ✓ `--probe-workers N` with ThreadPoolExecutor
- ~~**Adaptive backoff**~~ — ✓ Per-tool latency tracking, exponential retry with jitter
- ~~**Encoding bypass probes**~~ — ✓ 9 encoding techniques in input_sanitization
- ~~**Live exfil verification**~~ — ✓ Source→sink canary data confirmation
- ~~**Differential MCP scanning**~~ — ✓ `--baseline` and `--save-baseline`
- ~~**Fuzzing / live probing**~~ — ✓ Behavioral probe engine with safe tool invocation
- ~~**Docker image**~~ — ✓ `k8s/Dockerfile` with multi-stage Python 3.12-slim build
- ~~**Kubernetes deployment**~~ — ✓ Job, CronJob, RBAC, Kustomize manifests
- ~~**Attack chain profiling**~~ — ✓ 25 attack chain patterns with aggregate detection
- ~~**OIDC auth**~~ — ✓ `--oidc-url` / `--client-id` / `--client-secret`
- ~~**Verbose mode**~~ — ✓ Real output in transport detection, enumeration, and checks
- ~~**DVMCP test suite**~~ — ✓ 44 offline + 30 live tests covering all 10 challenges
- ~~**Response credential scanning**~~ — ✓ `response_credentials` with cached response reuse
- ~~**Webhook/callback persistence**~~ — ✓ `webhook_persistence` with name-based detection
- ~~**Exfiltration flow analysis**~~ — ✓ `exfil_flow` with live source→sink canary verification
- ~~**AI-powered description analysis**~~ — ✓ `--claude` three-phase AI analysis (tool defs, responses, chain reasoning)
