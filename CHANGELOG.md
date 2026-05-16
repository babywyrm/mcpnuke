# mcpnuke Changelog

All notable changes to this submodule are documented here.

## [6.11.0] - 2026-05-16

### Added

- **Model Integrity Verification** (`mcpnuke/checks/inference_backend.py`, MCP-T55): Baseline-driven integrity checking for Ollama model digests. Snapshots the known-good state of model digests, sizes, and metadata on first scan, then detects drift on subsequent scans. Four finding types:
  - **Model tampered** (`model_tampered`, CRITICAL) — digest changed for an existing model, indicating replacement with a backdoored version
  - **Model removed** (`model_removed`, HIGH) — model present in baseline is missing, indicating unauthorized deletion
  - **Model injected** (`model_injected`, MEDIUM) — new model appeared that wasn't in the baseline
  - **Model size drift** (`model_size_drift`, HIGH) — digest matches but file size changed, indicating partial corruption

- **CLI flags**: `--inference-baseline FILE` (compare against a known-good manifest) and `--save-inference-baseline FILE` (snapshot current model state). Both work with `--inference-host` for standalone scans and with `--targets` for full MCP+inference scans.

- **Baseline manifest format** (`model-manifest.json`): Versioned JSON manifest storing per-host model digests, sizes, families, parameter sizes, quantization levels, and timestamps. Generated via `--save-inference-baseline`.

- **Extended fingerprint metadata**: `fingerprint_backend()` now captures full model records from Ollama's `/api/tags` (digest, size, modified_at, family, parameter_size, quantization_level) in a `model_details` key. Non-breaking for existing callers.

- **MCP-T55**: New taxonomy entry "Inference Model Integrity Drift" added to both `mcpnuke/data/taxonomy/lanes.yaml` and `agentic-sec/docs/taxonomy/lanes.yaml`.

- **20 new tests** (`tests/test_model_integrity.py`): Digest mismatch detection, model removal, injection, size drift, baseline save/load round-trip, no findings when matching, graceful handling of missing/invalid baselines, timing recording, combined findings, and CLI flag parsing.

## [6.10.0] - 2026-05-16

### Added

- **Inference Backend Probe** (`mcpnuke/checks/inference_backend.py`, MCP-T54): Opt-in infrastructure check that discovers and audits unauthenticated LLM inference backends behind or alongside MCP servers. Fingerprints Ollama, vLLM/LocalAI (OpenAI-compatible), HuggingFace TGI, and llama.cpp via characteristic API endpoints. Runs four checks:
  - **Model enumeration** (`inference_model_enum`) — lists available models without auth
  - **Unauthenticated generation** (`inference_no_auth`) — confirms open compute access
  - **Management endpoint exposure** (`inference_mgmt_exposed`) — probes for destructive APIs (pull/delete/create/push)
  - **Network bind scope** (`inference_network_exposed`) — flags backends reachable over the network

- **CLI flags**: `--inference` (auto-detect backends from MCP server tool descriptions and metadata) and `--inference-host URL` (explicit target, e.g. `--inference-host http://gpu-box:11434`). Both feed into `probe_opts` and gate the inference check in `run_all_checks`.

- **MCP-T54**: New taxonomy entry "Unauthenticated Inference Backend Exposure" added to both `mcpnuke/data/taxonomy/lanes.yaml` and `agentic-sec/docs/taxonomy/lanes.yaml`.

- **20 new tests** (`tests/test_inference_backend.py`): Fingerprint detection for all four backend types, auto-inference from MCP tool descriptions, finding generation, management endpoint probing, CLI flag parsing, timing recording, and negative cases.

## [6.9.0] - 2026-05-15

### Added

- **`shell_injection` check** (`mcpnuke/checks/shell_injection.py`): Transport D behavioral probe that detects subprocess-wrapping MCP tools by schema signals (`shell`, `exec`, `subprocess`, `command`, `cmd`, `invoke`, `spawn`, `run`, `bash`, `sh`, `wrap` in tool name/description; `command`, `cmd`, `args`, `extra_args`, `base_cmd`, `shell`, `exec`, `script`, `operation` as parameter names) and sends targeted shell injection payloads:
  - Semicolon chain: `; echo MCPNUKE_SHELL_INJECTED`
  - Subshell expansion: `$(echo MCPNUKE_SUBSHELL_INJECTED)`
  - Backtick expansion: `` `echo MCPNUKE_BACKTICK_INJECTED` ``
  - Pipe chain: `| echo MCPNUKE_PIPE_INJECTED`
  - And-chain: `&& echo MCPNUKE_AND_INJECTED`
  - Dangerous base command probes: `bash -c id`, `sh -c 'echo ...'`

  Findings tagged `lane: 3, transport: D`. CRITICAL when injected command output is echoed back in the response. HIGH when a dangerous base command (`bash`, `sh`) executes successfully without an allowlist block. Pairs with camazotz `shell_exec_wrap_lab` (MCP-T53, Lane 3 / Transport D).

- **18 new tests** (`tests/test_shell_exec_wrap_lab.py`): coverage for injection payload detection across all five metacharacter categories, dangerous base command acceptance, clean tool negative cases, and timing recording.

## [6.8.0] - 2026-05-02

### Added

- **`--policy-name` / `--policy-namespace` / `--policy-selector` /
  `--policy-labels`** — Targeting controls for `--generate-policy`. The
  default selector (`matchLabels: {}`) matches every pod in every namespace
  in a real cluster, which is almost never what an operator wants. The new
  flags let scans emit policies that target a specific deployment
  (`--policy-selector app=brain-gateway`) and carry lane/transport labels
  for dashboards (`--policy-labels nullfield.io/lane=machine`). Required
  for the cross-repo feedback loop: scan → generate → kubectl apply →
  CRD-bridge → re-scan.

  The serializer now also renders `metadata.labels` and a populated
  `spec.selector.matchLabels` block. A new round-trip test confirms PyYAML
  loads the emitted YAML into the exact shape nullfield's controller
  expects (`apiVersion: nullfield.io/v1alpha1`, `kind: NullfieldPolicy`,
  identity/scope/budget rules preserved).

## [6.7.0] - 2026-05-01

### Added

- **MCP-T04 JWT boundary checks** — Two new HIGH-severity, Lane 1 / Transport A
  checks in `mcpnuke/checks/jwt_boundary.py`:
  - `jwt_audience_target_match` — decodes the bearer token, derives expected
    audiences from the target URL (full URL, scheme://netloc, host,
    host:port), and flags when the `aud` claim does not intersect any
    expected form. Catches cross-tool token replay where a token issued for
    service A is silently accepted by service B (audience validation
    disabled or trusted-aud overlap).
  - `jwt_cross_role_replay` — reads `scope` / `role` / `roles` claims;
    when all values are read-class but the server still exposes
    write/admin/delete tools to the token via `tools/list`, flags broken
    role isolation in the same OIDC realm. Static check; does not invoke
    the write tools.

  Live verification on the NUC reference deployment with a forged read-only
  token: Lane 1 went from 0 findings to 2 HIGH findings; total scan
  produced 168 findings, score 1380, 5/5 lanes covered.

- **`--by-lane`** — Group findings by agentic-identity lane (1..5), print a
  per-lane severity tally, and emit the same structure into the JSON
  report when `--json` is also set. Findings without a lane scope land in
  an "Uncategorized" bucket. Implemented per
  `docs/specs/2026-04-26-by-lane-reporting.md`.

- **`--coverage-report URL`** — Fetch `GET <URL>/api/lanes` (schema v1)
  from a running camazotz instance, intersect with the current scan's
  findings, and print a cross-project coverage report naming every lane
  camazotz declares. Schema mismatch (`SchemaMismatchError`) and HTTP
  failures are printed in red without aborting the scan; exit code stays
  driven by finding severity.

- **`--generate-policy FILE`** — Generate a nullfield NullfieldPolicy YAML
  from this scan's findings. Maps `code_execution` / `remote_access` →
  `DENY`, `webhook_persistence` → `DENY`, `response_credentials` →
  `SCOPE` redact, and so on. Pairs naturally with `--no-invoke` for safe
  production audits.

- **Lane / transport vocabulary on every Finding** — `Finding.lane:
  int | None` and `Finding.transport: str | None` are populated by
  lane-tagged checks per ADR 0001 (transports A–E). Unlabelled findings
  remain `None` and surface under "Uncategorized" in `--by-lane`.

### Notes

- Aligns the transport axis with
  [camazotz ADR 0001 — Five-Transport Taxonomy](https://github.com/babywyrm/camazotz/blob/main/docs/adr/0001-five-transport-taxonomy.md)
  (A = MCP JSON-RPC, B = Direct wire API, C = SDK / library,
  D = subprocess, E = native LLM function-calling). mcpnuke's own check
  emissions today are predominantly Transport A; D / E coverage shows up
  via `--coverage-report` against camazotz targets that exercise those
  surfaces.

---

## 6.6.0 (2026-04)

### Added

- **Mcp-Session-Id support** — Both `HTTPSession` (Streamable HTTP) and
  `MCPSession` (SSE) now capture `Mcp-Session-Id` response headers and forward
  them on all subsequent requests. Required by the MCP spec for session-aware
  servers; fixes silent 0-tool enumeration on platforms like Kosmos.

- **Paginated enumeration** — New `_paginated_list()` helper follows
  `nextCursor` across pages (capped at `--max-pages`, default 20) for
  `tools/list`, `resources/list`, and `prompts/list`. Servers with large tool
  sets (e.g. 73-tool Atlassian MCP) now enumerate completely. Emits a LOW
  finding when the page cap is reached.

- **Transport-aware finding filter** — `TargetResult.add()` now accepts
  `skip_transports` to declaratively suppress findings irrelevant to certain
  transports. The "Unauthenticated MCP initialize accepted" finding is now
  skipped for stdio transport, eliminating a common false positive.

- **JWT hardening checks** — Six new security checks in
  `mcpnuke/checks/jwt_validation.py`:
  - `jwt_algorithm` — flags `alg:none` (CRITICAL) and symmetric HS256/384/512 (HIGH)
  - `jwt_issuer` — flags missing `iss` claim (MEDIUM)
  - `jwt_audience` — flags missing `aud` claim (MEDIUM)
  - `jwt_token_id` — flags missing `jti` claim (LOW)
  - `jwt_ttl` — flags tokens with TTL > threshold (MEDIUM); configurable via
    `--jwt-max-ttl` or `MCPNUKE_JWT_MAX_TTL` env var (default: 4h)
  - `jwt_weak_key` — attempts verification with known weak keys (CRITICAL)

- **External K8s API access** — New `--k8s-api-url`, `--k8s-token`, and
  `--k8s-token-file` flags allow scanning K8s clusters from a laptop via
  `kubectl proxy` or direct API URL. Token precedence: `--k8s-token` >
  `--k8s-token-file` > `MCPNUKE_K8S_TOKEN` env > SA file auto-detection.
  Auto-detects in-cluster vs external mode.

### Changed

- **Scanner auth context** — Non-stdio targets now receive the full
  `auth_context_summary` (including `_raw_token` for JWT header decoding),
  not just `jwt_claims_summary`.

---

## 6.5.0 (2026-03)

### Added

- **Deterministic scan mode** — New `--deterministic` flag enforces stable tool
  ordering and single-threaded deep probes / AI Phase 2 to improve run-to-run
  repeatability for benchmarking and CI drift checks.

- **Parallel AI Phase 2 workers** — New `--claude-phase2-workers N` flag to run
  `llm_response_analysis` response reviews concurrently. Default remains `1`
  (serial) for safe, backward-compatible behavior.

- **Optional Bedrock Claude backend** — New `--bedrock` runtime path for
  `--claude` scans with `--bedrock-region`, `--bedrock-profile`, and
  `--bedrock-model`. Default remains direct Anthropic API unless `--bedrock`
  is explicitly set.

- **Typed LLM backend interface for analysis pipeline** — `run_llm_analysis()`
  now supports typed backend injection via `LLMBackend`, enabling cleaner
  integration tests with explicit fake backends.

- **Agentic auth flow controls** — Added repeatable `--header KEY:VALUE`,
  `--tls-verify`, and `--oidc-scope` flags, plus JWT claim-summary reporting
  in JSON output (`auth_context.jwt_claims_summary`) for bearer-token flows.

- **Independent advanced auth helpers** — Added optional `--dpop-proof`,
  `--token-introspect-url` (+ optional introspection client creds), and
  `--jwks-url` support. Results are reported under `auth_context` and are
  fully default-off to avoid behavior changes when not enabled.

### Changed

- **AI Phase 2 payload handling** — `llm_response_analysis` no longer skips
  short-but-meaningful tool responses. It now falls back to a structured raw
  response envelope when extracted text is empty or low-signal, improving
  Claude coverage on compact/structured tool outputs.

- **Doctor Bedrock visibility** — `--doctor` now reports boto3 presence and
  whether AWS credentials appear available for Bedrock scans.

- **Quickstart documentation expanded** — Added `QUICKSTART.md` scenario
  recipes for camazotz regular scans, deterministic benchmarking, Bedrock
  variation, and DVMCP bring-up + scan workflows.

---

## 6.4.0 (2026-03)

### Added

- **Active prompt injection check** — New `active_prompt_injection` behavioral check
  sends injection payloads as tool inputs and confirms whether the server follows
  injected instructions, leaks system prompts, or accepts role overrides. Catches
  vulnerabilities that static-only `prompt_injection` misses.

- **Enhanced indirect injection** — `check_indirect_injection` now probes
  content-processing tools (process, analyze, summarize, etc.) with embedded
  injection payloads, not just resources. Detects injection via document/message
  processing pipelines.

- **Semantic injection detection** — `_scan_response_threats` now detects
  instruction-like patterns in tool responses: mode switches, secrecy directives,
  credential requests, and XML/delimiter tool-call injection tags.

- **LLM-augmented probe classification** — New `classify_probe_response` function
  (300-token budget) classifies ambiguous probe responses via Claude when regex is
  inconclusive. Gated behind `--claude`, wired into `tool_response_injection`.

- **Evidence-based attack chains** — `AttackChain` now carries `evidence_tools`
  listing specific tool names extracted from findings. Chain messages show e.g.
  `input_sanitization → code_execution (execute_command)` instead of generic text.

### Changed

- **Risk-aware `--fast` mode** — `--fast` no longer blindly skips
  `input_sanitization`. If any tool has dangerous params (command, exec, code,
  sql, url, etc.), the check is retained.

- **Deep rug pull defaults** — `--probe-calls` default increased from 6 to 10.
  Added injection pattern drift detection: flags tools whose output is clean on
  call 1 but contains injection patterns by call N.

- **Permissions debouncing** — Description-only matches in `excessive_permissions`
  now require 2+ matching categories before reporting. Reduces noise from tools
  that incidentally mention keywords like "file" or "query" in descriptions.

---

## 6.3.0 (2026-03)

### Added

- **LLM-aware SSTI classification** — Template injection findings now distinguish
  between confirmed code-level SSTI (Jinja2/Mako/ERB/EL fingerprinting, CRITICAL)
  and LLM-evaluated math expressions (MEDIUM). Eliminates false CRITICALs on
  LLM-backed MCP servers.

- **Structured attack chains in JSON output** — `attack_chains` array populated
  with `{source, target}` objects alongside finding-level chain data.
  Machine-parseable for consumers.

### Changed

- **Exit code semantics** — `0` = clean, `1` = findings found, `2` = scan error.
  Previously both findings and errors returned `1`.

- **Parallel `input_sanitization`** — `check_input_sanitization` now uses
  `probe_workers` threads for per-tool fuzzing. Typical speedup 3–5× on 25+
  tool targets.

### Fixed

- **Test suite optimization** — Fixed 85s network timeout in actuator probe
  test (now under 0.2s total suite runtime).

### Notes

- Check count: **33** (unchanged).

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

_Roadmap aligned with the [agentic-sec threat taxonomy](https://github.com/babywyrm/agentic-sec/blob/main/docs/taxonomy/lanes.yaml) (MCP-T01–T53, schema v1.0.0). The taxonomy is the cross-repo vocabulary contract between camazotz, nullfield, mcpnuke, and the agentic-sec docs hub._

### Near-term — ecosystem alignment

_The current focus: make mcpnuke a first-class consumer of the shared taxonomy so the three-tool loop (camazotz → mcpnuke → nullfield) stays in lockstep as labs and threats grow._

- **Taxonomy consumption** — `--taxonomy PATH_OR_URL` flag to load `agentic-sec/docs/taxonomy/lanes.yaml`. Validate that every finding's `taxonomy_id` is a known threat in the taxonomy. Surface lane/transport metadata from the taxonomy instead of hard-coding it per check. Default falls back to a vendored copy bundled with mcpnuke.
- **Profile drift guard** — New test `test_camazotz_profile_in_sync` that loads `profiles/camazotz.json` and asserts every entry has a matching `camazotz_modules/*/scenario.yaml`. Fails loudly when a lab is added to camazotz without a corresponding profile entry (or vice versa). Mirrors the `test_agentic_sec_taxonomy_in_sync` guard that camazotz already has against the taxonomy.
- **Threat ID validation test** — Ensure every `taxonomy_id` emitted by any check exists in the loaded taxonomy. Prevents silent vocabulary drift between mcpnuke checks and the shared canonical list.

### Near-term — dedicated checks for ecosystem patterns

_camazotz now ships labs for MCP-T41–T52. mcpnuke catches some of these via static patterns today, but lacks dedicated checks. Prioritized by ROI:_

- **`schema_overdisclosure`** (MCP-T50, Lane 5 / Transport A) — Static scan of `tools/list` for credential patterns, internal hostnames, and `CZTZ_`-style env var references in tool descriptions. Pre-auth visible surface — runs without any token. Pairs with `anon_schema_harvest_lab`.
- **`anon_budget_exhaust`** (MCP-T51, Lane 5 / Transport A) — Behavioral probe that fires N anonymous calls and measures whether per-caller accounting exists. Detects when global rate limits can be exhausted by an unauthenticated caller, starving authenticated traffic.
- **`scope_pollution`** (MCP-T42, Lane 2 / Transport A) — JWT scope-narrowing check. Sibling to `jwt_audience_target_match` and `jwt_cross_role_replay`. Verifies that downstream-issued tokens have *narrower* scope than the calling token; flags when a low-privilege caller can mint a token containing higher-privilege scopes (shared-IdP cross-pollution).

### Medium effort — newer ecosystem checks

- **Audit log evasion** (MCP-T13, MCP-T47) — Verify that downstream audit logs attribute actions to the originating user, not just the agent service account. Combined with `agent_sdk_chain_lab` (MCP-T47) which proves sub-agent identities are routinely lost in audit trails.
- **Hallucination-driven destruction** (MCP-T10) — Send ambiguous instructions to tool-calling endpoints, verify confirmation gates and dry-run behavior before destructive ops.
- **Cross-tenant memory leak** (MCP-T11) — Plant canary strings via one session, probe retrieval from another; test vector DB tenant isolation.
- **LLM-mediated response detection** — Detect when tool responses are LLM-generated (hallucination risk, context bleed). Flag tools whose output shows LLM patterns (Ollama/OpenAI formatting, system prompt leakage through tool output).
- **AI prompt injection via tool parameters** — Detect when user-controlled tool parameters are passed into LLM prompts, creating an injection surface through tool args rather than tool descriptions. Pairs with `ai_governance_bypass_lab` (MCP-T41).
- **Active SSRF probing** (MCP-T06) — Beyond pattern matching: probe tools with IMDS URLs (169.254.169.254), internal K8s API, RFC1918 ranges, DNS rebinding detection, IP encoding bypasses (decimal, hex, octal, IPv6-mapped).
- **Interpreter blocklist bypass** (MCP-T44) — Input sanitization probes should try multiple interpreters beyond bash/python: `perl`, `lua`, `awk`, `ruby`, `php`, `node`. Pairs with `blocklist_bypass_lab`.

### Quick wins — practitioner-facing surfaces

- **SARIF export** — Export findings as SARIF for IDE/CI (VS Code, GitHub Code Scanning).
- **DVMCP scoreboard CLI** — `./scan --dvmcp-scoreboard` to auto-run all 10 challenges, report pass/fail per challenge, optional JSON.
- **Prometheus metrics endpoint** — `/metrics` for scan counts, finding rates, tool coverage.
- **`--watch` mode** — Continuous lane-coverage deltas against a long-running target. Listed in the agentic-sec ecosystem roadmap; lives here in mcpnuke.

### Horizon — CLI-agent / Transport D pattern

_The next wave: agents that call CLI tools directly via subprocess, with no MCP layer in the path (gh, kubectl, helm, jira, terraform). See `agentic-sec/docs/walkthroughs/beyond-mcp.md` § "The Emerging Pattern: Direct CLI Agents" for the threat model._

- ~~**Transport D behavioral probe**~~ — ✓ 2026-05-15. `shell_injection` check detects subprocess-wrapping tools by schema signals and sends targeted shell injection probes. Findings tagged `transport: D` with elevated severity when timing or output confirms real execution.
- **`--probe-transport D`** — Scope a scan to subprocess-wrapping tools only. Useful when reviewing platform-engineering agents that call CLI tools.
- ~~**Real subprocess lab pairing**~~ — ✓ 2026-05-15. camazotz `shell_exec_wrap_lab` (MCP-T53, Transport D) actually calls `subprocess.run`, not simulated. The behavioral probe has a real target to validate against.

### Larger investments — campaign framework

- **Multi-stage campaign runner** — Chain individual checks into named attack scenarios (CONTENT-TO-INFRA, COMMS-TO-CLUSTER, CODE-TO-PROD, the agentic-sec campaign personas) with stage-gating and blast radius tracking. The shape that complements `make campaign SCENARIO=...` in camazotz.
- **Purple team mode** — `--purple-team`: timestamp every attack, measure MTTD/MTTR, generate detection scorecard, SIEM alert correlation.
- **LLM-as-proxy detection** — Detect when an LLM sits between the user and dangerous tools (e.g. chat endpoint → LLM → shell exec tool). Map the indirect execution path and flag the amplified blast radius.
- **Active exploitation mode** — Controlled, opt-in exploit verification (beyond safe probing).
- **MCP registry** — Curated list of public MCP servers for periodic scanning.

### Done (recent — last shipped in this train)

- ~~**Transport D `shell_injection` behavioral probe**~~ — ✓ 2026-05-15. `shell_injection` check with 5 metacharacter injection categories (semicolon, subshell, backtick, pipe, and-chain) and dangerous base command probes (bash, sh). Lane 3 / Transport D. Pairs with `shell_exec_wrap_lab` (MCP-T53). 18 tests.
- ~~**Spring Actuator Phase 2 exploitation probes**~~ — ✓ 2026-05-10. Passive GET discovery gates active POST probes: heapdump download, env write, logger override, refresh, restart, gated shutdown. `actuator_exploitation` finding category.
- ~~**DPoP enforcement check (RFC 9449)**~~ — ✓ 2026-05-10. `dpop_enforcement` check with three RFC 9449 probes (no DPoP header accepted, malformed DPoP accepted, htm/htu binding not verified). Lane 3 / Transport A. Pairs with `dpop_forgery_lab` (MCP-T43).
- ~~**camazotz profile coverage for MCP-T41–T52**~~ — ✓ 2026-05-10/12. `profiles/camazotz.json` expanded 70 → 111 tools to cover AI governance bypass, shared IdP pollution, DPoP forgery, blocklist bypass, SDK exposure, agent chain dilution, and the Lane 5 anonymous patterns.

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
- ~~**JWT audience validation (MCP-T04)**~~ — ✓ 6.7.0. `jwt_audience_target_match`, Lane 1 / Transport A
- ~~**Cross-role token replay (MCP-T04)**~~ — ✓ 6.7.0. `jwt_cross_role_replay`, Lane 1 / Transport A
- ~~**Per-lane reporting**~~ — ✓ 6.7.0. `--by-lane` and `--coverage-report` against camazotz `/api/lanes` schema v1
- ~~**Nullfield policy generation**~~ — ✓ 6.7.0. `--generate-policy FILE` emits NullfieldPolicy YAML from findings
- ~~**Agent config tampering**~~ — ✓ `config_tampering` detects tools that modify agent config, system prompt, or tool registry
- ~~**Webhook/callback persistence (MCP-T14)**~~ — ✓ `webhook_persistence` with name-based + parameter-based detection
