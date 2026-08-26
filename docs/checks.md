# Security Checks Reference

Every check mcpnuke runs, with the severity it emits and what it detects.
85 checks in total: 61 in the check inventory in `mcpnuke/checks/__init__.py`,
plus the 24 deep behavioral probes `_build_deep_checks()` assembles.

Three conventions worth knowing before reading the tables:

- **The severity column is the literal string the check passes to
  `result.add(...)`.** A range like `CRITICAL–MEDIUM` means the check emits at
  several severities depending on what it matched, and the row says which is
  which. It is not an impact estimate.
- **A check name and the finding name it emits are not always the same.** The
  progress output shows the check name, a report shows the finding name. Where
  they differ the row gives both, so either one is searchable.
- **Most checks are conditional.** See [When each check runs](#when-each-check-runs).

An `MCP-T##` tag is a threat ID in the agentic-sec taxonomy vendored at
`mcpnuke/data/taxonomy/lanes.yaml`, which maps each ID to a title, category,
identity lane, transport, OWASP MCP entry and Camazotz lab; `--taxonomy` points
at a different copy.

**What is enforced and what is not.**
`tests/test_docs_current.py::TestChecksDocumented` fails when a check that runs
is absent from this file — that is how `inference_guardrail_variance` and the
three DPoP findings stayed invisible after being made functional. It covers
both the registered checks and the deep probe plan, so every check named here
is guarded against disappearing.

Nothing checks the other two columns. Severities and detection prose cannot be
derived from source, so each one was read by hand off the `result.add(...)` call
that emits it. A severity that changes in code will not fail a test — and of the
rows inherited from the README, seven named the wrong severity and three
described more than the code does. Treat a row that contradicts the code as a
bug in this file, and fix it here.

## Contents

- [When each check runs](#when-each-check-runs)
  - [Authentication findings on stdio](#authentication-findings-on-stdio)
- [Static Checks (metadata only)](#static-checks-metadata-only)
  - [Token & Identity Checks (JWT)](#token--identity-checks-jwt)
- [Behavioral Checks (active server interaction)](#behavioral-checks-active-server-interaction)
  - [Error-reflection grading](#error-reflection-grading)
- [Infrastructure Checks (opt-in)](#infrastructure-checks-opt-in)
  - [Target Surface](#target-surface)
  - [Teleport / Machine Identity](#teleport--machine-identity)
- [Transport & Aggregate Checks](#transport--aggregate-checks)
  - [DPoP Enforcement (RFC 9449)](#dpop-enforcement-rfc-9449)

## When each check runs

| Group | Condition |
|-------|-----------|
| Static | Always. |
| JWT / identity | Only when a token is supplied (`--auth-token`, OIDC, or an introspected token). |
| DPoP | Only with a token **and** an HTTP-family transport whose endpoint is resolved. |
| Light behavioral + deep probes | Unless `--no-invoke`. `--fast` drops the heavy and state-mutating ones. |
| Transport | Only when a base URL and an SSE path were both resolved. |
| Target surface, Teleport discovery | Only when a base URL was resolved. |
| Inference backend | Only with `--inference` or `--inference-host`. |
| Aggregate | Always, last, reading the findings everything else produced. |

`tbot_credential_exposure` and `teleport_bot_overprivilege` are the exceptions
to the base-URL rule: they run on every scan but return immediately unless
mcpnuke is running inside a Kubernetes pod with a service-account token.

### Authentication findings on stdio

A stdio server is a subprocess the scanner launched, connected by a pipe. It
has no header layer to carry a credential and exactly one caller, which is the
client that spawned it. A finding phrased as "unauthenticated X" or "no caller
identity" therefore describes stdio itself, and would be true of every stdio
server ever written — these three fired on 5 of 5 pinned open-source servers.

| Check | Behaviour on stdio |
|-------|--------------------|
| `auth` | Not reported |
| `pre_auth_injection` | Not reported |
| `native_function_identity_erasure` | Not reported |
| `anon_budget_exhaust` | Not probed — returns before its 25-call burst |
| `dpop_not_enforced` | Not reported (already required an HTTP endpoint) |

All are unchanged on HTTP and SSE, where the boundary is real. There is no
flag to re-enable them on stdio: the finding is not a matter of severity
taste, it is a statement about the transport rather than the server.

`behavioral_rate_limit` is the deliberate exception — it still fires on stdio,
because an agent stuck in a loop really can hammer a local server.

---

## Static Checks (metadata only)

Pattern-matching over tool names, descriptions and schemas, with no server
interaction beyond enumeration — except `exfil_flow`, which runs in this phase
but also attempts a live canary transfer when invocation is allowed.

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `prompt_injection` | CRITICAL | Injection payloads in tool/resource/prompt descriptions |
| `tool_poisoning` | CRITICAL | Hidden instructions, invisible Unicode in tool descriptions |
| `excessive_permissions` | CRITICAL–LOW | Dangerous capabilities (shell, filesystem, network, DB, cloud). A tool with no input schema at all is MEDIUM, an untyped parameter LOW |
| `code_execution` | CRITICAL–HIGH | Tools with exec/eval/shell parameters or descriptions |
| `remote_access` | CRITICAL–HIGH | Reverse shells, C2 beacons, port forwarding, data exfil |
| `token_theft` | CRITICAL–HIGH | Tools that accept or forward credentials as parameters |
| `supply_chain` | CRITICAL | Dynamic package install from user-controlled URLs |
| `schema_risks` (finding: `schema_risk`) | CRITICAL–MEDIUM | Command params, unbounded strings, freeform objects |
| `tool_shadowing` | HIGH–MEDIUM | Tool names that collide with common tools or other servers |
| `prompt_leakage` | HIGH | Tools that may echo, log, or expose internal prompts |
| `rate_limit` | MEDIUM | Descriptions suggesting unbounded/unthrottled usage |
| `webhook_persistence` | HIGH | Callback/webhook params or tool names enabling persistent re-injection |
| `credential_in_schema` | CRITICAL | Hardcoded credentials (API keys, JWTs, connection strings) in tool schemas |
| `config_tampering` | CRITICAL–HIGH | Tools that can modify agent config, system prompt, or tool registry. A matching tool name or description is CRITICAL; a config/prompt parameter name alone is HIGH |
| `exfil_flow` | CRITICAL–HIGH | Data flow from sensitive source tools to communication/network sinks. A sensitive source paired with a sink is CRITICAL, other sources paired with a sink HIGH. Unlike the rest of this table it also attempts a live canary transfer when a session is available and `--no-invoke` is off. Without `--oast`, acceptance by the sink is the honest ceiling (CRITICAL). With `--oast`, a canary callback — awaited briefly for queued sinks — upgrades the claim to confirmed out-of-band egress |
| `credential_forwarding` | CRITICAL–HIGH | A tool taking both a credential parameter and an endpoint parameter is CRITICAL — credential theft by design. A credential parameter on a tool whose description mentions fetching or sending is HIGH. MCP-T03 |
| `remote_package_execution` | CRITICAL–HIGH | Tools that fetch and then execute remote code (`curl … \| sh`, install-from-URL, remote script eval). Severity comes from the matched probe pattern. MCP-T08 |
| `agentic_loop` | HIGH–LOW | A parameter naming another tool or function to call is HIGH; an unbounded iteration/repeat parameter is MEDIUM; orchestration language in the description alone is LOW. MCP-T10 |
| `insecure_agent_comms` | HIGH–MEDIUM | Agent-to-agent message passing with no signature, HMAC or attestation parameter. HIGH when the tool is explicitly agent messaging, MEDIUM when only inferred from a payload parameter plus unsigned-transport language. MCP-T13 |
| `model_routing` | CRITICAL–MEDIUM | A model-management tool name is CRITICAL; a caller-supplied model/provider parameter is HIGH; routing language in the description alone is MEDIUM. MCP-T15 |
| `notification_sampling_abuse` | MEDIUM | Tools that push notifications to the client or sample the client's model — side-channel and DoS surface. MCP-T17 |
| `role_escalation_tool` | HIGH | Tools that grant, assume, elevate or impersonate a role. MCP-T28 |
| `delegation_depth` | MEDIUM | Delegation and multi-hop agent tools, where identity attribution dilutes at each hop. MCP-T32 |
| `sdk_cache_tamper` | CRITICAL–HIGH | A tool exposing a writable SDK token cache is HIGH; CRITICAL when a tool that consumes cached identity is present too, completing the write-then-use pair. MCP-T33 |
| `list_cache` | HIGH–MEDIUM | SEP-2549 `ttlMs` / `cacheScope` on list results and a sample of `resources/read` (up to five URIs, skipped under `--no-invoke`). Silent when the fields are absent. Invalid TTL or cacheScope is MEDIUM. Pages of the same list that disagree on cacheScope are HIGH. Mixed scope across different resource URIs is not that finding — each read is independently cacheable. MCP-T16 |
| `subprocess_cred_inheritance` | HIGH–MEDIUM | Subprocess-spawning tools whose children may inherit parent credentials. HIGH when an env or credential parameter is exposed, MEDIUM otherwise. MCP-T34 |
| `native_function_identity_erasure` | MEDIUM | No caller-identity parameter on any tool and no auth token — function calls carry no attribution. Not reported on stdio. MCP-T35 |
| `tool_description_injection` | CRITICAL | Instruction-override language in a tool description, which manipulates any agent that loads the manifest. MCP-T36 |
| `scope_pollution` | CRITICAL–MEDIUM | A token-minting tool accepting caller-controlled scope/audience with no narrowing is HIGH, or CRITICAL when the caller's own claims are read-class and the tool advertises privileged scopes. Shared-IdP topology disclosure alone is MEDIUM. MCP-T42 |
| `schema_overdisclosure` | CRITICAL–LOW | Pre-auth recon in `tools/list`: a credential pattern is CRITICAL, an internal hostname HIGH, an infrastructure env-var name MEDIUM, an internal filesystem path LOW. MCP-T50 |
| `pre_auth_injection` | HIGH | Tools enumerated and invocable with no auth token at all — every call is pre-authentication, with no identity binding. Not reported on stdio. MCP-T52 |
| `shell_wrapping_injection` | HIGH | Shell wrapping (`sh -c`, `subprocess(..., shell=True)`, `os.system`) in a description or schema — arguments stay injectable despite apparent validation. MCP-T53 |
| `cached_session_exposure` | MEDIUM | Session or cache identifier parameters — session fixation and token reuse surface. MCP-T57 |
| `host_network_loopback` | HIGH | `127.0.0.1`, `localhost`, `0.0.0.0` or `hostNetwork` references, suggesting a bridge to node-local services. MCP-T58 |

### Token & Identity Checks (JWT)

These run only when a token is present, decoded from the token the scan
authenticates with.

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `jwt_algorithm` | CRITICAL–HIGH | JWT `alg:none` (signature bypass) or symmetric HMAC algorithms |
| `jwt_issuer` | MEDIUM | JWT missing `iss` (issuer) claim |
| `jwt_audience` | MEDIUM | JWT missing `aud` (audience) claim — enables cross-service replay |
| `jwt_audience_target_match` | HIGH | Lane 1 / MCP-T04. Decodes the bearer token, derives expected audiences from the target URL (full URL, scheme://netloc, host, host:port), and flags when `aud` does not intersect any expected form. Catches cross-tool token replay where a token issued for service A is silently accepted by service B (audience validation disabled or trusted-aud overlap). |
| `jwt_cross_role_replay` | HIGH | Lane 1 / MCP-T04. Reads `scope` / `role` / `roles` claims; when all values are read-class (read, viewer, list, get, ...) but the server still exposes write/admin/delete tools to the token via `tools/list`, flags broken role isolation in the same OIDC realm. Static check — does not invoke the write tools. |
| `jwt_token_id` | LOW | JWT missing `jti` — replay detection not possible |
| `jwt_ttl` | HIGH–MEDIUM | JWT with no `exp` or TTL exceeding threshold (default 4h) |
| `jwt_weak_key` | CRITICAL | JWT signed with a known weak/default HMAC key |

---

## Behavioral Checks (active server interaction)

Light behavioral checks re-list tools and send malformed protocol messages.
Deep probes invoke tools with generated safe arguments and analyze what comes
back. All of them are skipped by `--no-invoke`.

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `rug_pull` | CRITICAL–HIGH | Tool list changes between two `tools/list` calls |
| `deep_rug_pull` | CRITICAL | Tool list/schema changes **after invoking tools** — catches state-dependent rug pulls, injection pattern drift (clean → poisoned after N calls) |
| `tool_response_injection` | CRITICAL–LOW | Calls every invocable tool with safe arguments and runs the **broad** response scan over the reply: injection payloads, exfil URLs, hidden content, invisible Unicode, semantic injection and base64-encoded attacks. The widest of the response-scanning checks. A reflection seen only in a **rejected** call reports LOW — see [error-reflection grading](#error-reflection-grading) |
| `cross_tool_manipulation` | HIGH | Tool output that directs the LLM to invoke a different tool. Emitted by `tool_response_injection`, in the same pass |
| `input_sanitization` | CRITICAL–LOW | Path traversal and command injection probes reflected back unsanitized. A canary that survives nowhere outside a verbatim echo of the probe, in a rejected call, reports LOW — see [error-reflection grading](#error-reflection-grading). SQL probes are sent to `query`/`sql` parameters but the reflection finding excludes them, so SQL only ever surfaces through `error_leakage`. **LLM-aware SSTI:** confirmed engine fingerprints (Jinja2/Mako/ERB/EL) stay CRITICAL; math-style template probes evaluated by the LLM (e.g. `{{7*7}}` → `49`) are downgraded to MEDIUM so LLM-backed MCP servers are not false-flagged as code SSTI. |
| `error_leakage` | HIGH–MEDIUM | Stack traces, internal paths, connection strings, or secrets in error responses |
| `temporal_consistency` | CRITICAL–MEDIUM | Escalating injection, wildly inconsistent responses, or new threats across repeated identical calls |
| `resource_poisoning` | CRITICAL–HIGH | Base64-encoded injection, data URIs, steganographic Unicode, CSS-hidden HTML, or markdown image exfiltration in resource content |
| `state_mutation` | HIGH–MEDIUM | Resources that appear, disappear, or change content after tool invocations |
| `notification_abuse` | CRITICAL–MEDIUM | Unsolicited `sampling/createMessage`, `roots/list`, or other server-initiated requests |
| `indirect_injection` | CRITICAL–HIGH | Injection/poison patterns in resource content; probes content-processing tools with embedded injection payloads |
| `active_prompt_injection` | CRITICAL–LOW | Sends injection payloads into the first string parameter of **every** invocable tool and flags only a confirmed effect: the indicator produced by the server, or a system-prompt indicator in the reply. The indicator is a word *inside* the payload, so the response has the payload subtracted before it is searched — a server that merely quoted the input it refused reports LOW. See [error-reflection grading](#error-reflection-grading) |
| `response_credentials` | CRITICAL | Credentials (API keys, passwords, private keys, connection strings) in tool responses |
| `protocol_robustness` | MEDIUM | Server answers an unknown JSON-RPC method with success instead of `-32601`, or returns a result for `tools/call` with no params |
| `routing_header_binding` | MEDIUM | A 2026-07-28 (stateless, `server/discover`) HTTP server returned a JSON-RPC result for `tools/list` tagged `Mcp-Method: tools/call`. SEP-2243 requires that disagreement to be rejected so a gateway routing on the header cannot desync from the body. Silent on legacy, stdio, and the tools/list-only AUTO fallback. |
| `ssrf_probe` | CRITICAL–MEDIUM | Sends IMDS and loopback URLs through URL-shaped parameters. Cloud metadata content in the response is CRITICAL; an internal-service indicator absent from the safe-URL baseline is HIGH; a large response-size differential, or a fetching tool that merely exposes URL parameters, is MEDIUM. MCP-T06 |
| `config_dump` | CRITICAL–MEDIUM | Internal configuration, service topology or secret paths in tool output. Severity is the strongest infrastructure-leak pattern matched, floored at MEDIUM |
| `behavioral_rate_limit` | MEDIUM | Rapid-fire identical calls that all succeed — no throttling in the request path |
| `anon_budget_exhaust` | HIGH–MEDIUM | A burst of unauthenticated calls that all succeed is HIGH; MEDIUM when the catalog advertises per-caller accounting but this surface still appears unmetered. Not probed at all on stdio. MCP-T51 |
| `shell_injection` | CRITICAL–HIGH | Shell metacharacter and base-command probes against subprocess-wrapping tools. MCP-T53 |
| `sdk_cache_poisoning` | CRITICAL–HIGH | Writes a forged JWT to the target's token cache, then invokes a tool that reads it. Sensitive content in the reply is CRITICAL; an accepted call with no denial is HIGH. **Mutates target state** — skipped by `--fast`. MCP-T33 |
| `ai_guardrail_probe` (finding: `ai_guardrail_bypass`) | CRITICAL–HIGH | Social-engineering strategies against AI-gated tools. Leaking under three or more strategies is CRITICAL, one or two is HIGH |
| `prompt_injection_t01` | CRITICAL–HIGH | The same idea as `active_prompt_injection` aimed at a narrower target: only tools whose name, description or parameter names suggest the argument reaches an LLM, and the most prompt-like parameter rather than the first string one. Four canary payloads — direct override, maintenance mode, template evaluation (HIGH), system-role injection — each flagged only when the server produces its marker, rather than merely quoting the payload back. See [error-reflection grading](#error-reflection-grading). MCP-T01 |
| `tool_output_poisoning_t02` (finding: `tool_output_poisoning`) | HIGH | Calls every invocable tool with safe arguments like `tool_response_injection`, but matches only the shared instruction-injection regexes, catching a tool whose *output* carries commands for whichever agent reads it. Narrower surface, one severity, tagged to the taxonomy. MCP-T02 |
| `command_injection_broad_t05` (finding: `command_injection_broad`) | CRITICAL–LOW | Command injection through any string parameter, not just command-named ones. Shell error text keeps its HIGH even in a failed response — a shell errors *because* it parsed the payload — but a canary that only comes back inside a quoted rejection reports LOW. MCP-T05 |
| `agentic_loop_behavioral_t10` (finding: `agentic_loop_behavioral`) | HIGH | Tool-call directives embedded in a tool's response, which drive the agent into a loop. MCP-T10 |

`--fast` skips `input_sanitization`, `error_leakage`, `temporal_consistency`,
`ssrf_probe` and `sdk_cache_poisoning`, and keeps `input_sanitization` anyway
when a tool exposes a dangerous parameter.

### Error-reflection grading

A well-behaved server rejects a bad argument and says which one it rejected:

```
Repository not found: /tmp/MCP_PROBE_8f4c2a
```

Five of the probes above look for a marker that is **part of the payload they
sent**, so that sentence hands the marker straight back and the check reads its
own input as proof the server complied. Measured against five real open-source
MCP servers, this was 61 findings, 29 of them CRITICAL.

Two conditions must now both hold before such a finding is weakened:

1. The response was a refusal (`isError`, a JSON-RPC error, or no response).
2. The marker survives **nowhere outside a verbatim copy of the payload**. The
   response has the payload subtracted from it, and only the remainder is
   searched. Anything left over, the server produced.

When both hold, the finding reports **LOW** and its title says
`(reflected in error response)`. It is not hidden — a server can return
`isError` and still be compromised.

Two things are exempt by design:

- **Execution evidence.** Shell error text such as `sh: 1: foo: not found`
  keeps its severity even in a failed response, because a shell errors
  *because* it parsed the payload. That is the server's output, not our echo.
- **Credential leakage.** `response_credentials` and `error_leakage` are
  untouched: a secret in an error string is a leak either way.

The operator sets the weighting:

```bash
--error-reflection downgrade   # default: LOW, retitled
--error-reflection keep        # previous severities, for diffing an old baseline
--error-reflection suppress    # drop the finding entirely
```

`keep` reproduces pre-6.15 output exactly, titles included — verified against
the committed [open-source target snapshots](oss-target-baseline.md).

---

## Infrastructure Checks (opt-in)

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `inference_model_enum` | HIGH | Unauthenticated model enumeration on LLM backends (Ollama, vLLM, LocalAI, TGI, llama.cpp) — MCP-T54 |
| `inference_no_auth` | CRITICAL | Unauthenticated text generation possible on exposed inference backend |
| `inference_mgmt_exposed` | HIGH | Management/destructive endpoints (model pull/delete/create) exposed without auth |
| `inference_network_exposed` | HIGH | Inference backend reachable over the network, bypassing MCP-layer controls |
| `model_tampered` | CRITICAL | Model digest changed since baseline — possible backdoor replacement (MCP-T55) |
| `model_removed` | HIGH | Model present in baseline is missing — unauthorized deletion |
| `model_injected` | MEDIUM | New model appeared that wasn't in the baseline — unauthorized pull |
| `model_size_drift` | HIGH | Digest matches but file size changed — partial corruption or metadata tampering |
| `inference_guardrail_variance` | HIGH–MEDIUM | Guardrail strength differs across the models a backend serves, so an attacker can pick the weakest one — MCP-T56 |

Enable with `--inference` (auto-detect from MCP context) or `--inference-host URL` (explicit target).

`inference_guardrail_variance` sends the same refusal-baiting prompt to each
model the backend exposes (capped at 6 to bound scan time) and compares
resistance. HIGH means the spread is wide enough that model choice alone
defeats the guardrail; MEDIUM means every model is weak.

**Model Integrity Verification** (MCP-T55): Snapshot known-good model digests with `--save-inference-baseline FILE`, then detect tampering on later scans with `--inference-baseline FILE`.

The two checks behind that table are `inference_backend`, which emits the four
`inference_*` findings, and `model_integrity`, which emits the four `model_*`
findings and runs only when a baseline is being read or written.

### Target Surface

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `actuator_probe` | CRITICAL–MEDIUM | Exposed debug and admin endpoints on the target's base URL (Spring Boot actuators, Werkzeug console, Go pprof/expvar, Swagger, `/.env`). Severity is per endpoint, escalated to CRITICAL when the response body itself contains credentials |
| `actuator_exploitation` | CRITICAL–MEDIUM | Emitted by the same check once passive discovery finds a live actuator. Downloads a heap dump (CRITICAL) and POSTs write probes: any status but 405 counts as accepted and takes the probe's own severity — CRITICAL for env write and shutdown, HIGH for logger override, refresh and restart. A 405 is the only MEDIUM: the endpoint exists but refuses the method. Shutdown is only attempted after another write has already succeeded |

### Teleport / Machine Identity

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `teleport_proxy_discovery` | MEDIUM | Teleport proxy endpoints reachable on the target host |
| `teleport_cert_validation` | HIGH | Teleport proxy serving a self-signed certificate |
| `teleport_app_enumeration` | HIGH | MCP applications registered in Teleport, enumerable from outside |
| `tbot_credential_exposure` | HIGH | tbot output secrets (`tbot-out`, `tbot-kube`) mounted into non-tbot pods. In-cluster only — returns immediately without a service-account token |
| `teleport_bot_overprivilege` | HIGH | ClusterRoleBindings that bind a `tbot`/`teleport` service account to `cluster-admin`, `admin` or `edit`. Only those three role names are matched, so a custom role with equivalent privilege is not flagged. In-cluster only, same precondition |
| `teleport_lab_bot_theft` | CRITICAL–INFO | Deep probe. Chains read-tbot-secret → replay stolen identity → check session binding against the Camazotz lab tools; self-skips unless those tools are present |
| `teleport_lab_role_escalation` | CRITICAL–INFO | Deep probe. Chains read-roles → request escalation → attempt a privileged operation |
| `teleport_lab_cert_replay` | CRITICAL–INFO | Deep probe. Chains fetch-expired-cert → replay → check replay detection. MEDIUM when the replay is only reported as first use |

The lab chains emit INFO when the defense held (nullfield denial, human-approval
hold, replay detection). INFO carries no risk weight — it records that the
attack path was exercised and blocked, which is not the same as not testing it.

---

## Transport & Aggregate Checks

| Check | Severity | What It Detects |
|-------|----------|----------------|
| `auth` | HIGH | Unauthenticated MCP/tool-server initialize accepted. Emitted by the enumerator during connection, not by a check, so it appears in reports without a corresponding entry in the progress count |
| `sse_security` | HIGH–MEDIUM | Unauthenticated SSE stream, CORS misconfiguration, cross-origin POST |
| `dpop_not_enforced` | HIGH | Request accepted with no DPoP proof — a stolen bearer token replays without the paired key (RFC 9449 §7). MCP-T43 |
| `dpop_header_not_validated` | HIGH | A malformed DPoP header is accepted, so the proof is decorative (RFC 9449 §7.1). MCP-T43 |
| `dpop_binding_not_enforced` | HIGH | Proof accepted without `htm`/`htu`, so it replays against any endpoint (RFC 9449 §4.2). MCP-T43 |
| `multi_vector` | CRITICAL | 2+ dangerous vulnerability categories active on one server. A category counts only if it has a finding at **MEDIUM or above** — a CRITICAL claim should not rest on evidence we ourselves graded LOW |
| `attack_chains` (finding: `attack_chain`) | CRITICAL | Linked vulnerability pairs (e.g. `input_sanitization → code_execution`), subject to the same MEDIUM floor as `multi_vector` |

### DPoP Enforcement (RFC 9449)

Runs only when a JWT is present and only on HTTP-family transports, against the
resolved MCP endpoint using the session's own auth headers — so a finding means
the live authenticated path is unprotected. Stdio is skipped; it has no header layer.

Each probe sends a single `tools/list` request, so none of them invokes a tool
and `--no-invoke` does not suppress them.

| Probe | Finding | Severity | Meaning |
|-------|---------|----------|---------|
| `dpop_no_header` | `dpop_not_enforced` | HIGH | Request accepted with no proof; a stolen bearer token replays without the paired key (§7) |
| `dpop_malformed` | `dpop_header_not_validated` | HIGH | A malformed proof is accepted, so the header is decorative (§7.1) |
| `dpop_missing_binding` | `dpop_binding_not_enforced` | HIGH | Proof accepted without `htm`/`htu`, so it replays against any endpoint (§4.2) |
