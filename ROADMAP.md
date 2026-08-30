# mcpnuke Roadmap

Where mcpnuke is going. The attack taxonomy (MCP-T01–T58) from the
[agentic-sec Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md)
is the coverage target. mcpnuke's lane is **outside-in runtime scanning** of live
MCP endpoints — static config scanning is skillseraph's job, model resistance is
stoneburner's, and runtime policy enforcement is nullfield's.

---

## Coverage at a glance

| Area | State |
|------|-------|
| Static metadata analysis (schema, permissions, credentials) | **Strong** — 17 static checks |
| Behavioral probes (tool invocation, SSRF, injection, exfil) | **Strong** — 12 behavioral checks |
| AI-augmented analysis (Claude + Ollama ensemble) | **Strong** — 3-phase analysis, consensus mode |
| Transport security (JWT, DPoP, scope, boundaries) | **Strong** — 8 transport checks |
| Lane coverage (5 identity lanes) | **All 5 represented** |
| Taxonomy coverage | **54/57 IDs (95%)** — Tier 1 complete, see gap map below |
| MCP spec surface (2026-08-22 roadmap) | **Mapped** — Speak/Scan/Ready in [docs/spec-surface.md](docs/spec-surface.md) |
| CI integration (SARIF, --fail-on) | **Done** |
| Actionable reporting (priority actions, fix/verify, policy) | **Done** — see below |
| False-positive measurement | **Done** — three harnesses, all baselined and gated; see below |
| Distribution (PyPI, install script) | **Ready** — `install.sh` + publish workflow, both tested; upload armed by the `PYPI_PUBLISH` variable once the trusted publisher is registered |
| CI/CD workflow for the tool itself | **CLI dogfood** — `tests.yml` scans the in-repo reference target via `python -m mcpnuke` |

---

## Taxonomy coverage map

Threat names in the tables follow `mcpnuke/data/taxonomy/lanes.yaml`.
`test_roadmap_table_titles_match_lanes_yaml` fails if a single-ID row
drifts. Range rows (`MCP-T16–T32`) are buckets, not IDs.

Every attributed finding sets `taxonomy_id` (`test_no_check_attributes_only_in_evidence`).
`shell_injection` is MCP-T53; T54 stays on `inference_backend`.

### Covered at the Tier 1 milestone (14 IDs — historical snapshot)

IDs this milestone claimed, with current `lanes.yaml` titles and the
module that emits them today. Not a claim that each check is a perfect
fit for that ID.

| ID | Threat | Check module |
|----|--------|--------------|
| MCP-T04 | Confused Deputy / Token Theft | `supply_chain.py` |
| MCP-T06 | SSRF via Tool | `ssrf_probe.py` |
| MCP-T07 | Secrets in Tool Output | `response_credentials.py`, `credential_in_schema.py` |
| MCP-T09 | Agent Config Tampering | `config_tampering.py` |
| MCP-T12 | Exfiltration via Chaining | `exfil_flow.py` |
| MCP-T14 | Persistence via Webhook | `webhook_persistence.py` |
| MCP-T33 | SDK Token Cache Poisoning | `sdk_cache_tamper.py` |
| MCP-T42 | Shared IdP Cross-Pollution (User → Agent Token Escalation) | `scope_pollution.py` |
| MCP-T43 | DPoP Key Exposure and JWT Forgery | `dpop_enforcement.py` |
| MCP-T50 | Anonymous Tool Schema Over-Disclosure | `schema_overdisclosure.py` |
| MCP-T51 | Anonymous Rate-Limit Exhaustion | `anon_budget_exhaust.py` |
| MCP-T54 | Unauthenticated Inference Backend Exposure | `inference_backend.py` |
| MCP-T55 | Inference Model Integrity Drift | `inference_backend.py` |
| MCP-T56 | AI Guardrail Bypass via Social Engineering | `ai_guardrail_probe.py` |

### Tier 1 — DONE (high-value, directly scannable from outside)

> **Completed 2026-06-28.** Live-verified against DVMCP on a K3s cluster.
> Coverage then: 14 → 22 IDs. T11 still needs multi-auth infra.

| ID | Threat | Approach |
|----|--------|----------|
| ✅ **MCP-T01** | Direct Prompt Injection | `injection.py`, `prompt_injection_t01.py` |
| ✅ **MCP-T02** | Indirect Prompt Injection | `tool_output_poisoning.py` |
| ✅ **MCP-T03** | Tool Behavior Mutation (Rug Pull) | `tool_output_poisoning.py` |
| ✅ **MCP-T05** | Cross-Tool Context Poisoning | `command_injection_broad.py` |
| ✅ **MCP-T08** | Supply Chain via Content | `remote_package_exec.py` |
| ✅ **MCP-T10** | Hallucination-Driven Destruction | `agentic_loop.py` |
| ✅ **MCP-T11** | Cross-Tenant Memory Leak | `taxonomy_coverage.py` (`cross_tenant_memory_leak`) |
| ✅ **MCP-T13** | Audit Log Evasion | `insecure_agent_comms.py` |
| ✅ **MCP-T15** | Error Information Disclosure | `model_routing.py` |

### Tier 2 audit results (T16–T32 mapping, 2026-06-28)

Titles match `lanes.yaml`. Action column is the 2026-06-28 note, not
current status — several of these are tagged now.

| ID | Threat | Existing check | Action |
|----|--------|---------------|--------|
| T16 | Temporal Consistency Drift | `behavioral.py` (state_mutation) | Tag |
| T17 | Notification / Sampling Abuse | `behavioral.py` (notification_abuse) | Tag |
| T18 | Bot Identity Theft via tbot Credential Exposure | `theft.py` | Tag |
| T19 | Short-Lived Certificate Replay Attack | `teleport.py` (cert_replay) | Tag |
| T20 | RBAC & Isolation Boundary Bypass | `permissions.py` | Tag |
| T21 | OAuth Token Theft & Replay | `theft.py` + `jwt_validation.py` | Tag |
| T22 | Execution Context Forgery | `execution_context_forgery` | Done |
| T23 | Credential Isolation & Sidecar Tampering | `sidecar_credential_tamper` | Done |
| T24 | Authentication Pattern Downgrade | `dpop_enforcement.py` | Tag |
| T25 | Agent Delegation Chain Abuse | `chaining.py` | Tag |
| T26 | Token Lifecycle & Revocation Gaps | `jwt_validation.py` | Tag |
| T27 | LLM Cost Exhaustion & Misattribution | `rate_limit.py` + `anon_budget_exhaust.py` | Tag |
| T28 | Teleport Role Escalation via MCP Tool | `teleport_labs.py` | Tag |
| T29 | Policy Authoring — Write Rules That Block Attack Chains | *out of scope* — defensive | Skip |
| T30 | Response Inspection — Craft Redaction Rules That Catch Leaks | *out of scope* — defensive | Skip |
| T31 | Budget Tuning — Rate Limits That Stop Attackers Without Blocking Users | *out of scope* — defensive | Skip |
| T32 | Delegation Depth — Multi-Agent Identity Dilution | `delegation_depth` | Done |

**Then:** 11 taggable, 3 defensive (skip). T22, T23, T32 shipped.
Coverage today is the glance row (measured, not this audit's 22).

### Tier 2 — Medium-term

| ID | Threat | Notes |
|----|--------|-------|
| MCP-T16–T32 | Transport/auth/identity (17 IDs) | Many overlap jwt/dpop/transport; T22/T23 have static checks |
| MCP-T34–T36 | Advanced delegation/chain attacks | T34/T35/T36 are attributed; multi-hop still thin |
| MCP-T37–T41 | RAG poisoning, HTTP bypass, governance redirect | Harder without internal corpus access |
| MCP-T44–T49 | Transport identity dilution (lanes B–E) | T44 has a probe; B–E still thin |
| MCP-T52 | Pre-Authentication Injection | `pre_auth_injection` in `taxonomy_coverage.py` |
| MCP-T53 | Shell Command Wrapping Injection | `shell_injection.py` |
| MCP-T57–T58 | K8s-specific (namespace escape, RBAC) | Attributed; namespace-boundary probes still thin |

### Out of scope (other tools' lanes)

| IDs | Covered by | Why not mcpnuke |
|-----|-----------|----------------|
| Domain J (config/automation) | **skillseraph** | Static file scanning, not runtime |
| Model resistance/reasoning | **stoneburner** | Model-level eval, not endpoint scanning |
| Runtime policy enforcement | **nullfield** | Inline enforcement, not external scanning |

---

## Reporting & remediation (done 2026-08-08)

Target-agnostic operator loop — labs (Camazotz / DVMCP) are oracles only:

| Piece | What shipped |
|-------|----------------|
| **Priority actions** | Proof-ranked “fix these first” list on every console/JSON report |
| **Impact / fix / verify** | Deterministic guidance on each priority action |
| **`--generate-policy`** | NullfieldPolicy YAML; proved chains → DENY(sink) + HOLD(source*) |
| **Lab baselines** | Offline fixtures in `tests/fixtures/scans/` guard A/C/B contracts in CI |

## False-positive measurement (done 2026-08-10)

How wrong mcpnuke is, measured rather than assumed. Three harnesses, because
they answer different questions:

| Harness | Question | Result |
|---------|----------|--------|
| **Hardened fixture, HTTP** — `tests/test_false_positives.py`, runs in default CI | How quiet are we against a server built to be clean? | 5 findings, 0 unexpected, each justified in writing. Ceiling ratchets down. See [docs/false-positive-baseline.md](docs/false-positive-baseline.md) |
| **Hardened fixture, stdio** — `tests/test_false_positives_stdio.py`, runs in default CI | Same question on the transport most users actually have | 4 findings, 0 unexpected, plus an invariant that no auth-shaped check may fire where there is no auth boundary |
| **Open-source targets** — `tests/test_oss_targets.py`, opt-in + weekly CI | How wrong are we about servers other people wrote? | 5 pinned servers over stdio, every finding triaged. See [docs/oss-target-baseline.md](docs/oss-target-baseline.md) |

Three false-positive classes found and fixed by this measurement:

| Fix | Effect across the five real servers |
|-----|-------------------------------------|
| **Pattern anchoring** — capability patterns matched substrings (`sh` in "show", `nc` in "branch") | 211 findings → 187; 71 CRITICAL → 49 |
| **Error-reflection grading** — a server quoting the input it refused was read as compliance | 187 → 185; 49 CRITICAL → **18** |
| **Transport-aware auth** — three checks reported a missing auth boundary on stdio, which has none to miss | 185 → 170; 34 HIGH → **24** |

Still decided: `behavioral_rate_limit` on stdio, 5 findings. Keep. An agent
in a loop can hammer a local server; that is not a missing auth boundary.
Tagged MCP-T27 like the static sibling. Do not apply the stdio auth skip.

## Infrastructure roadmap

### Near-term

- **First Ready-row spec-surface checks** — dual `tools/call` body, list caching, and SEP-2243 routing-header binding are done. ETags, Tasks, HTTP-over-stdio, WIF wait for a wire format. See [docs/spec-surface.md](docs/spec-surface.md).
- **First PyPI release** — everything below is built and tested; what remains
  is registering the trusted publisher on PyPI and pushing a `vX.Y.Z` tag
  - ~~Publish workflow — PyPI via OIDC trusted publishing on tag push~~ **Done**
  - ~~`install.sh` — one-liner macOS/Linux installer~~ **Done**

### Publishing, when the tag goes up

Two one-time steps, in this order:

1. On PyPI, under the project's Publishing settings: owner `babywyrm`,
   repository `mcpnuke`, workflow `publish.yml`, environment `pypi`. Create
   the matching `pypi` environment in repo settings.
2. Set the repository variable `PYPI_PUBLISH` to `true`.

Until step 2, a `vX.Y.Z` tag still runs the full build-and-verify job and
simply skips the upload, so tagging a release is safe before PyPI exists.
No API token is created or stored — `publish.yml` mints a short-lived OIDC credential per
run, and a stored token would be the same long-lived secret mcpnuke flags on
other people's servers.

The workflow refuses to build when the tag disagrees with the packaged
version (`scripts/check-tag-version.sh`), because a PyPI version can never be
replaced or reused. It then installs the built wheel into a clean environment
and checks both console scripts before anything is uploaded.

### Medium-term

- **`--coverage-report` improvements** — show per-taxonomy-ID coverage with pass/fail/untested status
- **Profile library** — curated scan profiles for common MCP server types (Cursor MCP, Claude Desktop, generic stdio)
- **Watch mode** — continuous scanning for runtime monitoring (sidecar use case)
- **Multi-target orchestration** — scan a fleet of MCP servers in parallel

### Horizon

- **OWASP MCP Top 10 alignment report** — map every finding to OWASP MCP01–MCP15
- **SARIF remediation** — carry Priority Action impact/fix/verify into SARIF `fixes` / help text
- **Camazotz lab coverage tracking** — which labs exercise which checks

---

## Contributing checks

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the check-authoring recipe,
the static vs behavioral signatures, severity calibration, and the invariants
guarded by tests.

In brief, a new check must:

1. Map to a taxonomy ID from the Atlas (MCP-T01–T58)
2. Assign a lane (1–5) and transport (A–E)
3. Wrap its body in `with time_check("<name>", result):`
4. Add `tests/test_<name>.py` covering positive, negative, and timing
5. Register in `mcpnuke/checks/__init__.py` (static or behavioral phase)
6. Update this ROADMAP's coverage table

Every check should be safe to run against production (no destructive operations)
unless explicitly gated behind `--deep` or `--destructive` flags, and behavioral
checks must honor `--no-invoke` and `--safe-mode`.

---

## Live test targets

| Target | Location | Auth | Tools | Use for |
|--------|----------|------|-------|---------|
| **DVMCP** | cluster :30901–30910 | none | 1–2 per challenge (10 challenges) | Quick check validation, injection/execution scenarios |
| **camazotz** | cluster :30080 (unpoliced), :30090 (policed) | OIDC (Zitadel) | 138 | Full T01/T02/T03 testing, ensemble AI, credential forwarding |
| **zerotrust** | cluster internal (ClusterIP) | k8s SA | varies | Zero-trust lane probes |

Scan commands:
```bash
# DVMCP (all challenges, no auth needed)
./scan --port-range <cluster-node>:30901-30910 --verbose

# Camazotz (needs OIDC token — use portal flow or --oidc-url)
./scan --targets http://<cluster-node>:30080/sse --oidc-url http://zitadel:8080 --client-id <id> --client-secret <secret>

# Full with AI analysis
./scan --port-range <cluster-node>:30901-30910 --ollama-analysis http://<ollama-host>:11434 --ollama-model qwen2.5:14b
```
