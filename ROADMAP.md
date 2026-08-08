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
| Taxonomy coverage | **22/56 IDs (39%)** — Tier 1 complete, see gap map below |
| CI integration (SARIF, --fail-on) | **Done** |
| Actionable reporting (priority actions, fix/verify, policy) | **Done** — see below |
| Distribution (PyPI, install script) | **Gap** — source-only |
| CI/CD workflow for the tool itself | **Partial** — `tests.yml` + reusable scan workflow; dogfood CI still thin |

---

## Taxonomy coverage map

### Covered (14 IDs — implemented with dedicated checks)

| ID | Threat | Check module |
|----|--------|--------------|
| MCP-T04 | Supply chain artifacts | `supply_chain.py` |
| MCP-T06 | Path traversal / TLS bypass | `ssrf_probe.py` |
| MCP-T07 | Secret exposure in tool responses | `response_credentials.py` |
| MCP-T09 | Config tampering / arbitrary exec | `config_tampering.py`, `execution.py` |
| MCP-T12 | Exfiltration flows | `exfil_flow.py` |
| MCP-T14 | Persistence / server redirect | `webhook_persistence.py` |
| MCP-T33 | SDK token cache tamper | `sdk_cache_tamper.py` |
| MCP-T42 | Actuator/management exposure | `actuator_probe.py` |
| MCP-T43 | AI guardrail bypass probe | `ai_guardrail_probe.py` |
| MCP-T50 | Anonymous pre-auth surface | `anon_budget_exhaust.py` |
| MCP-T51 | Anonymous tool enumeration | `transport.py` |
| MCP-T54 | Subprocess/shell injection | `shell_injection.py` |
| MCP-T55 | Inference backend integrity | `inference_backend.py` |
| MCP-T56 | DPoP enforcement gaps | `dpop_enforcement.py` |

### Tier 1 — DONE (high-value, directly scannable from outside)

> **Completed 2026-06-28.** All checks live-verified against DVMCP on a K3s cluster.
> Coverage: 14 → 22 IDs. Only T11 (cross-tenant) deferred (needs multi-auth infra).

| ID | Threat | Approach |
|----|--------|----------|
| ✅ **MCP-T01** | Prompt injection via tool args | Behavioral: inject override instructions in tool arguments, detect if server passes them unsanitized to LLM |
| ✅ **MCP-T02** | Tool output poisoning (indirect injection) | Behavioral: invoke tools and check if responses contain embedded instructions that would manipulate a downstream agent |
| ✅ **MCP-T03** | Credential forwarding in tool calls | Static: detect tools whose schema accepts credential-like parameters (tokens, keys, passwords) that could be forwarded to attacker-controlled endpoints |
| ✅ **MCP-T05** | Command injection via tool args | Behavioral: pass shell metacharacters (`;`, `|`, `$()`, backticks) in tool arguments, detect execution indicators in response |
| ✅ **MCP-T08** | Remote package execution | Static: detect tools that fetch and execute remote code (`npx`, `uvx`, `pip install`, `curl | sh` patterns in tool descriptions or args) |
| ✅ **MCP-T10** | Agentic loop / resource exhaustion | Behavioral: detect recursive tool invocations or unbounded fan-out (tool A calls tool B calls tool A) |
| **MCP-T11** | Cross-tenant data access | Behavioral: probe with different auth contexts, detect if one tenant's data leaks to another |
| ✅ **MCP-T13** | Insecure inter-agent communication | Static: detect unsigned message-passing tools, check for agent-to-agent trust without verification |
| ✅ **MCP-T15** | Model routing manipulation | Behavioral: probe if model selection can be influenced via tool parameters or headers |



### Tier 2 audit results (T16–T32 mapping, 2026-06-28)

| ID | Threat | Existing check | Action |
|----|--------|---------------|--------|
| T16 | Temporal Consistency Drift | `behavioral.py` (state_mutation) | Tag |
| T17 | Notification / Sampling Abuse | `behavioral.py` (notification_abuse) | Tag |
| T18 | Bot Identity Theft | `theft.py` | Tag |
| T19 | Short-Lived Certificate Replay | `teleport.py` (cert_replay) | Tag |
| T20 | RBAC & Isolation Boundary Bypass | `permissions.py` | Tag |
| T21 | OAuth Token Theft & Replay | `theft.py` + `jwt_validation.py` | Tag |
| T22 | Execution Context Forgery | **gap** | Write new |
| T23 | Credential Isolation & Sidecar Tampering | `credential_in_schema.py` partial | Tag + extend |
| T24 | Authentication Pattern Downgrade | `dpop_enforcement.py` | Tag |
| T25 | Agent Delegation Chain Abuse | `chaining.py` | Tag |
| T26 | Token Lifecycle & Revocation Gaps | `jwt_validation.py` | Tag |
| T27 | LLM Cost Exhaustion & Misattribution | `rate_limit.py` + `anon_budget_exhaust.py` | Tag |
| T28 | Teleport Role Escalation via MCP | `teleport_labs.py` | Tag |
| T29 | Policy Authoring (defense) | *out of scope* — defensive | Skip |
| T30 | Response Inspection (defense) | *out of scope* — defensive | Skip |
| T31 | Budget Tuning (defense) | *out of scope* — defensive | Skip |
| T32 | Delegation Depth / Identity Dilution | `chaining.py` partial | Tag + extend |

**Conclusion:** 11 can be tagged to existing checks (no new logic), 3 are defensive
(skip), 3 need new/extended logic (T22, T23, T32). Tagging would jump coverage
from 22 → ~33 IDs (59%) with zero new check code.

**Next action:** carefully tag each file with `taxonomy_id=` on the correct
`result.add()` calls (per-file surgical edits, not batch).

### Tier 2 — Medium-term

| ID | Threat | Notes |
|----|--------|-------|
| MCP-T16–T32 | Transport/auth/identity (17 IDs) | Many partially overlap with existing jwt/dpop/transport checks; need per-ID audit to identify true gaps vs already-covered-under-different-name |
| MCP-T34–T36 | Advanced delegation/chain attacks | Require multi-hop scanning (call server A, observe effect on server B) |
| MCP-T37–T41 | RAG poisoning, HTTP bypass, governance redirect | Harder to probe without internal corpus access; AI analysis can partially cover |
| MCP-T44–T49 | Transport identity dilution (lanes B–E) | Extend lane-aware checks with per-transport behavioral probes |
| MCP-T52 | Context window overflow | Behavioral: detect if oversized inputs cause truncation of security-critical context |
| MCP-T53 | Subprocess credential inheritance | Behavioral: check if spawned processes inherit parent credentials |
| MCP-T57–T58 | K8s-specific (namespace escape, RBAC) | Extend teleport checks with namespace-boundary probes |

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

## Infrastructure roadmap

### Near-term

- **CI dogfood** — broaden `.github/workflows/tests.yml` / scan workflow (matrix, self-scan)
- **Publish workflow** — PyPI via OIDC trusted publishing on tag push
- **`install.sh`** — one-liner macOS/Linux installer (same pattern as skillseraph)
- **PyPI package** — `pip install mcpnuke` / `uvx mcpnuke`

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

Each check lives in `mcpnuke/checks/<name>.py` and implements:

```python
async def check_<name>(session: McpSession, findings: list[Finding]) -> None:
    """One-line description of what this checks."""
    # ... probe logic ...
    findings.append(Finding(
        title="...",
        severity=Severity.HIGH,
        taxonomy_id="MCP-T##",
        lane=2,
        transport="A",
        detail="...",
    ))
```

Requirements:
1. Map to a taxonomy ID from the Atlas (MCP-T01–T58)
2. Assign a lane (1–5) and transport (A–E)
3. Add tests in `tests/test_<name>.py` (mock the session, assert findings)
4. Add to `mcpnuke/checks/__init__.py` (static or behavioral phase)
5. Update this ROADMAP's coverage table

Every check should be safe to run against production (no destructive operations)
unless explicitly gated behind `--deep` or `--destructive` flags.

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
