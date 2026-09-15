# Cross-Server Attack Chains — Design

Date: 2026-09-14. Status: proposed, not scheduled.

## 1. Problem

mcpnuke chains are per-target. `attack_chain`, `multi_vector`, and the Phase 4
replay engine all operate on one `TargetResult` — one MCP server, one session.

Real agent deployments connect several servers at once, and the documented
failures cross that boundary. The GitHub MCP toxic-flow incident read poisoned
content from a public issue (server A) and exfiltrated private repositories
through the same agent's other tools (server B). Unit 42 measured a 78.3%
attack success rate with five MCP servers on one agent. The OWASP MCP Top 10
(2025/2026 guidance) frames MCP02 scope creep and MCP06 intent-flow subversion
as cross-server phenomena: the blast radius lives in the composition, not in
any single server.

A scanner that only ever looks at one server at a time cannot see the
composition. Ours currently cannot.

## 2. What exists today

- Per-target deterministic chains (`attack_chain`, `multi_vector`) driven by
  `ATTACK_CHAIN_PATTERNS` over one result's finding categories.
- Phase 4 replay (`--chain-replay`): executes multi-step chains against one
  session, with placeholder/transform tracking (`{{stepN.output|b64}}`) and an
  OAST canary registry proving data movement.
- `tool_shadowing` already compares tool names *across* `all_results` — the
  one existing cross-target signal, and proof the plumbing is trivial.
- Per-target AIBOM `inventory` block (tool-surface sha256) in `--json`.

## 3. Proposed phases

### Phase A — cross-target chain detection (static, no new probes)

After all targets in a run are scanned, correlate findings across results:

- Server A carries a context-injection finding (indirect injection, tool
  output poisoning, rug pull) **and** server B carries an execution or
  credential sink (`code_execution`, `token_theft`, `shell_injection`) → emit
  `cross_server_chain` on both results, MEDIUM, naming the pair and the
  vector. Rationale: the agent reads A and acts on B; neither server alone
  shows the chain.
- A cross-target `tool_shadowing` name collision **plus** a sink on either
  side upgrades to HIGH: the agent can be routed to the shadow by name.
- Attribution: the finding lands on the sink-side result with `evidence`
  naming the peer URL. (Built 2026-09-14: sink-side only — the damage lands
  there; the source peer is named in evidence. Landing on both results was
  considered and dropped as double-reporting.)

No new network traffic; pure post-pass over `list[TargetResult]`. This is the
80% case and the only phase worth building first.

### Phase B — cross-session replay (behavioral, gated)

Extend the replay engine so chain steps carry a target URL; the placeholder
registry (`{{stepN.output}}`) is shared across sessions. Requires the scanner
to hold sessions open past enumeration (today the session lifecycle is
per-target), so this is a real architectural change, not a flag flip.
Gate: `--chain-replay --cross-server`, off by default.

### Phase C — shadow-aware chain scoring

Feed cross-target shadowing collisions into chain grading: a replayed chain
whose first step resolves to a shadowed name scores higher, because the agent
may invoke the decoy without any injection at all.

## 4. Safety

Cross-server replay multiplies blast radius: a payload planted on A is
*designed* to fire on B. Phase B must respect `--safe-mode` per target,
refuse state-mutating tools on any target not explicitly in scope, and keep
OAST canaries per-target so egress is attributable.

## 5. Test plan

- Unit: correlation matrix over synthetic `TargetResult` pairs (fires,
  no-fire when only one side has a finding, upgrade on name collision).
- Integration: two DVMCP targets in one run — poison surface on one, sink on
  the other — assert the paired finding on both.
- FP harness: the OSS-target snapshots must not gain `cross_server_chain`
  findings (single-target baselines have no peer, which is itself the guard).

## 6. Open questions

- Should a cross-server finding deduplicate to a run-level report section
  instead of landing on both targets? (Both-targets is simpler and keeps
  per-target JSON honest; run-level reads better. Decide at Phase A.)
- Session pooling for Phase B: keep-alive vs reconnect per step.
- Does the run need a declared "agent trust set" (these N servers share one
  agent) so single-run multi-target scans don't over-correlate unrelated
  targets? Probably yes for Phase B; Phase A can document the assumption.
