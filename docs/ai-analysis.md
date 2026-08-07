# AI-Powered Analysis (Claude)

Add `--claude` to any scan to layer LLM reasoning on top of deterministic checks.
Requires the `anthropic` package and `ANTHROPIC_API_KEY` env var.
By default, mcpnuke uses direct Claude API calls; Bedrock is opt-in via `--bedrock`.

**Setup:**
```bash
# If installed via quickstart.sh or uv sync --all-extras, anthropic is included.
# Otherwise install the AI extra:
uv pip install -e ".[ai]"    # or: pip install anthropic

export ANTHROPIC_API_KEY=sk-ant-...
```

For Bedrock mode, the same `ai` extra includes `boto3`; configure AWS credentials
and pass `--bedrock` (plus optional region/profile/model flags).

**Bedrock uses inference profiles, not bare model ids.** Current Anthropic
models on Bedrock advertise `INFERENCE_PROFILE` as their only inference type,
so the id carries a geography prefix — the default is
`us.anthropic.claude-sonnet-4-5-20250929-v1:0`. Outside the US, pass the
matching `eu.`, `apac.` or `global.` profile via `--bedrock-model`; a bare
`anthropic.*` id will fail on invoke. Bedrock also has no generally available
undated alias: `anthropic.claude-sonnet-5` exists in the catalog but returns
`AccessDenied` without a specific entitlement, which is why this default names
a dated version where the direct API default does not.

**`--claude` fails loud — no key, no run.** If `--claude` is set but the
`anthropic` package is missing or `ANTHROPIC_API_KEY` is unset, mcpnuke
exits immediately (exit code `2`) with a clear error message *before* any
scanning begins. There is no silent fallback to a stub responder. This is
deliberate: a missing key would otherwise downgrade an "AI scan" to a
deterministic-only scan with the same flag set, masking the regression.
(Camazotz's brain takes the opposite trade-off and degrades to a
`[cloud-stub]` responder when its key is missing — useful for live demos,
but unsafe for security tooling.)

**Usage:**
```bash
# Sonnet (fast, default)
./scan --targets http://localhost:9002/sse --claude --verbose

# Opus (deepest reasoning)
./scan --targets http://localhost:9002/sse --claude --claude-model claude-opus-5

# Fast mode + Claude (deterministic fast scan, then AI analysis)
./scan --targets http://localhost:9090 --fast --claude --verbose

# Faster Claude Phase 2 on medium/large toolsets
./scan --targets http://localhost:9090 --fast --claude --claude-max-tools 25 --claude-phase2-workers 3

# Repeatable benchmarking mode (recommended for run-to-run comparisons)
./scan --targets http://localhost:9090 --fast --claude --deterministic --verbose

# Claude via Bedrock (no ANTHROPIC_API_KEY required)
./scan --targets http://localhost:9090 --fast --claude --bedrock --bedrock-region us-east-1
```

**`--claude-phase2-workers` guidance:**
- Default is `1` (serial). This is safe and works out of the box.
- Use `2-4` to reduce wall-clock time when Phase 2 dominates runtime.
- Keep `1` if your key is rate-limited or target/network is unstable.
- This flag is optional; scans run normally without it.

**`--deterministic` guidance:**
- Forces stable tool ordering and single-threaded deep probes/AI Phase 2.
- Use this for benchmarking and CI drift checks when you need tighter run-to-run consistency.
- This does not remove model/target nondeterminism entirely, but it reduces scanner-side variance.

mcpnuke uses a three-layer analysis architecture. Each layer catches what
the previous one can't:

```
Layer 1: Deterministic (regex patterns)     — what tools SAY
Layer 2: Behavioral (call tools, probe)     — what tools DO
Layer 3: Claude AI (read, reason, chain)    — what tools MEAN
```

Claude runs four phases after deterministic + behavioral checks:

| Phase | What it does | Example finding |
|-------|-------------|----------------|
| **Tool analysis** | Reads definitions for subtle poisoning, social engineering, logical risks | "These tools chain into a privilege escalation path" |
| **Response analysis** | Reads actual tool output for manipulation, hidden intent, credential leakage | "Tool response is a fake paywall — social engineering the LLM" |
| **Chain reasoning** | Connects all findings into multi-step attack scenarios | "Unauthenticated access → command injection → lateral movement → persistence" |
| **Chain replay** (`--chain-replay`) | Proposes executable steps, runs them on the target, and grades the transcript | "Chain reproduced" / "exfiltrated out-of-band" CRITICAL; callable-but-unproven MEDIUM |

**Phase 4 (`--chain-replay`) in brief:**
- Honours `--safe-mode` and `--no-invoke` (dangerous steps refused before call).
  Namespaced tools count: `shellwrap.exec` / `sdk.write_cache` /
  `shadow.register_webhook` / `egress.fetch_url` are refused the same way as
  `delete_record` — the danger classifier splits on `.` as well as `_` / `-`,
  and treats webhook / callback / egress / exfil name tokens as dangerous.
- With `--oast`, may plant `{{oast.url}}`; a callback is out-of-band proof of
  egress. Verdicts await a short grace period (`CanaryListener.await_hits`) so
  a sink that queues its outbound request is not raced. `propose_chains` steers
  toward fetch/send-now sinks (or register **plus** a follow-up that fires the
  webhook) so register-only chains are not the end of the path.
- Under `--claude`, an optional judge can upgrade transformed data movement to HIGH.
- `--chain-replay-retries N` (default 1) revises a halted chain from its
  transcript and retries. Each revise/retry attempt is logged under `--verbose`.

Real example from DVMCP Challenge 4 (Rug Pull):

| Layer | Findings | Score |
|-------|----------|-------|
| Deterministic only | 5 (schema_risk, auth, SSE) | 26 |
| + Behavioral probes | 6 (+ deep_rug_pull) | 36 |
| + Claude Opus | 10 (+ social engineering, attack chains) | 64 |

AI findings are prefixed with `[AI]` and include taxonomy IDs (e.g. `[AI] [MCP-T03]`).
They appear alongside deterministic findings in the same report.

Tools are classified as **dangerous** if their name contains keywords like
`delete`, `execute`, `send`, `write`, `deploy`, `kill`, `transfer`,
`webhook`, `callback`, `egress`, `exfil`, etc.
In `--safe-mode`, these are skipped while read-only tools (`get`, `list`,
`search`, `check`, `verify`, etc.) are still probed.
