# Scan Modes

Which checks run, and against how much of the tool surface, is set by one of
five modes.

| Mode | Flag | What Runs | Use Case |
|------|------|-----------|----------|
| **Full** | (default) | Static + all behavioral probes | Dev/staging, DVMCP, CTFs |
| **Fast** | `--fast` | Static checks read the full catalog. Invoke probes sample the top 5 (tiered scoring), skip heavy probes (risk-aware: retains `input_sanitization` when dangerous params detected), cap probe workers at 2 | Quick triage, large tool sets |
| **Safe** | `--safe-mode` | Static + probes on read-only tools only; skips delete/exec/send/write and outbound sinks (webhook, egress, exfil), including dotted names like `shellwrap.exec` / `shadow.register_webhook` | Prod servers with mixed tool risk |
| **Static** | `--no-invoke` | Static checks only, no tool calls | Prod servers, zero side-effect risk |
| **AI** | `--claude` | All checks + Claude analysis | Deep analysis, subtle vuln hunting |

Every mode that produces findings also emits **Priority actions** (console +
JSON): a proof-ranked top-N fix list. Deep AI modes (`--claude --chain-replay`,
optionally `--oast`) feed the strongest ranks when chains reproduce or egress
is confirmed; static/safe modes still get an honest priority list from whatever
was found.

A run with more than one target treats every target as one agent unless
`--trust-set URL,URL` says otherwise. Repeat the flag for another agent.
Cross-server chains, name collisions, shadow grades, and `--cross-server`
replay stay inside a set. A target named in no set is scanned and not chained.

## Fast Mode Scoring

In `--fast` mode, static checks still read every enumerated tool. Invoke
probes rank those tools with a tiered weighted scoring algorithm
(`_tool_security_score`) and call the top 5. The scorer considers:

| Factor | How It Works |
|--------|-------------|
| **Keyword tiers** (6 levels) | Exec/eval/shell keywords score highest (10), followed by secret/credential (8), webhook/callback (7), run/command (6), upload/write/file (4), admin/root (3) |
| **Name vs description** | Keywords in the tool *name* get 3x the weight of keywords in the description |
| **Dangerous parameters** | Params named `url`, `command`, `code`, `query`, `script`, `host`, etc. add +8 each |
| **Schema complexity** | Number of input properties (capped at 3) adds a small bonus |
| **High-value floor** | Tools with names containing `secret`, `credential`, `password`, `token`, `config`, etc. get a minimum score of 15, even if other signals are weak |

This ensures zero-parameter tools like `server-config` and `secrets.leak_config`
rank above benign tools like `smelt-item` or `move-to-position`, and that tools
with dangerous parameter surfaces (`run-maintenance`, `admin-webhook`, `fetch-skin`)
are consistently selected.
