# Scan Modes

Which checks run, and against how much of the tool surface, is set by one of
five modes.

| Mode | Flag | What Runs | Use Case |
|------|------|-----------|----------|
| **Full** | (default) | Static + all behavioral probes | Dev/staging, DVMCP, CTFs |
| **Fast** | `--fast` | Static + top-5 tools (tiered scoring), skip heavy probes (risk-aware: retains `input_sanitization` when dangerous params detected), cap workers at 2 | Quick triage, large tool sets |
| **Safe** | `--safe-mode` | Static + probes on read-only tools only | Prod servers with mixed tool risk |
| **Static** | `--no-invoke` | Static checks only, no tool calls | Prod servers, zero side-effect risk |
| **AI** | `--claude` | All checks + Claude analysis | Deep analysis, subtle vuln hunting |

## Fast Mode Scoring

In `--fast` mode, mcpnuke ranks all discovered tools using a tiered weighted
scoring algorithm (`_tool_security_score`) and selects the top 5. The scorer
considers:

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
