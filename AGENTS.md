# AGENTS.md — Guidance for AI Coding Agents

Read this before making any change to mcpnuke. It is the product truth for
how this repo is built, tested, and kept safe.

## What this is

mcpnuke is an MCP red teaming and security scanner. Python 3.11+, package
manager `uv`. It actively probes MCP servers, so all code and docs must
assume authorized-use context — never add exploit PoCs, live credentials,
or real target data to the repo.

## Setup and verification

```bash
uv sync --all-extras          # install everything including dev
uv run pytest tests/ -v       # full suite must pass: 1040+ passed, 0 failed
uv run ruff check .           # must be zero
uv run mypy mcpnuke/          # must stay at or below the CI ceiling
```

CI gates all four on every push and PR. `mcpnuke/core/` additionally enforces
`disallow_untyped_defs`. If you edit `pyproject.toml`, run `uv lock` and
commit `uv.lock` — CI checks they are in sync.

## Code conventions

- Strong typing throughout: `dict`, `list`, `frozenset`, `int`, `str` hints on
  all functions. No `Any` to silence the checker.
- Module-level constants: `UPPER_SNAKE_CASE`, typed explicitly.
- Check signatures: `check_name(result: TargetResult)` for static checks;
  `check_name(session: MCPSessionProtocol, result: TargetResult, probe_opts: dict | None = None)`
  for behavioral checks.
- Every check body wrapped in `with time_check("check_name", result):`.
- Findings via `result.add(check_name, severity, title, detail, evidence=...)`.
  Severities: CRITICAL, HIGH, MEDIUM, LOW.
- Credential regexes live in `mcpnuke/patterns/credentials.py` only, in the
  tier matching their false-positive risk — never in `rules.py`, `probes.py`,
  or a check module.

## Adding a check

1. Write the failing test first: `tests/test_<check_name>.py` with at least
   positive detection, clean/negative, and timing-recorded cases. Use the
   `conftest.py` fixtures (`result_with_tools([{...}])`).
2. Implement the check in `mcpnuke/checks/<name>.py`.
3. Wire it into `run_all_checks` in `mcpnuke/checks/__init__.py`.
4. Document it in `docs/checks.md` and update the check totals in
   `README.md` / `docs/checks.md` — tests assert they match the registry.
5. Add a `CHANGELOG.md` entry.

## Architecture map

```
mcpnuke/checks/__init__.py   orchestrator, run_all_checks
mcpnuke/checks/<name>.py     individual check modules
mcpnuke/checks/base.py       time_check, tool_text (shared searchable surface)
mcpnuke/patterns/rules.py    static regex pattern sets
mcpnuke/patterns/probes.py   behavioral probe payloads and response analysis
mcpnuke/patterns/credentials.py  the only credential regexes, tiered by FP risk
mcpnuke/core/session.py      transport detection and the four session classes
mcpnuke/core/transports/     MCPSessionProtocol, HTTPCapableSession
mcpnuke/core/chain_replay.py multi-hop attack chain replay (DAG, OAST)
mcpnuke/core/models.py       Finding, TargetResult dataclasses
mcpnuke/scanner.py           parallel scan orchestration
mcpnuke/__main__.py          CLI entry point
```

## Invariants guarded by tests

These exist because each one broke once. Do not route around them:

- `tests/test_credential_patterns.py` — every consumer of the credential
  tiers detects the same set. Add new secrets to the corpus.
- `tests/test_injection_patterns.py` — one shared injection marker set, no
  private copies.
- `tests/test_session_protocol.py` — all four transports satisfy the
  Protocol, and stdio never gains `post_raw`.
- `tests/test_check_progress.py` — the progress denominator derives from the
  check inventory, never hardcoded.
- `tests/test_docs_current.py` — README/docs structure, link resolution, and
  stated check counts are all asserted. Update docs with code.

## Security rules for contributors

- Never commit secrets, tokens, flags, or live credentials. Synthetic test
  values only.
- Redact before pasting output into docs or issues.
- DVMCP live tests are gated behind `DVMCP_LIVE=1`; OSS target snapshots
  behind `MCPNUKE_OSS_TARGETS=1`. Keep network-dependent tests opt-in.

Further reading: [CONTRIBUTING.md](CONTRIBUTING.md),
[docs/checks.md](docs/checks.md), [SECURITY.md](SECURITY.md).
