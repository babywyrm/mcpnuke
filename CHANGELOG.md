# mcpnuke Changelog

All notable changes to this submodule are documented here.

## [Unreleased]

## [6.17.0] - 2026-08-26

Current-spec scan surface (dual `tools/call` body, SEP-2549 list cache,
SEP-2243 routing headers) and taxonomy IDs that reach the finding.

### Added

- **`docs/spec-surface.md`** — Speak / Scan / Ready map of mcpnuke against
  the MCP 2026-08-22 roadmap. The current-spec Ready rows (dual `tools/call`
  body, list caching, SEP-2243 routing-header binding) are done. Tasks,
  HTTP-over-stdio, WIF, and progressive discovery wait for a wire format.
  Cousin checks are named so they are not relabeled as the new primitives.
- **`routing_header_binding`** — SEP-2243: a discover-negotiated stateless
  HTTP server that returns a JSON-RPC result for `tools/list` tagged
  `Mcp-Method: tools/call` is MEDIUM. Load balancers route on the header;
  if the app honours the body, they disagree. Silent on legacy, stdio, and
  the AUTO tools/list-only fallback (that path is not a 2026-07-28 claim).
- **`list_cache`** — SEP-2549 `ttlMs` / `cacheScope` on `tools/list`,
  `resources/list`, `prompts/list`, and a sample of `resources/read` (up to
  five URIs; skipped under `--no-invoke`). Silent when the fields are
  absent, so servers that have not implemented caching stay quiet. Invalid
  TTL or cacheScope is MEDIUM; mixed cacheScope across pages of the same
  list is HIGH (the spec requires one scope; mixed public/private is a
  shared-cache footgun). Mixed scope across different resource URIs is not
  that finding — each read is independently cacheable.

### Fixed

- **Taxonomy IDs reach `Finding.taxonomy_id`.** `ssrf_probe` is MCP-T06 and
  `dpop_enforcement` is MCP-T43 on the finding, not only inside the evidence
  dict — SARIF tags and `--by-lane` can see them. `shell_injection` was
  emitting MCP-T54 (unauthenticated inference backend); it now emits MCP-T53
  (shell command wrapping), matching `shell_wrapping_injection`. T54 stays on
  `inference_backend`. Coverage stays 40/57; the IDs were already counted.
- **`structuredContent` is no longer invisible when `content` is a list.**
  `_response_text` used to return after extracting content blocks, so every
  poisoning, credential, and injection check that uses the helper missed the
  structured half of a `tools/call` result. An empty content list hid it
  too. Both bodies are now scanned. No dedicated check: fixing the extractor
  is the scan.

## [6.16.0] - 2026-08-11

Two independent threads: mcpnuke becomes installable, and three checks stop
reporting an authentication failure on a transport that has no authentication.

### Distribution

**mcpnuke becomes installable.** Until now the only way to get it was to clone
the repo. This release adds an installer and a publish pipeline, so the next
tag pushed puts `pip install mcpnuke` and `uv tool install mcpnuke` within
reach.

#### Added

- **`install.sh`** — one-liner installer for people who want the tool rather
  than the repo. Picks `uv tool`, `pipx` or `pip --user`, whichever is
  available; all three isolate the install so mcpnuke's pins cannot disturb
  the rest of your Python. `--extras`, `--version`, `--from` and `--dry-run`
  are supported. `quickstart.sh` is unchanged and remains the way to set up a
  development clone.
- **`.github/workflows/publish.yml`** — publishes to PyPI on a `vX.Y.Z` tag
  via OIDC trusted publishing, with no stored API token. It runs the full
  suite, refuses to build if the tag disagrees with the packaged version, and
  installs the built wheel into a clean environment to check both console
  scripts before uploading anything.
- **`scripts/check-tag-version.sh`** — the tag/version guard, as a tested
  script rather than inline workflow YAML. A PyPI version can never be
  replaced or reused, so a tag shipping the wrong artifact burns that number
  permanently.
- **`tests/test_packaging.py`** — invariants that are invisible from a source
  checkout and would first be hit by someone who just ran `pip install`.

#### Fixed

- **`mcpnuke-runner` no longer prints a traceback in a base install.** It is
  installed by the base package but implemented behind the optional `server`
  extra, so `pip install mcpnuke && mcpnuke-runner` produced a raw
  `ModuleNotFoundError` for pydantic. It now explains that the extra is
  needed and exits 2. The scanner itself never required it.

#### Changed

- `[project.urls]` gains Homepage, Documentation and Changelog links, which
  are what PyPI renders in the project sidebar.

### Findings

**Findings change again, in the same direction.** Three checks reported a
missing authentication boundary on stdio, a transport that has none to miss.
They fired on 5 of 5 pinned open-source servers — 100%, the signature of a
finding that carries no information. A scan of an **unchanged** stdio server
now reports 15 fewer findings across those five: 185 → 170, and **34 HIGH →
24**. The re-snapshot was a pure deletion; nothing else moved.

All three remain fully active on HTTP and SSE, where the boundary is real.

#### Fixed

- **`pre_auth_injection` no longer fires on stdio.** "N tools available
  without authentication" is true of every stdio server, because the
  transport is a pipe with nowhere to put a credential.
- **`anon_budget_exhaust` no longer probes stdio at all.** It returns before
  the burst rather than filtering the finding afterwards, sparing a local
  server 25 pointless calls per scan. There is no auth boundary to bypass and
  no second caller whose quota could be exhausted.
- **`native_function_identity_erasure` no longer fires on stdio.** stdio has
  exactly one caller — the process that spawned the server, running as the
  user who launched it — so there is no ambiguity to erase, and a `caller_id`
  parameter would be self-asserted by that same client.

#### Added

- **A stdio reference target and false-positive gate**
  (`tests/reference_target/stdio_server.py`,
  `tests/test_false_positives_stdio.py`). The harness measured HTTP only,
  which is how three checks shipped reporting findings on every stdio server.
  It reuses the existing tool schemas and hardened handlers, so only the
  transport differs, and it carries an invariant that no auth-shaped check may
  fire where there is no auth boundary. It found the third check on its first
  run.
- **First tests for `pre_auth_injection` and
  `native_function_identity_erasure`,** neither of which had any.

#### Known

- `behavioral_rate_limit` still fires on all five stdio targets. It was
  grouped with the class above originally and deliberately left alone: an
  agent stuck in a loop really can hammer a local server, so it needs its own
  decision rather than the same filter.

## [6.15.0] - 2026-08-10

**Findings change in this release.** Two classes of false positive stop firing,
so a scan of an **unchanged** server reports fewer of them and `--diff` against
an older baseline shows them as resolved. That is the fix landing, not the
server changing. Measured across five real open-source MCP servers: 211
findings → 185, and **71 CRITICAL → 18**, a 75% cut with no true positive lost.

Only two findings disappear outright. The rest are re-graded to LOW, where they
stay visible and countable, and `--error-reflection keep` restores the previous
severities exactly for anyone who needs a clean diff against an old baseline.

### Fixed

- **A server refusing bad input was scored as a vulnerability.** Five probes
  looked for a marker that was itself part of the payload they sent, so a
  server that rejected the call and quoted the offending input handed the
  marker straight back: `Repository not found: /tmp/<canary>` was read as proof
  the server had obeyed an injected instruction. Across five real servers this
  was **61 findings, 29 of them CRITICAL** — on `server-git` it was every
  single tool.

  Responses now have the payload subtracted before the marker is looked for. If
  the marker survives, the server produced it; if it vanishes, we were reading
  our own input. Findings whose only evidence is such an echo report at LOW and
  say so in the title. `--error-reflection {downgrade,keep,suppress}` controls
  the weighting, defaulting to `downgrade`.

  Two exemptions are deliberate: shell error text like `sh: 1: foo: not found`
  keeps its severity even under `isError`, because a shell errors *because* it
  parsed the payload, and credential leakage is untouched, because a secret in
  an error string is a leak either way.

- **`multi_vector` and `attack_chain` counted LOW findings as active attack
  vectors.** Both built their vector set from finding names with no severity
  filter, so a CRITICAL "multi-vector attack" could rest entirely on evidence
  graded LOW. A check now counts as a vector only when it has a finding at
  MEDIUM or above. Two CRITICALs on real servers were resting on exactly that.

- **The logic for "did this call fail" existed twice and reached neither
  probe.** `exfil_flow` and `chain_replay` each carried a private, byte-identical
  copy — written after treating "permission denied" as confirmed exfiltration —
  and none of the probe checks had it at all. Now one definition in
  `checks/base.py`, with a test that fails if a second appears.

- **Dangerous-capability patterns matched substrings, not words.** `shell_exec`
  matched `run` inside "running" and `sh` inside "show"; `reverse_shell` matched
  `nc` inside "reference", "branch" and "encoding"; `secrets_access` matched
  `key` inside "monkey". Real servers collected CRITICAL findings for tools
  named `git_show`, `git_branch`, `get-resource-reference` and
  `trigger-long-running-operation`, none of which execute anything —
  `remote_access` alone went from 14 findings to **zero across all five
  targets**, every one a false positive.

  Six further CRITICALs disappeared as a consequence, because they were derived
  from the false ones: three `attack_chain` findings were chaining into a
  `remote_access` that did not exist. Patterns are now anchored and applied to
  a normalized identifier, so `run_command` still matches while `long-running`
  does not.

- **A capability that was never reported.** The same fix closed a false
  negative: the pattern held a literal `file_read`, which never matched a
  dot-separated `file.read`, so that tool's filesystem access went unreported.

### Added

- **Open-source target snapshots.** Five pinned third-party MCP servers are
  scanned locally over stdio and diffed against committed snapshots, with every
  finding triaged in writing in
  [docs/oss-target-baseline.md](docs/oss-target-baseline.md). Opt-in locally
  via `MCPNUKE_OSS_TARGETS=1`, run weekly in CI. This is the first
  false-positive measurement against servers we did not write, and the first
  coverage of **stdio**, **resources** and **prompts**.

        The triage also records what is still wrong and unfixed. It named two
    classes; the larger one — a server's *error message* echoing your input
    being read as reflection — is fixed above. The remaining ~15 auth findings
    fire on a transport that has no auth boundary, and are still open.

## [6.14.0] - 2026-08-09

First tagged release since 6.13.0 (2026-05-19). Three months of work, and the
first release cut as an actual git tag and GitHub release rather than a
changelog heading alone.

**Findings change in this release.** Three checks stopped producing false
positives, so a scan of an unchanged server will report fewer findings than it
did on 6.13.0 — `--diff` against an older baseline will show them as resolved.
That is the fix landing, not the server changing.

### Added

- **`--version`** — there had been no way to ask an install which build it was.
  For a scanner that matters: the answer decides whether a report came from a
  build where a given check was still emitting a known false positive.

### Fixed

- **`auth` no longer claims unauthenticated access on authenticated scans.** The
  finding fired on a successful legacy handshake alone, so a scan run with
  `--auth-token` against a server requiring it was reported as "accepted
  initialize with no credentials" — telling operators their access control was
  missing while it worked.
- **`code_execution` matches parameter names by token, not substring.** `query`
  on any search tool, plus `country_code`, `zipcode` and `status_code`, were all
  reported HIGH as execution-like. Ambiguous names now require execution context
  in the tool text. This also cleared a CRITICAL `multi_vector` finding derived
  from it.
- **`.trufflehog.yaml` never worked.** Every key in it — `exclude_detectors`
  and `exclude_paths` — is absent from TruffleHog's config schema, so the tool
  aborted with "unknown field" on each run and none of the exclusions it
  appeared to declare had ever been applied. Replaced by
  `./scripts/secret-scan.sh`, which passes both on the command line and gates
  on verified findings only, since the repo intentionally ships fake
  credentials as scanner fixtures.
- **DPoP reports an absent implementation once, not three times.** A server
  without DPoP returns 200 to all three probes by construction, so probes 2 and
  3 restated probe 1 and called the proof header "decorative" on a server that
  never claimed to support it.

### Changed

- **ROADMAP / README** — document Priority Actions, hop-aware `--generate-policy`,
  and lab baseline fixtures; mark nullfield policy generation as shipped. README
  gains Authorized Use, Contributing, and License sections.
- **Packaging** — `pyproject.toml` moves to PEP 639 (`license = "MIT"` plus
  `license-files`), so built wheels carry `License-Expression` and bundle the
  LICENSE file. Redundant OSI classifier removed.
- **`MYPY_CEILING` lowered 47 → 42** to the current cold-cache count, applying
  the ratchet rule CONTRIBUTING.md documents. CI had been emitting its "mypy
  improved; lower the ceiling to lock it in" notice unheeded.
- **ROADMAP contributor snippet corrected** — the previous example used
  `async def check_x(session, findings)`, a `Severity` enum, and
  `findings.append(...)`, none of which match the codebase. It now points at
  CONTRIBUTING.md and the real `result.add` / `time_check` contract.

### Added

- **False-positive gate** (`tests/test_false_positives.py`,
  `tests/reference_target/`): a hardened stdlib MCP server scanned by the real
  pipeline in default CI. Fails on any unexpected CRITICAL or HIGH and caps
  total findings with a ceiling that ratchets down. The first true end-to-end
  test in the default suite — DVMCP and Camazotz are both env-gated and both
  deliberately vulnerable, so neither could measure quiet. First run: 13
  findings on a clean server, 4 after triage. See
  `docs/false-positive-baseline.md`.

- **Project governance** — `SECURITY.md` (private vulnerability reporting, what
  counts as a scanner-side vulnerability vs a detection bug, authorized-use
  guidance) and `CONTRIBUTING.md` (setup, real check-authoring signatures,
  severity calibration, guarded invariants).
- **Priority actions** (`reporting/priority.py`): every console and JSON report
  includes a proof-ranked "fix these first" list. Out-of-band / reproduced
  chains outrank capability inventory noise (`excessive_permissions` collapsed).
  Each action carries deterministic **impact / fix / verify** guidance for
  operators. Target-agnostic — ranks finding shapes only, not lab-specific names.
- **`--generate-policy` from proved chains** (`policy/generator.py`): out-of-band
  / reproduced `llm_chain_replay` and live-confirmed `exfil_flow` findings emit
  hop-aware NullfieldPolicy rules — **DENY** the sink, **HOLD** earlier sources
  (timeout → DENY). Unproven “callable end-to-end” chains stay out of policy.
  Operators can still edit the YAML; no new CLI flag.
- **Lab baseline harness** (`tests/test_lab_baselines.py`, `tests/fixtures/scans/`):
  offline Camazotz/DVMCP-shaped fixtures assert Priority Actions still rank
  proved chains above capability spam, guidance stays non-empty, and hop-aware
  policy DENY/HOLD still fires. Optional `CAMAZOTZ_LIVE=1` soft oracle. Golden
  VMs are out of scope (not MCP-facing).
- **Chain-replay hardening** (`core/chain_replay.py`, `checks/llm_analysis.py`):
  the propose-execute-judge loop is now a full red-team cycle, not just a
  single pass.
  - **`--safe-mode` gate**: each replay step is refused before the call when
    the tool is classified dangerous — the same classifier single-tool probes
    use — so a proposed chain cannot widen blast radius past what `--safe-mode`
    already forbids. Dangerous keywords now include webhook / callback /
    egress / exfil sinks (`shadow.register_webhook`, `egress.fetch_url`, …).
  - **Out-of-band chain confirmation**: when `--oast` is also set, chains may
    plant `{{oast.url}}` in a sending step; a callback proves a multi-step
    chain moved data off the target (egress-confirmed CRITICAL), not merely
    that the sink accepted it. `CanaryListener.await_hits` gives sinks a short
    grace period before the verdict (shared with `exfil_flow`), and
    `propose_chains` steers toward fetch/send-now sinks so register-only
    webhooks are not the end of the chain.
  - **Graded verdicts**: callable-but-unproven chains (ran end-to-end with no
    proven data movement) are reported MEDIUM instead of being discarded;
    halted chains stay silent.
  - **LLM judge for transformed movement**: under `--claude`, a callable-
    unproven transcript can be upgraded to HIGH when the model can name the
    transformation (base64, field extraction) that substring matching missed.
    Deterministic CRITICAL claims are untouched.
  - **`--chain-replay-retries N`** (default 1): a halted chain feeds its
    failing transcript back to the model for one bounded repair-and-retry;
    0 disables revision. Safe-mode still applies to every revision. Phase 4
    logs each revise/retry attempt so halt→repair is visible in `--verbose`
    output.
- **MCP 2026-07-28 stateless protocol support** (`core/protocol.py`): mcpnuke now
  scans servers speaking the stateless spec alongside legacy handshake servers.
  - `--protocol-mode {auto,legacy,stateless}` — `auto` (default) probes for
    whichever protocol the server speaks.
  - `Mcp-Method` / `Mcp-Name` / `MCP-Protocol-Version` routing headers (SEP-2243),
    with CR/LF stripped so a hostile tool name cannot smuggle extra headers.
  - Per-request client identity in `params._meta`
    (`io.modelcontextprotocol/clientInfo`), replacing the retired handshake.
  - `server/discover` probing, with a new Lane 5 / Transport A finding
    **"Unauthenticated MCP server/discover accepted"** when an anonymous caller
    can read server capabilities.
  - `TargetResult.protocol_mode` records the negotiated protocol for reporting.
- **MCP-T01 prompt injection probe** (`checks/prompt_injection_t01.py`): Behavioral
  check injecting instruction-override canaries in AI-facing tool parameters.
  Detects unsanitized passthrough to LLM context.
- **MCP-T02 tool output poisoning** (`checks/tool_output_poisoning.py`): Behavioral
  scan of tool responses for embedded instruction patterns (override commands,
  role markers, token boundaries) that would manipulate downstream agents.
- **MCP-T03 credential forwarding** (`checks/tool_output_poisoning.py`): Static
  detection of tools accepting both credential AND endpoint parameters — enabling
  credential theft by design.
- **MCP-T05 command injection (broad)** (`checks/command_injection_broad.py`):
  Behavioral probe testing ALL string params for shell metacharacters, not just
  shell-named tools. Catches injection in tools that internally shell out.
- **MCP-T08 remote package execution** (`checks/remote_package_exec.py`): Static
  detection of tools that fetch+execute remote code (npx, uvx, pip install URL,
  curl|sh, git clone+exec patterns).
- **MCP-T10 agentic loop** (`checks/agentic_loop.py`): Static + behavioral.
  Detects meta-tools (accept tool-name params), unbounded repetition, orchestration
  patterns, and tool-call JSON in responses that could trigger recursion.
- **MCP-T13 insecure agent comms** (`checks/insecure_agent_comms.py`): Static
  detection of unsigned inter-agent messaging tools. Skips tools with signature/
  HMAC/attestation parameters (safe).
- **MCP-T15 model routing** (`checks/model_routing.py`): Static detection of
  attacker-controllable model selection (management tools, model params, routing
  descriptions).
- **`core/transports/base.py`**: `MCPSessionProtocol` and `HTTPCapableSession`,
  the first shared contract across the four transports. 42 previously untyped
  `session` parameters now declare it, so a check can only rely on what every
  transport provides, and `post_raw` is an explicit capability rather than a
  member some transports raise on.
- **`patterns/credentials.py`**: single source of truth for credential detection,
  replacing five divergent definitions. Tiered by false-positive risk —
  `STRUCTURAL_CREDENTIALS` (shape-based, safe on tool schemas),
  `KEYWORD_CREDENTIALS` (`password: <value>`, body text only, since they also
  match a JSON Schema property declaration), `VENDOR_CREDENTIALS` (lab formats),
  and `REFERENCE_PATTERNS` (paths pointing at a secret). Backed by a golden
  corpus (`tests/test_credential_patterns.py`) asserting every consumer detects
  the same set, which is what stops the drift recurring.
- **ROADMAP.md**: Full taxonomy gap map (56 IDs), tiered priority, live test targets.

### Fixed

- **Phase 3/4 crash on structured finding evidence**: `tool_shadowing` stores a
  dict in `Finding.evidence`. Digesting it for the LLM used to raise
  `KeyError(slice(...))` and abort chain reasoning/replay on DVMCP challenge 5.
  Non-string evidence/detail is now serialized before clipping.
- **`--safe-mode` missed namespaced dangerous tools**: the danger classifier
  only split tool names on `_` and `-`, so Camazotz tools like `shellwrap.exec`
  and `sdk.write_cache` were still invoked under `--safe-mode` / chain replay.
  `.` is now a name separator (same class of bug as the earlier exfil dotted-name
  fix). Live re-run: 12 proposed chains → 2 MEDIUM reported, 0 CRITICAL.

### Changed

- **Docs synced to chain-replay / OAST / safe-mode hardening**: CLI
  help (and generated `docs/cli-reference.md`), `docs/ai-analysis.md`,
  `docs/checks.md`, and `docs/scan-modes.md` now describe graded chain
  verdicts, `await_hits` grace period, fetch-now propose guidance, revise
  logging, and webhook/egress/exfil dangerous keywords. Guarded by
  `TestChainReplayDocsCurrency`.
- **README restructured from 1018 lines to 304, with a table of contents.**
  Reference material moved into `docs/`, and the parts with a machine-readable
  source are now generated rather than transcribed: `docs/cli-reference.md` is
  rendered from the argparse parser, and coverage tests fail the build when a
  registered check or deep probe is missing from `docs/checks.md`. Relocating
  the prose without generating it would only have moved the problem — the
  hand-written reference had drifted to 62 of 76 flags with 8 documented
  nowhere, seven check severities disagreed with the code that emits them, and
  two working checks were invisible in the docs after being repaired. New
  documents: `docs/cli-reference.md`, `docs/checks.md`, `docs/scan-modes.md`,
  `docs/ai-analysis.md`, `docs/kubernetes.md`, `docs/methodology.md`. A link
  checker resolves every relative link across the project's markdown, and a
  length cap keeps reference material from creeping back into the README.
- **`mcpnuke --help` groups its 76 flags into 15 sections** instead of printing
  one flat list, and opens with a one-line usage summary rather than 31 lines of
  flag soup. The grouping previously existed only inside a README code block.
  `--doctor` moved out of `Output` — it is a mode that exits before scanning —
  and `--coverage` now sits with `--fast`, which is documented as its alias.
- Seven check severities in the inventory corrected against the emitting
  `result.add(...)` call: `excessive_permissions`, `credential_in_schema`,
  `config_tampering`, `exfil_flow`, `webhook_persistence`, `input_sanitization`
  and `response_credentials`. Documentation only; no behaviour changed.
- Enumeration negotiates the protocol (`initialize` → `server/discover` → bare
  `tools/list`) instead of assuming the legacy handshake. Previously a
  stateless-only server scored as a zero-tool target, silently disabling every
  downstream check.
- `Mcp-Session-Id` is now sent only in legacy mode — the header is retired by
  SEP-2567. `notifications/initialized` is likewise legacy-only.
- `MCPSession` (HTTP+SSE) intentionally stays on the legacy path; the 2026-07-28
  spec deprecates that transport with a twelve-month offramp.
- **CI actually runs now.** The Tests workflow had been failing on every run:
  `setup-uv` used `enable-cache: true`, whose `**/uv.lock` glob finds nothing
  because the lock file is untracked, so the job died before pytest. A `lint` job
  gates the suite — `ruff` strict at zero, `mypy` on a ratchet (ceiling 63,
  measured cold). First green run: ruff clean, mypy 63, 714 passed on 3.12+3.13.
- `uv.lock` is tracked, so CI installs one pinned set of 57 packages via
  `uv sync --frozen` with uv's cache restored. A `uv lock --check` step fails the
  build when `pyproject.toml` is edited without re-locking, since `--frozen`
  would otherwise install the stale set silently.
- Lint debt cleared: `ruff check` goes 370 → 0 errors. Scan findings verified
  byte-identical before and after across 359 findings.
- `mypy` errors 81 → 63, entirely by resolving lazily-imported optional extras in
  config, then 63 → 48 once `core/` was fully annotated. The CI ceiling tracks
  each drop, so the ratchet only tightens. No `# type: ignore` was added; the
  repo still has none.
- `mcpnuke.core.*` now enforces `disallow_untyped_defs`. With every function in
  the package annotated, the stricter setting is free to turn on and keeps the
  transport and model layer from regressing.
- Repo slimmed: nine scan reports (1.3 MB) untracked from `profiles/`, which now
  holds only the three hand-written target profiles. `pytest-asyncio` dropped as
  an unused dev dependency.
- Model ids audited against both provider catalogs (`GET /v1/models`,
  `bedrock list-foundation-models`) rather than assumed. Retired ids were still
  named in five test fixtures, where they were harmless — the calls are mocked —
  but advertised dead models to anyone reading them for a working example; they
  now name current ones. A guard test fails if any tracked document mentions a
  known-retired id, with the changelog exempted so it can keep describing the
  retirements. `gpt-4` appears only as fixture data standing in for a *scanned
  target's* advertised models and was confirmed still served; mcpnuke itself
  has no OpenAI call path, so there is no OpenAI default to rot.

### Added

- **Propose-execute-judge chain replay** (`core/chain_replay.py`,
  `--chain-replay`): phase 3's chains were arguments — "these tools compose" —
  with nothing to show they would. A new opt-in phase asks the model for
  chains as executable steps (`tool` + `args` with `{{stepN.output}}`
  placeholders), runs them against the live session, and reports CRITICAL only
  when an earlier step's output appears in a later request. Three verdicts,
  not two: halted, callable end-to-end without data movement, or reproduced
  with a transcript. Verified against Camazotz: a four-step chain
  (`subchain.spawn_agent` → `run_task` → `read_env_inheritance` →
  `comms.send_message`) completed with `AGENT_TOKEN: user-session-token-123`
  as the moved fragment. Off by default; ignored under `--no-invoke`.
- **Out-of-band egress verification** (`core/oast.py`, `--oast`): a callback
  listener the scanner controls, so exfiltration can be proven rather than
  inferred. Every signal the scanner had was in band — it asked a tool
  something and read the reply — which shows a path is *callable* but cannot
  show the payload went anywhere; a sink answering `{"status": "sent"}` and one
  answering it while discarding the data are the same conversation.
  `exfil_flow` now mints a token per source-sink pair and plants its URL in the
  canary alongside the source data. A request for that token means the target
  reached an address that existed nowhere else, which no tool response can
  counterfeit, and the finding becomes "Live exfil confirmed" with the callback
  as evidence. With no callback the wording stays at the weaker, honest claim,
  because a target with no outbound network is indistinguishable from one that
  dropped the payload. `--oast-host` sets the address advertised to the target,
  which a container or remote host needs; `--oast-port` fixes the port for a
  firewall rule. Off by default: it opens a socket and induces the target to
  send data outward.
- **Credentials written into description prose** (`patterns/credentials.py`):
  a new `PROSE_CREDENTIALS` tier, folded into `SCHEMA_CREDENTIALS`, matching a
  quoted literal assigned to a credential noun. Camazotz publishes "service API
  key is 'svc-internal-abc123'" in a tool description, so the key reaches every
  client that calls `tools/list`; the deterministic scan raised twenty findings
  against that tool and none was the key. `STRUCTURAL` had no shape to match on
  and `KEYWORD` is barred from tool definitions because its value clause is
  satisfied by a property declaration. The discriminator neither used is
  quoting: a leaked value is a quoted literal, a declared property is a type
  object opening with a brace. Requiring a quote after the separator admits the
  leak and rejects the declaration. Verified against the live 139-tool surface:
  one hit, the true positive, and no false positives among the 108 tools that
  publish schemas.

### Changed

- **Phase 1 is grounded in what the deterministic scan already found**
  (`core/llm.py`, `checks/llm_analysis.py`): it runs after the checks but was
  never given their findings, so it re-derived them less precisely and filed
  the result at its own severity. On DVMCP challenge 5 the scanner reported
  HIGH "Confusable tool names: 'get_user_role' vs 'get_user_roles' ...
  similarity 96%" and phase 1 reported LOW "Redundant/duplicate tool surface"
  about the same pair — one issue, two entries, contradicting each other. The
  prompt now lists the deterministic findings, tells the model not to restate
  them, and invites explicit disagreement instead of a quieter duplicate.
  Measured on that challenge: the duplicate is gone, the model instead argues
  the severity directly, and it surfaces a real coverage gap — the scanner
  flagged the unconstrained parameter on `get_user_role` but not on its
  identical sibling. AI findings are excluded from the grounding so a mistake
  cannot harden across phases.
- **Tool shadowing named as a phase 1 threat class**: unprompted, the model
  read two near-identical tool names as redundancy rather than as an attack on
  agent tool selection.
- **The phase 1 prompt is shared by every backend** (`core/llm_ollama.py`): it
  existed twice and the copies had drifted, with the Ollama one still pinning
  the taxonomy to a hardcoded `MCP-T01 through MCP-T55` range — exactly the
  drift `taxonomy_id_clause()` was added to prevent. The Ollama backend also
  gains the grounding.
- **Chain reasoning is given the evidence it is asked to reason from**
  (`core/llm.py`, `checks/llm_analysis.py`): phase 3 asks for multi-step
  exploitation paths, then received finding titles with no detail, evidence or
  tool attribution, and tools as a name plus 100 characters of description with
  no parameters — so it could not say how data moves between two tools because
  it was never told what either accepts or returns. The payload was also cut
  with a blunt slice of already-serialized JSON, so the prompt carried a
  document that ended mid-string.
  - Findings now carry `detail`, `evidence`, `taxonomy_id` and the `tool` named
    in their title; tools now carry their parameter names and types.
  - `_fit()` budgets by whole items, so the prompt is always valid JSON.
  - `_diverse_findings()` round-robins across checks, worst instance first.
    Volume and importance are unrelated — Camazotz reports 233 instances of one
    check and exactly one of eight others — so a prefix spent the budget on
    repeats and dropped every rare class.
  - Budgets raised to 40k characters of tools and 60k of findings, sized so a
    139-tool target with 47 vulnerability classes fits whole (~25k input
    tokens, an eighth of the context window).
  - Measured on Camazotz: tools shown went from 18 of 139 in malformed JSON to
    139 of 139 valid, vulnerability classes represented from roughly 6 of 47 to
    47 of 47, with 208 parameters, 116 details and 96 tool attributions now
    present where there had been none.

### Fixed

- **Namespaced tools were never classified as exfiltration sources**
  (`checks/exfil_flow.py`): `_classify_tool` split the tool name on
  `[_\-\s]+` to match its parts against keyword sets, and a dot is not in that
  class, so `vault.read_secret` split to `{'vault.read', 'secret'}`, `read`
  never appeared, and the tool was not a source. Namespacing is the norm — all
  139 tools on the Camazotz target carry a dot — and sinks sometimes survived
  by accident where the trailing segment was itself a keyword
  (`notify.send_message` matched on `message`), which hid the gap. Adding the
  dot as a separator takes that target from 48 recognised sources to 72.
- **Truncated AI responses read as clean targets** (`core/llm.py`): the two
  phases that reason across a whole target asked for at most 2000 output
  tokens, and `_parse_findings` answers `[]` on `JSONDecodeError`, so a
  response cut mid-array was indistinguishable from "nothing found". The
  failure is inverted — output length tracks how much the model found, so the
  ceiling bit hardest where the analysis was worth most. Measured against a
  synthetic finding set, every call from 5 findings upward stopped on
  `max_tokens` and yielded zero parsed findings; this is why a live Camazotz
  scan reported four findings from phase 2, whose per-response prompts stay
  small, and zero from phases 1 and 3. Three changes: `_ANALYSIS_MAX_TOKENS`
  raises the budget to 8000 (observed use is 2770–3792, so there is real
  headroom), `_complete_objects()` salvages the objects that completed before
  any future cut instead of discarding the response, and a truncated stop
  reason is now logged rather than passing in silence.
- **"Live exfil confirmed" fired on refusals** (`checks/exfil_flow.py`):
  `_try_sink_send` decided success with `sent = resp is not None`, but
  `_call_tool` returns the response whenever the JSON-RPC round trip completes,
  so `{"error": ...}` and `{"result": {"isError": true}}` both counted. A sink
  answering "permission denied" produced a CRITICAL finding claiming the canary
  was "successfully routed" and the payload "accepted". A new `_is_failure()`
  rejects transport failures, JSON-RPC errors and `isError` results, and the
  wording now claims only what is observable in band: the sink accepted a
  payload carrying source data without erroring. Delivery is explicitly *not*
  asserted, because the scanner has no out-of-band oracle to observe egress.
- **Attack chains claimed linkage they had not established**
  (`checks/chaining.py`): `check_attack_chains` intersects the set of checks
  that fired against a 34-pair table and emitted CRITICAL regardless of whether
  the two findings could reach each other, so two unrelated tools with
  unrelated flaws scored the same as a real source-to-sink path. Chains are now
  graded by the evidence available. A shared tool between both ends stays
  CRITICAL and names it. Two tool-scoped findings with disjoint tool sets are
  positive evidence of no shared entry point and grade to HIGH, labelled as
  unproven. A target-scoped finding (auth, transport) names no tool and could
  reach anything, so silence is not treated as evidence and the severity
  stands, with the basis stated as co-occurrence rather than implied.
  `AttackChain` carries `shared_tools` and `linkage`, both surfaced in JSON —
  the chain dict is hand-built, so a test now asserts every dataclass field is
  serialized, which is how `shared_tools` was caught going missing.
- **`--claude` failed on every invocation** (`core/constants.py`): the default
  model `claude-sonnet-4-20250514` was retired upstream, so the API answered
  `not_found_error` and all three AI phases produced nothing. The id was copied
  across eight call sites in five modules, which is why the rot went unnoticed;
  it now lives once as `DEFAULT_CLAUDE_MODEL` and is an undated alias
  (`claude-sonnet-5`), since dated snapshots are the ones that get retired. A
  test asserts the default is alias-shaped and that no module hardcodes the
  retired id, matching on string literals so the explanatory comment does not
  trip it.
- **`--bedrock` invoked a model that no longer exists** (`core/constants.py`):
  the default `anthropic.claude-3-5-sonnet-20241022-v2:0` had reached end of
  life and was absent from `list-foundation-models` altogether, so the runtime
  answered `ResourceNotFoundException`. The replacement is a
  `DEFAULT_BEDROCK_MODEL` constant set to
  `us.anthropic.claude-sonnet-4-5-20250929-v1:0`, chosen against two
  constraints the direct API does not have: current Anthropic models on
  Bedrock are `INFERENCE_PROFILE` only, so a bare `anthropic.*` id cannot be
  invoked, and the undated alias `anthropic.claude-sonnet-5` returns
  `AccessDenied` without a specific entitlement — picking it would have
  reproduced the same out-of-the-box failure. This is why the Bedrock default
  names a dated version where the direct API default deliberately does not.
  `docs/ai-analysis.md` now documents the profile prefix so non-US callers
  know to substitute `eu.`/`apac.`/`global.`. Verified end to end: a
  `--claude --bedrock` scan with no `ANTHROPIC_API_KEY` produced 11 AI
  findings including five reasoned attack chains, where the same command
  previously produced none.
- **Extended thinking silently voided every AI finding** (`core/llm.py`): both
  the SDK and Bedrock paths read `content[0].text`, but current models return a
  `thinking` block first and the answer in a later `text` block. Against
  `claude-sonnet-5` this raised `AttributeError: 'ThinkingBlock' object has no
  attribute 'text'` per phase; the handlers log at verbose level and continue,
  so a default-verbosity scan spent 35s of billed API calls and reported zero
  AI findings with no visible error. A shared `_response_text()` now joins the
  text blocks, excluding known non-text kinds by type rather than admitting
  only exact `type == "text"`, so a payload still counts when the type field is
  absent.
- **AI findings invented threat identifiers** (`core/llm.py`): the chain
  reasoning prompt asked for a "MCP threat taxonomy ID if applicable" without
  naming the vocabulary, and against a live DVMCP target the model returned
  `MCP-2024-AUTH-001` and similar — ids that map to nothing in the 57-entry
  taxonomy. Both prompts now share `taxonomy_id_clause()`, derived from
  `threat_ids()` so it tracks the taxonomy instead of drifting the way the
  hardcoded "MCP-T01 through MCP-T55" had. Parsing drops out-of-taxonomy ids
  while keeping the finding, and normalizes case and zero-padding.
- **Confusable tool names went undetected** (`checks/chaining.py`,
  [MCP-T25]): `check_tool_shadowing` only matched a fixed list of common names
  or exact collisions across *different* targets, so DVMCP challenge 5 — which
  serves `get_user_role` beside a `get_user_roles` that returns admin for
  everyone — produced nine findings, none about shadowing. Same-server pairs are
  now compared by name similarity, calibrated on real tool vocabularies where
  legitimate neighbours peak near 0.71 (`read_file`/`write_file`) and the decoy
  pair scores 0.96. A near-identical description raises the finding to HIGH,
  since that turns name ambiguity into a deliberate trap. Live re-scan of
  challenge 5 now reports it at HIGH with 96% name and 100% description
  similarity.
- **`--fast`'s help text named four skipped probes where the code skips five**
  (`cli.py`): `FAST_SKIP_CHECKS` gained `sdk_cache_poisoning`, which mutates
  target state, and the help string was never updated. Generating
  `docs/cli-reference.md` from the parser proves the document matches `--help`;
  it does not prove `--help` matches behaviour, and this was a live instance —
  the generated document reproduced the wrong four faithfully and contradicted
  the hand-written `docs/checks.md`, which had it right. A test now asserts the
  help string names exactly the members of `FAST_SKIP_CHECKS`.
- **The README's exit-code table contradicted the README** (`README.md`): the
  table said exit `1` meant "at least one finding was reported", while the
  Quick Start section 120 lines earlier correctly described the `--fail-on`
  threshold. `_should_fail` defaults to `high`, so a scan reporting only LOW
  findings exits `0`; the table was the version `QUICKSTART.md` cited as
  authoritative. Both places now describe the threshold.
- **`docs/methodology.md` documented 18 of 34 attack chains** — missing all
  three JWT chains and both halves of `ssrf_probe` and `actuator_probe`. The
  table is now complete and pinned to `ATTACK_CHAIN_PATTERNS` by a test.
- **`docs/kubernetes.md` named two different paths for the same manifest
  directory**; only `mcpnuke/k8s/manifests/` exists on disk.
- New guards, each verified by breaking what it guards: the README's table of
  contents must reach every section (behind an explicit exemption list, since
  the two sections that fell out were "handoffs" nobody had recorded a decision
  about); every row in `docs/checks.md` must name something that runs, not just
  the converse; the check totals in both documents' prose are computed from the
  registry and the deep probe plan; the link checker validates `#fragments`
  against real headings instead of discarding them; and the probes chained
  inside the orphaned `run_dpop_enforcement_checks` must match
  `_DPOP_CHECK_NAMES`, since that function has no production caller but is
  where every DPoP test enters and so where a fourth probe would be added.
- **DPoP probes now actually test DPoP** (`checks/dpop_enforcement.py`,
  `core/session.py`): the three probes were dead code with three independent
  defects. They called `session.post()`, which no session class defines; they
  aimed at `base` (`scheme://host`, no path) rather than the MCP endpoint, so a
  request that did go out could never return 200; and they sent no auth, so a
  401 meant "no token" rather than "proof required" — reading as *enforced* and
  suppressing the finding either way. Sessions gained `post_raw()`, which reuses
  the session's own auth and endpoint; its presence is the capability test for
  "this transport has headers worth probing", so stdio skips instead of being
  probed meaninglessly. Verified against a live target: 3 HIGH findings
  (`dpop_not_enforced`, `dpop_header_not_validated`, `dpop_binding_not_enforced`).
- **DPoP probes no longer abort the scan** (`checks/dpop_enforcement.py`): the three
  probe error handlers called `result.errors.append()`, but `TargetResult` has
  `error: str` — so the handler meant to absorb a failed probe raised
  `AttributeError` itself. Reachable on any scan carrying a JWT. Single-target scans
  died with a traceback; under `run_parallel` the worker died and the target
  vanished from results without a message. Added `TargetResult.note_error()`.
- **`check_inference_guardrail_variance` is wired in and works** (MCP-T56,
  `checks/inference_backend.py`): the check was fully written and tested but never
  called, and it carried two defects that its own fixtures hid. It read model
  names only from `model_details`, which `fingerprint_backend` populates for Ollama
  and not for the OpenAI-compatible branch — a permanent no-op against vLLM,
  LocalAI, and LiteLLM; it now falls back to the flat `models` list.
  `_guardrail_probe_model` built `f"http://{host}/api/chat"` while every other
  probe in the module treats `host` as already scheme-qualified, producing
  `http://http://host:port/api/chat`. It also recorded no timing, unlike every
  other check. `check_inference_backend` now hands its fingerprints to the caller
  via `metas_out`, so the guardrail probe reuses that discovery instead of
  re-fingerprinting each host, and both inference checks are counted in progress.
- **Scan progress no longer overflows its own denominator** (`checks/__init__.py`):
  `total_checks` was hardcoded arithmetic assuming 17 static and 13 deep checks;
  the real counts are 33 and 24, and the teleport and inference sections were never
  counted. Verbose output showed `[38/35]` then `All 41 checks complete`. The
  denominator is now derived from the check inventory, and `--fast` is accounted for
  exactly via the pre-built deep-probe plan. The duration estimate uses the real
  deep count, so it now reads more conservatively than before. The three DPoP
  probes were a residual gap in that fix: invoked directly rather than through
  `_run`, they touched neither side of the ratio, so a JWT-bearing HTTP scan
  silently ran three more checks than it reported. They now run through `_run`
  and are counted only when the transport can carry a proof, which
  `dpop_enforcement.dpop_probeable` decides for both the counter and the probes.
- **`negotiate_protocol` wrote `session.protocol_mode` on transports that never
  declared it.** Python creates the attribute on assignment, so three of the
  four silently grew a field nothing read. All four now declare it.
- **`TargetResult.scan_diff` was typed `object`**, leaving the four attributes
  the JSON reporter reads off it unverifiable, and `__main__` bound the same
  local name to two unrelated diff types in one scope.
- **`ACTIVE_INJECTION_PAYLOADS` inferred as `list[dict[str, object]]`**, hiding
  every field access on the active-injection probes from type checking.
- **Response text was silently dropped before any check saw it**
  (`tool_probes._response_text`, and the weaker copy in `behavioral.py`):
  `content` defaulted to `[]`, which is a list, making the `message` and JSON
  branches below it unreachable. Every error response and any structured result
  without a `content` list extracted as the empty string, so no check scanned
  it. The `behavioral.py` copy additionally dropped `blob` content blocks.
- **Four prompt-injection markers existed only in `tool_output_poisoning`'s
  private pattern copy** — `<|im_end|>`, `from now on, …`, `override/bypass/
  disable safety`, and `system: you must` — so the primary `prompt_injection`
  check and three other consumers could not see them. Now shared via
  `rules.INJECTION_PATTERNS`, with an 18-marker corpus.
- **`.gitignore` silently excluded a source module**: the path-agnostic
  secrets rule `credentials.*` matched `mcpnuke/patterns/credentials.py`.
- **Credential detection was inconsistent across checks**, which is a
  false-negative class, not a tidiness one: the same secret was caught on one
  code path and missed on another, and the gaps were invisible. Five definitions
  disagreed — an Anthropic key hardcoded in a tool schema was missed by
  `credential_in_schema`, the check whose entire job is that, along with GitLab
  PATs, GCP keys, OPENSSH private keys, and Slack `xoxo-` tokens. A GitHub PAT
  shorter than 36 chars was seen by exactly one of three consumers, and a
  capitalized `Bearer ` by only one. Where definitions conflicted the wider one
  won, since a false negative on a distinctively-prefixed token costs more than
  a false positive a human dismisses. Also fixed: `actuator_probe` escalated any
  body containing a bare `sk-` to CRITICAL, and `tool_probes` passed
  `re.IGNORECASE` alongside the pattern, which raises outright on a compiled one.
  Verified against a 139-tool reference target: zero findings lost, zero gained.
- **`InferenceBackend.VLLM` did not exist** (`checks/inference_backend.py`): both
  references would have raised `AttributeError`. vLLM fingerprints as
  `OPENAI_COMPAT`, which is now used. Latent only because
  `check_inference_guardrail_variance` was not yet wired into `run_all_checks`.
- Recovered a test that never ran: two module-level `test_no_token_skips_silently`
  definitions in `tests/test_jwt_boundary.py`, the second shadowing the first.
- Static-check signatures: `credential_forwarding` + `remote_package_execution`
  had behavioral-style `(session, result)` signatures but were in the static phase
  (which passes only `result`). Fixed.
- `_add()` pattern: new checks incorrectly used `result.findings.append(_add({...}))`
  instead of the correct `_add(result, ...)` call pattern. Fixed.
- `prompt_injection_t01`: removed `command` from LLM-param keywords to avoid
  false-positive overlap with T05 command injection.

### Coverage

- Taxonomy: 14 → 22 IDs (25% → 39%)
- Tier 1 complete (8 of 9 checks; T11 cross-tenant deferred for multi-auth infra)
- Live-verified against DVMCP (10 challenges, K3s cluster) + brainbox AI analysis

## [6.13.0] - 2026-05-19

### Added

- **Ollama AI analysis backend + ensemble mode** (`mcpnuke/core/llm_ollama.py`): New `OllamaBackend` class implementing the `LLMBackend` protocol for zero-cost AI-augmented scanning. Two modes:

  **Single-model** (`--ollama-analysis URL --ollama-model MODEL`):
  - Drop-in replacement for `--claude`, same 3-phase analysis routed to a local or networked Ollama instance.
  - `qwen2.5:14b` on BRAINBOX produced 12 AI findings vs Claude's 11 in 16s vs 27s at $0 cost.
  - Startup pre-flight validates reachability and warns if the model is not pulled.
  - Mutually exclusive with `--claude` (enforced at startup).

  **Ensemble** (`--ollama-analysis URL --ollama-ensemble model1,model2,model3`):
  - Runs AI analysis independently with each model, then clusters findings by `taxonomy_id`.
  - Findings where 2+ models independently flag the same taxonomy ID → `[CONSENSUS Nx]` (high confidence, validated signal).
  - Findings unique to one model → `[CANDIDATE]` (worth reviewing but single-source).
  - `cluster_findings()` helper deduplicates by taxonomy, picks the most severe representative, preserves model attribution.
  - Answers "should I trust a finding the LLM mentioned once?" — if two independent models agree on a taxonomy class, you should.
  - Baselines saved: `profiles/camazotz-ollama-brainbox-scan.json` (single) and `profiles/camazotz-ensemble-scan.json` (3-model ensemble).

### Benchmark: BRAINBOX Ollama vs Claude Sonnet on camazotz

| Metric | Claude Sonnet | Ollama qwen2.5:14b |
|---|---|---|
| Total findings | 293 | 294 |
| Static findings | 282 | 282 |
| AI findings | 11 | 12 |
| AI analysis time | 27s | 16s |
| CRITICAL | 145 | 150 |
| HIGH | 97 | 93 |
| Risk score | 2333 | 2355 |
| API cost | ~$0.04 | **$0.00** |

Both models found roughly the same number of AI-layer findings (11 vs 12) with zero *title* overlap — but **both independently found MCP-T03** (credential forwarding). Title overlap is the wrong metric; taxonomy-ID overlap is the right one. Claude focused on cross-cutting narrative chains (MCP-AUTH-001, MCP-AUDIT-001); Qwen systematically enumerated per-tool credential-forwarding instances (MCP-T03 × 7). Qwen was also 40% faster (16s vs 27s).

### Ensemble run: `qwen2.5:14b` + `qwen2.5:7b` + `qwen3:4b` on camazotz

| Metric | Value |
|---|---|
| Models run | 3 (14b, 7b, 4b) |
| CONSENSUS findings (2+ agree) | **2** — MCP-T03 (CRITICAL), MCP-T02 (HIGH) |
| CANDIDATE findings (1 model only) | 4 |
| Note | qwen3:4b returned 0 findings — context window too small for 138 tools |

The 4b model is too small for a 138-tool server. Practical sweet spot: `qwen2.5:14b` + `qwen2.5:7b` as your ensemble pair. The two CONSENSUS findings (MCP-T03, MCP-T02) are the highest-confidence signal: two independently parameterised models both said "this is real."

## [6.12.0] - 2026-05-19

### Added

- **SDK token cache tamper detection** (`mcpnuke/checks/sdk_cache_tamper.py`, MCP-T33): New Lane 1 / Transport C check closing the last SDK-path coverage gap. Two check functions:
  - **`check_sdk_cache_tamper`** (static) — detects tools whose schema exposes a writable SDK token cache. Emits `HIGH` when a cache-write tool is present and upgrades to `CRITICAL` when the matching cache-invoke tool is also found (full two-step attack chain available purely from schema inspection, no network calls required).
  - **`check_sdk_cache_poisoning`** (behavioral) — executes the proof-of-concept: writes a forged admin JWT (unsigned, far-future `exp`) via the write tool, then invokes a privileged operation via the invoke tool. Flags `CRITICAL` when the response contains sensitive data (`db_password`, `api_key`, `reset_token`, etc.), confirming the SDK accepted the forged credential without signature validation. Flags `HIGH` when the write was accepted but the invoke response is ambiguous.
  - All findings tagged `lane=1`, `transport="C"`, `taxonomy_id="MCP-T33"` — properly classified as Human Direct / In-process SDK in the `--by-lane` and `--coverage-report` outputs.
  - Forged JWT targets easy difficulty (blind `cached_role` trust) and medium difficulty (expiry-only check, no signature verification). Hard-mode targets (full HS256 validation) correctly produce no findings.

- **30 new tests** (`tests/test_sdk_cache_tamper.py`): Pattern-matching correctness (write/invoke tool detection), JWT forge structure, `_pick_invoke_args` privilege ordering, static check severity tiers, behavioral CRITICAL/HIGH/clean scenarios, lane+transport tagging, and taxonomy ID assertions.

### Changed

- `mcpnuke/checks/__init__.py`: `check_sdk_cache_tamper` added to the static analysis phase; `check_sdk_cache_poisoning` added to the deep behavioral probe phase. Static check count bumped from 16 → 17.

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

  Live verification on the reference cluster deployment with a forged read-only
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
