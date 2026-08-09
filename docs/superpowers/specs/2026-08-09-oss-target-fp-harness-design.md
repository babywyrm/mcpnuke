# Open-Source Target False-Positive Harness

**Status:** Approved — not yet implemented
**Date:** 2026-08-09
**Follows:** `2026-08-08-false-positive-harness-design.md`

## Problem

`tests/test_false_positives.py` measures mcpnuke against a server **we wrote to
be quiet**. That is honest as far as it goes, and it found three real bugs, but
it cannot answer the question an evaluator actually asks: *what does this tool
say about a server somebody else wrote?*

A four-second static scan of the official MCP reference server answers it, and
the answer is bad.

### Evidence

`npx -y @modelcontextprotocol/server-everything@2026.7.4`, scanned with
`--no-invoke` (static only, no tool calls), produces **22 findings, 6 of them
CRITICAL**, on a demo server with no real capability:

| Severity | Check | Title |
|----------|-------|-------|
| CRITICAL | `excessive_permissions` | Dangerous capability [shell_exec]: `trigger-long-running-operation` |
| CRITICAL | `remote_access` | Remote access [reverse_shell]: `get-resource-links` |
| CRITICAL | `remote_access` | Remote access [reverse_shell]: `get-resource-reference` |
| CRITICAL | `exfil_flow` | Exfiltration path: sensitive data → `get-annotated-message` |
| CRITICAL | `multi_vector` | Multi-vector attack: 2 categories active |
| CRITICAL | `attack_chain` | Attack chain: exfil_flow → remote_access |

Two root causes are already identified, both **unanchored regexes in the shared
pattern library**:

```python
# mcpnuke/patterns/rules.py
"shell_exec":    r"(shell|exec|run|execute|cmd|bash|sh|powershell|eval|system)"
"reverse_shell": r"(nc|ncat|socat|netcat|bash\s+-i|/dev/tcp|reverse.?shell)"
```

`trigger-long-running-operation` matches `run` inside "running".
`get-resource-reference` matches `nc` inside "refere**nc**e". The `sh`
alternative matches any word containing those two letters — push, publish,
hash, shadow. `eval` matches "retrieval".

The last two CRITICALs are derived from the first four, which is the expensive
half: a false positive that manufactures a second, louder finding. The same
amplification appeared in 6.14.0, where fixing `code_execution` also removed a
CRITICAL `multi_vector`.

This is the same defect class fixed in `code_execution` for 6.14.0, but in the
shared pattern library and at CRITICAL severity.

## Goal

Measure what mcpnuke reports against real MCP servers written by other people,
fix the false positives that measurement exposes, and keep the result from
regressing.

## Authorized use, and why the targets are local

mcpnuke's own `SECURITY.md` and README state:

> **Only scan systems you own or have written authorization to test.**
> Unauthorized scanning is likely illegal in your jurisdiction regardless of
> intent.

A default scan is not passive: it sends injection and SSRF payloads and bursts
25 anonymous calls at a tool (`ANON_BURST_COUNT`). We do not own
`mcp.deepwiki.com` or any other hosted endpoint, so scanning them would breach
the policy we publish — the first thing a skeptical reviewer would check.

Every target here is therefore an open-source server **launched locally as a
subprocess**, on our own machine, under our own control. Real third-party tool
manifests, no authorization problem, and pinned versions make the measurement
reproducible.

## Design

### Targets

Five servers, spanning two ecosystems. Version pins live in one table so "what
did we measure" has a single answer.

| Server | Launcher | Why it earns a slot |
|--------|----------|---------------------|
| `@modelcontextprotocol/server-everything` | `npx` | Built to exercise every MCP feature. Measured: 13 tools, **7 resources, 4 prompts** — the first coverage of resources and prompts, which the hardened fixture has none of. |
| `@modelcontextprotocol/server-filesystem` | `npx` | Genuinely reads files. Tests whether capability findings are proportionate to real capability. |
| `@modelcontextprotocol/server-memory` | `npx` | Deliberately boring. A server with almost no surface should be almost silent. |
| `mcp-server-git` | `uvx` | Real repository access; a different capability shape. |
| `mcp-server-fetch` | `uvx` | Real outbound fetch — the honest comparison against our hardened `http.fetch`. |

`server-git` and `server-fetch` are **Python packages on PyPI**, not npm. This
was verified against both registries rather than assumed; an earlier spec in
this series shipped a wrong dependency assumption and had to be corrected.

All five speak **stdio**, which the existing HTTP-only harness never exercises.

### Runner (`tests/oss_targets/runner.py`)

One function: given a pinned target, launch it, run the real pipeline, return a
normalized finding set, and terminate the subprocess. The pin table lives
beside it.

It calls `scanner.scan_stdio_target`, the same function `--stdio` uses, rather
than reassembling `StdioSession` → `enumerate_server` → `run_all_checks` by
hand. A harness that drives a private path measures that path, not the product
— and the first version of the HTTP fixture made exactly that mistake by
omitting the `auth_context` the CLI always sets, which fabricated three
findings and nearly cost three correct checks.

Skips cleanly with an explanatory message when `npx` or `uvx` is absent, rather
than failing — but see "Rot" below for why skipping is not the default posture.

### Snapshots (`tests/oss_targets/snapshots/<server>.json`)

One committed JSON per server: the normalized finding set as
`{check, severity, title}`, sorted for a stable diff, plus the server version
it was captured against. The test diffs the live scan against the file and
fails naming exactly what changed.

**Normalization is load-bearing.** Findings carry elapsed times
(`behavioral_rate_limit` reports `10/10 rapid calls succeeded in 0.0s`),
temporary paths, and PIDs. Any of these in a snapshot makes it differ on every
run. Volatile fields are stripped, and evidence blobs are excluded entirely.

`MCPNUKE_OSS_UPDATE=1` regenerates the files, so an intentional change is a
deliberate act with a reviewable diff, never an accident.

### Triage (`docs/oss-target-baseline.md`)

Every finding in every snapshot classified **true** or **false positive**, with
a written reason and the server version observed. This is what produces the
citable claim — "against five real MCP servers, mcpnuke produced N HIGH or
CRITICAL findings, of which M were wrong" — and what a snapshot diff sends you
back to.

The snapshot alone would only prove the output *changed*. The triage alone
would rot the moment a check was edited. The pair is the design.

### Pattern fixes, in scope

The unanchored regexes are fixed as part of this work, not deferred. Expected
shape, following the `code_execution` fix in 6.14.0:

- Word-boundary or token matching instead of substring containment.
- Short, ambiguous alternatives (`sh`, `nc`, `run`) either anchored to a token
  or dropped where they cannot be made precise.
- A test per fix proving the **true positive still fires** — a `run_command`
  tool must stay CRITICAL.

Risk to manage: DVMCP tests may depend on loose matching, and some may assert
current behaviour. Where a test encodes a bug it gets replaced, with the
reasoning recorded in the test — the precedent is
`test_all_three_findings_on_permissive_server` in the DPoP fix.

### Gating

Off by default. Two ways to run, as requested:

- **Manual:** `MCPNUKE_OSS_TARGETS=1 uv run pytest tests/test_oss_targets.py -v`
- **Scheduled:** a weekly GitHub Actions workflow running the same command.

A drifted snapshot fails **only** the scheduled run. No pull request ever pays
for it, and default CI is untouched: no new runtime dependencies, no added
duration, no change to the 1329-test suite.

**Rot** is the real risk of an opt-in gate. A gated check nobody runs stops
being true — exactly how `.trufflehog.yaml` sat broken and silently disabled.
The weekly schedule exists specifically to make that visible.

## Non-goals

- **Hosted third-party endpoints.** Excluded on authorized-use grounds above.
  `tests/test_public_targets.py` keeps its existing enumerate-only smoke tests.
- **The AI lane.** `--claude`, chain replay and OAST need a model and a budget;
  their own piece of work.
- **Adding these to default CI.** They need `npx`/`uvx`, network, and package
  downloads. The existing hermetic gate stays the one that blocks merges.
- **A finding-count ceiling per server.** These servers have real capability;
  the snapshot, not a number, is the control.

## Success criteria

1. Five servers scanned, snapshotted, and committed with version pins.
2. Every snapshot finding triaged in writing in `docs/oss-target-baseline.md`.
3. False positives exposed by triage are fixed, each with a test proving the
   corresponding true positive survives.
4. `server-everything` no longer reports CRITICAL shell execution or reverse
   shell for tools named `trigger-long-running-operation` and
   `get-resource-reference`.
5. Full suite green; default CI duration unchanged.
6. Snapshots stable across three consecutive runs.
