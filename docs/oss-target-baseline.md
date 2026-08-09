# Open-source target baseline

What mcpnuke reports against five MCP servers **we did not write**, pinned and
run locally over stdio. Captured 2026-08-09.

The hardened fixture in [false-positive-baseline.md](false-positive-baseline.md)
measures a server we built to be quiet. This measures servers other people
built to do real work, which is the harder and more honest question.

## Summary

| Server | Version | Findings | CRITICAL | HIGH |
|--------|---------|----------|----------|------|
| server-everything | 2026.7.4 | 33 | 12 | 6 |
| server-filesystem | 2026.7.10 | 67 | 20 | 24 |
| server-git | 2026.7.10 | 66 | 14 | 26 |
| server-fetch | 2026.7.10 | 12 | 3 | 5 |
| server-memory | 2026.7.4 | 9 | 0 | 5 |
| **Total** | | **187** | **49** | **66** |

**Headline:** the anchoring fix in this release removed **24 findings, 22 of
them CRITICAL** — a 31% cut in CRITICAL volume across five real servers, with
no loss of true positives. Of what remains, a large share is still suspected
false positive; see "Known false positives" below. This document does not
claim the remaining 187 are all correct.

## Two servers were not measurable at first

`mcp-server-git` and `mcp-server-fetch` both crashed on launch, because `uvx`
resolves the newest `mcp` SDK and the 2.0 release broke them:

```
mcp-server-git:   AttributeError: 'Server' object has no attribute 'list_tools'
mcp-server-fetch: ImportError: cannot import name 'McpError' ... Did you mean: 'MCPError'?
```

mcpnuke reported `No response to MCP initialize` for both, which was **correct**
— but it measured a crashed process, not a false-positive rate. Both targets now
pin `mcp==1.29.0`. server-git went from 1 finding to 72 once it could actually
start.

Worth keeping in mind when reading any scan report: one HIGH finding and
nothing else usually means the target never came up.

## What the anchoring fix removed

Every finding below was verified false and is gone. `remote_access` went from
14 findings to **zero across all five servers** — every one had been a
substring accident.

| Server | Removed | Why it was wrong |
|--------|---------|------------------|
| server-git | CRITICAL `remote_access` on `git_branch`, `git_checkout`, `git_create_branch`, `git_diff` | `nc` matched inside "bra**nc**h" |
| server-git | CRITICAL `excessive_permissions [shell_exec]` on `git_show` | `sh` matched inside "**sh**ow" |
| server-filesystem | CRITICAL `remote_access` on `directory_tree`, `edit_file`, `get_file_info`, `list_directory_with_sizes`, `read_media_file`, `read_multiple_files`, `read_text_file`, `write_file` | `nc` matched inside "e**nc**oding" in the descriptions |
| server-filesystem | CRITICAL + HIGH `excessive_permissions` on `search_files` | `sh` and `run` substrings |
| server-everything | CRITICAL `excessive_permissions [shell_exec]` on `trigger-long-running-operation` | `run` matched inside "**run**ning" |
| server-everything | CRITICAL `remote_access` on `get-resource-links`, `get-resource-reference` | `nc` matched inside "refere**nc**e" |

### The amplification tax

Six further CRITICALs disappeared without being targeted, because they were
**derived from the false ones**:

- 3 × `attack_chain` on server-everything (`exfil_flow → remote_access`,
  `indirect_injection → remote_access`, `response_credentials → remote_access`)
  — all three chained into a `remote_access` that did not exist.
- 1 × `attack_chain` on server-filesystem (`ssrf_probe → remote_access`).
- 2 × `multi_vector` "injection + exfiltration vector present".
- Three more `multi_vector` findings dropped their category counts (6→5, 4→3,
  3→2).

This is the expensive half of a false positive: it manufactures a second,
louder finding that looks like corroboration. The same pattern appeared in
6.14.0, where fixing `code_execution` also removed a CRITICAL `multi_vector`.

## Verified true positives

| Check | Count | Assessment |
|-------|-------|------------|
| `excessive_permissions` | 18 | **True.** Post-fix these name real capability: `read_file` on a filesystem server, `fetch` on a fetch server. Capability inventory, correctly scoped. |
| `schema_risk` | 44 | **True but low value.** These servers really do accept unbounded strings. Accurate; mostly MEDIUM/LOW, and the priority ranker collapses it. |
| `tool_shadowing` | 3 | **True.** `fetch` and `echo` are genuinely common names a malicious server could shadow. |

## Known false positives, not yet fixed

These are **not** fixed in this release. They are recorded here rather than
quietly left in the snapshot, and each needs its own piece of work.

### 1. Error-message echo read as injection — ~72 findings, the largest class

`active_prompt_injection` (26), `tool_response_injection` (24) and
`input_sanitization` (22) fire on nearly every tool of server-git and
server-filesystem.

The mechanism: the probe sends a path containing a canary, the server rejects
it and names the bad path in the error message — `Repository not found:
/tmp/<canary>` — and the check reads its canary coming back as reflection.

Evidence: `rg 'isError|is_error' mcpnuke/checks/tool_probes.py` returns
**nothing**. These probes never distinguish a *rejected* call from a
*successful* one, so a server doing exactly the right thing (refusing bad
input and saying which input it refused) is scored the same as one that
executed the payload.

Confidence: high on the mechanism, and the class is not yet confirmed
finding-by-finding. Fixing it means teaching the reflection probes to weigh
`isError` and to distinguish an error string from tool output — a behavioral
change, larger than this release's pattern work, and it must not weaken the
DVMCP true positives that depend on these checks.

### 2. Auth checks on a transport with no auth — ~15 findings

`pre_auth_injection` (5), `anon_budget_exhaust` (5) and
`behavioral_rate_limit` (5) fire on every stdio target.

A local stdio server is a **subprocess with a pipe**. There is no
authentication boundary to be missing and no anonymous caller to rate-limit:
whoever can spawn the process already has the privileges. "13 tools available
without authentication" is technically accurate and operationally meaningless
here.

These checks are correct for a networked server. They should be transport-aware
rather than deleted.

### 3. `command_injection_broad` — 4 findings

Fires on `git_status` and `read_file` for a `;`-chained path. Same root cause
as class 1: the server echoed the semicolon back inside a "no such path" error.
Nothing was executed. CRITICAL severity makes this the most costly of the
remaining false positives per finding.

### 4. `prompt_injection_t01` — 7 findings

Fires where a path parameter was reflected. Needs the same `isError` distinction
as class 1.

## How to reproduce

```bash
MCPNUKE_OSS_TARGETS=1 uv run pytest tests/test_oss_targets.py -v
```

Snapshots live in `tests/oss_targets/snapshots/`. Update deliberately with
`MCPNUKE_OSS_UPDATE=1`, and re-triage here when you do.
