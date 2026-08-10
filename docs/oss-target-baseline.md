# Open-source target baseline

What mcpnuke reports against five MCP servers **we did not write**, pinned and
run locally over stdio. Captured 2026-08-09, re-measured 2026-08-10 after the
error-reflection fix.

The hardened fixture in [false-positive-baseline.md](false-positive-baseline.md)
measures a server we built to be quiet. This measures servers other people
built to do real work, which is the harder and more honest question.

## Summary

| Server | Version | Findings | CRITICAL | HIGH | LOW |
|--------|---------|----------|----------|------|-----|
| server-everything | 2026.7.4 | 33 | 12 | 6 | 0 |
| server-filesystem | 2026.7.10 | 67 | 5 | 17 | 24 |
| server-git | 2026.7.10 | 65 | 0 | 2 | 42 |
| server-fetch | 2026.7.10 | 11 | 1 | 4 | 2 |
| server-memory | 2026.7.4 | 9 | 0 | 5 | 0 |
| **Total** | | **185** | **18** | **34** | **68** |

**Headline:** two fixes in this release cut CRITICAL findings across five real
servers from **71 to 18**, a 75% reduction, with no true positive lost.

| Fix | Findings | CRITICAL |
|-----|----------|----------|
| Starting point | 211 | 71 |
| After pattern anchoring | 187 | 49 |
| After error-reflection grading | 185 | 18 |

`server-git` is the clearest case: **14 CRITICAL and 26 HIGH became 0 and 2.**
Not one of them described anything the server does. They described what the
server *said* while refusing us.

Nothing was hidden to achieve this. Only two findings disappeared outright —
both `multi_vector` CRITICALs that existed solely because they were chaining
LOW-graded evidence. Every other change is a re-grading: 61 findings moved to
LOW, where they remain visible and countable.

This document does not claim the remaining 185 are all correct. The auth-on-stdio
class below is still unfixed.

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

## What the error-reflection fix removed

The largest class in the first measurement was a server's *error message*
being read as a successful injection. The probe sends a path containing a
canary, the server rejects it and names the bad path — `Repository not found:
/tmp/<canary>` — and the check reads its own canary coming back as proof the
server complied.

The discriminator turned out to be sharper than "did this response set
`isError`". Every one of these checks matched a marker that was **part of the
payload it sent**. So the response has the payload subtracted from it first,
and only what remains is searched. If the marker survives, the server produced
it. If it vanishes, we were reading our own input.

| Check | Was | Now | Severity move |
|-------|-----|-----|---------------|
| `active_prompt_injection` | 21 CRITICAL | 21 LOW | CRITICAL → LOW |
| `tool_response_injection` | 20 HIGH | 20 LOW | HIGH → LOW |
| `input_sanitization` | 12 HIGH | 12 LOW | HIGH → LOW |
| `prompt_injection_t01` | 5 CRITICAL | 5 LOW | CRITICAL → LOW |
| `command_injection_broad` | 3 CRITICAL | 3 LOW | CRITICAL → LOW |
| `multi_vector` | 2 CRITICAL | — | removed entirely |

The `multi_vector` pair is the interesting one. Both chaining checks built
their vector set from finding *names* with no severity filter, so downgrading
the evidence would have left the CRITICAL conclusion drawn from it standing.
A check now counts as an active vector only at MEDIUM or above.

Two exemptions were deliberate. `command_injection_broad` also matches shell
error text like `sh: 1: foo: not found`, and that is **not** downgraded even
though it arrives with `isError` set — a shell errors precisely *because* it
parsed the metacharacters, so that is the server's own output, not our echo.
Credential and secret leakage is likewise untouched: a password in an error
string is a leak whether or not the call succeeded.

**This is auditable, not a matter of trust.** `--error-reflection keep`
reproduces the pre-fix output exactly; it was checked against all three
changed targets, and all three matched finding-for-finding. Operators who
disagree with our grading can restore the old severities, or drop these
findings entirely with `suppress`.

## Known false positives, not yet fixed

### Auth checks on a transport with no auth — ~15 findings

`pre_auth_injection` (5), `anon_budget_exhaust` (5) and
`behavioral_rate_limit` (5) fire on every stdio target.

A local stdio server is a **subprocess with a pipe**. There is no
authentication boundary to be missing and no anonymous caller to rate-limit:
whoever can spawn the process already has the privileges. "13 tools available
without authentication" is technically accurate and operationally meaningless
here.

These checks are correct for a networked server. They should be transport-aware
rather than deleted.

This is now the only class recorded here as unfixed, and it is the next piece
of work on these targets.

## How to reproduce

```bash
MCPNUKE_OSS_TARGETS=1 uv run pytest tests/test_oss_targets.py -v
```

Snapshots live in `tests/oss_targets/snapshots/`. Update deliberately with
`MCPNUKE_OSS_UPDATE=1`, and re-triage here when you do.
