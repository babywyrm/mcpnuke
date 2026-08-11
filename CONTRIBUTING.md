# Contributing to mcpnuke

Thanks for helping. mcpnuke's value depends on operators trusting its output,
so the bar for a new check is **precision first**: a check that cries CRITICAL
on a well-built server costs more than the vulnerability it might catch.

## Setup

```bash
git clone https://github.com/babywyrm/mcpnuke.git && cd mcpnuke
./quickstart.sh
```

That creates a venv, installs all extras, and runs the suite. After it,
`uv run mcpnuke` and `./scan` work without activating anything.

Manual equivalent: `uv sync --all-extras`.

## The three commands

```bash
uv run pytest tests/ -v      # full suite — must be green before you push
uv run ruff check .          # must be zero
uv run mypy mcpnuke/         # must not exceed the CI ceiling
```

`mypy` has known debt. CI enforces a **ceiling** rather than zero (see
`MYPY_CEILING` in `.github/workflows/tests.yml`). Do not raise it. If your
change lowers the count, lower the ceiling in the same PR to lock the win in.
`mcpnuke.core.*` additionally enforces `disallow_untyped_defs`.

Coverage is available but off by default, since `--cov` roughly doubles an
80-second run:

```bash
uv run pytest tests/ --cov=mcpnuke
```

**63% branch coverage** as of 6.15.0. Two known holes account for most of the
gap and are not excluded from the report, because hiding them would raise the
number without covering a line: `mcpnuke/server/*` needs the optional `server`
extra and sits at 0%, and `mcpnuke/scanner.py` is low because most tests drive
`run_all_checks` directly rather than through the scan entry points. Check
modules are the part that matters, and they are well above the average.

Before pushing, also run the secret scan:

```bash
./scripts/secret-scan.sh
```

Use the script rather than calling either engine directly. It runs both, and
they answer different questions: TruffleHog reads the working tree and verifies
findings against the live provider, while Gitleaks walks git history and would
still see a key that was committed and later deleted.

The script carries TruffleHog's detector exclusions, which cannot be expressed
in a config file, and gates on *verified* findings only — the repo
intentionally ships fake credentials as scanner fixtures, so a scan that failed
on unverified results would fail every time and be ignored. One exclusion worth
knowing about: Lob API keys begin with `test_`, so that detector matches pytest
function names.

Gitleaks reads [.gitleaks.toml](.gitleaks.toml), where the same fixture corpus
is allowlisted by path. `mcpnuke/patterns/credentials.py` is deliberately *not*
path-allowlisted — it is shipping code, so only the two illustrative values in
its comments are excused, by value. A real key committed there is still caught.

Gitleaks is optional (`brew install gitleaks`); the script prints `SKIPPED`
rather than passing silently when it is missing.

## Reporting detection bugs

False positives and false negatives are **normal issues**, not security
reports, and they are among the most useful contributions.

A good report includes the tool definition that triggered it (name,
description, `inputSchema`), which check fired, and why the verdict is wrong.
**Redact credentials and internal hostnames first** — see
[SECURITY.md](SECURITY.md) for handling scan output.

## Adding a check

Checks live in `mcpnuke/checks/<name>.py`. There are two shapes.

**Static** — reads metadata the server already published, never calls a tool:

```python
from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check, tool_text
from mcpnuke.core.models import TargetResult

_add = lane_tagged(lane=5, transport="A")


def check_my_thing(result: TargetResult):
    with time_check("my_thing", result):
        for tool in result.tools:
            if _PATTERN.search(tool_text(tool)):
                _add(
                    result,
                    "my_thing",
                    "HIGH",
                    f"Short verdict naming '{tool.get('name', '')}'",
                    "Why this is exploitable, in one or two sentences.",
                    taxonomy_id="MCP-T##",
                )
```

**Behavioral** — invokes tools, so it takes a session and honors probe options:

```python
def check_my_probe(
    session: MCPSessionProtocol,
    result: TargetResult,
    probe_opts: dict | None = None,
):
    opts = probe_opts or {}
    if opts.get("no_invoke"):
        return
    with time_check("my_probe", result):
        ...
```

Non-negotiables:

1. **Every check wraps its body in `with time_check("<name>", result):`** —
   `tests/test_check_progress.py` derives the progress denominator from the
   check inventory, and untimed checks break the report.
2. **Emit through `result.add(...)` or a `lane_tagged` `_add(...)`** — severity
   is a plain string (`"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`), not an enum.
3. **Map to a taxonomy ID** from the
   [Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md)
   (MCP-T01–T58) and assign a lane (1–5) and transport (A–E).
4. **Use `tool_text(tool)`** for the searchable surface instead of hand-rolling
   name/description/schema concatenation.
5. **Behavioral checks must respect `no_invoke` and `--safe-mode`.** Operators
   run mcpnuke against production on that promise.
6. **Register it** in `mcpnuke/checks/__init__.py` in the static or behavioral
   phase, and update the coverage table in [ROADMAP.md](ROADMAP.md).

### Where patterns go

Credential regexes belong **only** in `mcpnuke/patterns/credentials.py`, in the
tier matching their false-positive risk — never in `rules.py`, `probes.py`, or a
check module. Static pattern sets go in `patterns/rules.py`; behavioral payloads
in `patterns/probes.py`.

## Testing a check

TDD, please: write the failing test first. Every check needs
`tests/test_<name>.py` with at least three cases:

1. **positive** — the vulnerable shape is flagged
2. **negative** — a legitimate, well-built tool stays quiet
3. **timing** — `result.timings["<name>"]` is recorded

The negative case is the one that protects users. Use a realistic clean tool,
not an empty dict. `tests/conftest.py` provides `result_with_tools([{...}])`.

### The false-positive gate

`tests/test_false_positives.py` scans a hardened reference server
(`tests/reference_target/`) with the real pipeline and fails if your check fires
on it. It runs in the normal suite — no Docker, no lab, no env gate.

If it fails, **the expectation is that you fix the check.** Adding an entry to
`_EXPECTED` requires a written reason a reviewer can disagree with, and
`_FP_CEILING` ratchets down only, the same rule as `MYPY_CEILING`. Otherwise the
ceiling becomes somewhere to park false positives and the number stops meaning
anything.

```bash
uv run pytest tests/test_false_positives.py -v
```

The first run of this gate found three real bugs, including a check that told
authenticated scans their server accepted anonymous access. See
[docs/false-positive-baseline.md](docs/false-positive-baseline.md).

### The open-source target snapshots

The gate above measures a server *we* wrote to be quiet. This one measures five
pinned servers written by other people, launched locally over stdio, and diffs
the findings against committed snapshots. It is off by default:

```bash
MCPNUKE_OSS_TARGETS=1 uv run pytest tests/test_oss_targets.py -v
```

A drifted snapshot means your change altered what mcpnuke reports about a real
server. That is not automatically wrong — but re-triage it in
[docs/oss-target-baseline.md](docs/oss-target-baseline.md), then update
deliberately with `MCPNUKE_OSS_UPDATE=1`. It also runs weekly in CI, because an
opt-in check nobody runs stops being true.

Two rules when adding to `tests/oss_targets/targets.py`:

- **Pin everything.** An unpinned target makes a diff ambiguous between "we
  changed" and "they changed". Both `uvx` targets also pin the `mcp` SDK, since
  the 2.0 release crashes them at startup.
- **Only servers you run yourself.** Never point this at a hosted third-party
  endpoint. A default scan sends injection and SSRF payloads and bursts 25
  anonymous calls, and [SECURITY.md](SECURITY.md) is explicit that we scan only
  what we control.

The first run of this harness removed 22 CRITICAL false positives caused by
dangerous-capability patterns matching substrings — `git_show` was flagged for
shell execution because "show" contains `sh`.

### Choosing a severity

Severity drives the operator's day, so calibrate against evidence, not vibes:

| Level | Means |
|-------|-------|
| CRITICAL | Proved impact, or a capability that is exploitable as-is |
| HIGH | Exploitable given a plausible precondition |
| MEDIUM | Real weakness, needs chaining or an unlikely precondition |
| LOW | Hygiene; worth knowing, not worth paging anyone |

If a check fires once per tool across a large inventory, it is describing
*capability surface*, not a vulnerability — prefer MEDIUM and expect the
priority ranker to collapse it. Reporting sorts by proof strength
(`mcpnuke/reporting/priority.py`); inflating severity to get attention just
buries the proved findings.

## Invariants guarded by tests

Each of these exists because it broke once. Do not route around them:

- `tests/test_credential_patterns.py` — every consumer of the credential tiers
  detects the same set. Add new secrets to the corpus.
- `tests/test_injection_patterns.py` — one shared injection marker set, no
  private copies.
- `tests/test_session_protocol.py` — all four transports satisfy the Protocol,
  and stdio never gains `post_raw`.
- `tests/test_check_progress.py` — the progress denominator comes from the check
  inventory, never a hardcoded number.
- `tests/test_lab_baselines.py` — proof-ranked reporting and hop-aware policy
  keep working against committed scan fixtures.
- `tests/test_docs_current.py` — `docs/cli-reference.md` is generated. After a
  CLI change run `uv run python -m mcpnuke._docsgen`.

## Keeping the tool target-agnostic

mcpnuke must behave identically against any MCP-shaped target. Lab targets
(Camazotz, DVMCP) are **test oracles only** — never special-case a hostname,
lab tool name, or challenge ID in `mcpnuke/`. Reporting and policy modules have
AST-level tests that fail if lab strings appear in them.

## Pull requests

- One logical change per PR; keep the diff reviewable.
- Full suite green, `ruff` at zero, `mypy` at or under the ceiling.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Note whether you validated against a real target, and which one.

For anything large — a new transport, a new check family, a reporting change —
open an issue first so we can agree on the shape before you build it.

## Scope

mcpnuke is **outside-in runtime scanning of live MCP endpoints**. Adjacent work
belongs elsewhere in the ecosystem: static config scanning in skillseraph,
model-resistance evaluation in stoneburner, runtime policy enforcement in
nullfield. Proposals that pull mcpnuke into those lanes will likely be
redirected rather than rejected — say what you are trying to accomplish and we
will point you at the right repository.
