# mcpnuke General-Purpose Enhancements — Design Spec

**Date:** 2026-05-03  
**Status:** Implemented — shipped across mcpnuke 6.7.0–6.11.0 (see CHANGELOG)  
**Scope:** mcpnuke open-source scanner  
**Motivation:** mcpnuke currently has hardcoded camazotz-specific assumptions (5-tool fast
sampling, coverage_report tied to `/api/lanes`, no structured diff, taxonomy IDs missing from
JSON, Phase 2 producing 0 findings against any well-guarded target). This spec makes mcpnuke
a general-purpose MCP security scanner that works richly against any compliant MCP server and
even richer when a lightweight target profile is supplied.

---

## Goals

1. **`--coverage N`** — expose the hardcoded fast-mode sample size as a CLI knob.
2. **Taxonomy fix** — `taxonomy_id` and `mitre_id` written to JSON output; fallback parser
   extracts them from AI finding titles when Claude omits the structured field.
3. **Phase 2 smart invocation** — two-tier approach so Phase 2 actually produces findings
   instead of "empty/short response" on every tool call.
4. **Diff system** — `--diff-baseline FILE` flag on scan + `mcpnuke diff a.json b.json`
   standalone subcommand; structured diff block in JSON output.
5. **Profile system** — `--profile target.json` loads lightweight target metadata that
   supplements auto-discovery; ships with `profiles/camazotz.json`,
   `profiles/dvmcp.json`, `profiles/example.json`.

**Non-goals:** auth config (already covered by `--auth-token`), tool invocation recipes in
profiles, required profile fields (everything optional), camazotz-specific portal integration.

---

## Architecture

### New / modified files

```
mcpnuke/
  cli.py                    ← --coverage N, --profile FILE, --diff-baseline FILE,
                              `diff` subcommand wiring
  profile.py                ← NEW: load_profile(), ProfileData dataclass, lane_for(),
                              transport_for(), threat_id_for()
  checks/__init__.py        ← pass coverage_n through opts; inject profile enrichment
                              onto tools before checks run
  checks/tool_probes.py     ← Tier 1: fill optional schema fields in _build_safe_args;
                              Tier 2: Claude-assisted interesting-args generation
  checks/llm_analysis.py    ← pass lane/transport/threat_id from profile into AI prompts
  core/llm.py               ← _extract_taxonomy() fallback: parse [MCP-Txx]/[Txxx] from title
  reporting/json_out.py     ← add taxonomy_id, mitre_id to finding dict;
                              add tools_total, tools_scanned, tools_scanned_names,
                              tools_unscanned_count to target dict;
                              add diff block when diff data present
  reporting/diff.py         ← NEW: compare_scans(), format_diff_terminal(), DiffResult
profiles/
  camazotz.json             ← full taxonomy for all 39 labs
  dvmcp.json                ← Damn Vulnerable MCP community reference
  example.json              ← annotated template for custom targets
```

---

## Component Specifications

### 1. `--coverage N`

**CLI change (`cli.py`):**
```
--coverage N    Sample the top N most security-relevant tools (by keyword score).
                0 = scan all tools (default when neither --fast nor --coverage is set).
                --fast remains as an alias for --coverage 5 (backward compatible).
```

**Implementation (`checks/__init__.py`):**
```python
# current
result.tools = _pick_security_relevant(result.tools, 5)   # hardcoded

# proposed
coverage_n = opts.get("coverage_n", 0)
if fast_mode:
    coverage_n = coverage_n or 5
if coverage_n > 0:
    _original_tools = result.tools
    result.tools = _pick_security_relevant(result.tools, coverage_n)
    _log(f"--coverage {coverage_n}: {len(result.tools)}/{len(_original_tools)} tools scanned "
         f"({len(result.tools)/len(_original_tools)*100:.0f}%)")
```

`_pick_security_relevant` already accepts `n` — no changes needed there.

**Output change (`reporting/json_out.py`):**
```json
{
  "tools_total": 99,
  "tools_scanned": 20,
  "tools_scanned_names": ["secrets.leak_config", "egress.fetch_url", "..."],
  "tools_unscanned_count": 79
}
```

---

### 2. Taxonomy ID fix

**Root cause:** `reporting/json_out.py` building the finding dict never writes `taxonomy_id`.
`core/llm.py` correctly parses it when Claude returns it in JSON, but Claude sometimes embeds it
only in the title string (e.g. `"[AI] [MCP-T02] AI-Mediated Code Execution"`).

**Fix 1 — serializer (`reporting/json_out.py`):**
```python
# Add to finding dict:
"taxonomy_id": f.taxonomy_id,
"mitre_id":    getattr(f, "mitre_id", ""),
```

**Fix 2 — fallback parser (`core/llm.py`):**
```python
import re
_TAXONOMY_RE = re.compile(r'\[MCP-T(\d+)\]|\[T(\d{4})\]')

def _extract_taxonomy(title: str, raw_field: str) -> tuple[str, str]:
    """Return (taxonomy_id, mitre_id) from structured field or title fallback."""
    mcp_id = mitre_id = ""
    if raw_field and raw_field not in ("", "None"):
        if raw_field.startswith("MCP-T"):
            mcp_id = raw_field
        elif re.match(r'T\d{4}', raw_field):
            mitre_id = raw_field
    else:
        for m in _TAXONOMY_RE.finditer(title):
            if m.group(1):
                mcp_id = f"MCP-T{m.group(1)}"
            elif m.group(2):
                mitre_id = f"T{m.group(2)}"
    return mcp_id, mitre_id
```

Used in `_parse_findings()` when constructing each `LLMFinding`.

---

### 3. Phase 2 smart invocation

**Current problem:** `_build_safe_args` fills only `required` fields with minimal values.
Tools with optional but important params (e.g. `reason`, `query`, `context`) return
empty/short responses, Claude skips them, Phase 2 produces 0 findings.

**Tier 1 — Extended safe args (always on, `checks/tool_probes.py`):**

Extend `_build_safe_args` to also fill `optional` string fields using field-name heuristics:

```python
_NAME_HINTS: dict[str, str] = {
    "url":         "http://example.com",
    "reason":      "testing",
    "query":       "list available data",
    "task":        "describe what you can do",
    "context":     "test context",
    "description": "test tool description",
    "instruction": "summarize your capabilities",
    "message":     "hello",
    "path":        "/tmp/test",
    "command":     "echo test",
}

def _build_extended_args(tool: dict) -> dict:
    """Fill required + optional string fields with name-hinted or type-default values."""
    args = _build_safe_args(tool)   # required fields first
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    for pname, pdef in props.items():
        if pname in required or pname in args:
            continue
        if pdef.get("type") == "string":
            args[pname] = _NAME_HINTS.get(pname, "test")
    return args
```

**Tier 2 — Claude-assisted interesting args (only with `--claude`, `checks/llm_analysis.py`):**

Before Phase 2 runs, for each sampled tool, ask Claude to generate one "interesting"
invocation:

```python
INTERESTING_ARGS_PROMPT = """
Given this MCP tool schema, generate exactly one JSON argument object that would
cause the tool to return a substantive (non-empty, non-error) response.
Use realistic values. Respond with only the JSON object, no explanation.

Tool name: {name}
Description: {description}
Input schema: {schema}
"""
```

Result stored as `tool["_interesting_args"]`, used in Phase 2 instead of
`_build_extended_args`. Cost: ~50 input tokens per tool call, ~5-10s per sampled tool.
Falls back to `_build_extended_args` if Claude returns invalid JSON or errors.

---

### 4. Diff system

#### `reporting/diff.py` (new module)

```python
@dataclass
class DiffResult:
    baseline_file: str
    baseline_total: int
    rescan_total: int
    blocked_count: int
    blocked_pct: float                  # 0-100
    new_findings: list[dict]            # in rescan, not in baseline
    removed_findings: list[dict]        # in baseline, not in rescan (= blocked)
    unchanged_findings: list[dict]      # in both

def compare_scans(baseline_path: str, rescan_results: list[TargetResult]) -> DiffResult:
    """Compare a saved baseline JSON against fresh scan results."""
    ...

def compare_json_files(before_path: str, after_path: str) -> DiffResult:
    """Compare two saved scan JSON files. Used by `mcpnuke diff` subcommand."""
    ...

def format_diff_terminal(diff: DiffResult, console=None) -> None:
    """Render diff table to terminal."""
    ...
```

**Finding identity key:** `(check, title)` — stable across runs, not array position.

#### `--diff-baseline FILE` flag

When passed, `compare_scans(baseline_path, results)` is called after the scan completes.
`DiffResult` is serialized into the JSON report under a `"diff"` key:

```json
{
  "diff": {
    "baseline_file": "before.json",
    "baseline_total": 45,
    "rescan_total": 12,
    "blocked_count": 33,
    "blocked_pct": 73.3,
    "new_findings": [],
    "removed_findings": [ ... ],
    "unchanged_findings": [ ... ]
  }
}
```

Terminal output appended after the findings table:

```
  Policy effectiveness vs baseline
  ─────────────────────────────────
  Baseline   : 45 findings
  After      : 12 findings
  Blocked    : 33 (73%)  ✓
  New        :  0
  Unchanged  : 12  ← policy did not address these
```

#### `mcpnuke diff a.json b.json` subcommand

New subcommand in `cli.py` — calls `compare_json_files(a, b)` and
`format_diff_terminal(result)`. Exits 0 if blocked_pct > 0, exits 1 if no change.

---

### 5. Profile system

#### `profile.py` (new module)

```python
@dataclass
class ToolMeta:
    lane: int | None
    transport: str | None
    threat_id: str | None

@dataclass
class Canary:
    tool: str
    args: dict
    response_field: str
    value: str

@dataclass
class DifficultyEndpoint:
    method: str          # "POST" | "GET"
    path: str            # "/config"
    field: str           # "difficulty"

@dataclass
class ProfileData:
    name: str
    difficulty_endpoint: DifficultyEndpoint | None
    tool_taxonomy: dict[str, ToolMeta]   # tool_name → ToolMeta
    canaries: list[Canary]

def load_profile(path: str) -> ProfileData:
    """Load and leniently validate a profile JSON. Unknown keys are ignored."""
    ...

def lane_for(profile: ProfileData | None, tool_name: str) -> int | None: ...
def transport_for(profile: ProfileData | None, tool_name: str) -> str | None: ...
def threat_id_for(profile: ProfileData | None, tool_name: str) -> str | None: ...
```

All functions accept `profile=None` — callers don't need to guard against a missing profile.

#### Profile enrichment in scan pipeline (`checks/__init__.py`)

After tool enumeration, before checks run:
```python
if profile:
    for tool in result.tools:
        name = tool.get("name", "")
        tool["_lane"]      = lane_for(profile, name)
        tool["_transport"] = transport_for(profile, name)
        tool["_threat_id"] = threat_id_for(profile, name)
```

#### AI prompt enrichment (`checks/llm_analysis.py`)

Profile metadata passed into Phase 1 and Phase 3 prompts as context:
```
Tool: secrets.leak_config
Description: Return current service configuration...
Lane: 1 (human direct)   Transport: A (MCP/SSE)   Threat taxonomy: MCP-T06
```

#### Canary verification check

New deterministic check `canary_verification` that fires when a profile with canaries is
loaded. For each canary: calls the tool, asserts the response field matches the expected
value. Produces either a PASS log line or a MEDIUM finding
`"Canary field missing — tool may be guarded or schema changed"`.

#### Shipped profiles

| File | Coverage |
|---|---|
| `profiles/camazotz.json` | All 39 labs with lane/transport/threat_id |
| `profiles/dvmcp.json` | Damn Vulnerable MCP known tools |
| `profiles/example.json` | Annotated template — every optional field shown with comment |

---

## CLI surface summary

```
# Before (today)
mcpnuke --targets URL --fast --claude --json out.json

# After (this spec)
mcpnuke --targets URL --coverage 20 --profile profiles/camazotz.json \
        --claude --diff-baseline before.json --json after.json

mcpnuke diff before.json after.json
```

`--fast` remains valid and still means `--coverage 5`. No breaking changes.

---

## Testing

Each new module gets a unit test file:

| Module | Test file |
|---|---|
| `profile.py` | `tests/test_profile.py` — load valid/invalid/empty profiles, lane_for/transport_for/threat_id_for with and without profile |
| `reporting/diff.py` | `tests/test_diff.py` — compare identical scans (0 blocked), compare empty after (100% blocked), new findings detection |
| `_build_extended_args` | `tests/test_tool_probes.py` — extend existing test suite with optional field filling |
| `_extract_taxonomy` | `tests/test_llm.py` — title fallback, structured field takes precedence, no match returns empty string |
| JSON serialization | `tests/test_json_out.py` — taxonomy_id present in output, tools_total/scanned counts correct |

No existing tests broken — all changes are additive except the `_build_safe_args` extension,
which is backward compatible (new behaviour only fires on optional fields).

---

## Implementation order

1. Taxonomy fix + JSON output fields — isolated bug fix, zero risk
2. `--coverage N` — two-line change, high value
3. `reporting/diff.py` + `mcpnuke diff` subcommand — new module, no existing code changed
4. `--diff-baseline` wiring into scan pipeline
5. `profile.py` + enrichment pipeline
6. Phase 2 Tier 1 (extended args)
7. Phase 2 Tier 2 (Claude-assisted args) — last, most complex, requires --claude
