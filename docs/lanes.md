# Identity Lanes & Transports

mcpnuke labels every lane-scoped finding with two ecosystem-shared dimensions
sourced from the agentic-identity Identity Flow Framework and frozen by
[ADR 0001 — Five-Transport Taxonomy](https://github.com/babywyrm/camazotz/blob/main/docs/adr/0001-five-transport-taxonomy.md).

## Identity lanes

The *who* — request initiator:

| Lane | Slug | Description |
|------|------|-------------|
| 1 | `human-direct` | Human authenticates directly to the MCP server |
| 2 | `delegated` | Human → agent token exchange (OAuth on-behalf-of) |
| 3 | `machine` | Workload identity (SPIFFE, SA tokens, bot certs) |
| 4 | `chain` | Agent → agent / chained delegation |
| 5 | `anonymous` | Pre-auth or unauthenticated surface |

## Transports

The *how* — wire / process surface, codes A through E per ADR 0001:

| Code | Name | Notes |
|------|------|-------|
| A | MCP JSON-RPC | The protocol most of this scanner exercises directly |
| B | Direct wire API | REST / gRPC / GraphQL the agent calls outside MCP |
| C | In-process SDK / library | Python imports, in-process function calls |
| D | Subprocess / native binary | Agent spawns `kubectl`, `terraform`, etc.; credentials cross the fork boundary |
| E | Native LLM function-calling | OpenAI tools, Anthropic `tool_use`, Gemini function-calling — no MCP wire involved |

## How findings carry them

The Finding dataclass carries `lane: int | None` and `transport: str | None`.
When a finding has a `taxonomy_id`, both are resolved automatically from the
taxonomy (`mcpnuke/data/taxonomy/lanes.yaml`); checks can also set them
explicitly via the `lane_tagged()` helpers in `mcpnuke/checks/_lane_helpers.py`.

- `--by-lane` groups findings by lane with per-lane severity tallies.
- `--coverage-report` intersects findings with camazotz's schema-v1 lane
  corpus.
- Findings that are not lane-scoped (rate limit, TLS hygiene, generic HTTP
  surface) keep `lane=None` and report under "Uncategorized."

Worked examples of both reports: [QUICKSTART.md](../QUICKSTART.md), section 12
(Per-Lane Reporting and Coverage).

> Transports D and E currently appear in the taxonomy and `--by-lane`
> output for camazotz-side coverage tracking; in mcpnuke's own check
> emissions, lane-tagged findings are predominantly Transport A (MCP
> JSON-RPC) since that is the wire mcpnuke speaks. D / E coverage shows
> up via `--coverage-report` against a camazotz target that exercises
> those surfaces.
