# Multi-Hop Chain Replay Depth — Design Spec

**Date:** 2026-09-01  
**Status:** Approved  
**Scope:** Enhance chain replay executor for 3+ hop chains, conditional branching, parallel execution, and lane-aware templates.

---

## 1. Purpose

Deepen `mcpnuke`'s multi-hop attack chain capabilities (T34–T36) and lane-specific coverage (T44–T49 lanes B–E) by extending the chain replay executor beyond linear 2-hop patterns. Enable sophisticated attack path validation while maintaining determinism, testability, and safety.

## 2. Architecture

### 2.1 Core Principle

**Deterministic-first with LLM fallback.** The executor remains a pure function of tool responses; LLM intervention is limited to per-step parameter adaptation when deterministic parsing fails.

### 2.2 Chain Topology

Current: Linear sequence (Step A → Step B)

Enhanced: Directed acyclic graph (DAG) with:
- **Linear chains:** 3+ hops (A → B → C)
- **Conditional branches:** Step executes based on prior outcome
- **Parallel groups:** Concurrent execution with result merging

```
Example: Credential theft with fallback
  [read_secrets] → [decode_token] → [exfil_primary]
       ↓ (if decode fails)
  [read_config] → [exfil_fallback]
```

### 2.3 New Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `ChainGraph` | `core/chain_replay.py` | DAG representation of chain topology |
| `ChainNode` | `core/chain_replay.py` | Step + dependencies + condition |
| `ConditionalStep` | `core/chain_replay.py` | Step with execution condition |
| `LaneTemplate` | `core/chain_templates.py` | Pre-built lane-specific patterns |
| `k8s_chain_probe` | `checks/k8s_chain_probe.py` | K8s namespace boundary chains |

## 3. Data Flow

### 3.1 Execution Pipeline

```
1. Parse proposed chain → ChainGraph
   - Validate: no cycles, no orphans, no self-dependencies
   - Build dependency edges from {{stepN.output}} references

2. Topological sort → execution order
   - Group parallelizable nodes (no inter-dependencies)

3. For each node in order:
   a. Resolve inputs from predecessor outputs
      - Apply transforms (b64, urlencode, etc.)
      - Track fragments for data movement
   b. Evaluate condition (if present)
      - Skip if condition false
   c. Execute tool call
   d. Record StepResult + tracked_fragments
   e. On failure: LLM fallback (if backend available)

4. Merge parallel branch results
   - First-write-wins for conflicts
   - Log merge events

5. Summarize run
   - Data movement graph (which steps fed which)
   - OAST correlation per branch
   - Verdict: reproduced / callable / halted
```

### 3.2 Data Movement Tracking

| Aspect | Current | Enhanced |
|--------|---------|----------|
| Fragment source | Single step output | Multi-step merge (A+B → C) |
| Transform chain | Single filter | Filter composition (`\|b64\|urlencode`) |
| OAST correlation | Single canary | Multiple canaries per branch |
| Verdict granularity | Binary | Path-specific (A→C moved, B→C didn't) |

## 4. Component Specifications

### 4.1 ChainGraph

```python
@dataclass
class ChainNode:
    step: ChainStep
    dependencies: list[int]  # indices of prerequisite steps
    condition: str | None = None  # e.g., "step0.failed == False"

@dataclass
class ChainGraph:
    nodes: list[ChainNode]
    parallel_groups: list[list[int]]  # indices that can run concurrently
```

### 4.2 ConditionalStep

```python
@dataclass(frozen=True)
class ConditionalStep(ChainStep):
    condition: str  # Python expression evaluated against prior results
    # e.g., "step0.response_text contains 'admin'"
```

Condition evaluation uses a restricted expression evaluator (no arbitrary code execution).

### 4.3 Lane-Aware Templates

Pre-built patterns in `mcpnuke/core/chain_templates.py`:

| Lane | Template | Attack Path |
|------|----------|-------------|
| B (delegated) | `delegated_escalation` | credential_theft → lateral_movement → exfil |
| C (machine) | `machine_to_machine` | service_account_enum → token_theft → api_abuse |
| D (chain) | `confused_deputy` | tool_shadow → confused_deputy → data_exfil |
| E (anonymous) | `resource_exhaustion` | budget_exhaust → resource_exhaust → dos |

Templates are instantiated with actual tool names from the target.

### 4.4 K8s Integration

New check `k8s_chain_probe`:
- Enumerates service accounts, tokens, namespace boundaries
- Constructs cross-namespace data movement chains
- Integrates with existing `k8s/` module discovery

## 5. Error Handling

| Error Type | Detection | Handling | User Feedback |
|------------|-----------|----------|---------------|
| Cycle | Parse time | Reject chain | "Chain contains circular dependency: step0 → step2 → step0" |
| Missing dependency | Runtime | Halt chain | "Step 3 requires step 1 output, but step 1 failed" |
| Condition failure | Runtime | Treat as false | "Condition 'step0.x' failed to evaluate, skipping branch" |
| Partial parallel failure | Runtime | Continue others | "Branch 2/3 succeeded; branch 1 failed on step X" |
| Merge conflict | Runtime | First-write-wins | "Parallel branches produced conflicting values for key 'token'" |
| LLM fallback exhausted | Runtime | Mark step failed | "LLM adaptation failed after 2 attempts" |

## 6. Safety

- `safe_mode` applies per-step, not per-chain
- Dangerous tool in any branch → that branch refused, others may continue
- OAST canaries scoped per-branch for attribution
- No arbitrary code execution in condition evaluation

## 7. Testing Strategy

### 7.1 Test Layers

| Layer | Scope | Count |
|-------|-------|-------|
| Unit | ChainGraph parsing, topological sort | 8+ |
| Unit | Conditional evaluation | 6+ |
| Unit | Parallel group execution | 4+ |
| Integration | Full 3-hop chain with transforms | 4+ |
| Integration | Lane template instantiation | 4+ |
| Regression | Existing 2-hop chains | All existing tests |

### 7.2 Key Test Cases

1. **Linear 3-hop:** `read_secret → decode → exfil` with tracked fragments
2. **Conditional branch:** `check_admin → (success: escalate | fail: enumerate)`
3. **Parallel exfil:** `get_creds ∥ get_tokens → merge → send`
4. **K8s chain:** `list_sa → steal_token → cross_namespace_call`
5. **LLM fallback per-step:** Unresolvable placeholder in step 2 of 3
6. **Cycle rejection:** Chain with circular dependency rejected at parse
7. **Orphan node:** Node with no path from root logged and excluded

### 7.3 Regression Prevention

- All existing `test_chain_replay.py` tests must pass unchanged
- New tests in `test_chain_replay_extended.py`
- CI dogfood includes 3-hop chain scenario

## 8. Success Criteria

- [ ] 3-hop chains execute successfully with fragment tracking
- [ ] Conditional branches evaluate correctly
- [ ] Parallel groups execute and merge results
- [ ] Lane templates instantiate for B, C, D, E lanes
- [ ] K8s chain probe detects cross-namespace movement
- [ ] All existing tests pass (no regressions)
- [ ] Full suite: 1,613+ tests passing

## 9. Out of Scope

- T29–T31 (defensive controls) — intentionally excluded
- MCP spec surfaces awaiting wire format finalization (tasks, subscriptions, ETags)
- PyPI publish arming — separate infrastructure task
- `session.py` split — cleanup phase

## 10. Future Work (Cleanup Phase)

- `core/session.py` split (~1100 lines → smaller modules)
- Root-level scan artifact cleanup
- Cursor rule version sync (6.13.0 → 6.17.0)
- MYPY_CEILING reduction (30 → 0)
