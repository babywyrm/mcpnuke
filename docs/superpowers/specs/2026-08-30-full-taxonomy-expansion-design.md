# Full Taxonomy Expansion (MCP-T11 to MCP-T58 Coverage) Design

**Date:** 2026-08-30  
**Target:** Expand mcpnuke's outside-in attack taxonomy coverage from 42/57 (74%) to 54/57 (95%), covering all remaining scannable threat IDs in the agentic-sec taxonomy.

---

## 1. Background & Scope

The agentic threat taxonomy (`lanes.yaml`) defines 57 threat IDs (MCP-T01 to MCP-T58, excluding reserved T40).
Three threats (MCP-T29, T30, T31) represent defensive rule authoring and budget tuning which belong to runtime policy enforcers (nullfield/skillseraph) rather than an outside-in scanner.

This design adds high-precision, transport-aware static and behavioral checks for the remaining 12 scannable threats:
- **MCP-T11:** Cross-Tenant Memory Leak (Lane 1, Transport A)
- **MCP-T18:** Bot Identity Theft via tbot / Machine Credential Exposure (Lane 3, Transport A)
- **MCP-T24:** Authentication Pattern Downgrade (Lane 2, Transport A)
- **MCP-T37:** Agent HTTP Bypass — Direct Transport B Access (Lane 3, Transport B)
- **MCP-T38:** Code Review Agent Subprocess Injection (Lane 2, Transport D)
- **MCP-T39:** RAG Pipeline Ingestion Injection (Lane 4, Transport C)
- **MCP-T41:** AI Governance Gate Bypass via Trusted Redirect (Lane 2, Transport A)
- **MCP-T45:** Agent-to-Agent Identity Dilution via Direct API Credential Forwarding (Lane 4, Transport B)
- **MCP-T46:** In-Process SDK Credential Cache Exposure (Lane 2, Transport C)
- **MCP-T47:** Agent Chain In-Process SDK Identity Dilution (Lane 4, Transport C)
- **MCP-T48:** Agent Chain Subprocess Credential Injection (Lane 4, Transport D)
- **MCP-T49:** Agent Chain LLM Function-Calling Context Leak (Lane 4, Transport E)

---

## 2. Check Architecture & Detectors

All 12 checks will reside in `mcpnuke/checks/taxonomy_coverage.py` (or existing dedicated modules where appropriate, e.g., tagging `teleport.py` for T18) following mcpnuke's standard signature:
`def check_<name>(result: TargetResult) -> None:`

Each check:
1. Wraps execution in `with time_check("<name>", result):`.
2. Inspects tool definitions, parameters (`_param_keys`), and schemas.
3. Applies transport-aware filters (`skip_transports=["stdio"]` where appropriate).
4. Emits findings tagged with precise `lane`, `transport`, and `taxonomy_id="MCP-Txx"`.

### Detailed Threat Detectors:

1. **`check_cross_tenant_memory_leak` (MCP-T11)**
   - Flags tools allowing arbitrary tenant selection or multi-tenant memory access (`tenant_id`, `target_tenant`, `other_tenant`, `cross_tenant`, `workspace_id`) without authentication binding.
   - Severity: `HIGH` (if unauthenticated/caller-controlled), `MEDIUM` (if scoped).

2. **`check_tbot_credential_exposure` / `check_bot_identity_theft` (MCP-T18)**
   - Tag K8s secret reader findings in `teleport.py` with `taxonomy_id="MCP-T18"`.
   - Add schema scanner in `taxonomy_coverage.py` detecting tools exposing `tbot`, `bot_token`, `bot_identity`, `machine_cert`.

3. **`check_auth_pattern_downgrade` (MCP-T24)**
   - Flags parameters or tools enabling auth bypass or fallback (`allow_unauthenticated`, `skip_auth`, `insecure_mode`, `bypass_auth`, `disable_token_validation`, `auth_mode` with choices `none`/`basic`).

4. **`check_agent_http_bypass` (MCP-T37)**
   - Flags tools that expose direct HTTP client invocations outside the MCP protocol boundary (`direct_url`, `bypass_gateway`, `raw_http`, `transport_b`).

5. **`check_code_review_subprocess_injection` (MCP-T38)**
   - Flags tools running git/lint/patch subprocesses on untrusted pull request or patch inputs (`apply_patch`, `review_diff`, `pr_content`, `run_linter`).

6. **`check_rag_pipeline_injection` (MCP-T39)**
   - Flags tools indexing untrusted documents, URLs, or external data directly into RAG stores or embeddings without validation (`ingest_document`, `add_to_knowledge_base`, `index_url`, `store_embedding`).

7. **`check_ai_governance_bypass_redirect` (MCP-T41)**
   - Flags tools exposing redirect or URL forward parameters in AI policy or gate evaluation contexts (`redirect_url`, `forward_to`, `policy_override_url`).

8. **`check_direct_api_credential_forwarding` (MCP-T45)**
   - Flags tools accepting raw bearer tokens or authorization headers to forward over direct REST/Transport B calls (`forward_auth`, `bearer_token`, `auth_header`).

9. **`check_sdk_credential_cache_exposure` (MCP-T46)**
   - Flags tools exposing in-memory SDK credential caches or token pools (`sdk_cache`, `token_cache`, `in_memory_tokens`).

10. **`check_agent_sdk_chain_identity_dilution` (MCP-T47)**
    - Flags in-process SDK chaining tools that discard caller attribution (`sdk_chain`, `call_sdk_function`, `in_process_delegate`).

11. **`check_agent_subprocess_credential_injection` (MCP-T48)**
    - Flags tools that inject parent process auth tokens into child process environment blocks (`env_passthrough`, `inject_credentials`, `child_env`).

12. **`check_agent_llm_function_context_leak` (MCP-T49)**
    - Flags tools that pass full raw conversation transcripts or system prompts into downstream tool calls (`full_transcript`, `raw_context`, `system_prompt_pass`).

---

## 3. Registration & Integration

- Register all 12 checks in `mcpnuke/checks/__init__.py` inside `_STATIC_CHECKS` list.
- Register their names in the check runner so progress accounting (`tests/test_check_progress.py`) remains exact.

---

## 4. Testing & Verification

1. **Unit Tests (`tests/test_taxonomy_coverage_extended.py` and dedicated test files)**:
   - For every check: positive test, clean negative test, reference target test (verifying 0 false positives on `TOOL_DEFINITIONS`), timing check.
2. **Taxonomy & Roadmap Consistency**:
   - Update `ROADMAP.md` coverage count to `54/57 IDs (95%)`.
   - Update `ROADMAP.md` tables with all newly covered IDs.
   - Run `tests/test_taxonomy_coverage_claim.py` to confirm the claim matches measured coverage.
3. **Quality Verification**:
   - `uv run pytest tests/ -v` (full suite passes).
   - `uv run ruff check .` (zero errors).
   - `uv run mypy mcpnuke/` (within CI ceiling).
