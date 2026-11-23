# Tasks Extension (SEP-2663) Check — Design

Date: 2026-11-22. Status: approved design, not implemented.

## 1. Problem

The 2026-07-28 spec adds the Tasks extension (`io.modelcontextprotocol/tasks`,
SEP-2663). A server MAY answer `tools/call` with a `CreateTaskResult`
(`resultType: "task"`) and serve the outcome later through `tasks/get`,
`tasks/update`, and `tasks/cancel`. SEP-2663 states two security MUSTs:

- Task IDs are unguessable. They may act as bearer handles.
- Every task-related request is authorized.

It also removes `tasks/list`, which cannot be scoped to a caller, and forbids
returning `CreateTaskResult` to a client that did not declare the extension.

mcpnuke never declares the extension and tests none of this.

## 2. Scope

First release: one self-contained behavioral check, `tasks_extension`. It
declares the extension only on its own requests.

Out of scope here: declaring the extension on the shared tool-call path so
every existing check sees task results. That changes `tools/call` for all
checks and ships later, separately.

## 3. Gate

The check runs only when all hold:

- `--no-invoke` is off.
- `result.protocol_mode` is stateless. Under `2025-11-25` the server MUST
  ignore the capability.
- `server_info["capabilities"]["extensions"]` lists
  `io.modelcontextprotocol/tasks`. Without it, only probe 1 runs.
- A tool exists that `_is_dangerous_tool` (`checks/tool_probes.py`) rejects.
  The filter applies regardless of `--safe-mode`. Arguments come from
  `_build_safe_args`.

No qualifying tool means no finding and no tool call.

## 4. Probes

At most nine requests, all against one tool and the scanner's own tasks.

1. `tools/call` without the capability. A `resultType: "task"` reply is
   an unsolicited task.
2. `tools/call` twice with
   `params._meta["io.modelcontextprotocol/clientCapabilities"].extensions["io.modelcontextprotocol/tasks"] = {}`.
   Yields two `taskId`s.
3. `tasks/get`, `tasks/update`, `tasks/cancel` on the first task with the
   `Authorization` header removed. Needs `post_raw` and a scan that is not
   `scanned_anonymously()`; otherwise skipped.
4. `tasks/list`.
5. Cleanup: `tasks/cancel` with the real token on both tasks.

## 5. Findings

| Finding | Severity | Taxonomy |
|---|---|---|
| Anonymous `tasks/get`, `tasks/update`, or `tasks/cancel` succeeds | CRITICAL | MCP-T11 |
| Guessable task ID: all digits, sequential pair, under 16 chars, or timestamp / UUIDv1 shape | HIGH | MCP-T11 |
| `tasks/list` answered | MEDIUM | none |
| `CreateTaskResult` returned without the capability | MEDIUM | none |

The vendored taxonomy has no ID for the last two. Do not add one.

## 6. Plumbing

`post_raw` merges `extra_headers` and cannot remove a header. Change: an
`extra_headers` value of `None` drops that header. One line each in the SSE,
HTTP, and toolserver transports. No new Protocol member; stdio still has no
`post_raw`. `tests/test_session_protocol.py` gets a case proving the dropped
header never reaches the server.

## 7. Fixtures

Both lab servers keep answering `initialize`, so default auto-mode scans stay
legacy. OWASP lab results and the HTTP/stdio FP ceilings do not move. Tests
force `--protocol-mode stateless`.

`tests/owasp_lab` (vulnerable):

- Answers `server/discover`, advertising the extension.
- One read-only tool returns a task only when the capability is declared.
- Sequential numeric task IDs.
- `tasks/get`, `tasks/update`, `tasks/cancel`, `tasks/list` with no auth.
- Takes no token. The positive test scans it with a synthetic token.

`tests/reference_target` (quiet):

- Answers `server/discover`, advertising the extension.
- Task IDs from `secrets.token_urlsafe(24)`.
- Every `tasks/*` request requires the bearer token.
- `tasks/list` returns method-not-found.
- Never returns a task without the declared capability.

## 8. Tests

`tests/test_tasks_extension.py`:

- Positive: stateless scan of `owasp_lab` with a token fires all four findings.
- Clean: stateless scan of `reference_target` gives zero `tasks_extension`
  findings.
- Skips: `--no-invoke`, legacy mode, extension not advertised, no safe tool.
  Each gives no finding and no `tools/call`.
- Cleanup: both scanner-owned tasks are cancelled.
- Timing recorded.
- Unit: the task-ID guessability helper.

## 9. Prerequisite fix

`negotiate_protocol` adds "Unauthenticated MCP server/discover accepted"
(HIGH) whenever discover succeeds, even when the scan carried a token.
`TargetResult.scanned_anonymously()` exists for this gate. Fix it first, test
first, in its own commit. Otherwise a stateless scan of `reference_target` is
noisy.

## 10. Rollout

- Wire into `run_all_checks`; document in `docs/checks.md`; update check
  totals in `README.md` and `docs/checks.md`.
- `docs/spec-surface.md` and `ROADMAP.md`: Tasks moves from Wait to Ready,
  then Shipped.
- CHANGELOG entry.
- Gate: pytest, ruff, strict mypy, secret scan; OSS snapshots unchanged.
