"""Run a proposed attack chain and record what actually happened.

Phase 3 produces chains as prose: these tools compose, this value carries data
from A to B. That is a hypothesis. Replaying it — calling the named tools in
order against a live session, threading each response into the next — is what
turns the hypothesis into a transcript.

The executor is deliberately free of any LLM call. Substitution (in
``chain_args``), sequencing and the verdict are pure functions of the tool
responses, so they are unit testable without a model and reproducible
without sampling noise. The model proposes; this module executes and judges.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcpnuke.checks.base import response_is_error
from mcpnuke.checks.tool_probes import (
    _build_extended_args,
    _build_safe_args,
    _call_tool,
    _is_dangerous_tool,
    _response_text,
)
from mcpnuke.core.chain_args import (
    _PLACEHOLDER_RE,
    _evaluate_condition,
    _parse_json_safe,
    _resolve_args,
)
from mcpnuke.core.transports.base import MCPSessionProtocol

if TYPE_CHECKING:
    from mcpnuke.core.oast import CanaryListener


# Cap the evidence a verdict carries so a chatty tool cannot flood the report.
_EVIDENCE_CHARS: int = 400


@dataclass(frozen=True)
class ChainStep:
    """One tool invocation in a proposed chain.

    ``target`` is the MCP URL for this step. Empty means the session the
    replay was given. A non-empty target is opened for this step and closed
    after it, and only when the caller passed an opener.
    """

    tool: str
    args: dict = field(default_factory=dict)
    target: str = ""


@dataclass(frozen=True)
class ConditionalStep(ChainStep):
    """A step that executes only if its condition evaluates true."""

    condition: str = ""


@dataclass(frozen=True)
class ProposedChain:
    """An executable chain description, typically produced by an LLM."""

    title: str
    steps: list[ChainStep]
    detail: str = ""
    taxonomy_id: str = ""


@dataclass
class StepResult:
    """What happened when one step was attempted."""

    tool: str
    request_args: dict
    response_text: str
    failed: bool
    reason: str = ""
    target: str = ""
    declared_params: frozenset[str] | None = None


@dataclass
class ChainRun:
    """The transcript of a replay."""

    chain: ProposedChain
    results: list[StepResult] = field(default_factory=list)
    oast_token: str = ""
    tracked_fragments: list[str] = field(default_factory=list)

    @property
    def completed(self) -> bool:
        return bool(self.results) and not any(r.failed for r in self.results)


@dataclass(frozen=True)
class ChainVerdict:
    """Whether the transcript reproduces the proposed chain."""

    reproduced: bool
    callable_end_to_end: bool
    detail: str
    evidence: str = ""
    egress_confirmed: bool = False


@dataclass
class ChainNode:
    """A node in the chain execution graph."""

    step: ChainStep
    dependencies: list[int] = field(default_factory=list)
    condition: str | None = None


@dataclass
class ChainGraph:
    """Directed acyclic graph of chain execution."""

    nodes: list[ChainNode] = field(default_factory=list)
    parallel_groups: list[list[int]] = field(default_factory=list)


def parse_proposed_chains(text: str) -> list[ProposedChain]:
    """Decode an LLM response into executable chains.

    Rejects anything that cannot be run: a finding with no `steps`, a single
    step (that is a tool call, not a chain), or a step that names no tool.
    Truncated JSON is salvaged the same way findings are — complete objects
    before the cut survive, the rest is simply absent.
    """
    from mcpnuke.core.llm import _complete_objects

    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]

    try:
        items = json.loads(text)
        if not isinstance(items, list):
            return []
    except json.JSONDecodeError:
        items = list(_complete_objects(text))

    chains: list[ProposedChain] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        raw_steps = item.get("steps")
        if not isinstance(raw_steps, list) or len(raw_steps) < 2:
            continue
        steps: list[ChainStep] = []
        valid = True
        for raw in raw_steps:
            if not isinstance(raw, dict):
                valid = False
                break
            tool = str(raw.get("tool") or "").strip()
            if not tool:
                valid = False
                break
            raw_args = raw.get("args")
            args = dict(raw_args) if isinstance(raw_args, dict) else {}
            target = str(raw.get("target") or "").strip()
            steps.append(ChainStep(tool=tool, args=args, target=target))
        if not valid or len(steps) < 2:
            continue
        chains.append(
            ProposedChain(
                title=str(item.get("title") or "proposed chain"),
                steps=steps,
                detail=str(item.get("detail") or ""),
                taxonomy_id=str(item.get("taxonomy_id") or ""),
            )
        )
    return chains


def parse_chain_graph(chain: ProposedChain) -> ChainGraph:
    """Parse a ProposedChain into a ChainGraph with dependency edges.

    Builds edges from {{stepN.output}} references in step args.
    Validates: no cycles, no self-dependencies.
    """
    nodes: list[ChainNode] = []
    for i, step in enumerate(chain.steps):
        deps: list[int] = []
        for arg_value in step.args.values():
            if isinstance(arg_value, str):
                for match in _PLACEHOLDER_RE.finditer(arg_value):
                    dep_idx = int(match.group(1))
                    if dep_idx == i:
                        raise ValueError(f"self-dependency in step {i}")
                    if dep_idx not in deps:
                        deps.append(dep_idx)
        condition = getattr(step, "condition", None)
        nodes.append(ChainNode(step=step, dependencies=sorted(deps), condition=condition))

    # Cycle detection via topological sort
    _topological_sort(nodes)  # raises ValueError on cycle

    return ChainGraph(nodes=nodes)


def _topological_sort(nodes: list[ChainNode]) -> list[int]:
    """Return execution order via Kahn's algorithm. Raises ValueError on cycle."""
    in_degree = {i: 0 for i in range(len(nodes))}
    for i, node in enumerate(nodes):
        for _dep in node.dependencies:
            in_degree[i] += 1

    queue = [i for i, deg in in_degree.items() if deg == 0]
    order: list[int] = []

    while queue:
        node_idx = queue.pop(0)
        order.append(node_idx)
        for i, node in enumerate(nodes):
            if node_idx in node.dependencies:
                in_degree[i] -= 1
                if in_degree[i] == 0:
                    queue.append(i)

    if len(order) != len(nodes):
        raise ValueError("circular dependency detected in chain")
    return order




def _adapt_step_args_with_llm(
    backend: Any,
    tool: dict,
    template_args: dict,
    prior_results: list[StepResult],
    model: str = "",
) -> dict | None:
    """Ask LLM backend to extract appropriate arguments for the tool based on prior step responses."""
    if not backend or not prior_results:
        return None

    prompt = (
        f"You are helping execute a multi-step security attack chain against an MCP tool.\n"
        f"Tool to call: {tool.get('name')}\n"
        f"Tool description: {tool.get('description', '')}\n"
        f"Tool input schema: {json.dumps(tool.get('inputSchema', {}))}\n"
        f"Step template args: {json.dumps(template_args)}\n\n"
        f"Prior step outputs:\n"
    )
    for i, r in enumerate(prior_results):
        status = "FAIL" if r.failed else "SUCCESS"
        prompt += f"[Step {i} ({r.tool}) - {status}]:\n{r.response_text}\n\n"

    prompt += (
        "Extract the exact parameters needed from the prior step outputs to call this tool.\n"
        "Return ONLY a valid JSON object of argument key-values, nothing else."
    )

    system = "You are an expert security automation assistant. Output valid JSON arguments only."
    try:
        if hasattr(backend, "adapt_step_args"):
            res = backend.adapt_step_args(tool, template_args, prior_results, model=model)
            if isinstance(res, dict):
                return res

        text = ""
        if hasattr(backend, "_call"):
            text = backend._call(system, prompt, max_tokens=1024)
        elif hasattr(backend, "call"):
            text = backend.call(system, prompt)
        elif hasattr(backend, "_call_claude"):
            text = backend._call_claude(system, prompt, model=model, max_tokens=1024)
        else:
            return None

        parsed = _parse_json_safe(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return None


def replay_chain(
    session: MCPSessionProtocol,
    chain: ProposedChain,
    tools: dict[str, dict],
    *,
    safe_mode: bool = False,
    oast: CanaryListener | None = None,
    backend: Any = None,
    model: str = "",
    open_session: Callable[[str], MCPSessionProtocol | None] | None = None,
    allowed_targets: frozenset[str] | None = None,
    catalogs: dict[str, dict[str, dict]] | None = None,
) -> ChainRun:
    """Execute *chain* against *session*, threading outputs into later args.

    Stops at the first failing step: a chain whose middle link refuses is not
    a chain that worked, and continuing would invent a path that isn't there.
    Under *safe_mode* a step whose tool is classified dangerous is refused
    before the call — the same gate single-tool probes use — and the chain
    halts, because a chain missing its middle link did not run.
    When *oast* is set, ``{{oast.url}}`` in step args is replaced with a
    fresh canary URL so a later callback can confirm egress.
    When *backend* is provided, dynamic LLM parameter adaptation extracts
    values when deterministic templating fails or leaves unresolved placeholders.
    A step with ``target`` set is sent to the session *open_session* returns
    for that URL. The peer is closed before the next step. With no opener
    the step is refused and is not sent to *session*.
    When *allowed_targets* is set, a target outside that set is refused
    before any connection.
    *catalogs* maps a server URL to that server's tools. A step with
    ``target`` set is resolved there, so a peer-only tool is not rejected
    for being absent locally and is not invoked on the current session.
    """
    run = ChainRun(chain=chain)
    oast_url = ""
    if oast is not None:
        run.oast_token = oast.issue()
        oast_url = oast.url_for(run.oast_token)

    for step in chain.steps:
        catalog = tools
        if step.target and catalogs is not None and step.target in catalogs:
            catalog = catalogs[step.target]
        tool = catalog.get(step.tool)
        if tool is None:
            run.results.append(
                StepResult(
                    tool=step.tool,
                    request_args={},
                    response_text="",
                    failed=True,
                    reason=f"unknown tool '{step.tool}'",
                )
            )
            break

        if safe_mode and _is_dangerous_tool(tool):
            run.results.append(
                StepResult(
                    tool=step.tool,
                    request_args={},
                    response_text="",
                    failed=True,
                    reason="refused under safe-mode: dangerous tool",
                    target=step.target,
                )
            )
            break

        # A named target is another server. Refuse it before falling through
        # to the session that produced the previous step.
        active: MCPSessionProtocol = session
        peer: MCPSessionProtocol | None = None
        if step.target:
            if allowed_targets is not None and step.target not in allowed_targets:
                run.results.append(
                    StepResult(
                        tool=step.tool,
                        request_args={},
                        response_text="",
                        failed=True,
                        reason="target is not in this scan",
                        target=step.target,
                    )
                )
                break
            if open_session is None:
                run.results.append(
                    StepResult(
                        tool=step.tool,
                        request_args={},
                        response_text="",
                        failed=True,
                        reason="cross-server replay is off",
                        target=step.target,
                    )
                )
                break
            peer = open_session(step.target)
            if peer is None:
                run.results.append(
                    StepResult(
                        tool=step.tool,
                        request_args={},
                        response_text="",
                        failed=True,
                        reason=f"could not connect to {step.target}",
                        target=step.target,
                    )
                )
                break
            active = peer

        try:
            args = _build_safe_args(tool)
            args.update(_resolve_args(step.args, run.results, oast_url, run.tracked_fragments))

            has_unresolved = any(
                isinstance(v, str) and _PLACEHOLDER_RE.search(v)
                for v in args.values()
            )
            if has_unresolved and backend is not None:
                adapted = _adapt_step_args_with_llm(
                    backend, tool, step.args, run.results, model=model
                )
                if adapted:
                    args.update(adapted)
                    for val in adapted.values():
                        if isinstance(val, str) and len(val.strip()) >= 4:
                            run.tracked_fragments.append(val.strip())

            resp = _call_tool(active, step.tool, args)
            text = _response_text(resp)
            failed = response_is_error(resp)

            # The model's first arguments are often a payload the tool
            # rejects. Required-only defaults omit optional strings such as
            # username, so the retry uses the same filler Phase 2 does.
            if failed and not run.results:
                filled = _build_extended_args(tool)
                if filled != args:
                    retry_resp = _call_tool(active, step.tool, filled)
                    retry_text = _response_text(retry_resp)
                    args = filled
                    text = retry_text
                    if not response_is_error(retry_resp):
                        resp = retry_resp
                        failed = False

            if failed and not has_unresolved and backend is not None:
                adapted = _adapt_step_args_with_llm(
                    backend, tool, step.args, run.results, model=model
                )
                if adapted and adapted != args:
                    retry_args = _build_safe_args(tool)
                    retry_args.update(adapted)
                    retry_resp = _call_tool(active, step.tool, retry_args)
                    retry_text = _response_text(retry_resp)
                    retry_failed = response_is_error(retry_resp)
                    if not retry_failed:
                        args = retry_args
                        resp = retry_resp
                        text = retry_text
                        failed = False
                        for val in adapted.values():
                            if isinstance(val, str) and len(val.strip()) >= 4:
                                run.tracked_fragments.append(val.strip())

            run.results.append(
                StepResult(
                    tool=step.tool,
                    request_args=args,
                    response_text=text,
                    failed=failed,
                    reason="tool returned an error" if failed else "",
                    target=step.target,
                    declared_params=_declared_params(tool),
                )
            )
            if failed:
                break
        finally:
            if peer is not None:
                peer.close()
    return run


def _declared_params(tool: dict) -> frozenset[str] | None:
    """Property names the tool's input schema declares.

    None when the tool has no properties object: there is no list to
    check, so every argument still counts. An empty properties object
    declares nothing, so an extra argument does not count.
    """
    schema = tool.get("inputSchema")
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return None
    return frozenset(str(name) for name in props)


def _data_moved(run: ChainRun) -> list[tuple[int, int, str]]:
    """Pairs of (source_step, sink_step, fragment) where an earlier output fed a later input.

    When the sink records the parameters its tool declares, a fragment in
    any other argument did not move: the tool never read it.
    """
    moves: list[tuple[int, int, str]] = []
    for sink_index, result in enumerate(run.results):
        sink_strings: list[str] = []
        args = result.request_args
        if result.declared_params is not None:
            args = {key: value for key, value in args.items() if key in result.declared_params}
        for value in args.values():
            if isinstance(value, str):
                sink_strings.append(value)
            elif isinstance(value, (dict, list)):
                with contextlib.suppress(Exception):
                    sink_strings.append(json.dumps(value))

        for source_index, source in enumerate(run.results[:sink_index]):
            fragment = (source.response_text or "").strip()
            if len(fragment) >= 4 and any(fragment in s for s in sink_strings):
                moves.append((source_index, sink_index, fragment[:80]))
                continue

            matched = False
            for frag in run.tracked_fragments:
                if len(frag) >= 4 and any(frag in s for s in sink_strings):
                    moves.append((source_index, sink_index, frag[:80]))
                    matched = True
                    break
            if matched:
                continue
    return moves


def summarize_run(
    run: ChainRun,
    oast: CanaryListener | None = None,
    *,
    oast_wait: float = 2.0,
) -> ChainVerdict:
    """Decide whether the transcript reproduces the proposed chain.

    Four outcomes: halted (not reproduced), callable end-to-end without
    proven data movement, completed with an earlier output appearing in a
    later request (reproduced), or completed with an out-of-band callback
    to a planted canary (egress confirmed — strongest tier). A single-step
    "chain" is never reproduced — that is just a tool call.

    When *oast* is set, wait up to *oast_wait* seconds for a callback before
    falling through to the weaker in-band tiers — a sink that queues its
    outbound request would otherwise lose the race.
    """
    if len(run.chain.steps) < 2:
        return ChainVerdict(
            reproduced=False,
            callable_end_to_end=False,
            detail="A single step is a tool call, not a chain.",
        )

    if not run.completed:
        failed = next((r for r in run.results if r.failed), None)
        reason = failed.reason if failed else "incomplete"
        return ChainVerdict(
            reproduced=False,
            callable_end_to_end=False,
            detail=f"Halted: {reason}.",
            evidence=(failed.response_text[:_EVIDENCE_CHARS] if failed else ""),
        )

    if oast is not None and run.oast_token:
        callbacks = oast.await_hits(run.oast_token, wait=oast_wait)
        if callbacks:
            tools_named = " → ".join(r.tool for r in run.results)
            cb = callbacks[0]
            data_leak_detail = ""
            for frag in run.tracked_fragments:
                if len(frag) >= 4 and (frag in cb.body or frag in cb.path):
                    data_leak_detail = f" Leaked fragment: '{frag[:40]}'."
                    break

            return ChainVerdict(
                reproduced=True,
                callable_end_to_end=True,
                egress_confirmed=True,
                detail=(
                    f"Chain exfiltrated data out-of-band ({tools_named}). "
                    f"The target reached the canary URL from {cb.peer}, which "
                    f"appeared nowhere except this replay.{data_leak_detail}"
                ),
                evidence=f"{cb.method} {cb.path}\n{cb.body[:_EVIDENCE_CHARS]}",
            )

    moves = _data_moved(run)
    if not moves:
        return ChainVerdict(
            reproduced=False,
            callable_end_to_end=True,
            detail=(
                "Every step completed without error, but no earlier output "
                "appeared in a declared parameter of a later step, so composition "
                "is unproven."
            ),
        )

    source, sink, fragment = moves[0]
    tools_named = " → ".join(r.tool for r in run.results)
    return ChainVerdict(
        reproduced=True,
        callable_end_to_end=True,
        detail=(
            f"Chain reproduced end to end ({tools_named}). "
            f"Output of step {source} appeared in the request to step {sink}."
        ),
        evidence=f"Moved fragment: {fragment}",
    )


def replay_chain_graph(
    session: MCPSessionProtocol,
    graph: ChainGraph,
    tools: dict[str, dict],
    *,
    safe_mode: bool = False,
    oast: CanaryListener | None = None,
    backend: Any = None,
    model: str = "",
) -> ChainRun:
    """Execute a ChainGraph against a session.

    Respects dependency order, evaluates conditions, and tracks
    data movement across all executed steps.
    """
    # Create a synthetic chain for the run record
    chain = ProposedChain(
        title="graph_execution",
        steps=[node.step for node in graph.nodes],
    )
    run = ChainRun(chain=chain)

    oast_url = ""
    if oast is not None:
        run.oast_token = oast.issue()
        oast_url = oast.url_for(run.oast_token)

    # Get execution order
    order = _topological_sort(graph.nodes)

    # Track which node index maps to which result index
    node_to_result: dict[int, int] = {}

    for node_idx in order:
        node = graph.nodes[node_idx]

        # Evaluate condition if present
        if node.condition:
            prior_results = [run.results[node_to_result[i]] for i in node.dependencies if i in node_to_result]
            if not _evaluate_condition(node.condition, prior_results):
                continue

        tool = tools.get(node.step.tool)
        if tool is None:
            run.results.append(
                StepResult(
                    tool=node.step.tool,
                    request_args={},
                    response_text="",
                    failed=True,
                    reason=f"unknown tool '{node.step.tool}'",
                )
            )
            node_to_result[node_idx] = len(run.results) - 1
            continue

        if safe_mode and _is_dangerous_tool(tool):
            run.results.append(
                StepResult(
                    tool=node.step.tool,
                    request_args={},
                    response_text="",
                    failed=True,
                    reason="refused under safe-mode: dangerous tool",
                )
            )
            node_to_result[node_idx] = len(run.results) - 1
            continue

        # Build args from dependencies
        args = _build_safe_args(tool)
        dep_results = [run.results[node_to_result[i]] for i in node.dependencies if i in node_to_result]
        args.update(_resolve_args(node.step.args, dep_results, oast_url, run.tracked_fragments))

        # Check for unresolved placeholders
        has_unresolved = any(
            isinstance(v, str) and _PLACEHOLDER_RE.search(v)
            for v in args.values()
        )
        if has_unresolved and backend is not None:
            adapted = _adapt_step_args_with_llm(backend, tool, node.step.args, dep_results, model=model)
            if adapted:
                args.update(adapted)
                for val in adapted.values():
                    if isinstance(val, str) and len(val.strip()) >= 4:
                        run.tracked_fragments.append(val.strip())

        resp = _call_tool(session, node.step.tool, args)
        text = _response_text(resp)
        failed = response_is_error(resp)

        # LLM fallback on failure
        if failed and not has_unresolved and backend is not None:
            adapted = _adapt_step_args_with_llm(backend, tool, node.step.args, dep_results, model=model)
            if adapted and adapted != args:
                retry_args = _build_safe_args(tool)
                retry_args.update(adapted)
                retry_resp = _call_tool(session, node.step.tool, retry_args)
                retry_text = _response_text(retry_resp)
                retry_failed = response_is_error(retry_resp)
                if not retry_failed:
                    args = retry_args
                    resp = retry_resp
                    text = retry_text
                    failed = False
                    for val in adapted.values():
                        if isinstance(val, str) and len(val.strip()) >= 4:
                            run.tracked_fragments.append(val.strip())

        run.results.append(
            StepResult(
                tool=node.step.tool,
                request_args=args,
                response_text=text,
                failed=failed,
                reason="tool returned an error" if failed else "",
                declared_params=_declared_params(tool),
            )
        )
        node_to_result[node_idx] = len(run.results) - 1

    return run
