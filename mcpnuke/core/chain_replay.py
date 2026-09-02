"""Run a proposed attack chain and record what actually happened.

Phase 3 produces chains as prose: these tools compose, this value carries data
from A to B. That is a hypothesis. Replaying it — calling the named tools in
order against a live session, threading each response into the next — is what
turns the hypothesis into a transcript.

The executor is deliberately free of any LLM call. Substitution, sequencing
and the verdict are pure functions of the tool responses, so they are unit
testable without a model and reproducible without sampling noise. The model
proposes; this module executes and judges.
"""

from __future__ import annotations

import base64
import contextlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcpnuke.checks.base import response_is_error
from mcpnuke.checks.tool_probes import (
    _build_safe_args,
    _call_tool,
    _is_dangerous_tool,
    _response_text,
)
from mcpnuke.core.transports.base import MCPSessionProtocol

if TYPE_CHECKING:
    from mcpnuke.core.oast import CanaryListener

# {{stepN.output}} or {{stepN.output.field|filter}} — placeholder template pattern.
_PLACEHOLDER_RE = re.compile(
    r"\{\{step(\d+)\.output(?:\.([a-zA-Z0-9_.\[\]]+))?(?:\|([a-zA-Z0-9_]+))?\}\}"
)

# {{oast.url}} — replaced with a per-run canary URL when a listener is active.
# A request for that URL is out-of-band proof the sink reached an address that
# appeared nowhere except this one replay.
_OAST_RE = re.compile(r"\{\{oast\.url\}\}")

# Cap the evidence a verdict carries so a chatty tool cannot flood the report.
_EVIDENCE_CHARS: int = 400


@dataclass(frozen=True)
class ChainStep:
    """One tool invocation in a proposed chain."""

    tool: str
    args: dict = field(default_factory=dict)


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
            steps.append(ChainStep(tool=tool, args=args))
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


def _evaluate_condition(condition: str, prior: list[StepResult]) -> bool:
    """Evaluate a condition expression against prior step results.

    Supports a restricted expression language:
    - stepN.response_text <op> <value>
    - stepN.failed == True/False
    - len(stepN.response_text) <op> <number>
    - 'contains' for substring matching

    Returns False on any evaluation error (safe default).
    """
    if not condition:
        return True

    # Build safe evaluation context
    context: dict[str, Any] = {"len": len}
    for i, result in enumerate(prior):
        context[f"step{i}"] = result

    # Replace 'contains' with 'in' for Python evaluation
    expr = condition.replace(" contains ", " in ")

    try:
        return bool(eval(expr, {"__builtins__": {}}, context))
    except Exception:
        return False


def _parse_json_safe(text: str) -> Any:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    try:
        return json.loads(cleaned)
    except Exception:
        return text


def _extract_path(data: Any, path: str) -> Any:
    """Extract a nested value from dict/list or JSON string via dot/bracket path."""
    if not path:
        return data
    if isinstance(data, str):
        parsed = _parse_json_safe(data)
        if isinstance(parsed, (dict, list)):
            data = parsed
        else:
            return None

    tokens: list[str | int] = []
    for part in path.split("."):
        if not part:
            continue
        subparts = re.findall(r"([^\[\]]+)|\[(\d+)\]", part)
        for name, idx in subparts:
            if name:
                tokens.append(name)
            elif idx:
                tokens.append(int(idx))

    curr = data
    for token in tokens:
        if isinstance(token, str):
            if isinstance(curr, dict) and token in curr:
                curr = curr[token]
            else:
                return None
        elif isinstance(token, int):
            if isinstance(curr, list) and 0 <= token < len(curr):
                curr = curr[token]
            else:
                return None
        else:
            return None
    return curr


def _apply_filter(value: Any, filter_name: str) -> str:
    """Apply a transform filter to a value."""
    if filter_name == "json":
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, default=str)
        except Exception:
            return str(value)

    text = value if isinstance(value, str) else str(value)
    f = filter_name.lower().strip()
    if f == "b64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    elif f == "b64decode":
        try:
            return base64.b64decode(text.encode("ascii")).decode("utf-8", errors="replace")
        except Exception:
            return text
    elif f == "urlencode":
        return urllib.parse.quote(text, safe="")
    elif f == "urldecode":
        return urllib.parse.unquote(text)
    elif f == "strip":
        return text.strip()
    return text


def _substitute(
    value: str,
    prior: list[StepResult],
    tracked_fragments: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Replace {{stepN.output...}} placeholders with extracted/transformed prior step responses."""
    fragments: list[str] = []

    def replace(match: re.Match[str]) -> str:
        index_str = match.group(1)
        path = match.group(2)
        filter_name = match.group(3)
        index = int(index_str)
        if not (0 <= index < len(prior) and not prior[index].failed):
            return match.group(0)

        raw_output = prior[index].response_text
        extracted = _extract_path(raw_output, path) if path else raw_output
        if extracted is None:
            return match.group(0)

        if isinstance(extracted, str) and len(extracted.strip()) >= 4:
            fragments.append(extracted.strip())

        if filter_name:
            filtered = _apply_filter(extracted, filter_name)
        elif isinstance(extracted, str):
            filtered = extracted
        else:
            filtered = _apply_filter(extracted, "json")

        if isinstance(filtered, str) and len(filtered.strip()) >= 4:
            fragments.append(filtered.strip())

        return filtered

    res = _PLACEHOLDER_RE.sub(replace, value)
    if tracked_fragments is not None:
        tracked_fragments.extend(fragments)
    return res, fragments


def _resolve_args(
    template: dict,
    prior: list[StepResult],
    oast_url: str = "",
    tracked_fragments: list[str] | None = None,
) -> dict:
    resolved: dict = {}
    for key, value in template.items():
        if isinstance(value, str):
            substituted, _ = _substitute(value, prior, tracked_fragments)
            if oast_url:
                substituted = _OAST_RE.sub(oast_url, substituted)
            resolved[key] = substituted
        else:
            resolved[key] = value
    return resolved


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
    """
    run = ChainRun(chain=chain)
    oast_url = ""
    if oast is not None:
        run.oast_token = oast.issue()
        oast_url = oast.url_for(run.oast_token)

    for step in chain.steps:
        tool = tools.get(step.tool)
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
                )
            )
            break

        args = _build_safe_args(tool)
        args.update(_resolve_args(step.args, run.results, oast_url, run.tracked_fragments))

        has_unresolved = any(
            isinstance(v, str) and _PLACEHOLDER_RE.search(v)
            for v in args.values()
        )
        if has_unresolved and backend is not None:
            adapted = _adapt_step_args_with_llm(backend, tool, step.args, run.results, model=model)
            if adapted:
                args.update(adapted)
                for val in adapted.values():
                    if isinstance(val, str) and len(val.strip()) >= 4:
                        run.tracked_fragments.append(val.strip())

        resp = _call_tool(session, step.tool, args)
        text = _response_text(resp)
        failed = response_is_error(resp)

        if failed and not has_unresolved and backend is not None:
            adapted = _adapt_step_args_with_llm(backend, tool, step.args, run.results, model=model)
            if adapted and adapted != args:
                retry_args = _build_safe_args(tool)
                retry_args.update(adapted)
                retry_resp = _call_tool(session, step.tool, retry_args)
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
            )
        )
        if failed:
            break
    return run


def _data_moved(run: ChainRun) -> list[tuple[int, int, str]]:
    """Pairs of (source_step, sink_step, fragment) where an earlier output fed a later input."""
    moves: list[tuple[int, int, str]] = []
    for sink_index, result in enumerate(run.results):
        sink_strings: list[str] = []
        for value in result.request_args.values():
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
                "appeared in a later request, so composition is unproven."
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
            )
        )
        node_to_result[node_idx] = len(run.results) - 1

    return run
