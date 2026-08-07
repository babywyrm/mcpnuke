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

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mcpnuke.checks.tool_probes import (
    _build_safe_args,
    _call_tool,
    _is_dangerous_tool,
    _response_text,
)
from mcpnuke.core.transports.base import MCPSessionProtocol

if TYPE_CHECKING:
    from mcpnuke.core.oast import CanaryListener

# {{stepN.output}} — the only placeholder form the executor understands. Kept
# narrow on purpose: a richer templating language would let a prompt smuggle
# arbitrary Python into the runner.
_PLACEHOLDER_RE = re.compile(r"\{\{step(\d+)\.output\}\}")

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


def _substitute(value: str, prior: list[StepResult]) -> str:
    """Replace {{stepN.output}} with the text of a prior step's response."""

    def replace(match: re.Match[str]) -> str:
        index = int(match.group(1))
        if 0 <= index < len(prior) and not prior[index].failed:
            return prior[index].response_text
        return match.group(0)

    return _PLACEHOLDER_RE.sub(replace, value)


def _resolve_args(template: dict, prior: list[StepResult], oast_url: str = "") -> dict:
    resolved: dict = {}
    for key, value in template.items():
        if isinstance(value, str):
            substituted = _substitute(value, prior)
            if oast_url:
                substituted = _OAST_RE.sub(oast_url, substituted)
            resolved[key] = substituted
        else:
            resolved[key] = value
    return resolved


def _is_failure(resp: dict | None) -> bool:
    if resp is None:
        return True
    if resp.get("error"):
        return True
    result = resp.get("result")
    return isinstance(result, dict) and bool(result.get("isError"))


def replay_chain(
    session: MCPSessionProtocol,
    chain: ProposedChain,
    tools: dict[str, dict],
    *,
    safe_mode: bool = False,
    oast: CanaryListener | None = None,
) -> ChainRun:
    """Execute *chain* against *session*, threading outputs into later args.

    Stops at the first failing step: a chain whose middle link refuses is not
    a chain that worked, and continuing would invent a path that isn't there.
    Under *safe_mode* a step whose tool is classified dangerous is refused
    before the call — the same gate single-tool probes use — and the chain
    halts, because a chain missing its middle link did not run.
    When *oast* is set, ``{{oast.url}}`` in step args is replaced with a
    fresh canary URL so a later callback can confirm egress.
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
        args.update(_resolve_args(step.args, run.results, oast_url))
        resp = _call_tool(session, step.tool, args)
        text = _response_text(resp)
        failed = _is_failure(resp)
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
        for source_index, source in enumerate(run.results[:sink_index]):
            fragment = (source.response_text or "").strip()
            if len(fragment) < 4:
                continue
            for value in result.request_args.values():
                if isinstance(value, str) and fragment in value:
                    moves.append((source_index, sink_index, fragment[:80]))
                    break
    return moves


def summarize_run(
    run: ChainRun, oast: CanaryListener | None = None
) -> ChainVerdict:
    """Decide whether the transcript reproduces the proposed chain.

    Four outcomes: halted (not reproduced), callable end-to-end without
    proven data movement, completed with an earlier output appearing in a
    later request (reproduced), or completed with an out-of-band callback
    to a planted canary (egress confirmed — strongest tier). A single-step
    "chain" is never reproduced — that is just a tool call.
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
        callbacks = oast.hits(run.oast_token)
        if callbacks:
            tools_named = " → ".join(r.tool for r in run.results)
            cb = callbacks[0]
            return ChainVerdict(
                reproduced=True,
                callable_end_to_end=True,
                egress_confirmed=True,
                detail=(
                    f"Chain exfiltrated data out-of-band ({tools_named}). "
                    f"The target reached the canary URL from {cb.peer}, which "
                    "appeared nowhere except this replay."
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
