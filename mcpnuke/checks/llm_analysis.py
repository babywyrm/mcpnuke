"""AI-powered security analysis using Claude.

Layers LLM reasoning on top of deterministic checks to catch subtle
vulnerabilities that regex patterns miss: social engineering in tool
descriptions, obfuscated injection, logical attack chains, and
context-dependent risks.
"""

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Protocol

from mcpnuke.checks.base import time_check
from mcpnuke.checks.chaining import _TOOL_NAME_RE
from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke
from mcpnuke.core.chain_replay import ChainRun, ChainVerdict, replay_chain, summarize_run
from mcpnuke.core.constants import DEFAULT_CLAUDE_MODEL
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol

# Enough of each field to carry the substance without letting one verbose
# finding crowd the rest of the target out of the prompt.
_FINDING_DETAIL_CHARS: int = 600
_FINDING_EVIDENCE_CHARS: int = 300


class LLMBackend(Protocol):
    """Typed protocol for pluggable LLM analysis backends."""

    def analyze_tools(
        self,
        tools: list[dict],
        model: str,
        log: Callable[[str], None],
        known_findings: list[str] | None = None,
    ) -> list:
        ...

    def analyze_findings(
        self,
        tools: list[dict],
        findings: list[dict],
        model: str,
        log: Callable[[str], None],
    ) -> list:
        ...

    def analyze_response(
        self,
        tool_name: str,
        tool_description: str,
        response_text: str,
        model: str,
        log: Callable[[str], None],
    ) -> list:
        ...


@dataclass
class _Phase2Candidate:
    tool_name: str
    tool_desc: str
    payload: str


@dataclass
class _Phase2Output:
    tool_name: str
    findings: list


def _implicated_tool(title: str) -> str:
    """The tool a finding names in its title, or '' if it names none.

    Findings record their subject in prose rather than a field, so chain
    reasoning had no way to tell which tools two findings have in common.
    """
    for match in _TOOL_NAME_RE.finditer(title):
        raw = match.group(1) or match.group(2)
        if raw and raw.lower() not in ("tool", "param"):
            return raw
    return ""


def _known_finding_lines(result: TargetResult) -> list[str]:
    """One line per deterministic finding, for grounding phase 1.

    AI findings are excluded: feeding the model its own prior output back as
    established fact would let a mistake harden across phases.
    """
    return [
        f"{f.severity} {f.check}: {f.title}"
        for f in result.findings
        if not f.check.startswith("llm_")
    ]


def _propose_chains(
    backend: Any,
    tools: list[dict],
    findings: list[dict],
    model: str,
    log: Callable[[str], None],
) -> list:
    """Ask the backend for executable chains, or return [] if it cannot."""
    propose = getattr(backend, "propose_chains", None)
    if propose is None:
        return []
    return list(propose(tools, findings, model=model, log=log) or [])


def _transcript(run: ChainRun, verdict: ChainVerdict) -> str:
    """A short, reportable record of what the replay actually did."""
    lines = [verdict.evidence] if verdict.evidence else []
    for index, step in enumerate(run.results):
        status = "FAIL" if step.failed else "ok"
        lines.append(
            f"[{status}] step{index} {step.tool} args={step.request_args!r} "
            f"→ {step.response_text[:200]!r}"
        )
    return "\n".join(lines)


def _analyze_tools(
    backend: LLMBackend, result: TargetResult, model: str, log: Callable[[str], None]
) -> list[Any]:
    """Call phase 1, grounded in what the checks already found.

    `known_findings` is passed positionally-optionally so an out-of-tree backend
    written against the older three-argument protocol keeps working rather than
    failing the whole phase with a TypeError.
    """
    known = _known_finding_lines(result)
    try:
        return backend.analyze_tools(
            result.tools, model=model, log=log, known_findings=known
        )
    except TypeError:
        return backend.analyze_tools(result.tools, model=model, log=log)


def _finding_digest(finding) -> dict:
    """What chain reasoning needs from a finding to argue about a data path.

    The title alone says a class of problem exists somewhere; the detail,
    evidence and implicated tool say where and with what.
    """
    return {
        "check": finding.check,
        "severity": finding.severity,
        "title": finding.title,
        "detail": (finding.detail or "")[:_FINDING_DETAIL_CHARS],
        "evidence": (finding.evidence or "")[:_FINDING_EVIDENCE_CHARS],
        "tool": _implicated_tool(finding.title),
        "taxonomy_id": finding.taxonomy_id,
    }


def _resolve_phase2_workers(opts: dict) -> int:
    if opts.get("deterministic", False):
        return 1
    return max(1, min(int(opts.get("claude_phase2_workers", 1)), 8))


def _build_phase2_payload(text: str, resp: dict | None, max_chars: int = 3000) -> str:
    """Build the payload sent to Claude for response analysis.

    Phase 2 used to skip short responses and sometimes only captured a single
    content item string representation, which drops useful structured context.
    This helper keeps short-but-meaningful text and falls back to the raw
    response envelope when extracted text is empty or low-signal.
    """
    cleaned: str = text.strip() if text else ""
    if not resp:
        return cleaned[:max_chars]

    try:
        raw_payload: str = json.dumps(resp, default=str)[:max_chars]
    except (TypeError, ValueError):
        raw_payload = str(resp)[:max_chars]

    if not cleaned:
        return raw_payload

    result_obj: dict | None = resp.get("result") if isinstance(resp, dict) else None
    low_signal: bool = False
    if isinstance(result_obj, dict):
        content = result_obj.get("content")
        extra_keys: list[str] = [k for k in result_obj if k not in {"content", "isError"}]
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict):
                    parts.append(item.get("text", "") or item.get("blob", "") or str(item))
                else:
                    parts.append(str(item))
            joined: str = "\n".join(parts).strip()
            if joined == cleaned and extra_keys:
                low_signal = True

    if (len(cleaned) < 20 or low_signal) and raw_payload and raw_payload.strip() != cleaned:
        return f"Extracted text:\n{cleaned}\n\nRaw response envelope:\n{raw_payload}"

    return cleaned[:max_chars]


def _default_backend() -> LLMBackend:
    from mcpnuke.core import llm as llm_core

    return llm_core


def run_llm_analysis(
    session: MCPSessionProtocol,
    result: TargetResult,
    probe_opts: dict | None = None,
    model: str = DEFAULT_CLAUDE_MODEL,
    console=None,
    llm_backend: LLMBackend | None = None,
):
    """Run all LLM-powered analysis phases against a scan result.

    Phase 1: Analyze tool definitions for subtle issues
    Phase 2: Analyze tool responses for embedded threats
    Phase 3: Reason about all findings to discover attack chains
    Phase 4 (opt-in via `--chain-replay`): propose executable chains and
    replay them against the target, reporting only those that reproduce
    """
    opts = probe_opts or {}
    _log = console.print if console else lambda msg: None
    no_invoke = opts.get("no_invoke", False)
    backend: LLMBackend = llm_backend or _default_backend()

    # Verify API prereqs only when using default Anthropic backend.
    if llm_backend is None:
        from mcpnuke.core.llm import is_bedrock_enabled
        if is_bedrock_enabled():
            try:
                import boto3  # noqa: F401
            except ImportError:
                _log("  [red]✗ boto3 not installed — skipping AI analysis[/red]")
                _log("  [dim]  Install with: uv pip install boto3[/dim]")
                return
        else:
            import os
            if not os.environ.get("ANTHROPIC_API_KEY"):
                _log("  [red]✗ ANTHROPIC_API_KEY not set — skipping AI analysis[/red]")
                _log("  [dim]  Set the env var or pass --claude to enable.[/dim]")
                return

            try:
                import anthropic  # noqa: F401
            except ImportError:
                _log("  [red]✗ anthropic package not installed — skipping AI analysis[/red]")
                _log("  [dim]  Install with: uv pip install mcpnuke[ai]  (or: pip install anthropic)[/dim]")
                return

    # Phase 1: Tool description analysis
    with time_check("llm_tool_analysis", result):
        _log("  [cyan]AI Phase 1: Analyzing tool definitions...[/cyan]")
        try:
            llm_findings = _analyze_tools(backend, result, model, _log)
            for f in llm_findings:
                tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                finding = result.add(
                    "llm_tool_analysis",
                    f.severity,
                    f"[AI]{tax} {f.title}",
                    f.detail,
                )
                if finding:
                    finding.taxonomy_id = f.taxonomy_id
                    finding.mitre_id = getattr(f, "mitre_id", "")
            _log(f"  [green]  Phase 1 complete: {len(llm_findings)} finding(s)[/green]")
        except KeyboardInterrupt:
            _log("  [yellow]  Phase 1 interrupted[/yellow]")
            return
        except Exception as e:
            _log(f"  [yellow]  Phase 1 failed: {type(e).__name__}: {e}[/yellow]")

    # Phase 2: Response analysis (call tools, analyze what comes back)
    if not no_invoke:
        with time_check("llm_response_analysis", result):
            _log("  [cyan]AI Phase 2: Calling tools and analyzing responses...[/cyan]")
            response_findings = 0
            try:
                max_tools = opts.get("claude_max_tools", 10)
                phase2_workers = _resolve_phase2_workers(opts)
                tools = result.tools
                if opts.get("deterministic", False):
                    tools = sorted(
                        tools,
                        key=lambda tool: str(tool.get("name", "")),
                    )
                tool_subset = tools[:max_tools]
                skipped = [t.get("name", "?") for t in tool_subset if not _should_invoke(t, opts)]
                if skipped:
                    _log(f"  [yellow]  Skipping dangerous tools ({len(skipped)}): {', '.join(skipped)}[/yellow]")
                _log(f"  [dim]  Analyzing up to {max_tools} tools (--claude-max-tools)[/dim]")
                if phase2_workers > 1:
                    _log(f"  [dim]  Phase 2 parallel workers: {phase2_workers}[/dim]")

                candidates: list[_Phase2Candidate] = []
                for tool in tool_subset:
                    if not _should_invoke(tool, opts):
                        continue
                    name = tool.get("name", "")
                    desc = tool.get("description", "")
                    args = _build_safe_args(tool)
                    _log(f"  [dim]  Calling tool '{name}' with args: {args}[/dim]")
                    resp = _call_tool(session, name, args)
                    text = _response_text(resp)
                    payload = _build_phase2_payload(text, resp)
                    if not payload:
                        _log(f"  [dim]  Tool '{name}' returned empty/short response, skipping[/dim]")
                        continue
                    candidates.append(_Phase2Candidate(tool_name=name, tool_desc=desc, payload=payload))

                def _analyze_candidate(candidate: _Phase2Candidate) -> _Phase2Output:
                    _log(
                        f"  [dim]  Tool '{candidate.tool_name}' returned "
                        f"{len(candidate.payload)} chars, sending to Claude...[/dim]"
                    )
                    findings = backend.analyze_response(
                        candidate.tool_name,
                        candidate.tool_desc,
                        candidate.payload,
                        model=model,
                        log=_log,
                    )
                    return _Phase2Output(tool_name=candidate.tool_name, findings=findings)

                outputs: list[_Phase2Output] = []
                if phase2_workers > 1 and len(candidates) > 1:
                    with ThreadPoolExecutor(max_workers=min(phase2_workers, len(candidates))) as pool:
                        futures = [pool.submit(_analyze_candidate, c) for c in candidates]
                        for future in as_completed(futures):
                            outputs.append(future.result())
                else:
                    for candidate in candidates:
                        outputs.append(_analyze_candidate(candidate))

                for output in outputs:
                    for f in output.findings:
                        tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                        finding = result.add(
                            "llm_response_analysis",
                            f.severity,
                            f"[AI]{tax} {f.title} (tool '{output.tool_name}')",
                            f.detail,
                        )
                        if finding:
                            finding.taxonomy_id = f.taxonomy_id
                            finding.mitre_id = getattr(f, "mitre_id", "")
                        response_findings += 1
                _log(f"  [green]  Phase 2 complete: {response_findings} finding(s) in tool responses[/green]")
            except KeyboardInterrupt:
                _log("  [yellow]  Phase 2 interrupted[/yellow]")
                return
            except Exception as e:
                _log(f"  [yellow]  Phase 2 failed: {type(e).__name__}: {e}[/yellow]")
    else:
        _log("  [dim]  Phase 2 skipped (--no-invoke): use --safe-mode to enable response analysis[/dim]")

    # Phase 3: Chain reasoning over all findings
    with time_check("llm_chain_reasoning", result):
        _log("  [cyan]AI Phase 3: Reasoning about attack chains...[/cyan]")
        try:
            existing = [
                _finding_digest(f)
                for f in result.findings
                if not f.check.startswith("llm_")
            ]
            chain_findings = backend.analyze_findings(result.tools, existing, model=model, log=_log)
            for f in chain_findings:
                tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                finding = result.add(
                    "llm_chain_reasoning",
                    f.severity,
                    f"[AI]{tax} {f.title}",
                    f.detail,
                )
                if finding:
                    finding.taxonomy_id = f.taxonomy_id
                    finding.mitre_id = getattr(f, "mitre_id", "")
            _log(f"  [green]  Phase 3 complete: {len(chain_findings)} chain(s)/insight(s)[/green]")
        except KeyboardInterrupt:
            _log("  [yellow]  Phase 3 interrupted[/yellow]")
        except Exception as e:
            _log(f"  [yellow]  Phase 3 failed: {type(e).__name__}: {e}[/yellow]")

    # Phase 4: Propose executable chains and replay them against the target.
    # Opt-in: it calls tools in sequence, so it inherits the same safety gate
    # as phase 2 and stays off unless --chain-replay is set.
    if opts.get("chain_replay") and not opts.get("no_invoke") and session is not None:
        with time_check("llm_chain_replay", result):
            _log("  [cyan]AI Phase 4: Proposing and replaying attack chains...[/cyan]")
            try:
                existing = [
                    _finding_digest(f)
                    for f in result.findings
                    if not f.check.startswith("llm_")
                ]
                proposed = _propose_chains(backend, result.tools, existing, model, _log)
                tools_by_name = {
                    str(t.get("name") or ""): t for t in result.tools if t.get("name")
                }
                oast = opts.get("oast")
                reproduced = 0
                for chain in proposed:
                    run = replay_chain(
                        session,
                        chain,
                        tools_by_name,
                        safe_mode=opts.get("safe_mode", False),
                        oast=oast,
                    )
                    verdict = summarize_run(run, oast=oast)
                    if not verdict.reproduced:
                        continue
                    tax = f" [{chain.taxonomy_id}]" if chain.taxonomy_id else ""
                    evidence = _transcript(run, verdict)
                    finding = result.add(
                        "llm_chain_replay",
                        "CRITICAL",
                        f"[AI]{tax} Chain reproduced: {chain.title}",
                        f"{verdict.detail} {chain.detail}".strip(),
                        evidence=evidence,
                    )
                    if finding and chain.taxonomy_id:
                        finding.taxonomy_id = chain.taxonomy_id
                    reproduced += 1
                _log(
                    f"  [green]  Phase 4 complete: {reproduced} of "
                    f"{len(proposed)} proposed chain(s) reproduced[/green]"
                )
            except KeyboardInterrupt:
                _log("  [yellow]  Phase 4 interrupted[/yellow]")
            except Exception as e:
                _log(f"  [yellow]  Phase 4 failed: {type(e).__name__}: {e}[/yellow]")
    elif opts.get("chain_replay") and opts.get("no_invoke"):
        _log("  [dim]  Phase 4 skipped (--no-invoke)[/dim]")
