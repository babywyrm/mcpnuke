"""AI-powered security analysis using Claude.

Layers LLM reasoning on top of deterministic checks to catch subtle
vulnerabilities that regex patterns miss: social engineering in tool
descriptions, obfuscated injection, logical attack chains, and
context-dependent risks.
"""

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Protocol

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke


class LLMBackend(Protocol):
    """Typed protocol for pluggable LLM analysis backends."""

    def analyze_tools(self, tools: list[dict], model: str, log: Callable[[str], None]) -> list:
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
        extra_keys: list[str] = [k for k in result_obj.keys() if k not in {"content", "isError"}]
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

    if len(cleaned) < 20 or low_signal:
        if raw_payload and raw_payload.strip() != cleaned:
            return f"Extracted text:\n{cleaned}\n\nRaw response envelope:\n{raw_payload}"

    return cleaned[:max_chars]


def _default_backend() -> LLMBackend:
    from mcpnuke.core import llm as llm_core

    return llm_core


def run_llm_analysis(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
    model: str = "claude-sonnet-4-20250514",
    console=None,
    llm_backend: LLMBackend | None = None,
):
    """Run all LLM-powered analysis phases against a scan result.

    Phase 1: Analyze tool definitions for subtle issues
    Phase 2: Analyze tool responses for embedded threats
    Phase 3: Reason about all findings to discover attack chains
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
            llm_findings = backend.analyze_tools(result.tools, model=model, log=_log)
            for f in llm_findings:
                tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                result.add(
                    "llm_tool_analysis",
                    f.severity,
                    f"[AI]{tax} {f.title}",
                    f.detail,
                )
            _log(f"  [green]  Phase 1 complete: {len(llm_findings)} finding(s)[/green]")
        except KeyboardInterrupt:
            _log(f"  [yellow]  Phase 1 interrupted[/yellow]")
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
                phase2_workers = max(1, min(int(opts.get("claude_phase2_workers", 1)), 8))
                tool_subset = result.tools[:max_tools]
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
                        result.add(
                            "llm_response_analysis",
                            f.severity,
                            f"[AI]{tax} {f.title} (tool '{output.tool_name}')",
                            f.detail,
                        )
                        response_findings += 1
                _log(f"  [green]  Phase 2 complete: {response_findings} finding(s) in tool responses[/green]")
            except KeyboardInterrupt:
                _log(f"  [yellow]  Phase 2 interrupted[/yellow]")
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
                {"check": f.check, "severity": f.severity, "title": f.title}
                for f in result.findings
                if not f.check.startswith("llm_")
            ]
            chain_findings = backend.analyze_findings(result.tools, existing, model=model, log=_log)
            for f in chain_findings:
                tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                result.add(
                    "llm_chain_reasoning",
                    f.severity,
                    f"[AI]{tax} {f.title}",
                    f.detail,
                )
            _log(f"  [green]  Phase 3 complete: {len(chain_findings)} chain(s)/insight(s)[/green]")
        except KeyboardInterrupt:
            _log(f"  [yellow]  Phase 3 interrupted[/yellow]")
        except Exception as e:
            _log(f"  [yellow]  Phase 3 failed: {type(e).__name__}: {e}[/yellow]")
