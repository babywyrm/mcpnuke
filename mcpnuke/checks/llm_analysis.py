"""AI-powered security analysis using Claude.

Layers LLM reasoning on top of deterministic checks to catch subtle
vulnerabilities that regex patterns miss: social engineering in tool
descriptions, obfuscated injection, logical attack chains, and
context-dependent risks.
"""

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke


def run_llm_analysis(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
    model: str = "claude-sonnet-4-20250514",
    console=None,
):
    """Run all LLM-powered analysis phases against a scan result.

    Phase 1: Analyze tool definitions for subtle issues
    Phase 2: Analyze tool responses for embedded threats
    Phase 3: Reason about all findings to discover attack chains
    """
    from mcpnuke.core.llm import analyze_tools, analyze_findings, analyze_response

    opts = probe_opts or {}
    _log = console.print if console else lambda msg: None
    no_invoke = opts.get("no_invoke", False)

    # Verify API key is set
    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        _log("  [red]✗ ANTHROPIC_API_KEY not set — skipping AI analysis[/red]")
        _log("  [dim]  Set the env var or pass --claude to enable.[/dim]")
        return

    try:
        import anthropic  # noqa: F401
    except ImportError:
        _log("  [red]✗ anthropic package not installed — skipping AI analysis[/red]")
        _log("  [dim]  Install with: pip install anthropic[/dim]")
        return

    # Phase 1: Tool description analysis
    with time_check("llm_tool_analysis", result):
        _log("  [cyan]AI Phase 1: Analyzing tool definitions...[/cyan]")
        try:
            llm_findings = analyze_tools(result.tools, model=model, log=_log)
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
                tool_subset = result.tools[:max_tools]
                skipped = [t.get("name", "?") for t in tool_subset if not _should_invoke(t, opts)]
                if skipped:
                    _log(f"  [yellow]  Skipping dangerous tools ({len(skipped)}): {', '.join(skipped)}[/yellow]")
                _log(f"  [dim]  Analyzing up to {max_tools} tools (--claude-max-tools)[/dim]")
                for tool in tool_subset:
                    if not _should_invoke(tool, opts):
                        continue
                    name = tool.get("name", "")
                    desc = tool.get("description", "")
                    args = _build_safe_args(tool)
                    _log(f"  [dim]  Calling tool '{name}' with args: {args}[/dim]")
                    resp = _call_tool(session, name, args)
                    text = _response_text(resp)
                    if not text or len(text) < 20:
                        _log(f"  [dim]  Tool '{name}' returned empty/short response, skipping[/dim]")
                        continue

                    _log(f"  [dim]  Tool '{name}' returned {len(text)} chars, sending to Claude...[/dim]")
                    llm_resp_findings = analyze_response(name, desc, text, model=model, log=_log)
                    for f in llm_resp_findings:
                        tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                        result.add(
                            "llm_response_analysis",
                            f.severity,
                            f"[AI]{tax} {f.title} (tool '{name}')",
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
            chain_findings = analyze_findings(result.tools, existing, model=model, log=_log)
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
