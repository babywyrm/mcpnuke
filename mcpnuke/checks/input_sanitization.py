"""Input sanitization: fuzz tool parameters with injection probes and
flag reflected, executed, or timing-revealed payloads."""

import contextlib
import re
import time
from collections.abc import Callable

from mcpnuke.checks.base import (
    ERROR_REFLECTION_SUFFIX,
    grade_reflection,
    payload_echo_removed,
    response_is_error,
    time_check,
)
from mcpnuke.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol
from mcpnuke.patterns.probes import (
    CANARY,
    COMMAND_INJECTION_PROBES,
    ENCODING_BYPASS_PROBES,
    ERROR_LEAKAGE_PATTERNS,
    INTERPRETER_INJECTION_PROBES,
    PATH_TRAVERSAL_PROBES,
    SQL_INJECTION_PROBES,
    SSTI_ENGINE_FINGERPRINTS,
    TEMPLATE_INJECTION_PROBES_V2,
)

SSTI_LATENCY_THRESHOLD: float = 0.1


def _classify_ssti(
    *,
    math_hit: bool,
    engine_hits: list[str],
    response_latency: float,
) -> str:
    """Classify an SSTI finding as code-level or LLM-evaluated.

    Returns: engine name (e.g. 'jinja2'), 'code_ssti', 'llm_evaluated', or 'unknown'.
    """
    if engine_hits:
        return engine_hits[0]
    if response_latency < SSTI_LATENCY_THRESHOLD and math_hit:
        return "code_ssti"
    if math_hit:
        return "llm_evaluated"
    return "unknown"


def _canary_sighting(
    result: TargetResult,
    *,
    resp: dict | None,
    text: str,
    payload: str,
    base_severity: str,
    title: str,
    detail: str,
    evidence: str,
    policy: str,
) -> bool:
    """Report a canary in *text*, graded by who put it there.

    Returns True when the canary was seen at all, so callers can stop probing.
    Suppression is a reporting choice and must not change what we probe.

    The finding is only weakened when *both* things are true: the response was
    a refusal, and the canary survives nowhere outside a verbatim copy of the
    probe. Either alone is not enough — a canary loose in an error response is
    execution evidence, and an echo in a *successful* response is a different
    question that `tool_response_injection` already asks.
    """
    if CANARY not in text:
        return False

    echoed_only = CANARY not in payload_echo_removed(text, payload)
    reflected_in_error = echoed_only and response_is_error(resp)

    graded = grade_reflection(
        base_severity, reflected_in_error=reflected_in_error, policy=policy
    )
    if graded:
        severity, annotate = graded
        if annotate:
            title += ERROR_REFLECTION_SUFFIX
            detail += (
                ". The canary appeared only inside a verbatim echo of the probe "
                "in a rejected call — what a server does when it refuses input "
                "and names what it refused"
            )
        result.add("input_sanitization", severity, title, detail, evidence=evidence)
    return True


def _fuzz_single_tool(
    session: MCPSessionProtocol,
    tool: dict,
    result: TargetResult,
    opts: dict,
    _log: Callable[[str], None],
    idx: int,
    total: int,
) -> None:
    name = tool.get("name", "")
    _log(f"    [dim]    [{idx + 1}/{total}] {name}[/dim]")
    props = tool.get("inputSchema", {}).get("properties", {})

    for pname, pdef in props.items():
        if pdef.get("type") not in (None, "string"):
            continue

        base_args = _build_safe_args(tool)
        pname_lower = pname.lower()

        # Pick probes based on param semantics
        if any(kw in pname_lower for kw in ("path", "file", "dir", "folder")):
            probes = [("path_traversal", p) for p in PATH_TRAVERSAL_PROBES[:2]]
        elif any(kw in pname_lower for kw in ("command", "cmd", "exec", "code", "script", "expression")):
            probes = [("command_injection", p) for p in COMMAND_INJECTION_PROBES[:2]]
        elif any(kw in pname_lower for kw in ("query", "sql")):
            probes = [("sql_injection", p) for p in SQL_INJECTION_PROBES[:2]]
        else:
            probes = []

        text = ""
        probe_type = "input"
        for probe_type, probe_value in probes:
            test_args = {**base_args, pname: probe_value}
            resp = _call_tool(session, name, test_args, timeout=8)
            text = _response_text(resp)
            if not text:
                continue

            # Canary reflected back = no sanitization — unless the canary only
            # came back because the server quoted our probe while refusing it.
            if probe_type in ("command_injection", "path_traversal"):
                _canary_sighting(
                    result,
                    resp=resp,
                    text=text,
                    payload=probe_value,
                    base_severity="HIGH",
                    title=f"Tool '{name}' reflects probe canary unsanitized",
                    detail=f"Probe: {probe_type}, param: {pname}",
                    evidence=f"Sent: {probe_value}\nGot: {text[:300]}",
                    policy=opts.get("error_reflection", "downgrade"),
                )

        probe_text = text  # main-loop responses for error leakage (before interpreter/SSTI)

        # Interpreter diversity: try non-bash interpreters that blocklists often miss
        if any(kw in pname_lower for kw in ("command", "cmd", "exec", "code", "script", "expression", "query")):
            for interp_name, interp_probe in INTERPRETER_INJECTION_PROBES:
                test_args = {**base_args, pname: interp_probe}
                resp = _call_tool(session, name, test_args, timeout=8)
                text = _response_text(resp)
                if _canary_sighting(
                    result,
                    resp=resp,
                    text=text,
                    payload=interp_probe,
                    base_severity="CRITICAL",
                    title=f"Blocklist bypass: '{interp_name}' executed in tool '{name}'",
                    detail=f"Interpreter '{interp_name}' not blocked — param '{pname}'",
                    evidence=f"Sent: {interp_probe}\nGot: {text[:300]}",
                    policy=opts.get("error_reflection", "downgrade"),
                ):
                    break

        # Encoding bypass probes: 9 techniques that evade blocklists
        if any(kw in pname_lower for kw in ("command", "cmd", "exec", "code", "script", "expression", "query")):
            for enc_name, enc_payload in ENCODING_BYPASS_PROBES:
                test_args = {**base_args, pname: enc_payload}
                resp = _call_tool(session, name, test_args, timeout=8)
                text = _response_text(resp)
                if _canary_sighting(
                    result,
                    resp=resp,
                    text=text,
                    payload=enc_payload,
                    base_severity="CRITICAL",
                    title=f"Encoding bypass ({enc_name}): canary executed in tool '{name}'",
                    detail=f"Technique '{enc_name}' bypassed input filter — param '{pname}'",
                    evidence=f"Sent: {enc_payload[:120]}\nGot: {text[:300]}",
                    policy=opts.get("error_reflection", "downgrade"),
                ):
                    break

        # Dedicated template injection with engine fingerprinting
        math_hit = False
        engine_hits: list[str] = []
        tpl_latency = 0.0
        tpl_evidence = ""

        for tpl_payload, tpl_expected in TEMPLATE_INJECTION_PROBES_V2[:2]:
            t0 = time.time()
            test_args = {**base_args, pname: tpl_payload}
            resp = _call_tool(session, name, test_args, timeout=8)
            tpl_latency = time.time() - t0
            text = _response_text(resp)
            if text and tpl_expected in text:
                math_hit = True
                tpl_evidence = text[:300]
                break

        if math_hit:
            for fp in SSTI_ENGINE_FINGERPRINTS:
                fp_args = {**base_args, pname: fp["payload"]}
                resp = _call_tool(session, name, fp_args, timeout=8)
                fp_text = _response_text(resp)
                if fp_text and fp["expected"] in fp_text:
                    engine_hits.append(fp["engine"])
                    break

            classification = _classify_ssti(
                math_hit=math_hit,
                engine_hits=engine_hits,
                response_latency=tpl_latency,
            )

            if classification == "llm_evaluated":
                severity = "MEDIUM"
                title = f"LLM evaluates template syntax in '{name}' param '{pname}'"
                detail = (
                    "Payload evaluated to expected result but no engine-specific "
                    "fingerprint matched — likely LLM math evaluation, not code SSTI"
                )
            elif classification == "code_ssti":
                severity = "CRITICAL"
                title = f"Probable code-level SSTI in '{name}' param '{pname}'"
                detail = (
                    f"Fast response ({tpl_latency:.2f}s) with math evaluation "
                    f"but no engine fingerprint — likely unidentified template engine"
                )
            else:
                severity = "CRITICAL"
                title = f"SSTI ({classification}) in '{name}' param '{pname}'"
                detail = f"Engine '{classification}' confirmed via fingerprint payload"

            result.add(
                "input_sanitization", severity, title, detail,
                evidence=tpl_evidence,
                taxonomy_id="MCP-T44",
            )

        if not probe_text and tpl_evidence:
            probe_text = tpl_evidence

        # Error leakage triggered by injection probe
        for pat in ERROR_LEAKAGE_PATTERNS:
            m = re.search(pat, probe_text, re.IGNORECASE)
            if m:
                result.add(
                    "error_leakage",
                    "MEDIUM",
                    f"Tool '{name}' leaks internals on {probe_type} probe",
                    f"Leaked: {m.group()[:200]}",
                    evidence=probe_text[:400],
                )
                break


def check_input_sanitization(session: MCPSessionProtocol, result: TargetResult, probe_opts: dict | None = None) -> None:
    """Send injection probe payloads and detect missing sanitization."""
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    probe_workers = opts.get("probe_workers", 1)
    with time_check("input_sanitization", result):
        invokable = [t for t in result.tools if _should_invoke(t, opts)]
        _log(f"    [dim]    fuzzing {len(invokable)} tools for input sanitization[/dim]")

        if probe_workers > 1 and len(invokable) > 1:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=min(probe_workers, len(invokable))) as pool:
                futures = {
                    pool.submit(
                        _fuzz_single_tool, session, tool, result, opts, _log, idx, len(invokable)
                    ): tool
                    for idx, tool in enumerate(invokable)
                }
                for f in as_completed(futures):
                    with contextlib.suppress(Exception):
                        f.result()
        else:
            for idx, tool in enumerate(invokable):
                _fuzz_single_tool(session, tool, result, opts, _log, idx, len(invokable))
