"""Shared plumbing for the behavioral probes: classify, build arguments for,
invoke, and read back MCP tools.

The checks built on it live in their own modules: tool_response_injection,
input_sanitization, error_leakage, temporal_consistency, resource_poisoning.
"""

import base64
import json
import re
import time

from mcpnuke.core.constants import DEFAULT_CLAUDE_MODEL
from mcpnuke.core.llm import _call_claude
from mcpnuke.core.transports.base import MCPSessionProtocol
from mcpnuke.patterns.probes import (
    CANARY,
    HIDDEN_CONTENT_PATTERNS,
    PARAM_SAFE_VALUES,
    RESPONSE_EXFIL_PATTERNS,
    RESPONSE_INJECTION_PATTERNS,
    SAFE_DEFAULTS,
    SEMANTIC_INJECTION_PATTERNS,
    has_invisible_unicode,
)

# ---------------------------------------------------------------------------
# Tool danger classification
# ---------------------------------------------------------------------------

_DANGEROUS_TOOL_KEYWORDS = {
    "delete", "remove", "drop", "destroy", "kill", "terminate", "purge",
    "send", "email", "sms", "notify", "post", "publish", "broadcast",
    "exec", "execute", "run", "shell", "bash", "eval", "system", "spawn",
    "write", "overwrite", "truncate", "format", "wipe",
    "deploy", "restart", "shutdown", "reboot",
    "transfer", "pay", "charge", "invoice",
    # Outbound / beacon sinks: register-only webhooks and SSRF fetch helpers
    # still move data off-host when invoked under --safe-mode.
    "webhook", "callback", "egress", "exfil", "exfiltrate",
}

_READ_ONLY_TOOL_KEYWORDS = {
    "get", "read", "list", "search", "find", "query", "fetch", "describe",
    "info", "status", "check", "verify", "validate", "count", "show",
    "view", "browse", "lookup", "inspect", "ping", "health", "version",
    "weather", "time", "date", "calculate", "convert",
}


def _is_dangerous_tool(tool: dict) -> bool:
    """Classify a tool as dangerous based on name and description."""
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    combined = f"{name} {desc}"

    # Split on _, -, ., and whitespace. MCP tools are often namespaced
    # (shellwrap.exec, shadow.register_webhook); without the dot, `exec`
    # never appears as a token and --safe-mode silently invokes them.
    name_parts = set(re.split(r"[_\-\s.]+", name))
    for kw in _DANGEROUS_TOOL_KEYWORDS:
        if kw in name_parts:
            return True

    return bool(any(kw in combined for kw in ("side effect", "irreversible", "destructive", "permanent")))


def _should_invoke(tool: dict, probe_opts: dict) -> bool:
    """Decide whether to invoke a tool given the current probe options."""
    if probe_opts.get("no_invoke"):
        return False
    return not (probe_opts.get("safe_mode") and _is_dangerous_tool(tool))


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _build_safe_args(tool: dict) -> dict:
    """Generate minimal safe arguments from a tool's input schema."""
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    args: dict = {}

    for pname, pdef in props.items():
        if pname not in required:
            continue

        if "enum" in pdef:
            args[pname] = pdef["enum"][0]
            continue

        ptype = pdef.get("type", "string")

        # Respect schema constraints
        if ptype in ("number", "integer"):
            lo = pdef.get("minimum", pdef.get("exclusiveMinimum"))
            hi = pdef.get("maximum", pdef.get("exclusiveMaximum"))
            if lo is not None and hi is not None:
                args[pname] = (lo + hi) // 2
            elif lo is not None:
                args[pname] = int(lo) + 1
            elif hi is not None:
                args[pname] = int(hi) - 1
            else:
                args[pname] = SAFE_DEFAULTS.get(ptype, 1)
            continue

        if ptype == "boolean":
            args[pname] = pdef.get("default", False)
            continue

        if ptype == "array":
            args[pname] = pdef.get("default", [])
            continue

        if ptype == "object":
            args[pname] = pdef.get("default", {})
            continue

        # String: try name-aware safe value
        if "pattern" in pdef:
            args[pname] = "test"
            continue

        matched = False
        for pattern, value in PARAM_SAFE_VALUES:
            if re.search(pattern, pname, re.IGNORECASE):
                args[pname] = value
                matched = True
                break

        if not matched:
            desc = pdef.get("description", "")
            for pattern, value in PARAM_SAFE_VALUES:
                if re.search(pattern, desc, re.IGNORECASE):
                    args[pname] = value
                    matched = True
                    break

        if not matched:
            args[pname] = pdef.get("default", SAFE_DEFAULTS.get(ptype, "test"))

    return args


def _build_extended_args(tool: dict) -> dict:
    """Generate arguments including optional params filled with heuristic probe values.

    Tier 1 of Phase 2 smart invocation: extends _build_safe_args to also fill in
    optional parameters, using context-aware probe values.  Optional path params
    get a traversal probe; optional URL params get a loopback SSRF probe.  All
    other optional params get the same name-aware heuristics used for required ones.

    This gives Phase 2 real coverage over optional attack surfaces that the minimal
    _build_safe_args leaves untouched.
    """
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    if not props:
        return {}

    required = set(schema.get("required", []))

    # Start with required-param values from _build_safe_args
    args = _build_safe_args(tool)

    for pname, pdef in props.items():
        if pname in required:
            continue  # already handled

        if "enum" in pdef:
            args[pname] = pdef["enum"][0]
            continue

        ptype = pdef.get("type", "string")

        if ptype in ("number", "integer"):
            lo = pdef.get("minimum", pdef.get("exclusiveMinimum"))
            hi = pdef.get("maximum", pdef.get("exclusiveMaximum"))
            if lo is not None and hi is not None:
                args[pname] = (int(lo) + int(hi)) // 2
            elif lo is not None:
                args[pname] = int(lo) + 1
            elif hi is not None:
                args[pname] = int(hi) - 1
            else:
                args[pname] = pdef.get("default", SAFE_DEFAULTS.get(ptype, 1))
            continue

        if ptype == "boolean":
            args[pname] = pdef.get("default", False)
            continue

        if ptype == "array":
            args[pname] = pdef.get("default", [])
            continue

        if ptype == "object":
            args[pname] = pdef.get("default", {})
            continue

        # String: use security-interesting values for optional params
        # path/file params: path traversal probe
        if re.search(r"(path|file|dir|folder)", pname, re.IGNORECASE):
            args[pname] = f"../../{CANARY}"
            continue
        # url/endpoint params: SSRF probe (internal loopback)
        if re.search(r"(url|uri|endpoint|href|callback|webhook)", pname, re.IGNORECASE):
            args[pname] = "http://169.254.169.254/latest/meta-data/"
            continue
        # command/exec params: benign echo
        if re.search(r"(command|cmd|exec)", pname, re.IGNORECASE):
            args[pname] = "echo probe"
            continue

        # General: name-aware safe value or pattern
        matched = False
        for pattern, value in PARAM_SAFE_VALUES:
            if re.search(pattern, pname, re.IGNORECASE):
                args[pname] = value
                matched = True
                break
        if not matched:
            desc = pdef.get("description", "")
            for pattern, value in PARAM_SAFE_VALUES:
                if re.search(pattern, desc, re.IGNORECASE):
                    args[pname] = value
                    matched = True
                    break
        if not matched:
            args[pname] = pdef.get("default", SAFE_DEFAULTS.get(ptype, "test"))

    return args


_latency_tracker: dict[str, list[float]] = {}


def _is_stdio(session: MCPSessionProtocol) -> bool:
    return hasattr(session, "_proc")


def _call_claude_for_args(tool: dict, model: str = DEFAULT_CLAUDE_MODEL) -> dict | None:
    """Ask Claude to generate semantically interesting args for a tool.

    Returns a dict of parameter name → value, or None on failure.  The caller
    should fall back to _build_extended_args() on None.
    """
    import json as _json

    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    if not props:
        return None

    system = (
        "You are a security researcher generating test inputs for MCP tool fuzzing. "
        "Return ONLY a valid JSON object mapping parameter names to values. "
        "Choose values that are likely to trigger security issues: "
        "path traversal for file paths, SSRF for URLs, SQL injection for queries, "
        "prompt injection for text fields, privilege escalation for identity fields. "
        "Values should be realistic but clearly adversarial test inputs, not harmful production data."
    )
    user = (
        f"Tool name: {tool.get('name', 'unknown')}\n"
        f"Description: {tool.get('description', 'no description')}\n"
        f"Parameters: {_json.dumps(props, indent=2)}\n"
        f"Required: {schema.get('required', [])}\n\n"
        "Return a single JSON object with all parameter names as keys and adversarial test values."
    )

    try:
        response = _call_claude(system, user, model=model, max_tokens=512)
        if not response:
            return None
        # Strip markdown fences
        text = response.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
        parsed = _json.loads(text)
        if not isinstance(parsed, dict):
            return None
        return parsed
    except Exception:
        return None


def _generate_claude_args(
    tool: dict, session: MCPSessionProtocol, model: str = DEFAULT_CLAUDE_MODEL
) -> dict:
    """Tier 2 argument generation: Claude-assisted, with _build_extended_args fallback.

    Calls _call_claude_for_args and merges result with extended_args baseline so
    required params are always populated even if Claude omits them.
    """
    base = _build_extended_args(tool)
    try:
        claude_result = _call_claude_for_args(tool, model=model)
    except Exception:
        return base
    if not claude_result:
        return base
    # Merge: Claude values override base, but base ensures required fields present
    merged = dict(base)
    merged.update(claude_result)
    return merged


def _call_tool(
    session: MCPSessionProtocol,
    name: str,
    args: dict,
    timeout: float = 10.0,
    retries: int = 2,
) -> dict | None:
    """Call a tool via tools/call with adaptive backoff and jitter.

    Tracks per-tool latency to set progressive timeouts and retries with
    exponential backoff + jitter on failure. Stdio sessions get a lower
    timeout ceiling (15s) and fewer retries since high latency is inherent
    to subprocess I/O, not a transient failure.
    """
    import random

    stdio = _is_stdio(session)
    max_timeout = 15.0 if stdio else 30.0
    effective_retries = min(retries, 1) if stdio else retries

    history = _latency_tracker.setdefault(name, [])
    effective_timeout = timeout
    if history and not stdio:
        avg = sum(history) / len(history)
        effective_timeout = min(max(avg * 2.5, timeout), max_timeout)

    delay = 0.5
    for attempt in range(effective_retries + 1):
        t0 = time.time()
        try:
            resp = session.call(
                "tools/call",
                {"name": name, "arguments": args},
                timeout=effective_timeout,
            )
            elapsed = time.time() - t0
            history.append(elapsed)
            if len(history) > 10:
                history.pop(0)
            return resp
        except Exception:
            elapsed = time.time() - t0
            history.append(elapsed)
            if len(history) > 10:
                history.pop(0)
            if attempt < effective_retries:
                jitter = random.uniform(0, delay * 0.5)
                time.sleep(delay + jitter)
                delay = min(delay * 2, 8.0)
                effective_timeout = min(effective_timeout * 1.5, max_timeout)
    return None


def _serialize_structured(value: object) -> str:
    """JSON for a structuredContent payload, same 2000-char cap as the fallback."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value)[:2000]


def _response_text(resp: dict | None) -> str:
    """Extract all text content from a tools/call response.

    A successful result may carry ``content`` (blocks for humans) and
    ``structuredContent`` (the same payload for machines) at once. Returning
    after the content list used to hide the structured half from every check
    that scans this string.
    """
    if not resp:
        return ""
    result = resp.get("result", resp.get("error", {}))
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        # .get("content") rather than .get("content", []): an absent content key
        # used to yield an empty list, which is a list, so the branches below
        # were unreachable. Error messages and structured results extracted as
        # "" and no check ever scanned them.
        content = result.get("content")
        if isinstance(content, list):
            parts: list[str] = []
            for c in content:
                if isinstance(c, dict):
                    parts.append(c.get("text", "") or c.get("blob", "") or str(c))
                else:
                    parts.append(str(c))
            structured = _serialize_structured(result.get("structuredContent"))
            if structured:
                parts.append(structured)
            return "\n".join(parts)
        # error responses
        if "message" in result:
            message = result["message"]
            return message if isinstance(message, str) else str(message)
        return json.dumps(result)[:2000] if result else ""
    return str(result) if result else ""


def _scan_response_threats(text: str) -> list[tuple[str, str, str]]:
    """Scan response text for embedded threats. Returns [(category, severity, detail)]."""
    threats: list[tuple[str, str, str]] = []

    for pat in RESPONSE_INJECTION_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            threats.append((
                "response_injection", "CRITICAL",
                f"Injection payload in response: \"{m.group()[:120]}\"",
            ))

    for pat in RESPONSE_EXFIL_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            threats.append((
                "exfiltration_url", "HIGH",
                f"Exfiltration URL in response: {m.group()[:150]}",
            ))

    for pat in HIDDEN_CONTENT_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if m:
            threats.append((
                "hidden_content", "HIGH",
                f"Hidden content block in response ({len(m.group())} chars)",
            ))

    inv = has_invisible_unicode(text)
    if inv:
        threats.append((
            "invisible_unicode", "CRITICAL",
            f"{len(inv)} invisible Unicode chars — possible steganographic instructions",
        ))

    # Semantic injection — instruction-like patterns that bypass explicit markers
    for pat, category in SEMANTIC_INJECTION_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            threats.append((
                f"semantic_injection:{category}", "HIGH",
                f"Semantic injection ({category}): \"{m.group()[:120]}\"",
            ))

    # Decode suspicious base64 blobs
    for b64 in re.findall(r"[A-Za-z0-9+/]{50,}={0,2}", text)[:3]:
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
            if any(re.search(p, decoded, re.IGNORECASE) for p in RESPONSE_INJECTION_PATTERNS):
                threats.append((
                    "encoded_injection", "CRITICAL",
                    f"Base64-encoded injection: {decoded[:120]}",
                ))
        except Exception:
            pass

    return threats
