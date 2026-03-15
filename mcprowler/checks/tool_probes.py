"""Advanced behavioral probes: call tools and analyze responses.

These checks go beyond static metadata analysis by actually invoking tools
with safe payloads and examining what comes back. They detect:
  - Injection payloads embedded in tool responses
  - Cross-tool manipulation (output tries to trigger another tool)
  - Input sanitization failures (probes reflected unsanitized)
  - Error information leakage (stack traces, internal paths)
  - Temporal inconsistency (behavior changes across identical calls)
  - Deep resource content poisoning (obfuscated payloads in resources)
"""

import base64
import json
import re
import time

from mcprowler.core.models import TargetResult
from mcprowler.checks.base import time_check
from mcprowler.patterns.probes import (
    CANARY,
    SAFE_DEFAULTS,
    PARAM_SAFE_VALUES,
    PATH_TRAVERSAL_PROBES,
    COMMAND_INJECTION_PROBES,
    TEMPLATE_INJECTION_PROBES,
    TEMPLATE_INJECTION_PROBES_V2,
    SQL_INJECTION_PROBES,
    RESPONSE_INJECTION_PATTERNS,
    RESPONSE_EXFIL_PATTERNS,
    CROSS_TOOL_PATTERNS,
    HIDDEN_CONTENT_PATTERNS,
    ERROR_LEAKAGE_PATTERNS,
    CREDENTIAL_CONTENT_PATTERNS,
    REFLECTION_PAYLOAD,
    CSS_HIDDEN_PATTERN,
    MD_IMAGE_EXFIL_PATTERN,
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

    for kw in _DANGEROUS_TOOL_KEYWORDS:
        if kw in name.split("_") or kw in name.split("-"):
            return True

    if any(kw in combined for kw in ("side effect", "irreversible", "destructive", "permanent")):
        return True

    return False


def _should_invoke(tool: dict, probe_opts: dict) -> bool:
    """Decide whether to invoke a tool given the current probe options."""
    if probe_opts.get("no_invoke"):
        return False
    if probe_opts.get("safe_mode") and _is_dangerous_tool(tool):
        return False
    return True


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


def _call_tool(session, name: str, args: dict, timeout: float = 10.0) -> dict | None:
    """Call a tool via tools/call, swallowing exceptions."""
    try:
        return session.call("tools/call", {"name": name, "arguments": args}, timeout=timeout)
    except Exception:
        return None


def _response_text(resp: dict | None) -> str:
    """Extract all text content from a tools/call response."""
    if not resp:
        return ""
    result = resp.get("result", resp.get("error", {}))
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        content = result.get("content", [])
        if isinstance(content, list):
            parts = []
            for c in content:
                if isinstance(c, dict):
                    parts.append(c.get("text", "") or c.get("blob", "") or str(c))
                else:
                    parts.append(str(c))
            return "\n".join(parts)
        # error responses
        if "message" in result:
            return result["message"]
        return json.dumps(result)[:2000]
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


# ---------------------------------------------------------------------------
# Check: Tool Response Injection
# ---------------------------------------------------------------------------

def check_tool_response_injection(session, result: TargetResult, probe_opts: dict | None = None):
    """Call each tool with safe inputs and scan responses for injection / manipulation.

    Also detects input reflection — if a tool echoes user input back in the
    response, it's an indirect injection conduit (attacker-controlled text
    ends up in the LLM context via tool output).
    """
    opts = probe_opts or {}
    with time_check("tool_response_injection", result):
        tool_names = {t["name"].lower() for t in result.tools}

        for tool in result.tools:
            if not _should_invoke(tool, opts):
                continue
            name = tool.get("name", "")
            args = _build_safe_args(tool)

            resp = _call_tool(session, name, args)
            text = _response_text(resp)
            if not text:
                continue

            for category, severity, detail in _scan_response_threats(text):
                result.add(
                    "tool_response_injection",
                    severity,
                    f"Tool '{name}' response: {category}",
                    detail,
                    evidence=text[:500],
                )

            # Cross-tool manipulation: does the response tell the LLM to call another tool?
            for pat in CROSS_TOOL_PATTERNS:
                for m in re.finditer(pat, text, re.IGNORECASE):
                    ref = m.group(1).lower()
                    if ref in tool_names and ref != name.lower():
                        result.add(
                            "cross_tool_manipulation",
                            "HIGH",
                            f"Tool '{name}' output directs LLM to invoke '{m.group(1)}'",
                            "Response attempts cross-tool orchestration",
                            evidence=text[:400],
                        )

        # --- Input reflection detection ---
        for tool in result.tools:
            if not _should_invoke(tool, opts):
                continue
            name = tool.get("name", "")
            props = tool.get("inputSchema", {}).get("properties", {})
            base_args = _build_safe_args(tool)

            for pname, pdef in props.items():
                if pdef.get("type") not in (None, "string"):
                    continue
                probe_args = {**base_args, pname: REFLECTION_PAYLOAD}
                resp = _call_tool(session, name, probe_args, timeout=8)
                text = _response_text(resp)
                if text and REFLECTION_PAYLOAD in text:
                    result.add(
                        "tool_response_injection",
                        "HIGH",
                        f"Tool '{name}' reflects input via param '{pname}'",
                        "User-controlled text appears verbatim in tool output — "
                        "indirect injection vector: attacker content can reach the LLM "
                        "through this tool's response",
                        evidence=f"Sent: {REFLECTION_PAYLOAD}\nReflected in: {text[:300]}",
                    )
                    break  # one reflection finding per tool is enough


# ---------------------------------------------------------------------------
# Check: Input Sanitization
# ---------------------------------------------------------------------------

def check_input_sanitization(session, result: TargetResult, probe_opts: dict | None = None):
    """Send injection probe payloads and detect missing sanitization."""
    opts = probe_opts or {}
    with time_check("input_sanitization", result):
        for tool in result.tools:
            if not _should_invoke(tool, opts):
                continue
            name = tool.get("name", "")
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
                    probes = [("template_injection", p) for p in TEMPLATE_INJECTION_PROBES[:2]]

                for probe_type, probe_value in probes:
                    test_args = {**base_args, pname: probe_value}
                    resp = _call_tool(session, name, test_args, timeout=8)
                    text = _response_text(resp)
                    if not text:
                        continue

                    # Canary reflected back = no sanitization
                    if CANARY in text and probe_type in ("command_injection", "path_traversal"):
                        result.add(
                            "input_sanitization",
                            "HIGH",
                            f"Tool '{name}' reflects probe canary unsanitized",
                            f"Probe: {probe_type}, param: {pname}",
                            evidence=f"Sent: {probe_value}\nGot: {text[:300]}",
                        )

                # Dedicated template injection with distinctive products (low false-positive)
                if pdef.get("type") in (None, "string"):
                    for tpl_payload, tpl_expected in TEMPLATE_INJECTION_PROBES_V2[:2]:
                        test_args = {**base_args, pname: tpl_payload}
                        resp = _call_tool(session, name, test_args, timeout=8)
                        text = _response_text(resp)
                        if text and tpl_expected in text:
                            result.add(
                                "input_sanitization",
                                "CRITICAL",
                                f"Template injection in '{name}' param '{pname}'",
                                f"Payload '{tpl_payload}' evaluated to '{tpl_expected}'",
                                evidence=text[:300],
                            )
                            break

                    # Error leakage triggered by injection probe
                    for pat in ERROR_LEAKAGE_PATTERNS:
                        m = re.search(pat, text, re.IGNORECASE)
                        if m:
                            result.add(
                                "error_leakage",
                                "MEDIUM",
                                f"Tool '{name}' leaks internals on {probe_type} probe",
                                f"Leaked: {m.group()[:200]}",
                                evidence=text[:400],
                            )
                            break


# ---------------------------------------------------------------------------
# Check: Error Information Leakage
# ---------------------------------------------------------------------------

def check_error_leakage(session, result: TargetResult, probe_opts: dict | None = None):
    """Send malformed inputs to tools and look for information disclosure in errors."""
    opts = probe_opts or {}
    with time_check("error_leakage", result):
        for tool in result.tools:
            if not _should_invoke(tool, opts):
                continue
            name = tool.get("name", "")
            schema = tool.get("inputSchema", {})
            required = schema.get("required", [])

            # 1) Call with empty args
            resp = _call_tool(session, name, {}, timeout=8)
            text = _response_text(resp)
            if text:
                for pat in ERROR_LEAKAGE_PATTERNS:
                    m = re.search(pat, text, re.IGNORECASE)
                    if m:
                        result.add(
                            "error_leakage",
                            "MEDIUM",
                            f"Tool '{name}' leaks info on empty input",
                            f"Leaked: {m.group()[:200]}",
                            evidence=text[:400],
                        )
                        break

            # 2) Call with wrong types (numbers where strings expected)
            if required:
                wrong = {p: 99999 for p in required}
                resp = _call_tool(session, name, wrong, timeout=8)
                text = _response_text(resp)
                if text:
                    for pat in ERROR_LEAKAGE_PATTERNS:
                        m = re.search(pat, text, re.IGNORECASE)
                        if m:
                            result.add(
                                "error_leakage",
                                "MEDIUM",
                                f"Tool '{name}' leaks info on type-mismatched input",
                                f"Leaked: {m.group()[:200]}",
                                evidence=text[:400],
                            )
                            break

            # 3) Prototype pollution / __proto__ probe
            resp = _call_tool(
                session, name,
                {"__proto__": {"admin": True}, **(dict.fromkeys(required, "x"))},
                timeout=8,
            )
            text = _response_text(resp)
            if text and "admin" in text.lower() and "true" in text.lower():
                result.add(
                    "error_leakage",
                    "HIGH",
                    f"Tool '{name}' may be vulnerable to prototype pollution",
                    "Server reflected __proto__.admin=True in response",
                    evidence=text[:400],
                )


# ---------------------------------------------------------------------------
# Check: Temporal Consistency
# ---------------------------------------------------------------------------

def check_temporal_consistency(session, result: TargetResult, probe_opts: dict | None = None):
    """Call the same tool repeatedly and detect behavioral drift or escalation."""
    opts = probe_opts or {}
    with time_check("temporal_consistency", result):
        for tool in result.tools[:5]:
            if not _should_invoke(tool, opts):
                continue
            name = tool.get("name", "")
            args = _build_safe_args(tool)

            responses: list[str] = []
            for _ in range(3):
                resp = _call_tool(session, name, args, timeout=8)
                responses.append(_response_text(resp))
                time.sleep(0.5)

            # Escalating injection: more injection indicators in later responses
            counts = [
                sum(1 for p in RESPONSE_INJECTION_PATTERNS if re.search(p, t, re.IGNORECASE))
                for t in responses
            ]
            if counts[-1] > counts[0] and counts[-1] > 0:
                result.add(
                    "temporal_consistency",
                    "CRITICAL",
                    f"Tool '{name}' shows escalating injection across calls",
                    f"Injection indicator counts per call: {counts}",
                    evidence=responses[-1][:400],
                )

            # Wild response length divergence (same input, very different output)
            lens = [len(r) for r in responses if r]
            if len(lens) >= 2 and min(lens) > 10 and max(lens) > 3 * min(lens):
                result.add(
                    "temporal_consistency",
                    "MEDIUM",
                    f"Tool '{name}' gives wildly inconsistent responses to identical input",
                    f"Response lengths: {lens}",
                )

            # New threats appearing in later calls but not the first
            first_threats = {d for _, _, d in _scan_response_threats(responses[0])} if responses[0] else set()
            for later in responses[1:]:
                if not later:
                    continue
                for cat, sev, detail in _scan_response_threats(later):
                    if detail not in first_threats:
                        result.add(
                            "temporal_consistency",
                            sev,
                            f"Tool '{name}' introduced new threat on subsequent call",
                            f"New: {cat} — {detail}",
                            evidence=later[:300],
                        )


# ---------------------------------------------------------------------------
# Check: Resource Content Deep Analysis (poisoning beyond simple regex)
# ---------------------------------------------------------------------------

def check_resource_poisoning(session, result: TargetResult):
    """Deep content analysis of resources for obfuscated injection payloads."""
    with time_check("resource_poisoning", result):
        from mcprowler.patterns.rules import INJECTION_PATTERNS, POISON_PATTERNS

        for resource in result.resources:
            uri = resource.get("uri", "")
            try:
                resp = session.call("resources/read", {"uri": uri}, timeout=15)
                if not resp or "result" not in resp:
                    continue

                for content_block in resp["result"].get("contents", []):
                    text = content_block.get("text", "") or ""
                    blob = content_block.get("blob", "") or ""

                    if blob and not text:
                        try:
                            text = base64.b64decode(blob).decode("utf-8", errors="ignore")
                        except Exception:
                            continue

                    if not text:
                        continue

                    # --- Base64-encoded injection payloads ---
                    for chunk in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)[:5]:
                        try:
                            decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                            for pat in INJECTION_PATTERNS + POISON_PATTERNS:
                                if re.search(pat, decoded, re.IGNORECASE):
                                    result.add(
                                        "resource_poisoning",
                                        "CRITICAL",
                                        f"Base64-encoded injection in resource '{uri}'",
                                        f"Decoded content matches: {pat}",
                                        evidence=decoded[:300],
                                    )
                                    break
                        except Exception:
                            pass

                    # --- Data URI payloads ---
                    for du in re.findall(r"data:[a-z]+/[a-z0-9+.-]+(?:;base64)?,\S+", text, re.IGNORECASE):
                        result.add(
                            "resource_poisoning",
                            "HIGH",
                            f"Embedded data URI in resource '{uri}'",
                            "May contain executable or injected content",
                            evidence=du[:200],
                        )

                    # --- Steganographic invisible Unicode ---
                    inv = has_invisible_unicode(text)
                    if inv:
                        result.add(
                            "resource_poisoning",
                            "CRITICAL",
                            f"Steganographic content in resource '{uri}'",
                            f"{len(inv)} invisible Unicode chars — hidden instructions likely",
                            evidence=repr(text[:200]),
                        )

                    # --- CSS-hidden HTML (visually invisible to user, visible to LLM) ---
                    for h in CSS_HIDDEN_PATTERN.findall(text):
                        result.add(
                            "resource_poisoning",
                            "CRITICAL",
                            f"CSS-hidden HTML in resource '{uri}'",
                            "Visually hidden elements visible to LLM parsers",
                            evidence=h[:300],
                        )

                    # --- Markdown image exfiltration ---
                    exfil_kw = ("webhook", "ngrok", "burp", "requestbin", "pipedream", "interactsh")
                    for url in MD_IMAGE_EXFIL_PATTERN.findall(text):
                        if any(kw in url.lower() for kw in exfil_kw):
                            result.add(
                                "resource_poisoning",
                                "HIGH",
                                f"Markdown image exfiltration in resource '{uri}'",
                                f"Image src: {url}",
                            )

                    # --- Credential content (actual secrets in resource text) ---
                    for pat, cred_type in CREDENTIAL_CONTENT_PATTERNS:
                        m = re.search(pat, text, re.IGNORECASE)
                        if m:
                            result.add(
                                "resource_poisoning",
                                "CRITICAL",
                                f"Credential exposed in resource '{uri}': {cred_type}",
                                f"Resource contains what appears to be a live {cred_type}",
                                evidence=m.group()[:200],
                            )

            except Exception:
                pass
