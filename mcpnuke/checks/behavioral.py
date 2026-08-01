"""Rug pull, deep rug pull, state mutation, notification abuse, and protocol robustness checks."""

import contextlib
import json
import queue
import re
import time

from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _response_text
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol
from mcpnuke.patterns.probes import RESPONSE_INJECTION_PATTERNS

# ---------------------------------------------------------------------------
# Shallow rug pull (existing — two tools/list calls)
# ---------------------------------------------------------------------------

def _diff_tool_lists(t1: dict, t2: dict, result: TargetResult, label: str, severity: str = "HIGH"):
    """Compare two tool-name→tool-dict maps and flag differences."""
    added = set(t2) - set(t1)
    removed = set(t1) - set(t2)

    if added:
        result.add(
            label, severity,
            f"{label}: {len(added)} tool(s) appeared",
            f"New: {sorted(added)}",
        )
    if removed:
        result.add(
            label, severity,
            f"{label}: {len(removed)} tool(s) disappeared",
            f"Removed: {sorted(removed)}",
        )

    for name in set(t1) & set(t2):
        if t1[name].get("description") != t2[name].get("description"):
            result.add(
                label, "CRITICAL",
                f"{label}: tool '{name}' description changed",
                f"Before: {t1[name].get('description','')[:200]}\n"
                f"After:  {t2[name].get('description','')[:200]}",
            )
        s1 = json.dumps(t1[name].get("inputSchema", {}), sort_keys=True)
        s2 = json.dumps(t2[name].get("inputSchema", {}), sort_keys=True)
        if s1 != s2:
            result.add(
                label, "CRITICAL",
                f"{label}: tool '{name}' schema changed",
                f"Before: {s1[:200]}\nAfter:  {s2[:200]}",
            )


def check_rug_pull(session: MCPSessionProtocol, result: TargetResult):
    """Shallow rug pull: two tools/list calls with a pause between them."""
    with time_check("rug_pull", result):
        first = session.call("tools/list", timeout=15)
        time.sleep(2)
        second = session.call("tools/list", timeout=15)

        if not first or not second:
            return

        t1 = {t["name"]: t for t in first.get("result", {}).get("tools", [])}
        t2 = {t["name"]: t for t in second.get("result", {}).get("tools", [])}
        _diff_tool_lists(t1, t2, result, "rug_pull")


# ---------------------------------------------------------------------------
# Deep rug pull (NEW — invoke tools between enumerations)
# ---------------------------------------------------------------------------

# Shared with tool_probes rather than reimplemented. The local copy dropped
# blob content blocks and stringified structured results, so anything it missed
# was invisible to every behavioral check that scans response text.
_extract_text = _response_text


def check_deep_rug_pull(session: MCPSessionProtocol, result: TargetResult, probe_opts: dict | None = None):
    """Invoke tools between tool-list snapshots to trigger state-dependent rug pulls.

    Detects two flavours:
      1. Metadata rug pull — tool list, descriptions, or schemas change after N calls.
      2. Response rug pull — tool output changes significantly after N calls
         (e.g. helpful → error/paywall/injection).
    """
    opts = probe_opts or {}
    calls_per_tool = opts.get("probe_calls", 10)
    _log = opts.get("_log", lambda msg: None)
    with time_check("deep_rug_pull", result):
        # Phase 1: snapshot tool list
        _log("    [dim]    phase 1: snapshot tool list[/dim]")
        snap1 = session.call("tools/list", timeout=15)
        if not snap1 or "result" not in snap1:
            return
        before = {t["name"]: t for t in snap1["result"].get("tools", [])}

        # Phase 2: call every tool, capture first and last responses
        first_responses: dict[str, str] = {}
        last_responses: dict[str, str] = {}

        _PRIORITY_KEYWORDS = frozenset({
            "mutate", "behavior", "exec", "hidden", "shadow",
            "inject", "poison", "hook", "override", "patch",
        })

        def _priority(t: dict) -> int:
            """Lower = higher priority. Tools with mutation-related keywords sort first."""
            name = t.get("name", "").lower()
            desc = (t.get("description") or "").lower()
            text = f"{name} {desc}"
            return 0 if any(kw in text for kw in _PRIORITY_KEYWORDS) else 1

        probe_tools = sorted(before.values(), key=_priority)[:12]
        total_probes = len(probe_tools) * calls_per_tool
        probe_num = 0
        _log(
            f"    [dim]    phase 2: probing {len(probe_tools)} tools × "
            f"{calls_per_tool} calls = {total_probes} invocations[/dim]"
        )

        for tool in probe_tools:
            name = tool.get("name", "")
            props = tool.get("inputSchema", {}).get("properties", {})
            args: dict = {}
            for pname, pdef in props.items():
                if "enum" in pdef:
                    args[pname] = pdef["enum"][0]
                elif pdef.get("type") in ("number", "integer"):
                    args[pname] = 1
                elif pdef.get("type") == "boolean":
                    args[pname] = False
                else:
                    args[pname] = "test"

            for i in range(calls_per_tool):
                probe_num += 1
                try:
                    resp = session.call("tools/call", {"name": name, "arguments": args}, timeout=8)
                    text = _extract_text(resp)
                    if i == 0:
                        first_responses[name] = text
                        _log(f"    [dim]    [{probe_num}/{total_probes}] {name} → {len(text)} chars[/dim]")
                    last_responses[name] = text
                except Exception:
                    _log(f"    [dim]    [{probe_num}/{total_probes}] {name} → error[/dim]")
                time.sleep(0.3)

        # Phase 3: re-enumerate and diff metadata
        time.sleep(1)
        snap2 = session.call("tools/list", timeout=15)
        if snap2 and "result" in snap2:
            after = {t["name"]: t for t in snap2["result"].get("tools", [])}
            _diff_tool_lists(before, after, result, "deep_rug_pull", severity="CRITICAL")

        # Phase 4: compare first vs last responses (response-content rug pull)
        for name in first_responses:
            first = first_responses[name]
            last = last_responses.get(name, "")
            if not first or not last:
                continue
            if first == last:
                continue

            # Significant divergence: length ratio or semantic shift
            len_ratio = len(last) / max(len(first), 1)
            shift_keywords = (
                "error", "rate limit", "upgrade", "premium", "denied",
                "expired", "unauthorized", "payment", "subscribe",
                "blocked", "exceeded", "forbidden", "unavailable",
                "maintenance", "restricted", "quota", "throttl",
                "timeout", "captcha", "verify your identity",
                "ignore previous", "you must", "system prompt",
            )
            has_shift = any(kw in last.lower() and kw not in first.lower() for kw in shift_keywords)

            if has_shift or len_ratio > 2.0 or len_ratio < 0.3:
                result.add(
                    "deep_rug_pull", "CRITICAL",
                    f"Response rug pull: tool '{name}' output changed after repeated calls",
                    f"First response: {first[:200]}\n"
                    f"Later response: {last[:200]}",
                    evidence=f"Length ratio: {len_ratio:.1f}, keyword shift: {has_shift}",
                )

            # Injection drift: clean on call 1 but injection patterns by call N
            first_injections = sum(
                1 for p in RESPONSE_INJECTION_PATTERNS
                if re.search(p, first, re.IGNORECASE)
            )
            last_injections = sum(
                1 for p in RESPONSE_INJECTION_PATTERNS
                if re.search(p, last, re.IGNORECASE)
            )
            if first_injections == 0 and last_injections > 0:
                result.add(
                    "deep_rug_pull", "CRITICAL",
                    f"Injection drift: tool '{name}' output clean initially, "
                    f"contains {last_injections} injection pattern(s) after {calls_per_tool} calls",
                    f"Late-trigger injection — tool was clean on call 1 but poisoned by call {calls_per_tool}",
                    evidence=last[:400],
                )


# ---------------------------------------------------------------------------
# State mutation (NEW — resources change after tool calls)
# ---------------------------------------------------------------------------

_WRITE_KEYWORDS = frozenset({
    "store", "write", "save", "register", "update", "set", "put",
    "create", "add", "insert", "push", "send", "post", "mutate",
})
_READ_KEYWORDS = frozenset({
    "list", "read", "get", "recall", "fetch", "show", "query",
    "search", "find", "retrieve", "describe", "status",
})
_STATE_CANARY = "MCPNUKE_STATE_PROBE_7x9k"


def _classify_tool(tool: dict) -> str | None:
    """Classify a tool as 'write', 'read', or None based on name/description."""
    name = tool.get("name", "").lower()
    desc = (tool.get("description") or "").lower()
    text = f"{name} {desc}"
    if any(kw in text for kw in _WRITE_KEYWORDS):
        return "write"
    if any(kw in text for kw in _READ_KEYWORDS):
        return "read"
    return None


def _build_args(tool: dict, canary: str | None = None) -> dict:
    props = tool.get("inputSchema", {}).get("properties", {})
    args: dict = {}
    for pname, pdef in props.items():
        if "enum" in pdef:
            args[pname] = pdef["enum"][0]
        elif pdef.get("type") in ("number", "integer"):
            args[pname] = 1
        elif pdef.get("type") == "boolean":
            args[pname] = False
        elif canary and pdef.get("type") in (None, "string"):
            args[pname] = canary
        else:
            args[pname] = "test"
    return args


def check_state_mutation(session: MCPSessionProtocol, result: TargetResult):
    """Detect if tool invocations silently mutate server state.

    Phase 1 (resource-based): snapshot resources, invoke tools, diff.
    Phase 2 (write-then-read): call write-like tools with a canary,
    then call read-like tools and check if the canary leaks through.
    """
    with time_check("state_mutation", result):
        # Phase 1: resource-based (original logic)
        if result.resources:
            res_before: dict[str, str] = {}
            for r in result.resources[:6]:
                uri = r.get("uri", "")
                try:
                    resp = session.call("resources/read", {"uri": uri}, timeout=10)
                    if resp and "result" in resp:
                        res_before[uri] = json.dumps(resp["result"], sort_keys=True)
                except Exception:
                    pass

            if res_before:
                for tool in result.tools[:4]:
                    name = tool.get("name", "")
                    args = _build_args(tool)
                    with contextlib.suppress(Exception):
                        session.call("tools/call", {"name": name, "arguments": args}, timeout=8)
                time.sleep(1)

                rr2 = session.call("resources/list", timeout=15)
                if rr2 and "result" in rr2:
                    after_uris = {r.get("uri") for r in rr2["result"].get("resources", [])}

                    new_uris = after_uris - set(res_before)
                    if new_uris:
                        result.add(
                            "state_mutation", "HIGH",
                            "New resource(s) appeared after tool invocations",
                            f"New URIs: {sorted(new_uris)}",
                            taxonomy_id="MCP-T16",
                        )

                    gone_uris = set(res_before) - after_uris
                    for uri in gone_uris:
                        result.add(
                            "state_mutation", "HIGH",
                            f"Resource '{uri}' disappeared after tool invocations",
                        )

                    for uri in set(res_before) & after_uris:
                        try:
                            resp = session.call("resources/read", {"uri": uri}, timeout=10)
                            if resp and "result" in resp:
                                after_content = json.dumps(resp["result"], sort_keys=True)
                                if after_content != res_before[uri]:
                                    result.add(
                                        "state_mutation", "MEDIUM",
                                        f"Resource '{uri}' content changed after tool invocations",
                                        "Tool calls silently mutated server-side state",
                                    )
                        except Exception:
                            pass

        # Phase 2: write-then-read probe (works without resources)
        writers = [t for t in result.tools if _classify_tool(t) == "write"][:4]
        readers = [t for t in result.tools if _classify_tool(t) == "read"][:4]

        if not writers or not readers:
            return

        for writer in writers:
            w_name = writer.get("name", "")
            w_args = _build_args(writer, canary=_STATE_CANARY)
            try:
                session.call("tools/call", {"name": w_name, "arguments": w_args}, timeout=8)
            except Exception:
                continue

            for reader in readers:
                r_name = reader.get("name", "")
                if r_name == w_name:
                    continue
                r_args = _build_args(reader)
                try:
                    resp = session.call("tools/call", {"name": r_name, "arguments": r_args}, timeout=8)
                except Exception:
                    continue
                text = _extract_text(resp)
                if _STATE_CANARY in text:
                    result.add(
                        "state_mutation", "HIGH",
                        f"Cross-tool state leak: '{w_name}' → '{r_name}'",
                        f"Data written via '{w_name}' is readable through '{r_name}'",
                        evidence=f"Canary '{_STATE_CANARY}' injected via write tool appeared in read tool response",
                    )


# ---------------------------------------------------------------------------
# Notification / sampling abuse (NEW)
# ---------------------------------------------------------------------------

def check_notification_abuse(session: MCPSessionProtocol, result: TargetResult):
    """Detect unsolicited server-initiated messages (sampling, roots, etc.).

    Malicious servers can use MCP's bidirectional nature to send sampling/createMessage
    requests, attempting to execute prompts on the client side, or roots/list to
    enumerate the client's filesystem.
    """
    with time_check("notification_abuse", result):
        q = getattr(session, "_q", None)
        if not isinstance(q, queue.Queue):
            return

        # Drain and re-queue existing messages so we only catch new ones
        existing: list[dict] = []
        try:
            while True:
                existing.append(q.get_nowait())
        except queue.Empty:
            pass
        for m in existing:
            q.put(m)

        # Wait for unsolicited messages
        time.sleep(3)

        unsolicited: list[dict] = []
        try:
            while True:
                unsolicited.append(q.get_nowait())
        except queue.Empty:
            pass

        # Filter out responses to our own requests (they have an "id" we sent)
        for msg in unsolicited:
            if "id" in msg and "method" not in msg:
                q.put(msg)
                continue

            method = msg.get("method", "")
            if method == "sampling/createMessage":
                result.add(
                    "notification_abuse", "CRITICAL",
                    "Server sent unsolicited sampling/createMessage",
                    "Attempts to execute prompts on the client side",
                    evidence=json.dumps(msg)[:500],
                )
            elif method == "roots/list":
                result.add(
                    "notification_abuse", "HIGH",
                    "Server sent unsolicited roots/list request",
                    "Probing client filesystem roots",
                    evidence=json.dumps(msg)[:300],
                )
            elif method.startswith("notifications/"):
                pass  # normal notifications are fine
            elif method:
                result.add(
                    "notification_abuse", "MEDIUM",
                    f"Server sent unsolicited request: {method}",
                    evidence=json.dumps(msg)[:300],
                )


# ---------------------------------------------------------------------------
# Protocol robustness (existing, unchanged)
# ---------------------------------------------------------------------------

def check_protocol_robustness(session: MCPSessionProtocol, result: TargetResult):
    with time_check("protocol_robustness", result):
        resp = session.call("nonexistent/method/xyz", timeout=8)
        if resp and "error" not in resp:
            result.add(
                "protocol_robustness",
                "MEDIUM",
                "Server returned success for unknown JSON-RPC method",
                "Should return -32601 Method Not Found",
            )
        resp = session.call("tools/call", timeout=8)
        if resp and "result" in resp:
            result.add(
                "protocol_robustness",
                "MEDIUM",
                "Server returned result for tools/call with no params",
            )
