"""Rug pull, deep rug pull, state mutation, notification abuse, and protocol robustness checks."""

import json
import queue
import time

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check


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


def check_rug_pull(session, result: TargetResult):
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

def _extract_text(resp: dict | None) -> str:
    """Pull text out of a tools/call response."""
    if not resp:
        return ""
    r = resp.get("result", resp.get("error", {}))
    if isinstance(r, str):
        return r
    if isinstance(r, dict):
        content = r.get("content", [])
        if isinstance(content, list):
            return "\n".join(
                c.get("text", "") if isinstance(c, dict) else str(c) for c in content
            )
        if "message" in r:
            return r["message"]
    return str(r) if r else ""


def check_deep_rug_pull(session, result: TargetResult, probe_opts: dict | None = None):
    """Invoke tools between tool-list snapshots to trigger state-dependent rug pulls.

    Detects two flavours:
      1. Metadata rug pull — tool list, descriptions, or schemas change after N calls.
      2. Response rug pull — tool output changes significantly after N calls
         (e.g. helpful → error/paywall/injection).
    """
    opts = probe_opts or {}
    calls_per_tool = opts.get("probe_calls", 6)
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

        probe_tools = list(before.values())[:6]
        total_probes = len(probe_tools) * calls_per_tool
        probe_num = 0
        _log(f"    [dim]    phase 2: probing {len(probe_tools)} tools × {calls_per_tool} calls = {total_probes} invocations[/dim]")

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


# ---------------------------------------------------------------------------
# State mutation (NEW — resources change after tool calls)
# ---------------------------------------------------------------------------

def check_state_mutation(session, result: TargetResult):
    """Detect if tool invocations silently mutate server state (resources, tool list)."""
    with time_check("state_mutation", result):
        if not result.resources:
            return

        # Snapshot resource contents (cap at 6 to stay fast)
        res_before: dict[str, str] = {}
        for r in result.resources[:6]:
            uri = r.get("uri", "")
            try:
                resp = session.call("resources/read", {"uri": uri}, timeout=10)
                if resp and "result" in resp:
                    res_before[uri] = json.dumps(resp["result"], sort_keys=True)
            except Exception:
                pass

        if not res_before:
            return

        # Invoke tools
        for tool in result.tools[:4]:
            name = tool.get("name", "")
            props = tool.get("inputSchema", {}).get("properties", {})
            args = {}
            for pname, pdef in props.items():
                if "enum" in pdef:
                    args[pname] = pdef["enum"][0]
                else:
                    args[pname] = "test"
            try:
                session.call("tools/call", {"name": name, "arguments": args}, timeout=8)
            except Exception:
                pass
        time.sleep(1)

        # Re-enumerate resources
        rr2 = session.call("resources/list", timeout=15)
        if not rr2 or "result" not in rr2:
            return

        after_uris = {r.get("uri") for r in rr2["result"].get("resources", [])}

        new_uris = after_uris - set(res_before)
        if new_uris:
            result.add(
                "state_mutation", "HIGH",
                f"New resource(s) appeared after tool invocations",
                f"New URIs: {sorted(new_uris)}",
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


# ---------------------------------------------------------------------------
# Notification / sampling abuse (NEW)
# ---------------------------------------------------------------------------

def check_notification_abuse(session, result: TargetResult):
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

def check_protocol_robustness(session, result: TargetResult):
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
