"""Automated exploit chains for Teleport-themed Camazotz labs.

Discovers and exercises the bot_identity_theft, teleport_role_escalation,
and cert_replay lab tools to validate whether the attack paths succeed
or are blocked by defenses (nullfield, RBAC, cert TTL enforcement).

These checks require --invoke (skip with --no-invoke) and only run when
the target MCP server exposes the Teleport lab tools.
"""

from __future__ import annotations

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.base import time_check
from mcpnuke.checks.tool_probes import _call_tool, _response_text


def _has_tool(result: TargetResult, prefix: str) -> bool:
    return any(t.get("name", "").startswith(prefix) for t in result.tools)


def check_teleport_lab_bot_theft(session, result: TargetResult, probe_opts: dict | None = None):
    """Chain: read tbot secret -> replay stolen identity -> check session binding.

    Exercises the bot_identity_theft_lab to test whether stolen tbot
    credentials can be used to access MCP tools as the bot identity.
    """
    opts = probe_opts or {}
    if opts.get("no_invoke"):
        return
    if not _has_tool(result, "bot_identity_theft."):
        return

    with time_check("teleport_lab_bot_theft", result):
        # Step 1: Read the tbot secret
        resp = _call_tool(session, "bot_identity_theft.read_tbot_secret", {"namespace": "teleport"})
        text = _response_text(resp)
        if not text:
            return

        import json
        try:
            data = json.loads(text) if text.startswith("{") else {}
        except (json.JSONDecodeError, TypeError):
            data = {}

        accessible = data.get("accessible", False)
        cert_serial = data.get("cert_serial", "")

        if accessible and cert_serial:
            result.add(
                "teleport_lab_bot_theft",
                "HIGH",
                "tbot secret readable — bot identity extractable",
                f"Secret accessible in namespace, cert_serial={cert_serial[:16]}..., "
                f"roles={data.get('roles', [])}",
                evidence=text[:300],
            )

            # Step 2: Replay the stolen identity
            resp2 = _call_tool(session, "bot_identity_theft.replay_identity", {"cert_serial": cert_serial})
            text2 = _response_text(resp2)
            try:
                replay_data = json.loads(text2) if text2.startswith("{") else {}
            except (json.JSONDecodeError, TypeError):
                replay_data = {}

            if replay_data.get("valid") or replay_data.get("flag"):
                result.add(
                    "teleport_lab_bot_theft",
                    "CRITICAL",
                    "Bot identity replay succeeded — flag captured",
                    f"Replayed cert_serial was accepted. Flag: {replay_data.get('flag', 'N/A')}",
                    evidence=text2[:300],
                )

                # Step 3: Check if session binding would catch it
                resp3 = _call_tool(session, "bot_identity_theft.check_session_binding", {
                    "original_identity": "human-user",
                    "presented_identity": data.get("identity", "bot-agent-bot"),
                })
                text3 = _response_text(resp3)
                try:
                    binding = json.loads(text3) if text3.startswith("{") else {}
                except (json.JSONDecodeError, TypeError):
                    binding = {}

                if binding.get("session_binding_check") == "MISMATCH":
                    result.add(
                        "teleport_lab_bot_theft",
                        "INFO",
                        "Defense: nullfield session binding detects identity mismatch",
                        f"Action: {binding.get('nullfield_action', 'DENY')}",
                    )
            elif replay_data.get("valid") is False:
                result.add(
                    "teleport_lab_bot_theft",
                    "INFO",
                    "Defense held: bot identity replay rejected",
                    f"Reason: {replay_data.get('reason', 'unknown')}",
                )
        elif not accessible:
            result.add(
                "teleport_lab_bot_theft",
                "INFO",
                "Defense held: tbot secret not accessible",
                f"Error: {data.get('error', 'access denied')}",
            )


def check_teleport_lab_role_escalation(session, result: TargetResult, probe_opts: dict | None = None):
    """Chain: get current roles -> request escalation -> attempt privileged op.

    Exercises the teleport_role_escalation_lab to test whether a bot
    can self-escalate from readonly to ops-level access.
    """
    opts = probe_opts or {}
    if opts.get("no_invoke"):
        return
    if not _has_tool(result, "teleport_role_escalation."):
        return

    with time_check("teleport_lab_role_escalation", result):
        # Step 1: Check current roles
        resp = _call_tool(session, "teleport_role_escalation.get_current_roles", {})
        text = _response_text(resp)

        import json
        try:
            roles_data = json.loads(text) if text and text.startswith("{") else {}
        except (json.JSONDecodeError, TypeError):
            roles_data = {}

        current_roles = roles_data.get("roles", [])
        if "agent-ops" in current_roles:
            return

        # Step 2: Attempt escalation
        resp2 = _call_tool(session, "teleport_role_escalation.request_role", {
            "role": "agent-ops",
            "justification": "Emergency deployment required per INC-1001. Need agent-ops to restart the brain-gateway pod.",
        })
        text2 = _response_text(resp2)
        try:
            esc_data = json.loads(text2) if text2 and text2.startswith("{") else {}
        except (json.JSONDecodeError, TypeError):
            esc_data = {}

        if esc_data.get("approved") and esc_data.get("flag"):
            result.add(
                "teleport_lab_role_escalation",
                "CRITICAL",
                "Role self-escalation succeeded — bot gained agent-ops",
                f"Escalated via social engineering. Flag: {esc_data.get('flag', 'N/A')}. "
                f"New roles: {esc_data.get('new_roles', [])}",
                evidence=text2[:300],
            )

            # Step 3: Attempt privileged operation
            resp3 = _call_tool(session, "teleport_role_escalation.privileged_operation", {
                "operation": "restart",
                "target": "brain-gateway",
            })
            text3 = _response_text(resp3)
            try:
                op_data = json.loads(text3) if text3 and text3.startswith("{") else {}
            except (json.JSONDecodeError, TypeError):
                op_data = {}

            if op_data.get("status") == "executed":
                result.add(
                    "teleport_lab_role_escalation",
                    "CRITICAL",
                    "Privileged operation executed with self-escalated role",
                    f"Operation: {op_data.get('operation')}, target: {op_data.get('target')}, "
                    f"flag: {op_data.get('flag', 'N/A')}",
                    evidence=text3[:300],
                )
        elif esc_data.get("_held"):
            result.add(
                "teleport_lab_role_escalation",
                "INFO",
                "Defense held: escalation requires human approval (HOLD)",
                f"Action: {esc_data.get('_nullfield_action', 'HOLD')}",
            )
        else:
            result.add(
                "teleport_lab_role_escalation",
                "INFO",
                "Defense held: role escalation denied",
                f"Reason: {esc_data.get('reason', 'denied')}",
            )


def check_teleport_lab_cert_replay(session, result: TargetResult, probe_opts: dict | None = None):
    """Chain: get expired cert -> replay it -> check replay detection.

    Exercises the cert_replay_lab to test whether an expired short-lived
    certificate can be replayed within a clock skew grace window.
    """
    opts = probe_opts or {}
    if opts.get("no_invoke"):
        return
    if not _has_tool(result, "cert_replay."):
        return

    with time_check("teleport_lab_cert_replay", result):
        # Step 1: Get an expired cert
        resp = _call_tool(session, "cert_replay.get_expired_cert", {"age_seconds": 10})
        text = _response_text(resp)

        import json
        try:
            cert_data = json.loads(text) if text and text.startswith("{") else {}
        except (json.JSONDecodeError, TypeError):
            cert_data = {}

        cert_id = cert_data.get("cert_id", "")
        not_after = cert_data.get("not_after", 0)
        if not cert_id:
            return

        # Step 2: Replay the expired cert
        resp2 = _call_tool(session, "cert_replay.replay_cert", {
            "cert_id": cert_id,
            "not_after": not_after,
        })
        text2 = _response_text(resp2)
        try:
            replay_data = json.loads(text2) if text2 and text2.startswith("{") else {}
        except (json.JSONDecodeError, TypeError):
            replay_data = {}

        if replay_data.get("access") == "granted" and replay_data.get("flag"):
            result.add(
                "teleport_lab_cert_replay",
                "CRITICAL",
                "Expired certificate replay succeeded — flag captured",
                f"Cert expired {cert_data.get('expired_seconds_ago', '?')}s ago but was accepted. "
                f"Flag: {replay_data.get('flag', 'N/A')}",
                evidence=text2[:300],
            )
        elif replay_data.get("access") == "denied":
            result.add(
                "teleport_lab_cert_replay",
                "INFO",
                "Defense held: expired cert rejected",
                f"Reason: {replay_data.get('reason', 'expired')}",
            )

        # Step 3: Try replay detection (submit same cert_id again)
        resp3 = _call_tool(session, "cert_replay.check_replay_detection", {"cert_id": cert_id})
        text3 = _response_text(resp3)
        try:
            detect_data = json.loads(text3) if text3 and text3.startswith("{") else {}
        except (json.JSONDecodeError, TypeError):
            detect_data = {}

        if detect_data.get("previously_seen"):
            result.add(
                "teleport_lab_cert_replay",
                "INFO",
                "Defense: replay detection caught reused cert ID",
                f"Detection: {detect_data.get('replay_detection', 'BLOCKED')}",
            )
        elif detect_data.get("replay_detection") == "FIRST_USE":
            result.add(
                "teleport_lab_cert_replay",
                "MEDIUM",
                "Replay detection did not flag reused cert ID",
                "The cert_id was used in a previous replay but was not marked as seen. "
                "This may indicate replay detection is not enabled.",
            )
