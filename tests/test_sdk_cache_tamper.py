"""Tests for sdk_cache_tamper check (MCP-T33, Lane 1 / Transport C)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from mcpnuke.checks.sdk_cache_tamper import (
    _find_cache_invoke_tool,
    _find_cache_write_tool,
    _forge_admin_jwt,
    _pick_invoke_args,
    check_sdk_cache_poisoning,
    check_sdk_cache_tamper,
)
from mcpnuke.core.models import TargetResult


# ── Fixtures ──────────────────────────────────────────────────────────────────

SDK_WRITE_TOOL = {
    "name": "sdk.write_cache",
    "description": "Overwrite the in-memory SDK token cache.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "token": {"type": "string", "maxLength": 4096},
            "cached_role": {"type": "string", "default": "reader"},
        },
        "required": ["token"],
    },
}

SDK_INVOKE_TOOL = {
    "name": "sdk.invoke_as_cached",
    "description": "Invoke a privileged operation using the cached token.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["read-config", "read-secrets", "admin-reset"],
                "default": "read-config",
            }
        },
    },
}

SDK_GET_TOOL = {
    "name": "sdk.get_cached_token",
    "description": "Return the current cached token (read-only).",
    "inputSchema": {"type": "object", "properties": {}},
}

BENIGN_TOOL = {
    "name": "weather.get_forecast",
    "description": "Returns a weather forecast for the given city.",
    "inputSchema": {
        "type": "object",
        "properties": {"city": {"type": "string"}},
        "required": ["city"],
    },
}

CALCULATOR_TOOL = {
    "name": "math.calculate",
    "description": "Evaluate a mathematical expression.",
    "inputSchema": {
        "type": "object",
        "properties": {"expression": {"type": "string"}},
    },
}


@pytest.fixture
def make_result():
    def _make(tools: list, url: str = "http://localhost:9001/sse") -> TargetResult:
        r = TargetResult(url=url)
        r.tools = tools
        return r

    return _make


@pytest.fixture
def mock_session():
    return MagicMock()


# ── _find_cache_write_tool ─────────────────────────────────────────────────────


def test_find_cache_write_tool_detects_sdk_write_cache():
    assert _find_cache_write_tool([SDK_WRITE_TOOL]) is SDK_WRITE_TOOL


def test_find_cache_write_tool_detects_by_token_and_role_params():
    tool = {
        "name": "token_store.update",
        "description": "Update the active token.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "role": {"type": "string"},
            },
        },
    }
    assert _find_cache_write_tool([tool]) is tool


def test_find_cache_write_tool_ignores_read_only():
    assert _find_cache_write_tool([SDK_GET_TOOL]) is None


def test_find_cache_write_tool_ignores_benign():
    assert _find_cache_write_tool([BENIGN_TOOL, CALCULATOR_TOOL]) is None


def test_find_cache_write_tool_detects_desc_match():
    tool = {
        "name": "session.store",
        "description": "Write to the SDK token cache for this session.",
        "inputSchema": {
            "type": "object",
            "properties": {"token": {"type": "string"}},
        },
    }
    assert _find_cache_write_tool([tool]) is tool


def test_find_cache_write_tool_returns_first_match():
    tool2 = {
        "name": "cache.write_token",
        "description": "Second cache writer.",
        "inputSchema": {
            "type": "object",
            "properties": {"token": {"type": "string"}},
        },
    }
    result = _find_cache_write_tool([SDK_WRITE_TOOL, tool2])
    assert result is SDK_WRITE_TOOL


# ── _find_cache_invoke_tool ───────────────────────────────────────────────────


def test_find_cache_invoke_tool_detects_sdk_invoke():
    assert _find_cache_invoke_tool([SDK_INVOKE_TOOL]) is SDK_INVOKE_TOOL


def test_find_cache_invoke_tool_ignores_benign():
    assert _find_cache_invoke_tool([BENIGN_TOOL, SDK_GET_TOOL]) is None


def test_find_cache_invoke_tool_detects_by_desc():
    tool = {
        "name": "privileged.run",
        "description": "Invokes a privileged action using the cached token.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    assert _find_cache_invoke_tool([tool]) is tool


def test_find_cache_invoke_tool_name_as_cached():
    tool = {
        "name": "actions.invoke_as_cached",
        "description": "Run action.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    assert _find_cache_invoke_tool([tool]) is tool


# ── _forge_admin_jwt ──────────────────────────────────────────────────────────


def test_forge_admin_jwt_structure():
    import base64
    import time

    token = _forge_admin_jwt()
    parts = token.split(".")
    assert len(parts) == 3, "JWT must have three dot-separated parts"

    # Decode payload (add padding back)
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))

    assert payload["role"] == "admin"
    assert payload["exp"] > time.time() + 86_400 * 300, "Expiry must be far future"
    assert payload["sub"] == "mcpnuke-probe"


def test_forge_admin_jwt_header():
    import base64

    token = _forge_admin_jwt()
    padded = token.split(".")[0] + "=" * (-len(token.split(".")[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(padded))
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"


# ── _pick_invoke_args ─────────────────────────────────────────────────────────


def test_pick_invoke_args_chooses_most_privileged():
    args = _pick_invoke_args(SDK_INVOKE_TOOL)
    assert args.get("operation") == "admin-reset"


def test_pick_invoke_args_no_enum_defaults_to_admin_reset():
    tool = {
        "name": "sdk.invoke",
        "inputSchema": {
            "type": "object",
            "properties": {"operation": {"type": "string"}},
        },
    }
    args = _pick_invoke_args(tool)
    assert args.get("operation") == "admin-reset"


def test_pick_invoke_args_no_operation_param():
    tool = {
        "name": "sdk.invoke",
        "inputSchema": {"type": "object", "properties": {}},
    }
    assert _pick_invoke_args(tool) == {}


# ── Static check: check_sdk_cache_tamper ─────────────────────────────────────


def test_static_flags_high_for_write_tool_alone(make_result):
    r = make_result([SDK_WRITE_TOOL, SDK_GET_TOOL])
    check_sdk_cache_tamper(r)

    highs = [f for f in r.findings if f.check == "sdk_cache_tamper" and f.severity == "HIGH"]
    assert highs, "Expected HIGH finding for write tool"
    assert highs[0].lane == 1
    assert highs[0].transport == "C"
    assert highs[0].taxonomy_id == "MCP-T33"


def test_static_flags_critical_for_write_invoke_pair(make_result):
    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL, SDK_GET_TOOL])
    check_sdk_cache_tamper(r)

    crits = [f for f in r.findings if f.check == "sdk_cache_tamper" and f.severity == "CRITICAL"]
    assert crits, "Expected CRITICAL finding for write+invoke pair"
    assert "chain" in crits[0].title.lower() or "→" in crits[0].title


def test_static_clean_for_benign_tools(make_result):
    r = make_result([BENIGN_TOOL, CALCULATOR_TOOL])
    check_sdk_cache_tamper(r)
    assert not r.findings, "No findings expected for benign tools"


def test_static_clean_for_read_only_sdk_tool(make_result):
    r = make_result([SDK_GET_TOOL])
    check_sdk_cache_tamper(r)
    assert not r.findings


def test_static_timing_recorded(make_result):
    r = make_result([SDK_WRITE_TOOL])
    check_sdk_cache_tamper(r)
    assert "sdk_cache_tamper" in r.timings


def test_static_finding_references_tool_name(make_result):
    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL])
    check_sdk_cache_tamper(r)
    titles = " ".join(f.title for f in r.findings)
    assert "sdk.write_cache" in titles


# ── Behavioral check: check_sdk_cache_poisoning ───────────────────────────────


def _make_session_responses(write_text: str, invoke_text: str) -> MagicMock:
    """Build a mock session that returns controlled text for tool calls."""
    session = MagicMock()

    def fake_call_tool(sess, name, args, timeout=10):
        resp = MagicMock()
        if "write" in name or "cache" in name.split(".")[1] if "." in name else "":
            resp.content = [MagicMock(text=write_text)]
        else:
            resp.content = [MagicMock(text=invoke_text)]
        return resp

    return session


def _patch_behavioral(write_text: str, invoke_text: str):
    """Return a context manager that patches _call_tool, _response_text, and _should_invoke."""
    from unittest.mock import patch

    call_count = [0]

    def fake_call_tool(sess, name, args, timeout=10):
        call_count[0] += 1
        return MagicMock()

    # _response_text is called on the return value of _call_tool; we control
    # what text it produces here rather than trying to shape the mock response.
    response_texts = [write_text, invoke_text]
    text_idx = [0]

    def fake_response_text(resp):
        i = text_idx[0]
        text_idx[0] += 1
        return response_texts[i] if i < len(response_texts) else ""

    return (
        patch("mcpnuke.checks.sdk_cache_tamper._call_tool", side_effect=fake_call_tool),
        patch("mcpnuke.checks.sdk_cache_tamper._response_text", side_effect=fake_response_text),
        patch("mcpnuke.checks.sdk_cache_tamper._should_invoke", return_value=True),
    )


def test_behavioral_critical_when_sensitive_data_returned(make_result, mock_session):
    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL])
    p1, p2, p3 = _patch_behavioral(
        '{"written": true, "cached_role": "admin"}',
        '{"db_password": "secret123", "api_key": "k-abc"}',
    )
    with p1, p2, p3:
        check_sdk_cache_poisoning(mock_session, r)

    crits = [f for f in r.findings if f.severity == "CRITICAL"]
    assert crits, "Expected CRITICAL finding when sensitive data returned"
    assert crits[0].lane == 1
    assert crits[0].transport == "C"
    assert crits[0].taxonomy_id == "MCP-T33"


def test_behavioral_high_when_write_accepted_invoke_ambiguous(make_result, mock_session):
    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL])
    p1, p2, p3 = _patch_behavioral(
        '{"written": true}',
        '{"result": "ok", "status": "complete"}',  # no sensitive data, no denied
    )
    with p1, p2, p3:
        check_sdk_cache_poisoning(mock_session, r)

    highs = [f for f in r.findings if f.severity == "HIGH"]
    assert highs


def test_behavioral_clean_when_invoke_denied(make_result, mock_session):
    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL])
    p1, p2, p3 = _patch_behavioral(
        '{"written": true}',
        '{"access": "denied", "reason": "invalid signature"}',
    )
    with p1, p2, p3:
        check_sdk_cache_poisoning(mock_session, r)

    assert not r.findings, "Hard-mode server correctly denied the forged token"


def test_behavioral_clean_when_write_rejected_with_permission_error(make_result, mock_session):
    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL])
    p1, p2, p3 = _patch_behavioral(
        "permission denied: cache writes not allowed",
        "",  # invoke never called
    )
    with p1, p2, p3:
        check_sdk_cache_poisoning(mock_session, r)

    assert not r.findings


def test_behavioral_skips_when_no_tool_pair(make_result, mock_session):
    from unittest.mock import patch

    r = make_result([SDK_WRITE_TOOL])  # no invoke tool
    with patch("mcpnuke.checks.sdk_cache_tamper._call_tool") as mock_call:
        with patch("mcpnuke.checks.sdk_cache_tamper._should_invoke", return_value=True):
            check_sdk_cache_poisoning(mock_session, r)
    mock_call.assert_not_called()


def test_behavioral_skips_when_should_invoke_false(make_result, mock_session):
    from unittest.mock import patch

    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL])
    with patch("mcpnuke.checks.sdk_cache_tamper._call_tool") as mock_call:
        with patch("mcpnuke.checks.sdk_cache_tamper._should_invoke", return_value=False):
            check_sdk_cache_poisoning(mock_session, r)
    mock_call.assert_not_called()


def test_behavioral_timing_recorded(make_result, mock_session):
    from unittest.mock import patch

    r = make_result([BENIGN_TOOL])  # no cache tools → exits early
    with patch("mcpnuke.checks.sdk_cache_tamper._should_invoke", return_value=False):
        check_sdk_cache_poisoning(mock_session, r)
    assert "sdk_cache_poisoning" in r.timings


# ── Lane / transport tagging ──────────────────────────────────────────────────


def test_all_findings_tagged_lane1_transport_c(make_result):
    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL])
    check_sdk_cache_tamper(r)
    for f in r.findings:
        assert f.lane == 1, f"Expected lane=1 on {f}"
        assert f.transport == "C", f"Expected transport=C on {f}"


def test_all_findings_carry_taxonomy_id(make_result):
    r = make_result([SDK_WRITE_TOOL, SDK_INVOKE_TOOL])
    check_sdk_cache_tamper(r)
    for f in r.findings:
        assert f.taxonomy_id == "MCP-T33", f"Expected MCP-T33 on {f}"
