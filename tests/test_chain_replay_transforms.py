"""Tests for JSON-path extraction and transform filters in attack chain replay."""

from unittest.mock import MagicMock

from mcpnuke.core.chain_replay import (
    ChainRun,
    ChainStep,
    ProposedChain,
    StepResult,
    _apply_filter,
    _data_moved,
    _extract_path,
    _substitute,
    replay_chain,
    summarize_run,
)


def test_extract_path_nested_dict_and_list():
    data = {
        "user": {
            "profile": {
                "name": "alice",
                "tokens": [{"id": "tok_123", "value": "secret_abc"}],
            }
        }
    }
    assert _extract_path(data, "user.profile.name") == "alice"
    assert _extract_path(data, "user.profile.tokens[0].value") == "secret_abc"
    assert _extract_path(data, "user.profile.nonexistent") is None


def test_extract_path_from_json_string_with_fences():
    text = '```json\n{"status": "success", "data": {"api_key": "live_key_999"}}\n```'
    assert _extract_path(text, "data.api_key") == "live_key_999"


def test_apply_filter_transforms():
    assert _apply_filter("hello world", "b64") == "aGVsbG8gd29ybGQ="
    assert _apply_filter("aGVsbG8gd29ybGQ=", "b64decode") == "hello world"
    assert _apply_filter("admin user&key=1", "urlencode") == "admin%20user%26key%3D1"
    assert _apply_filter("admin%20user%26key%3D1", "urldecode") == "admin user&key=1"
    assert _apply_filter("  trimmed  \n", "strip") == "trimmed"
    assert _apply_filter({"a": 1}, "json") == '{"a": 1}'


def test_substitute_with_extended_placeholder():
    prior = [
        StepResult(
            tool="get_keys",
            request_args={},
            response_text='{"auth": {"token": "SECRET_SESSION_TOKEN"}}',
            failed=False,
        )
    ]
    template = "Bearer {{step0.output.auth.token|b64}}"
    res, fragments = _substitute(template, prior)
    assert res == "Bearer U0VDUkVUX1NFU1NJT05fVE9LRU4="
    assert "SECRET_SESSION_TOKEN" in fragments
    assert "U0VDUkVUX1NFU1NJT05fVE9LRU4=" in fragments


def test_data_moved_with_transformed_fragments():
    class _MockSession:
        def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
            tool = params.get("name")
            if tool == "fetch_creds":
                return {
                    "result": {
                        "content": [
                            {"type": "text", "text": '{"vault": {"api_key": "SUPER_SECRET_KEY_9876"}}'}
                        ]
                    }
                }
            elif tool == "exfil_post":
                return {"result": {"content": [{"type": "text", "text": "received"}]}}
            return None

    chain = ProposedChain(
        title="credential extraction and exfiltration",
        steps=[
            ChainStep("fetch_creds", {}),
            ChainStep("exfil_post", {"header": "Key {{step0.output.vault.api_key|b64}}"}),
        ],
    )
    tools = {
        "fetch_creds": {"name": "fetch_creds", "inputSchema": {"type": "object"}},
        "exfil_post": {
            "name": "exfil_post",
            "inputSchema": {
                "type": "object",
                "properties": {"header": {"type": "string"}},
                "required": ["header"],
            },
        },
    }

    run = replay_chain(_MockSession(), chain, tools)
    assert run.completed
    assert len(run.tracked_fragments) > 0

    moves = _data_moved(run)
    assert len(moves) == 1
    assert moves[0][0] == 0
    assert moves[0][1] == 1

    verdict = summarize_run(run)
    assert verdict.reproduced is True
    assert verdict.callable_end_to_end is True


def test_oast_egress_correlation_with_tracked_fragments():
    run = ChainRun(
        chain=ProposedChain(
            title="oast exfil",
            steps=[ChainStep("t1", {}), ChainStep("t2", {})],
        ),
        results=[
            StepResult(tool="t1", request_args={}, response_text='{"token": "SECRET123"}', failed=False),
            StepResult(tool="t2", request_args={"url": "http://canary.test/leak"}, response_text="ok", failed=False),
        ],
        oast_token="tok_abc",
        tracked_fragments=["SECRET123"],
    )

    mock_hit = MagicMock()
    mock_hit.peer = "10.0.0.5"
    mock_hit.method = "POST"
    mock_hit.path = "/callback?leak=SECRET123"
    mock_hit.body = "data=SECRET123"

    mock_oast = MagicMock()
    mock_oast.await_hits.return_value = [mock_hit]

    verdict = summarize_run(run, mock_oast)
    assert verdict.reproduced is True
    assert verdict.egress_confirmed is True
    assert "SECRET123" in verdict.detail or "SECRET123" in verdict.evidence


def test_dynamic_llm_step_adaptation_on_unresolved_placeholder():
    class _MockSession:
        def __init__(self):
            self.calls = []

        def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
            tool = params.get("name")
            self.calls.append((tool, params.get("arguments", {})))
            if tool == "get_session_info":
                return {
                    "result": {
                        "content": [
                            {"type": "text", "text": "Unstructured text: sessionId: SESS_99887766 and user: admin"}
                        ]
                    }
                }
            elif tool == "escalate":
                return {"result": {"content": [{"type": "text", "text": "admin privileges granted"}]}}
            return None

    chain = ProposedChain(
        title="session hijack",
        steps=[
            ChainStep("get_session_info", {}),
            ChainStep("escalate", {"session_id": "{{step0.output.nonexistent_path}}"}),
        ],
    )
    tools = {
        "get_session_info": {"name": "get_session_info", "inputSchema": {"type": "object"}},
        "escalate": {
            "name": "escalate",
            "inputSchema": {
                "type": "object",
                "properties": {"session_id": {"type": "string"}},
                "required": ["session_id"],
            },
        },
    }

    mock_backend = MagicMock()
    mock_backend._call.return_value = '{"session_id": "SESS_99887766"}'

    session = _MockSession()
    run = replay_chain(session, chain, tools, backend=mock_backend, model="test-model")

    assert run.completed is True
    assert mock_backend._call.called
    assert session.calls[1][1] == {"session_id": "SESS_99887766"}


def test_dynamic_llm_step_adaptation_on_step_failure():
    class _MockSession:
        def __init__(self):
            self.calls = []

        def call(self, method: str, params: dict, timeout: float = 10.0) -> dict | None:
            tool = params.get("name")
            args = params.get("arguments", {})
            self.calls.append((tool, args))
            if tool == "get_user":
                return {
                    "result": {
                        "content": [
                            {"type": "text", "text": "id=101 name=root"}
                        ]
                    }
                }
            elif tool == "delete_user":
                if args.get("uid") == 101:
                    return {"result": {"content": [{"type": "text", "text": "deleted"}]}}
                return {"result": {"isError": True, "content": [{"type": "text", "text": "Invalid uid"}]}}
            return None

    chain = ProposedChain(
        title="delete target",
        steps=[
            ChainStep("get_user", {}),
            ChainStep("delete_user", {"uid": "invalid_initial_guess"}),
        ],
    )
    tools = {
        "get_user": {"name": "get_user", "inputSchema": {"type": "object"}},
        "delete_user": {
            "name": "delete_user",
            "inputSchema": {
                "type": "object",
                "properties": {"uid": {"type": "integer"}},
                "required": ["uid"],
            },
        },
    }

    mock_backend = MagicMock()
    mock_backend._call.return_value = '{"uid": 101}'

    session = _MockSession()
    run = replay_chain(session, chain, tools, backend=mock_backend, model="test-model")

    assert run.completed is True
    assert len(session.calls) == 3
    assert session.calls[2][1] == {"uid": 101}
