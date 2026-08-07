"""Chain replay must honour --safe-mode, refusing dangerous steps before the call."""

from mcpnuke.core.chain_replay import ChainStep, ProposedChain, replay_chain, summarize_run


class _RecordingSession:
    """Records every tools/call so a test can assert a step never ran."""

    def __init__(self):
        self.calls: list[str] = []

    def call(self, method, params, timeout=10.0):
        self.calls.append(params["name"])
        return {"result": {"content": [{"type": "text", "text": "ok"}]}}


def _read_then_delete() -> ProposedChain:
    return ProposedChain(
        title="read then delete",
        steps=[
            ChainStep(tool="get_record", args={}),
            ChainStep(tool="delete_record", args={"id": "{{step0.output}}"}),
        ],
    )


def _tools() -> dict[str, dict]:
    return {
        "get_record": {"name": "get_record", "description": "read a record"},
        "delete_record": {"name": "delete_record", "description": "delete a record"},
    }


def test_safe_mode_refuses_dangerous_step_before_calling_it():
    session = _RecordingSession()
    run = replay_chain(session, _read_then_delete(), _tools(), safe_mode=True)
    assert "delete_record" not in session.calls
    assert run.results[-1].failed
    assert "safe-mode" in run.results[-1].reason
    assert not summarize_run(run).reproduced


def test_without_safe_mode_dangerous_step_runs():
    session = _RecordingSession()
    replay_chain(session, _read_then_delete(), _tools(), safe_mode=False)
    assert "delete_record" in session.calls


def test_safe_mode_allows_read_only_chain():
    session = _RecordingSession()
    chain = ProposedChain(
        title="read then read",
        steps=[
            ChainStep(tool="get_record", args={}),
            ChainStep(tool="list_records", args={}),
        ],
    )
    tools = {
        "get_record": {"name": "get_record", "description": "read"},
        "list_records": {"name": "list_records", "description": "list"},
    }
    run = replay_chain(session, chain, tools, safe_mode=True)
    assert session.calls == ["get_record", "list_records"]
    assert run.completed


def test_safe_mode_refuses_namespaced_dangerous_tools():
    """Camazotz-style shellwrap.exec must be refused; the dot is a separator."""
    session = _RecordingSession()
    chain = ProposedChain(
        title="read then exec",
        steps=[
            ChainStep(tool="vault.read", args={}),
            ChainStep(tool="shellwrap.exec", args={"cmd": "{{step0.output}}"}),
        ],
    )
    tools = {
        "vault.read": {"name": "vault.read", "description": "read a secret"},
        "shellwrap.exec": {"name": "shellwrap.exec", "description": "run a command"},
    }
    run = replay_chain(session, chain, tools, safe_mode=True)
    assert "shellwrap.exec" not in session.calls
    assert run.results[-1].failed
    assert "safe-mode" in run.results[-1].reason


def test_safe_mode_refuses_webhook_and_exfil_sinks():
    """Register-webhook / egress sinks must not run under --safe-mode."""
    from mcpnuke.checks.tool_probes import _is_dangerous_tool

    assert _is_dangerous_tool({"name": "shadow.register_webhook", "description": "register"})
    assert _is_dangerous_tool({"name": "egress.fetch_url", "description": "fetch a url"})
    assert _is_dangerous_tool({"name": "comms.exfil_channel", "description": "open channel"})
    assert not _is_dangerous_tool({"name": "vault.read", "description": "read a secret"})

    session = _RecordingSession()
    chain = ProposedChain(
        title="read then webhook",
        steps=[
            ChainStep(tool="vault.read", args={}),
            ChainStep(
                tool="shadow.register_webhook",
                args={"url": "{{step0.output}}"},
            ),
        ],
    )
    tools = {
        "vault.read": {"name": "vault.read", "description": "read a secret"},
        "shadow.register_webhook": {
            "name": "shadow.register_webhook",
            "description": "Register a webhook callback URL",
        },
    }
    run = replay_chain(session, chain, tools, safe_mode=True)
    assert "shadow.register_webhook" not in session.calls
    assert run.results[-1].failed
    assert "safe-mode" in run.results[-1].reason
