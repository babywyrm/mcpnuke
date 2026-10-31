"""AI backend flags are validated before any scan or network call."""

import pytest

from mcpnuke import __main__ as cli_main
from mcpnuke.__main__ import EXIT_ERROR


def _args(*flags: str):
    return cli_main.parse_args(["--targets", "http://127.0.0.1:9/mcp", *flags])


def test_claude_with_ollama_is_rejected_before_contacting_ollama(monkeypatch) -> None:
    def _no_network(*_a, **_k):
        raise AssertionError("contacted Ollama for a rejected flag combination")

    monkeypatch.setattr("httpx.get", _no_network)
    with pytest.raises(SystemExit) as exc:
        cli_main._validate_ai_backend(_args("--claude", "--ollama-analysis", "http://127.0.0.1:9"))
    assert exc.value.code == EXIT_ERROR


def test_claude_without_api_key_is_rejected(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        cli_main._validate_ai_backend(_args("--claude"))
    assert exc.value.code == EXIT_ERROR


def test_no_ai_flags_is_a_no_op() -> None:
    cli_main._validate_ai_backend(_args())
