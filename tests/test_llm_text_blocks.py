"""Response text must survive extended-thinking content blocks.

Current-generation models may return a `thinking` block as `content[0]` and
put the answer in a later `text` block. Both call paths read `content[0].text`
unconditionally, so against `claude-sonnet-5` a live scan raised
`AttributeError: 'ThinkingBlock' object has no attribute 'text'`, the caller
swallowed it, and all three AI phases reported zero findings after 35s of
billed API work.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from mcpnuke.core import llm


class _Usage(SimpleNamespace):
    input_tokens: int = 1
    output_tokens: int = 1


def _resp(*blocks) -> SimpleNamespace:
    return SimpleNamespace(
        content=list(blocks), usage=_Usage(), stop_reason="end_turn"
    )


def _text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def _thinking_block(thought: str = "hmm") -> SimpleNamespace:
    """A ThinkingBlock has no `.text` attribute at all."""
    return SimpleNamespace(type="thinking", thinking=thought)


@pytest.fixture
def sdk(monkeypatch):
    """Route _call_claude at a fake Anthropic client; return a setter."""
    holder: dict = {}

    class _Messages:
        def create(self, **kwargs):
            holder["kwargs"] = kwargs
            return holder["resp"]

    monkeypatch.setattr(llm, "is_bedrock_enabled", lambda: False)
    monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(messages=_Messages()))

    def _set(*blocks):
        holder["resp"] = _resp(*blocks)
        return holder

    return _set


class TestSdkPath:
    def test_a_lone_text_block_still_works(self, sdk) -> None:
        sdk(_text_block("[]"))
        assert llm._call_claude("s", "u", "m", 10) == "[]"

    def test_a_leading_thinking_block_is_skipped(self, sdk) -> None:
        sdk(_thinking_block(), _text_block('[{"a": 1}]'))
        assert llm._call_claude("s", "u", "m", 10) == '[{"a": 1}]'

    def test_multiple_text_blocks_are_joined(self, sdk) -> None:
        sdk(_thinking_block(), _text_block("[1,"), _text_block("2]"))
        assert json.loads(llm._call_claude("s", "u", "m", 10)) == [1, 2]

    def test_no_text_block_returns_empty_not_a_crash(self, sdk) -> None:
        sdk(_thinking_block())
        assert llm._call_claude("s", "u", "m", 10) == ""

    def test_empty_content_returns_empty(self, sdk) -> None:
        sdk()
        assert llm._call_claude("s", "u", "m", 10) == ""

    def test_a_block_without_a_type_but_with_text_is_used(self, sdk) -> None:
        """Older SDK objects did not always carry `.type`."""
        sdk(SimpleNamespace(text="ok"))
        assert llm._call_claude("s", "u", "m", 10) == "ok"

    def test_every_non_text_kind_is_skipped(self, sdk) -> None:
        for kind in llm._NON_TEXT_BLOCKS:
            sdk(SimpleNamespace(type=kind, text="leak"), _text_block("body"))
            assert llm._call_claude("s", "u", "m", 10) == "body", kind

    def test_a_block_with_an_opaque_type_is_still_read(self, sdk) -> None:
        """Test doubles auto-generate `.type`; a real payload must not be lost
        just because the type field is not a recognizable string."""
        sdk(SimpleNamespace(type=object(), text="body"))
        assert llm._call_claude("s", "u", "m", 10) == "body"

    def test_logging_does_not_crash_on_a_thinking_block(self, sdk) -> None:
        sdk(_thinking_block(), _text_block("body"))
        lines: list[str] = []
        assert llm._call_claude("s", "u", "m", 10, log=lines.append) == "body"
        assert lines


class TestBedrockPath:
    def _invoke(self, monkeypatch, content: list) -> str:
        payload = {
            "content": content,
            "usage": {"input_tokens": 1, "output_tokens": 1},
            "stop_reason": "end_turn",
        }

        class _Client:
            def invoke_model(self, **kwargs):
                return {"body": json.dumps(payload).encode()}

        class _Session:
            def __init__(self, *a, **k):
                pass

            def client(self, *a, **k):
                return _Client()

        monkeypatch.setitem(
            __import__("sys").modules, "boto3", SimpleNamespace(Session=_Session)
        )
        return llm._call_bedrock_claude("s", "u", "m", 10)

    def test_a_lone_text_block_still_works(self, monkeypatch) -> None:
        out = self._invoke(monkeypatch, [{"type": "text", "text": "[]"}])
        assert out == "[]"

    def test_a_leading_thinking_block_is_skipped(self, monkeypatch) -> None:
        out = self._invoke(
            monkeypatch,
            [{"type": "thinking", "thinking": "hmm"}, {"type": "text", "text": "[1]"}],
        )
        assert out == "[1]"

    def test_no_text_block_returns_empty(self, monkeypatch) -> None:
        out = self._invoke(monkeypatch, [{"type": "thinking", "thinking": "hmm"}])
        assert out == ""


class TestParsingAnEmptyResponse:
    def test_empty_text_parses_to_no_findings(self) -> None:
        assert llm._parse_findings("") == []
