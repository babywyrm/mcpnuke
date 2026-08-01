"""Tests for JSON-wrapped error leakage detection.

Verifies that check_error_leakage (and the helpers it uses) can detect
error information that has been json.dumps()-encoded inside MCP TextContent,
as many MCP servers do.
"""

import json
import re

from mcpnuke.checks.tool_probes import _extract_json_strings, _match_error_patterns

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _matches(text: str) -> re.Match | None:
    """Run the full detection pipeline: raw text + JSON-decoded strings."""
    candidates = [text] + _extract_json_strings(text)
    return _match_error_patterns(candidates)


# ---------------------------------------------------------------------------
# 1. JSON-wrapped tracebacks are detected
# ---------------------------------------------------------------------------

class TestJsonWrappedTracebacks:
    def test_json_encoded_traceback(self):
        raw_error = (
            'Traceback (most recent call last):\n'
            '  File "/app/main.py", line 42, in handler\n'
            '    raise ValueError("bad input")\n'
            'ValueError: bad input'
        )
        text = json.dumps({"error": raw_error})
        m = _matches(text)
        assert m is not None, "Should detect traceback inside JSON-encoded string"

    def test_json_encoded_file_path(self):
        text = json.dumps({"detail": 'Error at File "/opt/server/db.py", line 7'})
        m = _matches(text)
        assert m is not None, "Should detect File path inside JSON"

    def test_json_encoded_db_connection_string(self):
        text = json.dumps({"config": "postgres://admin:secret@db.internal:5432/app"})
        m = _matches(text)
        assert m is not None, "Should detect DB connection string inside JSON"

    def test_nested_json_traceback(self):
        inner = {"traceback": "Traceback (most recent call last):\n  File \"/app/x.py\", line 1"}
        text = json.dumps({"result": inner})
        m = _matches(text)
        assert m is not None, "Should detect traceback in nested JSON dict"

    def test_raw_traceback_still_works(self):
        text = 'Traceback (most recent call last):\n  File "/app/main.py", line 42'
        m = _matches(text)
        assert m is not None, "Raw (non-JSON) tracebacks should still be caught"


# ---------------------------------------------------------------------------
# 2. JSON error keys are detected
# ---------------------------------------------------------------------------

class TestJsonErrorKeys:
    def test_error_key_pattern(self):
        text = json.dumps({"error": "something went wrong"})
        m = _matches(text)
        assert m is not None, "JSON key 'error' with string value should match"

    def test_exception_key_pattern(self):
        text = json.dumps({"exception": "NullPointerException at com.app.Main"})
        m = _matches(text)
        assert m is not None, "JSON key 'exception' should match"

    def test_traceback_key_pattern(self):
        text = json.dumps({"traceback": "line 1\nline 2"})
        m = _matches(text)
        assert m is not None, "JSON key 'traceback' should match"

    def test_stack_trace_key_pattern(self):
        text = json.dumps({"stack_trace": "at module.func"})
        m = _matches(text)
        assert m is not None, "JSON key 'stack_trace' should match"

    def test_detail_with_error_class(self):
        text = json.dumps({"detail": "ValueError: invalid literal"})
        m = _matches(text)
        assert m is not None, "JSON 'detail' containing Error class name should match"

    def test_message_with_exception(self):
        text = json.dumps({"message": "Unhandled RuntimeException in worker"})
        m = _matches(text)
        assert m is not None, "JSON 'message' containing Exception should match"

    def test_internal_server_error(self):
        text = json.dumps({"status": "internal server error"})
        m = _matches(text)
        assert m is not None, "'internal server error' should match"

    def test_unexpected_error(self):
        text = "An unexpected error occurred while processing your request"
        m = _matches(text)
        assert m is not None, "'unexpected error' should match"


# ---------------------------------------------------------------------------
# 3. Non-error JSON responses don't false-positive
# ---------------------------------------------------------------------------

class TestNoFalsePositives:
    def test_normal_json_response(self):
        text = json.dumps({"result": "success", "data": [1, 2, 3]})
        m = _matches(text)
        assert m is None, "Normal success response should not trigger"

    def test_json_with_benign_message(self):
        text = json.dumps({"message": "Operation completed successfully"})
        m = _matches(text)
        assert m is None, "Benign message should not trigger"

    def test_json_with_safe_paths(self):
        text = json.dumps({"path": "/users/profile/settings"})
        m = _matches(text)
        assert m is None, "Non-sensitive path should not trigger"

    def test_json_with_numbers(self):
        text = json.dumps({"count": 42, "items": ["apple", "banana"]})
        m = _matches(text)
        assert m is None, "Simple data response should not trigger"

    def test_plain_text_ok(self):
        text = "Here is the weather forecast for today: sunny, 72F"
        m = _matches(text)
        assert m is None, "Plain informational text should not trigger"

    def test_json_with_word_error_in_value_not_key(self):
        text = json.dumps({"description": "This tool helps you find errors in your code"})
        m = _matches(text)
        assert m is None, "Word 'errors' in a description value should not trigger"

    def test_empty_json(self):
        text = json.dumps({})
        m = _matches(text)
        assert m is None, "Empty JSON object should not trigger"


# ---------------------------------------------------------------------------
# _extract_json_strings unit tests
# ---------------------------------------------------------------------------

class TestExtractJsonStrings:
    def test_flat_dict(self):
        text = json.dumps({"a": "hello", "b": "world"})
        strings = _extract_json_strings(text)
        assert "hello" in strings
        assert "world" in strings

    def test_nested_dict(self):
        text = json.dumps({"outer": {"inner": "deep_value"}})
        strings = _extract_json_strings(text)
        assert "deep_value" in strings

    def test_list_values(self):
        text = json.dumps({"items": ["one", "two"]})
        strings = _extract_json_strings(text)
        assert "one" in strings
        assert "two" in strings

    def test_non_json_returns_empty(self):
        assert _extract_json_strings("not json at all") == []

    def test_plain_string_json(self):
        text = json.dumps("just a string")
        strings = _extract_json_strings(text)
        assert "just a string" in strings

    def test_numeric_json_returns_empty(self):
        assert _extract_json_strings("42") == []
