"""Tests for the core dataclasses in mcpnuke.core.models."""

from mcpnuke.core.models import TargetResult


class TestNoteError:
    def test_first_note_sets_error(self):
        r = TargetResult(url="http://t/mcp")
        r.note_error("probe failed")
        assert r.error == "probe failed"

    def test_second_note_appends_rather_than_clobbering(self):
        r = TargetResult(url="http://t/mcp")
        r.note_error("first")
        r.note_error("second")
        assert r.error == "first; second"

    def test_appends_after_direct_assignment(self):
        """scanner.py assigns result.error directly; notes must not discard it."""
        r = TargetResult(url="http://t/mcp")
        r.error = "connection reset"
        r.note_error("probe failed")
        assert r.error == "connection reset; probe failed"

    def test_error_stays_a_string(self):
        """Reporting and inference_backend concatenate result.error as a str."""
        r = TargetResult(url="http://t/mcp")
        for i in range(3):
            r.note_error(f"e{i}")
        assert isinstance(r.error, str)
        assert r.error == "e0; e1; e2"

    def test_default_error_is_empty(self):
        assert TargetResult(url="http://t/mcp").error == ""
