"""One definition of what an error response is, and what it costs a finding.

The logic already existed twice — exfil_flow and chain_replay carried
byte-identical private copies — and never reached the probe checks at all.
"""

from __future__ import annotations

import subprocess

from mcpnuke.checks.base import response_is_error


class TestResponseIsError:
    def test_none_is_an_error(self):
        assert response_is_error(None) is True

    def test_jsonrpc_error_is_an_error(self):
        assert response_is_error({"error": {"code": -32602}}) is True

    def test_is_error_flag_is_an_error(self):
        assert response_is_error({"result": {"content": [], "isError": True}}) is True

    def test_plain_success_is_not(self):
        assert response_is_error({"result": {"content": [{"text": "ok"}]}}) is False

    def test_is_error_false_is_not(self):
        assert response_is_error({"result": {"content": [], "isError": False}}) is False

    def test_non_dict_result_is_not_an_error(self):
        """A bare string result is unusual but not a failure signal."""
        assert response_is_error({"result": "ok"}) is False


def test_only_one_definition_of_the_error_check():
    """Two copies drifted once. This is the same guard the tokenizer has."""
    out = (
        subprocess.run(
            ["rg", "-n", r"def response_is_error|def _is_failure", "mcpnuke/"],
            capture_output=True,
            text=True,
        )
        .stdout.strip()
        .splitlines()
    )
    assert len(out) == 1, "expected exactly one definition, found:\n" + "\n".join(out)
    assert "checks/base.py" in out[0]
