"""CI must run the mcpnuke CLI against a real in-repo target.

The reusable scan workflow used to also fire on this repo's push/PR and
default to http://localhost:8080/mcp, which is not a server in CI. tests.yml
ran pytest only. Neither is dogfood.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TESTS_YML = _ROOT / ".github" / "workflows" / "tests.yml"
_SCAN_YML = _ROOT / ".github" / "workflows" / "mcp-security-scan.yml"


def _uncommented(path: Path) -> str:
    return "\n".join(
        ln for ln in path.read_text().splitlines() if not ln.lstrip().startswith("#")
    )


def test_tests_workflow_has_a_dogfood_job() -> None:
    text = _uncommented(_TESTS_YML)
    assert "dogfood:" in text
    assert "test_cli_dogfood.py" in text


def test_reusable_scan_workflow_is_call_only() -> None:
    """Consumers pass a target. This repo must not scan a missing :8080."""
    header = _uncommented(_SCAN_YML).split("jobs:", 1)[0]
    assert "workflow_call:" in header
    assert "pull_request:" not in header
    assert "push:" not in header
