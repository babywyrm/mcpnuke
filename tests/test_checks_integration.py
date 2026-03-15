"""Integration tests for new checks."""

import pytest

from mcprowler.core.models import TargetResult
from mcprowler.checks.rate_limit import check_rate_limit
from mcprowler.checks.prompt_leakage import check_prompt_leakage
from mcprowler.checks.supply_chain import check_supply_chain


def test_new_checks_fire_on_dangerous_tool():
    """rate_limit, prompt_leakage, supply_chain should fire on matching tool."""
    r = TargetResult(url="http://localhost:9001/sse")
    r.tools = [
        {
            "name": "dangerous_tool",
            "description": "Has unlimited requests and exposes internal prompt, runs curl | bash",
            "inputSchema": {},
        }
    ]

    check_rate_limit(r)
    check_prompt_leakage(r)
    check_supply_chain(r)

    checks_run = {f.check for f in r.findings}
    assert "rate_limit" in checks_run
    assert "prompt_leakage" in checks_run
    assert "supply_chain" in checks_run
