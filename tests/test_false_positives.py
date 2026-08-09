"""Measures how many findings mcpnuke produces against a server that is not vulnerable.

The number this guards is only meaningful under one rule: when a finding appears
here, the default response is to fix the check. Adding an entry to _EXPECTED is
the exception, and it has to be argued in writing. Otherwise the ceiling becomes
somewhere to park false positives.
"""

from __future__ import annotations

import pytest

from mcpnuke.checks import run_all_checks
from mcpnuke.core.enumerator import enumerate_server
from mcpnuke.core.models import TargetResult
from mcpnuke.core.session import detect_transport
from tests.reference_target import start_reference_server

# Ratchets down only, never up. See CONTRIBUTING.md.
# 2026-08-09: 13 on the first run, 4 after triage. See
# docs/false-positive-baseline.md for what the other nine were.
_FP_CEILING: int = 4

# check name -> why a finding from this check is legitimate here, not a false
# positive. Every entry needs a reason a reviewer can disagree with.
#
# The test for these two: would a competent operator, reading this about this
# server, want to know? Not "is it technically accurate" — accuracy is the
# floor, and inaccurate findings get the check fixed instead.
_EXPECTED: dict[str, str] = {
    "excessive_permissions": (
        "http.fetch really can reach the network. Inventorying capability is "
        "true and worth surfacing; the priority ranker collapses it so it "
        "cannot bury a proved finding."
    ),
    "dpop_not_enforced": (
        "The target authenticates with a plain bearer token and does not "
        "implement RFC 9449, so a stolen token is replayable. True, and a "
        "deliberate property of the fixture: DPoP is uncommon enough that "
        "requiring it here would stop the target from resembling a real "
        "server. Fires once, not three times, since the DPoP redundancy fix."
    ),
}


@pytest.fixture(scope="module")
def scanned():
    """Run the real pipeline once against the reference target."""
    server = start_reference_server()
    try:
        session = detect_transport(server.url, auth_token=server.token)
        assert session is not None, "reference target was not detected"
        result = TargetResult(url=server.url)
        # The CLI records the credential it scanned with (__main__.py) and the
        # scanner copies it onto the result (scanner.py). Checks that ask "was
        # this an anonymous session?" read it. Omitting it here would tell them
        # the scan was anonymous when it was not, and manufacture findings the
        # real CLI would never produce.
        result.auth_context["_raw_token"] = server.token
        enumerate_server(session, result)
        run_all_checks(
            session,
            result,
            [result],
            probe_opts={"safe_mode": False},
        )
        yield result
    finally:
        server.stop()


def _describe(findings) -> str:
    return "\n".join(f"  {f.severity:<8} {f.check:<32} {f.title}" for f in findings)


def test_no_unexpected_high_severity_findings(scanned):
    offenders = [
        f
        for f in scanned.findings
        if f.severity in ("CRITICAL", "HIGH") and f.check not in _EXPECTED
    ]
    assert not offenders, (
        f"{len(offenders)} unexpected high-severity finding(s) on a clean "
        f"server:\n{_describe(offenders)}\n\n"
        "Fix the check. Only add to _EXPECTED if the finding is genuinely true "
        "of this server, with a written reason."
    )


def test_total_findings_within_ceiling(scanned):
    count = len(scanned.findings)
    assert count <= _FP_CEILING, (
        f"{count} findings exceeds the ceiling of {_FP_CEILING}:\n"
        f"{_describe(scanned.findings)}"
    )
