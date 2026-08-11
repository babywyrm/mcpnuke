"""How quiet mcpnuke is against a clean server on stdio.

The sibling of tests/test_false_positives.py, which measures the same
hardened fixture over HTTP. This one exists because stdio was entirely
unmeasured while being the transport most users have: three checks reported
findings on every stdio server, and nothing caught it until five real
open-source servers were scanned by hand.

Runs the real entry point, ``scan_stdio_target`` — the same function
``--stdio`` uses. A harness that reassembles the pipeline measures the
harness, which is a mistake the HTTP fixture made once already.
"""

from __future__ import annotations

import shlex
import sys

import pytest

from mcpnuke.core.models import Finding
from mcpnuke.scanner import scan_stdio_target

STDIO_COMMAND = f"{shlex.quote(sys.executable)} -m tests.reference_target.stdio_server"

# Ratchets down, never up. See tests/test_false_positives.py for the rule and
# the single documented exception to it.
#
# Measured, not predicted: 2 excessive_permissions (HIGH) + ssrf_probe and
# behavioral_rate_limit (MEDIUM). dpop_not_enforced correctly stays away —
# that check already skips transports with no header layer.
_FP_CEILING: int = 4

# (check name, substring the title must contain) -> why this finding is
# legitimate here, not a false positive.
#
# Keyed on the title too, not the check alone: an allowance for one true
# finding must not become a blanket pass for everything that check might ever
# say about any server.
_EXPECTED: dict[tuple[str, str], str] = {
    ("excessive_permissions", "Dangerous capability [network]: 'http.fetch'"): (
        "http.fetch really can reach the network. Inventorying a true "
        "capability is worth surfacing, and the priority ranker collapses it "
        "so it cannot bury a proved finding. Same on the HTTP fixture."
    ),
    ("excessive_permissions", "Dangerous capability [filesystem]: 'file.read'"): (
        "file.read really does read files off disk — the same kind of true "
        "capability statement. Same on the HTTP fixture."
    ),
}


@pytest.fixture(scope="module")
def scanned():
    """Scan the stdio reference target once for the whole module."""
    return scan_stdio_target(STDIO_COMMAND, timeout=30.0)


def _matches(key: tuple[str, str], finding: Finding) -> bool:
    check, title_marker = key
    return finding.check == check and title_marker in finding.title


def _unexpected(findings: list[Finding]) -> list[Finding]:
    return [
        f
        for f in findings
        if f.severity in ("CRITICAL", "HIGH")
        and not any(_matches(key, f) for key in _EXPECTED)
    ]


def _describe(findings) -> str:
    return "\n".join(f"  {f.severity:<8} {f.check:<34} {f.title}" for f in findings)


def test_the_target_was_actually_scanned(scanned):
    """A subprocess that failed to start reports zero findings, which would
    satisfy every assertion below for entirely the wrong reason."""
    assert scanned.transport == "stdio", scanned.error
    assert scanned.tools, "no tools enumerated — did the subprocess start?"


def test_no_unexpected_high_severity_findings(scanned):
    offenders = _unexpected(scanned.findings)
    assert not offenders, (
        f"{len(offenders)} unexpected high-severity finding(s) on a clean "
        f"stdio server:\n{_describe(offenders)}\n\n"
        "Fix the check. Only add to _EXPECTED if the finding is genuinely "
        "true of this server, with a written reason."
    )


def test_total_findings_under_the_ceiling(scanned):
    count = len(scanned.findings)
    assert count <= _FP_CEILING, (
        f"{count} findings exceeds the ceiling of {_FP_CEILING}:\n"
        f"{_describe(scanned.findings)}"
    )


def test_no_auth_findings_on_a_transport_without_auth(scanned):
    """The invariant this fixture exists to establish.

    stdio is a pipe to a subprocess the scanner launched, so there is no
    credential to withhold and no second caller. Any finding phrased as
    "unauthenticated X" or "no identity" describes the transport rather than
    the server, and would be true of every stdio server ever written.

    Named checks rather than a keyword match on titles, so that a new auth
    check forces a deliberate decision here instead of silently inheriting
    a filter.
    """
    auth_shaped = {
        "auth",
        "anon_budget_exhaust",
        "pre_auth_injection",
        "native_function_identity_erasure",
    }
    offenders = [f for f in scanned.findings if f.check in auth_shaped]
    assert not offenders, (
        "auth findings on stdio, which has no auth boundary:\n"
        + _describe(offenders)
    )
