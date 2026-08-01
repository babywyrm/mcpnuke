"""Tests for the DPoP enforcement probes (MCP-T43, RFC 9449).

Known gap, deliberately not papered over here: the probes call
``session.post()``, but no session class in ``mcpnuke.core.session`` defines
``post`` — only ``call`` and ``notify``. Against a real session every probe
therefore lands in its error handler. The detection tests below drive the RFC
logic through a duck-typed stub so the logic is covered, and
``TestProbeErrorHandling`` pins the error path that real sessions hit today.
"""

import base64
import json

from unittest.mock import MagicMock

from mcpnuke.checks.dpop_enforcement import (
    _minimal_jwt,
    _probe_malformed_dpop,
    _probe_missing_htm_htu,
    _probe_no_dpop_header,
    run_dpop_enforcement_checks,
)
from mcpnuke.core.models import TargetResult

_BASE = "http://target.invalid/mcp"


def _resp(status: int):
    r = MagicMock()
    r.status_code = status
    return r


def _session(status: int = 200):
    """A duck-typed session exposing the ``post`` the probes expect."""
    s = MagicMock()
    s.post.return_value = _resp(status)
    return s


class _SessionWithoutPost:
    """Mirrors the real session classes, which have no ``post`` method."""

    def call(self, method, params=None, **kw):
        return None


# ── Probe error handling ──────────────────────────────────────────────


class TestProbeErrorHandling:
    def test_session_without_post_records_error_not_raises(self):
        """Regression: the except handlers called .append on a str field.

        Reproduces the real-world path — HTTPSession has no ``post`` — which
        raised AttributeError out of the handler meant to absorb it. In
        single-target mode that aborted the scan; under run_parallel the
        worker died and the target silently vanished from results.
        """
        result = TargetResult(url=_BASE)

        run_dpop_enforcement_checks(
            result, session=_SessionWithoutPost(), base_url=_BASE, no_invoke=False,
        )

        assert "post" in result.error, result.error
        assert result.findings == []

    def test_each_probe_records_its_own_error(self):
        session = MagicMock()
        session.post.side_effect = RuntimeError("connection refused")

        result = TargetResult(url=_BASE)
        run_dpop_enforcement_checks(
            result, session=session, base_url=_BASE, no_invoke=False,
        )

        for probe in ("dpop_no_header", "dpop_malformed", "dpop_missing_binding"):
            assert probe in result.error, f"{probe} missing from {result.error!r}"
        assert result.error.count("connection refused") == 3

    def test_error_notes_accumulate_without_clobbering(self):
        result = TargetResult(url=_BASE)
        result.note_error("earlier failure")

        session = MagicMock()
        session.post.side_effect = RuntimeError("boom")
        _probe_no_dpop_header(result, session, _BASE)

        assert "earlier failure" in result.error
        assert "boom" in result.error

    def test_error_is_still_a_flat_string(self):
        """Other code reads result.error as a str (scanner, inference_backend)."""
        result = TargetResult(url=_BASE)
        session = MagicMock()
        session.post.side_effect = RuntimeError("boom")

        run_dpop_enforcement_checks(
            result, session=session, base_url=_BASE, no_invoke=False,
        )

        assert isinstance(result.error, str)


# ── Detection logic (RFC 9449) ────────────────────────────────────────


class TestNoDpopHeaderProbe:
    def test_200_flags_not_enforced(self):
        result = TargetResult(url=_BASE)
        _probe_no_dpop_header(result, _session(200), _BASE)

        assert [f.check for f in result.findings] == ["dpop_not_enforced"]
        assert result.findings[0].severity == "HIGH"

    def test_401_is_clean(self):
        result = TargetResult(url=_BASE)
        _probe_no_dpop_header(result, _session(401), _BASE)
        assert result.findings == []

    def test_sends_no_dpop_header(self):
        session = _session(401)
        _probe_no_dpop_header(TargetResult(url=_BASE), session, _BASE)

        kwargs = session.post.call_args.kwargs
        assert "DPoP" not in (kwargs.get("headers") or {})


class TestMalformedDpopProbe:
    def test_200_flags_not_validated(self):
        result = TargetResult(url=_BASE)
        _probe_malformed_dpop(result, _session(200), _BASE)

        assert [f.check for f in result.findings] == ["dpop_header_not_validated"]
        assert result.findings[0].severity == "HIGH"

    def test_401_is_clean(self):
        result = TargetResult(url=_BASE)
        _probe_malformed_dpop(result, _session(401), _BASE)
        assert result.findings == []

    def test_sends_a_malformed_proof(self):
        session = _session(401)
        _probe_malformed_dpop(TargetResult(url=_BASE), session, _BASE)

        assert session.post.call_args.kwargs["headers"]["DPoP"] == "not.a.valid.jwt"


class TestMissingBindingProbe:
    def test_200_flags_binding_not_enforced(self):
        result = TargetResult(url=_BASE)
        _probe_missing_htm_htu(result, _session(200), _BASE)

        assert [f.check for f in result.findings] == ["dpop_binding_not_enforced"]
        assert result.findings[0].severity == "HIGH"

    def test_401_is_clean(self):
        result = TargetResult(url=_BASE)
        _probe_missing_htm_htu(result, _session(401), _BASE)
        assert result.findings == []

    def test_sends_proof_without_htm_or_htu(self):
        session = _session(401)
        _probe_missing_htm_htu(TargetResult(url=_BASE), session, _BASE)

        proof = session.post.call_args.kwargs["headers"]["DPoP"]
        payload = _decode_segment(proof.split(".")[1])
        assert "htm" not in payload
        assert "htu" not in payload


class TestRunAll:
    def test_all_three_findings_on_permissive_server(self):
        result = TargetResult(url=_BASE)
        run_dpop_enforcement_checks(
            result, session=_session(200), base_url=_BASE, no_invoke=False,
        )

        assert {f.check for f in result.findings} == {
            "dpop_not_enforced",
            "dpop_header_not_validated",
            "dpop_binding_not_enforced",
        }

    def test_compliant_server_is_clean(self):
        result = TargetResult(url=_BASE)
        run_dpop_enforcement_checks(
            result, session=_session(401), base_url=_BASE, no_invoke=False,
        )
        assert result.findings == []

    def test_timings_recorded(self):
        result = TargetResult(url=_BASE)
        run_dpop_enforcement_checks(
            result, session=_session(401), base_url=_BASE, no_invoke=False,
        )

        for probe in ("dpop_no_header", "dpop_malformed", "dpop_missing_binding"):
            assert probe in result.timings

    def test_findings_tagged_lane3_transport_a(self):
        result = TargetResult(url=_BASE)
        run_dpop_enforcement_checks(
            result, session=_session(200), base_url=_BASE, no_invoke=False,
        )

        assert all(f.lane == 3 for f in result.findings)
        assert all(f.transport == "A" for f in result.findings)


# ── Proof construction ────────────────────────────────────────────────


def _decode_segment(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


class TestMinimalJwt:
    def test_is_three_segment_jwt(self):
        assert len(_minimal_jwt().split(".")) == 3

    def test_includes_htm_and_htu_by_default(self):
        payload = _decode_segment(_minimal_jwt().split(".")[1])
        assert payload["htm"] == "POST"
        assert "htu" in payload

    def test_omits_claims_when_disabled(self):
        proof = _minimal_jwt(include_htm=False, include_htu=False)
        payload = _decode_segment(proof.split(".")[1])
        assert "htm" not in payload
        assert "htu" not in payload

    def test_header_declares_dpop_type(self):
        header = _decode_segment(_minimal_jwt().split(".")[0])
        assert header["typ"] == "dpop+jwt"
