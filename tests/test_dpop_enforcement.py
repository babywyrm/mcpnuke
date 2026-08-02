"""Tests for the DPoP enforcement probes (MCP-T43, RFC 9449).

The probes go through Session.post_raw() so the request carries the session's
own auth and lands on the real MCP endpoint. Both matter for the verdict: an
unauthenticated or misrouted request returns 401/404 for reasons that have
nothing to do with DPoP, which would read as "enforced" and hide the finding.
"""

import base64
import json
from unittest.mock import MagicMock

from mcpnuke.checks.dpop_enforcement import (
    _minimal_jwt,
    _probe_malformed_dpop,
    _probe_missing_htm_htu,
    _probe_no_dpop_header,
    dpop_probeable,
    run_dpop_enforcement_checks,
)
from mcpnuke.core.models import TargetResult

_URL = "http://target.invalid/mcp"
_ENDPOINT = "http://target.invalid/mcp"


def _resp(status: int):
    r = MagicMock()
    r.status_code = status
    return r


def _session(status: int = 200, post_url: str = _ENDPOINT):
    s = MagicMock()
    s.post_url = post_url
    s.post_raw.return_value = _resp(status)
    return s


class _StdioLikeSession:
    """Mirrors StdioSession: a post_url, but no post_raw and no HTTP layer."""

    post_url = "stdio://server.py"

    def call(self, method, params=None, **kw):
        return None


# ── Transport capability predicate ────────────────────────────────────


class TestDpopProbeable:
    """The single source of truth for "can this transport carry a proof?".

    Both the orchestrator's progress gate and run_dpop_enforcement_checks'
    early return read this, so a drift between them is not expressible.
    """

    def test_http_session_with_a_resolved_endpoint(self):
        assert dpop_probeable(_session()) is True

    def test_missing_post_raw(self):
        """stdio has no HTTP layer for a proof header to live in."""

        class _NoPostRaw:
            post_url = _ENDPOINT

        assert dpop_probeable(_NoPostRaw()) is False

    def test_stdio_like_session_is_excluded_by_post_raw_not_post_url(self):
        """StdioSession sets a truthy stdio:// post_url; post_raw is the discriminator."""
        stdio = _StdioLikeSession()

        assert stdio.post_url, "fixture must keep a truthy post_url to be meaningful"
        assert dpop_probeable(stdio) is False

    def test_post_url_empty_string(self):
        """SSE before the handshake: the endpoint is not resolved yet."""
        assert dpop_probeable(_session(post_url="")) is False

    def test_post_url_none(self):
        assert dpop_probeable(_session(post_url=None)) is False

    def test_post_url_missing_entirely(self):
        class _NoPostUrl:
            def post_raw(self, *a, **kw):
                raise AssertionError("not called")

        assert dpop_probeable(_NoPostUrl()) is False

    def test_none_session(self):
        assert dpop_probeable(None) is False


# ── Transport gating ──────────────────────────────────────────────────


class TestTransportGating:
    def test_non_http_transport_is_skipped(self):
        """DPoP is an HTTP header mechanism; stdio has nothing to probe."""
        result = TargetResult(url="stdio://server.py", transport="stdio")

        run_dpop_enforcement_checks(result, session=_StdioLikeSession())

        assert result.findings == []
        assert result.error == ""
        assert result.timings == {}

    def test_session_without_a_resolved_endpoint_is_skipped(self):
        """MCPSession has no post_url until the SSE handshake resolves one."""
        result = TargetResult(url=_URL)
        session = _session(200, post_url="")

        run_dpop_enforcement_checks(result, session=session)

        assert result.findings == []
        assert session.post_raw.call_count == 0


# ── Request shape ─────────────────────────────────────────────────────


class TestRequestShape:
    def test_probes_target_the_mcp_endpoint_via_post_raw(self):
        """Regression: probes used to POST to the bare scheme://host base URL.

        run_all_checks passes base as scheme://netloc with no path, so those
        requests never reached the MCP endpoint and could not return 200.
        """
        session = _session(401)
        run_dpop_enforcement_checks(TargetResult(url=_URL), session=session)

        assert session.post_raw.call_count == 3
        assert session.post.call_count == 0, "post() does not exist on real sessions"

    def test_first_probe_sends_no_dpop_header(self):
        session = _session(401)
        _probe_no_dpop_header(TargetResult(url=_URL), session)

        extra = session.post_raw.call_args.kwargs.get("extra_headers") or {}
        assert "DPoP" not in extra

    def test_second_probe_sends_a_malformed_proof(self):
        session = _session(401)
        _probe_malformed_dpop(TargetResult(url=_URL), session)

        assert session.post_raw.call_args.kwargs["extra_headers"]["DPoP"] == "not.a.valid.jwt"

    def test_third_probe_sends_a_proof_without_htm_or_htu(self):
        session = _session(401)
        _probe_missing_htm_htu(TargetResult(url=_URL), session)

        proof = session.post_raw.call_args.kwargs["extra_headers"]["DPoP"]
        payload = _decode_segment(proof.split(".")[1])
        assert "htm" not in payload
        assert "htu" not in payload

    def test_probes_send_a_valid_jsonrpc_body(self):
        session = _session(401)
        run_dpop_enforcement_checks(TargetResult(url=_URL), session=session)

        for call in session.post_raw.call_args_list:
            payload = call[0][0]
            assert payload["jsonrpc"] == "2.0"
            assert payload["method"] == "tools/list"


# ── Detection logic (RFC 9449) ────────────────────────────────────────


class TestNoDpopHeaderProbe:
    def test_200_flags_not_enforced(self):
        result = TargetResult(url=_URL)
        _probe_no_dpop_header(result, _session(200))

        assert [f.check for f in result.findings] == ["dpop_not_enforced"]
        assert result.findings[0].severity == "HIGH"

    def test_401_is_clean(self):
        result = TargetResult(url=_URL)
        _probe_no_dpop_header(result, _session(401))
        assert result.findings == []


class TestMalformedDpopProbe:
    def test_200_flags_not_validated(self):
        result = TargetResult(url=_URL)
        _probe_malformed_dpop(result, _session(200))

        assert [f.check for f in result.findings] == ["dpop_header_not_validated"]
        assert result.findings[0].severity == "HIGH"

    def test_401_is_clean(self):
        result = TargetResult(url=_URL)
        _probe_malformed_dpop(result, _session(401))
        assert result.findings == []


class TestMissingBindingProbe:
    def test_200_flags_binding_not_enforced(self):
        result = TargetResult(url=_URL)
        _probe_missing_htm_htu(result, _session(200))

        assert [f.check for f in result.findings] == ["dpop_binding_not_enforced"]
        assert result.findings[0].severity == "HIGH"

    def test_401_is_clean(self):
        result = TargetResult(url=_URL)
        _probe_missing_htm_htu(result, _session(401))
        assert result.findings == []


class TestRunAll:
    def test_all_three_findings_on_permissive_server(self):
        result = TargetResult(url=_URL)
        run_dpop_enforcement_checks(result, session=_session(200))

        assert {f.check for f in result.findings} == {
            "dpop_not_enforced",
            "dpop_header_not_validated",
            "dpop_binding_not_enforced",
        }

    def test_compliant_server_is_clean(self):
        result = TargetResult(url=_URL)
        run_dpop_enforcement_checks(result, session=_session(401))
        assert result.findings == []

    def test_timings_recorded(self):
        result = TargetResult(url=_URL)
        run_dpop_enforcement_checks(result, session=_session(401))

        for probe in ("dpop_no_header", "dpop_malformed", "dpop_missing_binding"):
            assert probe in result.timings

    def test_findings_tagged_lane3_transport_a(self):
        result = TargetResult(url=_URL)
        run_dpop_enforcement_checks(result, session=_session(200))

        assert all(f.lane == 3 for f in result.findings)
        assert all(f.transport == "A" for f in result.findings)


# ── Probe error handling ──────────────────────────────────────────────


class TestProbeErrorHandling:
    def test_transport_error_is_recorded_not_raised(self):
        """Regression: the handlers called .append() on a str field."""
        session = _session()
        session.post_raw.side_effect = RuntimeError("connection refused")

        result = TargetResult(url=_URL)
        run_dpop_enforcement_checks(result, session=session)

        assert "connection refused" in result.error
        assert result.findings == []

    def test_each_probe_records_its_own_error(self):
        session = _session()
        session.post_raw.side_effect = RuntimeError("boom")

        result = TargetResult(url=_URL)
        run_dpop_enforcement_checks(result, session=session)

        for probe in ("dpop_no_header", "dpop_malformed", "dpop_missing_binding"):
            assert probe in result.error, f"{probe} missing from {result.error!r}"

    def test_error_notes_accumulate_without_clobbering(self):
        result = TargetResult(url=_URL)
        result.note_error("earlier failure")

        session = _session()
        session.post_raw.side_effect = RuntimeError("boom")
        _probe_no_dpop_header(result, session)

        assert "earlier failure" in result.error
        assert "boom" in result.error

    def test_error_is_still_a_flat_string(self):
        session = _session()
        session.post_raw.side_effect = RuntimeError("boom")

        result = TargetResult(url=_URL)
        run_dpop_enforcement_checks(result, session=session)

        assert isinstance(result.error, str)


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
