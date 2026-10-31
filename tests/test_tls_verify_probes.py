"""Base-URL probes honor --tls-verify; actuator_probe carries the bearer."""

from unittest.mock import MagicMock, patch

import httpx

from mcpnuke.checks import run_all_checks
from mcpnuke.checks.actuator_probe import _check_actuator_exploitation, check_actuator_probe
from mcpnuke.checks.transport import check_sse_security
from mcpnuke.core.models import TargetResult


def _offline_client() -> MagicMock:
    client = MagicMock()
    client.get.side_effect = httpx.ConnectError("offline")
    client.post.side_effect = httpx.ConnectError("offline")
    client.stream.side_effect = httpx.ConnectError("offline")
    return client


def _verify_flags(target: str, call) -> list[object]:
    with patch(target, return_value=_offline_client()) as cls:
        call()
    assert cls.call_args_list
    return [c.kwargs.get("verify") for c in cls.call_args_list]


def test_actuator_probe_verifies_when_asked() -> None:
    r = TargetResult(url="https://t")
    flags = _verify_flags(
        "mcpnuke.checks.actuator_probe.httpx.Client",
        lambda: check_actuator_probe("https://t", r, auth_token="tok", verify_tls=True),
    )
    assert flags == [True]


def test_actuator_exploitation_verifies_when_asked() -> None:
    r = TargetResult(url="https://t")
    flags = _verify_flags(
        "mcpnuke.checks.actuator_probe.httpx.Client",
        lambda: _check_actuator_exploitation(
            "https://t", r, {}, {"/actuator/heapdump"}, verify_tls=True
        ),
    )
    assert flags == [True]


def test_actuator_probe_default_stays_unverified() -> None:
    r = TargetResult(url="https://t")
    flags = _verify_flags(
        "mcpnuke.checks.actuator_probe.httpx.Client",
        lambda: check_actuator_probe("https://t", r),
    )
    assert flags == [False]


def test_sse_security_verifies_when_asked() -> None:
    r = TargetResult(url="https://t")
    flags = _verify_flags(
        "mcpnuke.checks.transport.httpx.Client",
        lambda: check_sse_security("https://t", "/sse", r, verify_tls=True),
    )
    assert flags[0] is True


def test_run_all_checks_passes_tls_verify_to_base_url_probes() -> None:
    r = TargetResult(url="https://t/sse")
    with (
        patch("mcpnuke.checks.check_actuator_probe") as actuator,
        patch("mcpnuke.checks.check_sse_security") as sse,
    ):
        run_all_checks(
            None, r, [r], base="https://t", sse_path="/sse",
            probe_opts={"no_invoke": True, "tls_verify": True},
        )
    assert actuator.call_args.kwargs["verify_tls"] is True
    assert sse.call_args.kwargs["verify_tls"] is True
