"""In-cluster Kubernetes API calls carry the service-account token, so
they must verify the API server against the mounted CA."""

import os
import ssl
from unittest.mock import MagicMock, patch

import certifi
import pytest

from mcpnuke.k8s import discovery, scanner


@pytest.fixture
def mounted_ca(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(discovery, "SA_CA_PATH", certifi.where())
    return certifi.where()


@pytest.fixture
def no_mounted_ca(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(discovery, "SA_CA_PATH", str(tmp_path / "absent.crt"))


def test_in_cluster_context_verifies_with_mounted_ca(mounted_ca: str) -> None:
    ctx = discovery.k8s_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_external_api_url_keeps_unverified_context(mounted_ca: str) -> None:
    ctx = discovery.k8s_ssl_context("https://k3s.lab:6443")
    assert ctx.verify_mode == ssl.CERT_NONE


def test_no_mounted_ca_falls_back_to_unverified(no_mounted_ca: None) -> None:
    assert discovery.k8s_ssl_context().verify_mode == ssl.CERT_NONE


@pytest.mark.parametrize(
    "call",
    [
        lambda: discovery._k8s_api("/api/v1/services", "tok"),
        lambda: scanner._k8s_get("/api/v1/pods", "tok"),
    ],
)
def test_token_bearing_calls_use_verified_context(mounted_ca: str, call) -> None:
    resp = MagicMock()
    resp.__enter__.return_value.read.return_value = b"{}"
    with patch("urllib.request.urlopen", return_value=resp) as opened:
        call()
    assert opened.call_args.kwargs["context"].verify_mode == ssl.CERT_REQUIRED


def test_teleport_k8s_calls_use_verified_context(
    mounted_ca: str, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from mcpnuke.checks import teleport
    from mcpnuke.core.models import TargetResult

    token = tmp_path / "token"
    token.write_text("tok")
    real_exists = os.path.exists
    monkeypatch.setattr(
        os.path, "exists",
        lambda p: True if p.endswith("serviceaccount/token") else real_exists(p),
    )
    real_open = open
    monkeypatch.setattr(
        "builtins.open",
        lambda p, *a, **k: real_open(token if str(p).endswith("serviceaccount/token") else p, *a, **k),
    )
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

    resp = MagicMock()
    resp.__enter__.return_value.read.return_value = b'{"items": []}'
    with patch("urllib.request.urlopen", return_value=resp) as opened:
        teleport.check_tbot_credential_exposure(TargetResult(url="http://t"))
        teleport.check_teleport_bot_overprivilege(TargetResult(url="http://t"))
    contexts = [c.kwargs["context"] for c in opened.call_args_list]
    assert contexts
    assert all(c.verify_mode == ssl.CERT_REQUIRED for c in contexts)
