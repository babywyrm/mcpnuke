"""Tests for external K8s API access."""

from __future__ import annotations

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from mcpnuke.k8s.discovery import _k8s_api, discover_services, _get_sa_token
from mcpnuke.k8s.scanner import _k8s_get, run_k8s_checks, GLOBAL_K8S_FINDINGS
from mcpnuke.cli import parse_args


class TestK8sApiParameterized:
    """_k8s_api and _k8s_get accept api_url parameter."""

    def test_discovery_k8s_api_uses_custom_url(self):
        with patch("mcpnuke.k8s.discovery.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"items": []}).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _k8s_api("/api/v1/namespaces/default/services", "tok", api_url="http://localhost:8001")

            call_args = mock_urlopen.call_args
            request_obj = call_args[0][0]
            assert request_obj.full_url.startswith("http://localhost:8001")

    def test_scanner_k8s_get_uses_custom_url(self):
        import urllib.request
        with patch.object(urllib.request, "urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"items": []}).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _k8s_get("/api/v1/pods", "tok", api_url="http://proxy:8001")

            call_args = mock_urlopen.call_args
            request_obj = call_args[0][0]
            assert "http://proxy:8001" in request_obj.full_url

    def test_default_url_when_none(self):
        with patch("mcpnuke.k8s.discovery.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("connection refused")
            _k8s_api("/api/v1/namespaces", "tok", api_url=None)
            call_args = mock_urlopen.call_args
            request_obj = call_args[0][0]
            assert "kubernetes.default" in request_obj.full_url


class TestK8sTokenNoAuth:
    """When using kubectl proxy, no Authorization header is needed."""

    def test_no_auth_header_when_empty_token(self):
        with patch("mcpnuke.k8s.discovery.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"items": []}).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            _k8s_api("/api/v1/namespaces", "", api_url="http://localhost:8001")

            call_args = mock_urlopen.call_args
            request_obj = call_args[0][0]
            assert "Authorization" not in request_obj.headers


class TestDiscoverServicesExternal:
    """discover_services accepts api_url and token params."""

    def test_external_token_used(self):
        with patch("mcpnuke.k8s.discovery._k8s_api") as mock_api:
            mock_api.return_value = {"items": []}
            discover_services(
                namespaces=["test-ns"],
                probe=False,
                api_url="http://localhost:8001",
                token="external-token",
            )
            mock_api.assert_called_with(
                "/api/v1/namespaces/test-ns/services",
                "external-token",
                api_url="http://localhost:8001",
            )

    def test_falls_back_to_sa_token(self):
        with patch("mcpnuke.k8s.discovery._get_sa_token", return_value="sa-token"), \
             patch("mcpnuke.k8s.discovery._k8s_api") as mock_api:
            mock_api.return_value = {"items": []}
            discover_services(namespaces=["default"], probe=False)
            mock_api.assert_called()
            _, kwargs = mock_api.call_args
            assert kwargs.get("api_url") is None

    def test_skips_when_no_token_no_url(self):
        with patch("mcpnuke.k8s.discovery._get_sa_token", return_value=None):
            result = discover_services(namespaces=["default"], probe=False)
            assert result == []


class TestRunK8sChecksExternal:
    """run_k8s_checks works with external api_url and token."""

    def setup_method(self):
        GLOBAL_K8S_FINDINGS.clear()

    def test_external_mode(self):
        with patch("mcpnuke.k8s.scanner._k8s_get") as mock_get:
            mock_get.return_value = {"items": []}
            run_k8s_checks("default", api_url="http://localhost:8001", token="ext-tok")
            assert mock_get.called
            call_kwargs = mock_get.call_args_list[0]
            assert call_kwargs.kwargs.get("api_url") == "http://localhost:8001"

    def test_skips_when_no_token_no_sa(self):
        with patch("os.path.exists", return_value=False):
            run_k8s_checks("default")


class TestCliK8sFlags:
    """CLI parser accepts K8s external access flags."""

    def test_k8s_api_url_flag(self):
        args = parse_args(["--targets", "http://t:9090", "--k8s-api-url", "http://localhost:8001"])
        assert args.k8s_api_url == "http://localhost:8001"

    def test_k8s_token_flag(self):
        args = parse_args(["--targets", "http://t:9090", "--k8s-token", "my-token"])
        assert args.k8s_token == "my-token"

    def test_k8s_token_file_flag(self):
        args = parse_args(["--targets", "http://t:9090", "--k8s-token-file", "/tmp/token"])
        assert args.k8s_token_file == "/tmp/token"

    def test_k8s_token_env_fallback(self):
        with patch.dict(os.environ, {"MCPNUKE_K8S_TOKEN": "env-token"}):
            args = parse_args(["--targets", "http://t:9090"])
            assert args.k8s_token == "env-token"

    def test_k8s_api_url_env_fallback(self):
        with patch.dict(os.environ, {"MCPNUKE_K8S_API_URL": "http://proxy:8001"}):
            args = parse_args(["--targets", "http://t:9090"])
            assert args.k8s_api_url == "http://proxy:8001"
