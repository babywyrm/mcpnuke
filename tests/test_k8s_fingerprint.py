"""Tests for K8s internal service fingerprinting (mcpnuke/k8s/fingerprint.py).

HTTP is mocked at ``httpx.Client`` (for _http_probe) or at ``_http_probe``
directly (for per-service and fleet-level tests). The K8s API is mocked at
``mcpnuke.k8s.scanner._k8s_get``, which fingerprint_services imports
function-locally at call time.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcpnuke.core.models import Finding
from mcpnuke.k8s.fingerprint import (
    ServiceFingerprint,
    _detect_framework,
    _fingerprint_one_service,
    _http_probe,
    fingerprint_services,
)
from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS


@pytest.fixture(autouse=True)
def _clean_global():
    GLOBAL_K8S_FINDINGS.clear()
    yield
    GLOBAL_K8S_FINDINGS.clear()


def _httpx_client(status: int = 200, headers: dict | None = None,
                  text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = text
    client = MagicMock()
    client.get.return_value = resp
    client.__enter__ = lambda s: s
    client.__exit__ = MagicMock(return_value=False)
    return client


class TestHttpProbe:
    def test_success_returns_status_headers_body(self):
        client = _httpx_client(200, {"Server": "nginx"}, "hello body")
        with patch("httpx.Client", return_value=client):
            status, headers, body = _http_probe("http://svc:8080")
        assert status == 200
        assert headers == {"Server": "nginx"}
        assert body == "hello body"

    def test_body_truncated_to_2048(self):
        client = _httpx_client(200, {}, "x" * 5000)
        with patch("httpx.Client", return_value=client):
            _, _, body = _http_probe("http://svc:8080")
        assert len(body) == 2048

    def test_connection_failure_returns_zero_tuple(self):
        client = _httpx_client()
        client.get.side_effect = Exception("connection refused")
        with patch("httpx.Client", return_value=client):
            assert _http_probe("http://dead:8080") == (0, {}, "")


class TestDetectFrameworkGaps:
    """Signatures beyond those covered in tests/test_k8s.py."""

    def test_django_header(self):
        assert _detect_framework({"X-Frame-Options": "DENY"}, "") == "Django"

    def test_django_body(self):
        assert _detect_framework({}, "powered by Django") == "Django"

    def test_aspnet_header(self):
        assert _detect_framework({"X-Powered-By": "ASP.NET"}, "") == "ASP.NET"

    def test_aspnet_version_header_alone(self):
        assert _detect_framework({"X-AspNet-Version": "4.0"}, "") == "ASP.NET"

    def test_go_net_http_content_type(self):
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        assert _detect_framework(headers, "") == "Go net/http"

    def test_nginx_server_header(self):
        assert _detect_framework({"Server": "nginx/1.25"}, "") == "Nginx"

    def test_header_key_case_insensitive(self):
        assert _detect_framework({"server": "nginx"}, "") == "Nginx"

    def test_body_match_case_insensitive(self):
        assert _detect_framework({}, "WHITELABEL ERROR PAGE") == "Spring Boot"

    def test_header_present_but_value_mismatch(self):
        assert _detect_framework({"X-Powered-By": "PHP"}, "") == ""

    def test_django_header_value_mismatch(self):
        assert _detect_framework({"X-Frame-Options": "SAMEORIGIN"}, "") == ""

    def test_first_signature_wins_on_overlap(self):
        # Spring Boot is declared before Flask/Go in _FRAMEWORK_SIGNATURES.
        headers = {"X-Application-Context": "app",
                   "Content-Type": "text/plain; charset=utf-8"}
        assert _detect_framework(headers, "") == "Spring Boot"


class TestFingerprintOneService:
    BASE = "http://web.default:8080"

    def _probe(self, exposed: dict[str, tuple[int, str]],
               base_headers: dict | None = None):
        def _probe_fn(url: str, timeout: float = 3.0):
            if url == self.BASE:
                return 200, base_headers or {}, "home page body"
            for path, (status, body) in exposed.items():
                if url.endswith(path):
                    return status, {}, body
            return 404, {}, ""
        return _probe_fn

    def test_unreachable_service_returns_empty(self):
        with patch("mcpnuke.k8s.fingerprint._http_probe",
                   return_value=(0, {}, "")):
            fp, findings = _fingerprint_one_service("web", "default", 8080, self.BASE)
        assert fp.framework == ""
        assert fp.exposed_paths == []
        assert findings == []

    def test_framework_recorded_from_base_response(self):
        probe = self._probe({}, base_headers={"Server": "nginx"})
        with patch("mcpnuke.k8s.fingerprint._http_probe", side_effect=probe):
            fp, findings = _fingerprint_one_service("web", "default", 8080, self.BASE)
        assert fp.framework == "Nginx"
        assert findings == []

    def test_actuator_env_is_high(self):
        probe = self._probe({"/actuator/env": (200, "x" * 20)})
        with patch("mcpnuke.k8s.fingerprint._http_probe", side_effect=probe):
            fp, findings = _fingerprint_one_service("web", "default", 8080, self.BASE)
        assert "/actuator/env" in fp.exposed_paths
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert "Actuator" in findings[0].title
        assert findings[0] is fp.findings[0]

    def test_actuator_health_only_is_medium(self):
        probe = self._probe({"/actuator/health": (200, "x" * 20)})
        with patch("mcpnuke.k8s.fingerprint._http_probe", side_effect=probe):
            _, findings = _fingerprint_one_service("web", "default", 8080, self.BASE)
        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"

    def test_pprof_is_medium(self):
        probe = self._probe({"/debug/pprof": (200, "x" * 20)})
        with patch("mcpnuke.k8s.fingerprint._http_probe", side_effect=probe):
            _, findings = _fingerprint_one_service("web", "default", 8080, self.BASE)
        assert any("Debug profiling" in f.title and f.severity == "MEDIUM"
                   for f in findings)

    def test_swagger_is_low(self):
        probe = self._probe({"/swagger-ui.html": (200, "x" * 20)})
        with patch("mcpnuke.k8s.fingerprint._http_probe", side_effect=probe):
            _, findings = _fingerprint_one_service("web", "default", 8080, self.BASE)
        assert any("API documentation" in f.title and f.severity == "LOW"
                   for f in findings)

    def test_short_body_not_counted_as_exposed(self):
        probe = self._probe({"/metrics": (200, "short")})
        with patch("mcpnuke.k8s.fingerprint._http_probe", side_effect=probe):
            fp, findings = _fingerprint_one_service("web", "default", 8080, self.BASE)
        assert fp.exposed_paths == []
        assert findings == []

    def test_redirect_counts_as_exposed_but_uncategorized(self):
        probe = self._probe({"/console": (302, "x" * 20)})
        with patch("mcpnuke.k8s.fingerprint._http_probe", side_effect=probe):
            fp, findings = _fingerprint_one_service("web", "default", 8080, self.BASE)
        assert fp.exposed_paths == ["/console"]
        assert findings == []


class TestFingerprintServices:
    def _svc(self, name: str, cluster_ip: str | None = "10.0.0.1",
             ports: list[dict] | None = None) -> dict:
        spec: dict = {"ports": ports if ports is not None else [{"port": 8080}]}
        if cluster_ip is not None:
            spec["clusterIP"] = cluster_ip
        return {"metadata": {"name": name}, "spec": spec}

    def test_no_services_returns_empty(self):
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=None):
            assert fingerprint_services("default", "tok") == []

    def test_headless_and_portless_services_skipped(self):
        svcs = {"items": [
            self._svc("headless", cluster_ip="None"),
            self._svc("no-ip", cluster_ip=None),
            self._svc("zero-port", ports=[{"port": 0}]),
        ]}
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=svcs), \
             patch("mcpnuke.k8s.fingerprint._fingerprint_one_service") as mock_fp:
            assert fingerprint_services("default", "tok") == []
            mock_fp.assert_not_called()

    def test_findings_flow_into_global_list(self):
        finding = Finding(target="k8s", check="service_fingerprint",
                          severity="HIGH", title="Spring Actuator exposed")
        fp = ServiceFingerprint(service_name="web", namespace="default",
                                port=8080, framework="Spring Boot")
        fp.findings.append(finding)
        svcs = {"items": [self._svc("web")]}
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=svcs), \
             patch("mcpnuke.k8s.fingerprint._fingerprint_one_service",
                   return_value=(fp, [finding])):
            results = fingerprint_services("default", "tok",
                                           fingerprint_workers=1)
        assert results == [fp]
        assert finding in GLOBAL_K8S_FINDINGS

    def test_service_with_no_signals_not_in_results(self):
        fp = ServiceFingerprint(service_name="plain", namespace="default",
                                port=8080)
        svcs = {"items": [self._svc("plain")]}
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=svcs), \
             patch("mcpnuke.k8s.fingerprint._fingerprint_one_service",
                   return_value=(fp, [])):
            assert fingerprint_services("default", "tok") == []

    def test_probe_exception_does_not_abort_fleet(self):
        good = ServiceFingerprint(service_name="good", namespace="default",
                                  port=8080, framework="Nginx")
        svcs = {"items": [self._svc("bad"), self._svc("good")]}

        def _one(name, ns, port, base_url):
            if name == "bad":
                raise RuntimeError("probe blew up")
            return good, []

        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=svcs), \
             patch("mcpnuke.k8s.fingerprint._fingerprint_one_service",
                   side_effect=_one):
            results = fingerprint_services("default", "tok",
                                           fingerprint_workers=2)
        assert results == [good]
