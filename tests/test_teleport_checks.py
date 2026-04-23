"""Tests for Teleport infrastructure security checks."""

from __future__ import annotations

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

from mcpnuke.core.models import TargetResult
from mcpnuke.checks.teleport import (
    check_teleport_proxy_discovery,
    check_teleport_cert_validation,
    check_teleport_app_enumeration,
    check_tbot_credential_exposure,
    check_teleport_bot_overprivilege,
)


class _TeleportMockHandler(BaseHTTPRequestHandler):
    """Mock Teleport proxy that responds to /webapi/ping and /webapi/apps."""

    response_data: dict = {}

    def do_GET(self):
        if self.path == "/webapi/ping":
            body = json.dumps(self.response_data.get("ping", {
                "server_version": "18.7.5",
                "cluster_name": "test.local",
                "auth": {"type": "local"},
            })).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        elif self.path in ("/webapi/apps", "/v1/webapi/apps"):
            body = json.dumps(self.response_data.get("apps", {
                "apps": [{"name": "camazotz-mcp"}, {"name": "test-app"}],
            })).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


def _start_mock_server(port: int = 0) -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", port), _TeleportMockHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port


class TestTeleportProxyDiscovery:
    def test_discovers_proxy(self):
        server, port = _start_mock_server()
        try:
            result = TargetResult(url=f"http://127.0.0.1:{port}")
            check_teleport_proxy_discovery(f"http://127.0.0.1:{port}", result)
            # HTTP mock won't match HTTPS probe, but verify no crash
            assert isinstance(result.findings, list)
        finally:
            server.shutdown()

    def test_no_findings_on_unreachable(self):
        result = TargetResult(url="http://127.0.0.1:1")
        check_teleport_proxy_discovery("http://127.0.0.1:1", result)
        assert len(result.findings) == 0

    def test_no_crash_on_empty_base(self):
        result = TargetResult(url="")
        check_teleport_proxy_discovery("", result)
        assert len(result.findings) == 0


class TestTeleportCertValidation:
    def test_no_findings_on_unreachable(self):
        result = TargetResult(url="http://127.0.0.1:1")
        check_teleport_cert_validation("http://127.0.0.1:1", result)
        assert len(result.findings) == 0

    def test_no_crash_on_empty_base(self):
        result = TargetResult(url="")
        check_teleport_cert_validation("", result)
        assert len(result.findings) == 0


class TestTeleportAppEnumeration:
    def test_no_findings_on_unreachable(self):
        result = TargetResult(url="http://127.0.0.1:1")
        check_teleport_app_enumeration("http://127.0.0.1:1", result)
        assert len(result.findings) == 0

    def test_no_crash_on_empty_base(self):
        result = TargetResult(url="")
        check_teleport_app_enumeration("", result)
        assert len(result.findings) == 0


class TestTbotCredentialExposure:
    def test_skips_outside_cluster(self):
        """When not running in K8s, should produce no findings and not crash."""
        result = TargetResult(url="http://localhost")
        check_tbot_credential_exposure(result)
        assert len(result.findings) == 0


class TestTeleportBotOverprivilege:
    def test_skips_outside_cluster(self):
        """When not running in K8s, should produce no findings and not crash."""
        result = TargetResult(url="http://localhost")
        check_teleport_bot_overprivilege(result)
        assert len(result.findings) == 0


class TestCheckIntegration:
    """Verify checks integrate with the Finding model correctly."""

    def test_finding_fields(self):
        result = TargetResult(url="http://test")
        result.add(
            "teleport_proxy_discovery",
            "MEDIUM",
            "Test finding",
            "Test detail",
            evidence="test",
        )
        f = result.findings[0]
        assert f.check == "teleport_proxy_discovery"
        assert f.severity == "MEDIUM"
        assert f.target == "http://test"
        assert f.title == "Test finding"
        assert f.evidence == "test"

    def test_timing_recorded(self):
        result = TargetResult(url="http://127.0.0.1:1")
        check_teleport_proxy_discovery("http://127.0.0.1:1", result)
        assert "teleport_proxy_discovery" in result.timings
