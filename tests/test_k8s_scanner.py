"""Tests for K8s scanner internals: Helm scan/drift, SA blast radius,
network policy, hostNetwork loopback, session token exposure, and the
GLOBAL_K8S_FINDINGS lifecycle.

No cluster: the kubernetes API is mocked at ``_k8s_get`` (reads) and
``urllib.request.urlopen`` (SelfSubjectRulesReview POSTs and pod exec),
matching the pattern in tests/test_k8s_external.py.
"""

from __future__ import annotations

import base64
import gzip
import json
from unittest.mock import MagicMock, patch

import pytest

from mcpnuke.core.models import Finding
from mcpnuke.k8s.scanner import (
    GLOBAL_K8S_FINDINGS,
    _check_configmap_leaks,
    _check_helm_version_drift,
    _check_hostnetwork_loopback,
    _check_network_policies,
    _check_pod_security,
    _check_sa_blast_radius,
    _check_session_token_exposure,
    _scan_helm,
    run_k8s_checks,
)


@pytest.fixture(autouse=True)
def _clean_global():
    GLOBAL_K8S_FINDINGS.clear()
    yield
    GLOBAL_K8S_FINDINGS.clear()


def _urlopen_payload(payload: dict) -> MagicMock:
    """Context-manager mock of urlopen returning a JSON body."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _helm_release_secret(release: str, version: int, values: dict) -> dict:
    """Build a helm.sh/release.v1 Secret: b64(b64(gzip(json)))."""
    payload = json.dumps({"chart": {"values": values}}).encode()
    b64 = base64.b64encode(base64.b64encode(gzip.compress(payload))).decode()
    return {
        "metadata": {"name": f"sh.helm.release.v1.{release}.v{version}"},
        "type": "helm.sh/release.v1",
        "data": {"release": b64},
    }


class TestScanHelm:
    def test_private_key_value_is_critical(self):
        _scan_helm("rel", {"tls": {"key": "-----BEGIN PRIVATE KEY-----\nx"}}, "")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.severity == "CRITICAL"
        assert f.check == "helm_secrets"
        assert "tls.key" in f.title

    def test_sensitive_key_name_is_high(self):
        _scan_helm("rel", {"db_password": "hunter2"}, "")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.severity == "HIGH"
        assert "db_password" in f.title

    def test_recurses_into_lists(self):
        _scan_helm("rel", {"servers": [{"api_token": "abc"}]}, "")
        assert any("servers[0].api_token" in f.title for f in GLOBAL_K8S_FINDINGS)

    def test_non_string_value_with_sensitive_name_ignored(self):
        _scan_helm("rel", {"password": 12345, "token": {"nested": True}}, "")
        assert GLOBAL_K8S_FINDINGS == []

    def test_clean_values_no_findings(self):
        _scan_helm("rel", {"app_name": "web", "replicas": 2}, "")
        assert GLOBAL_K8S_FINDINGS == []


class TestPodSecurityGaps:
    """Branches not covered by tests/test_k8s.py."""

    def test_host_pid(self):
        pod = {"metadata": {"name": "pid-pod"},
               "spec": {"hostPID": True, "containers": [{"name": "c"}]}}
        _check_pod_security(pod, "default")
        assert any("hostPID" in f.title for f in GLOBAL_K8S_FINDINGS)

    def test_run_as_root_user(self):
        pod = {"metadata": {"name": "root-pod"},
               "spec": {"containers": [{"name": "c",
                                        "securityContext": {"runAsUser": 0},
                                        "resources": {"limits": {"cpu": "1"}}}]}}
        _check_pod_security(pod, "default")
        assert any("runs as root" in f.title for f in GLOBAL_K8S_FINDINGS)

    def test_run_as_root_group(self):
        pod = {"metadata": {"name": "grp-pod"},
               "spec": {"containers": [{"name": "c",
                                        "securityContext": {"runAsGroup": 0},
                                        "resources": {"limits": {"cpu": "1"}}}]}}
        _check_pod_security(pod, "default")
        assert any("runs as root" in f.title for f in GLOBAL_K8S_FINDINGS)

    def test_init_containers_scanned(self):
        pod = {"metadata": {"name": "init-pod"},
               "spec": {
                   "containers": [{"name": "main",
                                   "resources": {"limits": {"cpu": "1"}}}],
                   "initContainers": [{"name": "setup",
                                       "securityContext": {"privileged": True}}],
               }}
        _check_pod_security(pod, "default")
        assert any("Privileged container: init-pod/setup" in f.title
                   for f in GLOBAL_K8S_FINDINGS)

    def test_serviceaccount_mount_skips_hostpath_check(self):
        """Mounts under /var/run/secrets are excluded from hostPath flagging."""
        pod = {"metadata": {"name": "sa-pod"},
               "spec": {
                   "containers": [{
                       "name": "c",
                       "resources": {"limits": {"cpu": "1"}},
                       "volumeMounts": [{
                           "name": "token",
                           "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                       }],
                   }],
                   "volumes": [{"name": "token",
                                "hostPath": {"path": "/var/run/secrets"}}],
               }}
        _check_pod_security(pod, "default")
        assert not any("hostPath" in f.title for f in GLOBAL_K8S_FINDINGS)

    def test_benign_capability_not_flagged(self):
        pod = {"metadata": {"name": "chown-pod"},
               "spec": {"containers": [{
                   "name": "c",
                   "securityContext": {"capabilities": {"add": ["CHOWN"]}},
                   "resources": {"limits": {"cpu": "1"}},
               }]}}
        _check_pod_security(pod, "default")
        assert not any("capabilities" in f.title.lower()
                       for f in GLOBAL_K8S_FINDINGS)

    def test_missing_metadata_name_defaults(self):
        pod = {"spec": {"hostNetwork": True, "containers": []}}
        _check_pod_security(pod, "default")
        assert any("Pod ? uses hostNetwork" in f.title
                   for f in GLOBAL_K8S_FINDINGS)


class TestConfigMapLeakGaps:
    def test_non_string_value_skipped(self):
        cm = {"metadata": {"name": "cm"},
              "data": {"password": {"nested": "not-a-string"}}}
        _check_configmap_leaks(cm, "default")
        assert GLOBAL_K8S_FINDINGS == []

    def test_private_key_and_sensitive_key_both_flagged(self):
        cm = {"metadata": {"name": "cm"},
              "data": {"private_key": "-----BEGIN PRIVATE KEY-----\nx"}}
        _check_configmap_leaks(cm, "default")
        sevs = {f.severity for f in GLOBAL_K8S_FINDINGS}
        assert sevs == {"CRITICAL", "MEDIUM"}

    def test_missing_metadata_name_defaults(self):
        cm = {"data": {"db_password": "x"}}
        _check_configmap_leaks(cm, "default")
        assert any("?/db_password" in f.title for f in GLOBAL_K8S_FINDINGS)


class TestSABlastRadius:
    def _get_with_sas(self, sa_names: list[str], pods: list[dict] | None = None):
        def _get(path: str, token: str, api_url: str | None = None):
            if path.endswith("/serviceaccounts"):
                return {"items": [{"metadata": {"name": n}} for n in sa_names]}
            if path.endswith("/pods"):
                return {"items": pods or []}
            return None
        return _get

    def _rules_review(self, rules: list[dict]) -> MagicMock:
        return _urlopen_payload({"status": {"resourceRules": rules}})

    def test_secret_reader_flagged_high(self):
        pods = [{"metadata": {"name": "web-1"},
                 "spec": {"serviceAccountName": "builder"}}]
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_sas(["builder"], pods)), \
             patch("urllib.request.urlopen",
                   return_value=self._rules_review(
                       [{"verbs": ["get", "list"], "resources": ["secrets"]}])):
            _check_sa_blast_radius("default", "tok")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.check == "sa_blast_radius"
        assert f.severity == "HIGH"
        assert "builder" in f.title
        assert "pods: web-1" in f.title
        assert "can read secrets" in f.detail

    def test_wildcard_rules_are_critical(self):
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_sas(["admin-sa"])), \
             patch("urllib.request.urlopen",
                   return_value=self._rules_review(
                       [{"verbs": ["*"], "resources": ["*"]}])):
            _check_sa_blast_radius("default", "tok")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.severity == "CRITICAL"
        assert "wildcard access" in f.detail

    def test_pod_exec_flagged(self):
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_sas(["exec-sa"])), \
             patch("urllib.request.urlopen",
                   return_value=self._rules_review(
                       [{"verbs": ["create"], "resources": ["pods/exec"]}])):
            _check_sa_blast_radius("default", "tok")
        assert any("can exec into pods" in f.detail
                   for f in GLOBAL_K8S_FINDINGS)

    def test_benign_rules_no_finding(self):
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_sas(["reader"])), \
             patch("urllib.request.urlopen",
                   return_value=self._rules_review(
                       [{"verbs": ["get", "list"], "resources": ["pods"]}])):
            _check_sa_blast_radius("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_empty_rules_no_finding(self):
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_sas(["empty-sa"])), \
             patch("urllib.request.urlopen",
                   return_value=self._rules_review([])):
            _check_sa_blast_radius("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_rules_review_failure_skips_sa(self):
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_sas(["broken-sa"])), \
             patch("urllib.request.urlopen", side_effect=Exception("forbidden")):
            _check_sa_blast_radius("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_unused_sa_labeled(self):
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_sas(["lonely-sa"])), \
             patch("urllib.request.urlopen",
                   return_value=self._rules_review(
                       [{"verbs": ["get"], "resources": ["secrets"]}])):
            _check_sa_blast_radius("default", "tok")
        assert any("(unused)" in f.title for f in GLOBAL_K8S_FINDINGS)

    def test_no_sa_listing_returns_early(self):
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=None):
            _check_sa_blast_radius("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []


class TestHelmVersionDrift:
    def _get_with_secrets(self, secrets: list[dict]):
        def _get(path: str, token: str, api_url: str | None = None):
            if path.endswith("/secrets"):
                return {"items": secrets}
            return None
        return _get

    def test_removed_credential_flagged_high(self):
        secrets = [
            _helm_release_secret("app", 1, {"db_password": "old-pass"}),
            _helm_release_secret("app", 2, {}),
        ]
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_secrets(secrets)):
            _check_helm_version_drift("default", "tok")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.check == "helm_version_drift"
        assert f.severity == "HIGH"
        assert "v1" in f.title and "app" in f.title
        assert "db_password" in f.title

    def test_removed_private_key_flagged_critical(self):
        secrets = [
            _helm_release_secret("app", 1, {"tls": "-----BEGIN PRIVATE KEY-----\nx"}),
            _helm_release_secret("app", 2, {}),
        ]
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_secrets(secrets)):
            _check_helm_version_drift("default", "tok")
        assert any(f.severity == "CRITICAL" and "private key" in f.title.lower()
                   for f in GLOBAL_K8S_FINDINGS)

    def test_rotated_credential_flagged_medium(self):
        secrets = [
            _helm_release_secret("app", 1, {"api_token": "old-value"}),
            _helm_release_secret("app", 2, {"api_token": "new-value"}),
        ]
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_secrets(secrets)):
            _check_helm_version_drift("default", "tok")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.severity == "MEDIUM"
        assert "Rotated credentials" in f.title
        assert "api_token" in f.detail

    def test_single_version_no_drift(self):
        secrets = [_helm_release_secret("app", 1, {"db_password": "x"})]
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_secrets(secrets)):
            _check_helm_version_drift("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_identical_versions_no_findings(self):
        secrets = [
            _helm_release_secret("app", 1, {"db_password": "same"}),
            _helm_release_secret("app", 2, {"db_password": "same"}),
        ]
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_secrets(secrets)):
            _check_helm_version_drift("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_non_helm_and_malformed_secrets_skipped(self):
        secrets = [
            {"metadata": {"name": "plain-secret"}, "type": "Opaque",
             "data": {"password": "eA=="}},
            {"metadata": {"name": "sh.helm.release.v1.badname"},
             "type": "helm.sh/release.v1", "data": {"release": "eA=="}},
            {"metadata": {"name": "sh.helm.release.v1.app.v1"},
             "type": "helm.sh/release.v1", "data": {}},
            {"metadata": {"name": "sh.helm.release.v1.app.v2"},
             "type": "helm.sh/release.v1", "data": {"release": "not-valid-b64!!"}},
        ]
        with patch("mcpnuke.k8s.scanner._k8s_get",
                   side_effect=self._get_with_secrets(secrets)):
            _check_helm_version_drift("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_no_secrets_listing_returns_early(self):
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=None):
            _check_helm_version_drift("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []


class TestNetworkPolicies:
    def test_api_failure_no_finding(self):
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=None):
            _check_network_policies("default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_no_policies_is_medium(self):
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value={"items": []}):
            _check_network_policies("default", "tok")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.check == "network_policy"
        assert f.severity == "MEDIUM"
        assert "No NetworkPolicies" in f.title

    def test_existing_policies_is_info(self):
        data = {"items": [{"metadata": {"name": "deny-all"}}]}
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value=data):
            _check_network_policies("default", "tok")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.severity == "INFO"
        assert "1 NetworkPolicy" in f.title


class TestHostNetworkLoopback:
    def test_hostnetwork_pod_flagged(self):
        pods = {"items": [{
            "metadata": {"name": "gw"},
            "spec": {"hostNetwork": True,
                     "containers": [{"name": "c",
                                     "ports": [{"containerPort": 8080}]}]},
        }]}
        _check_hostnetwork_loopback(pods, "default")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.check == "hostnetwork_loopback"
        assert f.severity == "MEDIUM"
        assert f.taxonomy_id == "MCP-T58"
        assert "8080" in f.detail

    def test_non_hostnetwork_pod_skipped(self):
        pods = {"items": [{"metadata": {"name": "normal"},
                           "spec": {"containers": []}}]}
        _check_hostnetwork_loopback(pods, "default")
        assert GLOBAL_K8S_FINDINGS == []

    def test_no_pods_data(self):
        _check_hostnetwork_loopback(None, "default")
        assert GLOBAL_K8S_FINDINGS == []


class TestSessionTokenExposure:
    def _pods(self) -> dict:
        return {"items": [{"metadata": {"name": "app-pod"},
                           "spec": {"containers": [{"name": "app"}]}}]}

    def _text_response(self, text: str) -> MagicMock:
        resp = MagicMock()
        resp.read.return_value = text.encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_session_file_flagged(self):
        hit = self._text_response("/tmp/.sessions/session_1.json\n")
        empty = self._text_response("")
        with patch("urllib.request.urlopen", side_effect=[hit, empty, empty]):
            _check_session_token_exposure(self._pods(), "default", "tok")
        assert len(GLOBAL_K8S_FINDINGS) == 1
        f = GLOBAL_K8S_FINDINGS[0]
        assert f.check == "session_token_exposure"
        assert f.severity == "HIGH"
        assert f.taxonomy_id == "MCP-T57"
        assert "session_1.json" in f.title

    def test_unrelated_filenames_not_flagged(self):
        resp = self._text_response("/tmp/metrics.json\n/tmp/config.json\n")
        with patch("urllib.request.urlopen", return_value=resp):
            _check_session_token_exposure(self._pods(), "default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_empty_output_no_finding(self):
        with patch("urllib.request.urlopen",
                   return_value=self._text_response("")):
            _check_session_token_exposure(self._pods(), "default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_exec_forbidden_breaks_silently(self):
        with patch("urllib.request.urlopen", side_effect=Exception("403")):
            _check_session_token_exposure(self._pods(), "default", "tok")
        assert GLOBAL_K8S_FINDINGS == []

    def test_no_pods_data(self):
        _check_session_token_exposure(None, "default", "tok")
        assert GLOBAL_K8S_FINDINGS == []


class TestGlobalFindingsLifecycle:
    """GLOBAL_K8S_FINDINGS is a module-level mutable list. These tests pin
    the current contract: run_k8s_checks appends and never clears; callers
    (mcpnuke/server/runner.py) must clear() between scans."""

    def test_run_k8s_checks_appends_without_clearing(self):
        sentinel = Finding(target="k8s", check="prior_run",
                           severity="LOW", title="leftover from earlier scan")
        GLOBAL_K8S_FINDINGS.append(sentinel)
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value={"items": []}):
            run_k8s_checks("default", token="tok")
        assert sentinel in GLOBAL_K8S_FINDINGS
        assert len(GLOBAL_K8S_FINDINGS) > 1

    def test_explicit_clear_resets_between_runs(self):
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value={"items": []}):
            run_k8s_checks("default", token="tok")
            first_run_count = len(GLOBAL_K8S_FINDINGS)
            assert first_run_count > 0
            GLOBAL_K8S_FINDINGS.clear()
            run_k8s_checks("default", token="tok")
            assert len(GLOBAL_K8S_FINDINGS) == first_run_count

    def test_reimport_shares_the_same_list(self):
        """k8s.fingerprint's function-local import resolves to the same
        list object, so .extend() there mutates the global."""
        from mcpnuke.k8s.scanner import GLOBAL_K8S_FINDINGS as reimported
        assert reimported is GLOBAL_K8S_FINDINGS


class TestRunK8sChecks:
    def test_rbac_findings_for_readable_resources(self):
        with patch("mcpnuke.k8s.scanner._k8s_get", return_value={"items": []}):
            run_k8s_checks("default", token="tok")
        rbac = [f for f in GLOBAL_K8S_FINDINGS if f.check == "rbac"]
        by_sev = {f.title.split()[3]: f.severity for f in rbac}
        assert by_sev.get("secrets") == "HIGH"
        assert by_sev.get("configmaps") == "INFO"
        assert by_sev.get("pods") == "INFO"

    def test_helm_secret_scanned_end_to_end(self):
        helm_secret = _helm_release_secret(
            "app", 1, {"tls_key": "-----BEGIN PRIVATE KEY-----\nx"})

        def _get(path: str, token: str, api_url: str | None = None):
            if path.endswith("/secrets"):
                return {"items": [helm_secret]}
            return {"items": []}

        with patch("mcpnuke.k8s.scanner._k8s_get", side_effect=_get):
            run_k8s_checks("default", token="tok")
        assert any(f.check == "helm_secrets" and f.severity == "CRITICAL"
                   for f in GLOBAL_K8S_FINDINGS)

    def test_skips_without_token_or_api_url(self):
        with patch("os.path.exists", return_value=False):
            run_k8s_checks("default")
        assert GLOBAL_K8S_FINDINGS == []
