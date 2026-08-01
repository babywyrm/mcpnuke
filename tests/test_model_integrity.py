"""Tests for model integrity verification (MCP-T55)."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from mcpnuke.checks.inference_backend import (
    InferenceBackend,
    _load_manifest,
    check_model_integrity,
    fingerprint_backend,
    save_inference_baseline,
)
from mcpnuke.core.models import TargetResult


def _mock_response(status_code: int, json_data: dict | None = None, text: str = ""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data or {}
    r.text = text or (str(json_data) if json_data else "")
    return r


SAMPLE_TAGS = {
    "models": [
        {
            "name": "qwen2.5:7b",
            "size": 4683087332,
            "digest": "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e",
            "modified_at": "2026-05-15T16:30:39Z",
            "details": {
                "family": "qwen2",
                "parameter_size": "7.6B",
                "quantization_level": "Q4_K_M",
            },
        },
        {
            "name": "llama3:8b",
            "size": 3825819519,
            "digest": "fe938a131f40e6f6d40083c9f0f430a515233eb2edaa6d72eb85c50d64f2300e",
            "modified_at": "2026-05-15T16:27:12Z",
            "details": {
                "family": "llama",
                "parameter_size": "8B",
                "quantization_level": "Q4_K_M",
            },
        },
    ]
}

SAMPLE_BASELINE = {
    "version": 1,
    "created_at": "2026-05-15T20:00:00Z",
    "hosts": {
        "http://gpu:11434": {
            "backend": "ollama",
            "models": {
                "qwen2.5:7b": {
                    "digest": "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e",
                    "size": 4683087332,
                    "modified_at": "2026-05-15T16:30:39Z",
                    "parameter_size": "7.6B",
                    "quantization_level": "Q4_K_M",
                    "family": "qwen2",
                },
                "llama3:8b": {
                    "digest": "fe938a131f40e6f6d40083c9f0f430a515233eb2edaa6d72eb85c50d64f2300e",
                    "size": 3825819519,
                    "modified_at": "2026-05-15T16:27:12Z",
                    "parameter_size": "8B",
                    "quantization_level": "Q4_K_M",
                    "family": "llama",
                },
            },
        }
    },
}


# ── Fingerprint metadata extension ────────────────────────────────────


class TestFingerprintMetadata:
    def test_ollama_returns_model_details(self):
        client = MagicMock()
        client.get.return_value = _mock_response(200, SAMPLE_TAGS)

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://gpu:11434")

        assert backend == InferenceBackend.OLLAMA
        assert "model_details" in meta
        details = meta["model_details"]
        assert "qwen2.5:7b" in details
        assert details["qwen2.5:7b"]["digest"] == "845dbda0ea48ed749caafd9e6037047aa19acfcfd82e704d7ca97d631a0b697e"
        assert details["qwen2.5:7b"]["size"] == 4683087332
        assert details["qwen2.5:7b"]["family"] == "qwen2"
        assert details["qwen2.5:7b"]["parameter_size"] == "7.6B"

    def test_openai_compat_has_no_model_details(self):
        client = MagicMock()
        client.get.side_effect = [
            _mock_response(404),
            _mock_response(200, {"data": [{"id": "gpt-4"}]}),
        ]

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://vllm:8000")

        assert backend == InferenceBackend.OPENAI_COMPAT
        assert "model_details" not in meta


# ── Baseline save/load ────────────────────────────────────────────────


class TestBaselineIO:
    def test_save_and_load_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "manifest.json")
            hosts_data = {
                "http://gpu:11434": (
                    InferenceBackend.OLLAMA,
                    {
                        "models": ["qwen2.5:7b"],
                        "model_count": 1,
                        "model_details": {
                            "qwen2.5:7b": {
                                "digest": "abc123",
                                "size": 1000,
                                "modified_at": "2026-01-01T00:00:00Z",
                                "parameter_size": "7.6B",
                                "quantization_level": "Q4_K_M",
                                "family": "qwen2",
                            }
                        },
                    },
                )
            }
            save_inference_baseline(hosts_data, path)

            manifest = _load_manifest(path)
            assert manifest["version"] == 1
            assert "http://gpu:11434" in manifest["hosts"]
            models = manifest["hosts"]["http://gpu:11434"]["models"]
            assert "qwen2.5:7b" in models
            assert models["qwen2.5:7b"]["digest"] == "abc123"

    def test_save_skips_non_ollama(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "manifest.json")
            hosts_data = {
                "http://vllm:8000": (
                    InferenceBackend.OPENAI_COMPAT,
                    {"models": ["gpt-4"], "model_count": 1},
                )
            }
            save_inference_baseline(hosts_data, path)
            manifest = _load_manifest(path)
            assert manifest["hosts"] == {}

    def test_load_missing_file(self):
        manifest = _load_manifest("/nonexistent/path.json")
        assert manifest == {}

    def test_load_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json{{{")
            f.flush()
            manifest = _load_manifest(f.name)
            assert manifest == {}


# ── Model integrity checks ───────────────────────────────────────────


class TestModelIntegrity:
    def _run_integrity(self, baseline: dict, current_tags: dict) -> TargetResult:
        """Helper: write baseline to temp file, mock fingerprint, run check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = str(Path(tmpdir) / "baseline.json")
            Path(baseline_path).write_text(json.dumps(baseline))

            client = MagicMock()
            client.get.return_value = _mock_response(200, current_tags)

            result = TargetResult(url="http://target:3000/sse")
            with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
                check_model_integrity(
                    result,
                    probe_opts={
                        "inference_host": "http://gpu:11434",
                        "inference_baseline": baseline_path,
                    },
                )
            return result

    def test_no_findings_when_matching(self):
        result = self._run_integrity(SAMPLE_BASELINE, SAMPLE_TAGS)
        assert len(result.findings) == 0

    def test_detects_tampered_model(self):
        tampered_tags = json.loads(json.dumps(SAMPLE_TAGS))
        tampered_tags["models"][0]["digest"] = "deadbeef" * 8

        result = self._run_integrity(SAMPLE_BASELINE, tampered_tags)
        tampered = [f for f in result.findings if f.check == "model_tampered"]
        assert len(tampered) == 1
        assert tampered[0].severity == "CRITICAL"
        assert "qwen2.5:7b" in tampered[0].title
        assert tampered[0].taxonomy_id == "MCP-T55"

    def test_detects_removed_model(self):
        partial_tags = {"models": [SAMPLE_TAGS["models"][0]]}

        result = self._run_integrity(SAMPLE_BASELINE, partial_tags)
        removed = [f for f in result.findings if f.check == "model_removed"]
        assert len(removed) == 1
        assert removed[0].severity == "HIGH"
        assert "llama3:8b" in removed[0].title

    def test_detects_injected_model(self):
        extra_tags = json.loads(json.dumps(SAMPLE_TAGS))
        extra_tags["models"].append({
            "name": "evil:latest",
            "size": 999999,
            "digest": "badc0de" * 9 + "bad",
            "modified_at": "2026-05-16T00:00:00Z",
            "details": {"family": "evil", "parameter_size": "666B", "quantization_level": "Q4_0"},
        })

        result = self._run_integrity(SAMPLE_BASELINE, extra_tags)
        injected = [f for f in result.findings if f.check == "model_injected"]
        assert len(injected) == 1
        assert injected[0].severity == "MEDIUM"
        assert "evil:latest" in injected[0].title

    def test_detects_size_drift(self):
        drifted_tags = json.loads(json.dumps(SAMPLE_TAGS))
        drifted_tags["models"][0]["size"] = 9999999999

        result = self._run_integrity(SAMPLE_BASELINE, drifted_tags)
        drift = [f for f in result.findings if f.check == "model_size_drift"]
        assert len(drift) == 1
        assert drift[0].severity == "HIGH"
        assert "qwen2.5:7b" in drift[0].title

    def test_no_findings_without_baseline(self):
        client = MagicMock()
        client.get.return_value = _mock_response(200, SAMPLE_TAGS)

        result = TargetResult(url="http://target:3000/sse")
        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            check_model_integrity(
                result,
                probe_opts={"inference_host": "http://gpu:11434"},
            )
        assert len(result.findings) == 0

    def test_graceful_on_missing_baseline_file(self):
        client = MagicMock()
        client.get.return_value = _mock_response(200, SAMPLE_TAGS)

        result = TargetResult(url="http://target:3000/sse")
        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            check_model_integrity(
                result,
                probe_opts={
                    "inference_host": "http://gpu:11434",
                    "inference_baseline": "/nonexistent/baseline.json",
                },
            )
        assert len(result.findings) == 0

    def test_timing_recorded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = str(Path(tmpdir) / "baseline.json")
            Path(baseline_path).write_text(json.dumps(SAMPLE_BASELINE))

            client = MagicMock()
            client.get.return_value = _mock_response(200, SAMPLE_TAGS)

            result = TargetResult(url="http://target:3000/sse")
            with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
                check_model_integrity(
                    result,
                    probe_opts={
                        "inference_host": "http://gpu:11434",
                        "inference_baseline": baseline_path,
                    },
                )
            assert "model_integrity" in result.timings

    def test_save_baseline_during_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            save_path = str(Path(tmpdir) / "new_baseline.json")

            client = MagicMock()
            client.get.return_value = _mock_response(200, SAMPLE_TAGS)

            result = TargetResult(url="http://target:3000/sse")
            with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
                check_model_integrity(
                    result,
                    probe_opts={
                        "inference_host": "http://gpu:11434",
                        "save_inference_baseline": save_path,
                    },
                )

            assert Path(save_path).is_file()
            saved = json.loads(Path(save_path).read_text())
            assert saved["version"] == 1
            assert "http://gpu:11434" in saved["hosts"]
            models = saved["hosts"]["http://gpu:11434"]["models"]
            assert "qwen2.5:7b" in models
            assert "llama3:8b" in models

    def test_unknown_backend_skipped(self):
        client = MagicMock()
        client.get.side_effect = httpx.ConnectError("unreachable")

        result = TargetResult(url="http://target:3000/sse")
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline_path = str(Path(tmpdir) / "baseline.json")
            Path(baseline_path).write_text(json.dumps(SAMPLE_BASELINE))

            with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
                check_model_integrity(
                    result,
                    probe_opts={
                        "inference_host": "http://gpu:11434",
                        "inference_baseline": baseline_path,
                    },
                )
        assert len(result.findings) == 0

    def test_multiple_findings_combined(self):
        """Tamper one model, remove another, inject a third."""
        modified_tags = {
            "models": [
                {
                    "name": "qwen2.5:7b",
                    "size": 4683087332,
                    "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "modified_at": "2026-05-16T00:00:00Z",
                    "details": {"family": "qwen2", "parameter_size": "7.6B", "quantization_level": "Q4_K_M"},
                },
                {
                    "name": "injected:1b",
                    "size": 100000,
                    "digest": "bbbb" * 16,
                    "modified_at": "2026-05-16T01:00:00Z",
                    "details": {"family": "test", "parameter_size": "1B", "quantization_level": "Q4_0"},
                },
            ]
        }

        result = self._run_integrity(SAMPLE_BASELINE, modified_tags)
        checks = {f.check for f in result.findings}
        assert "model_tampered" in checks
        assert "model_removed" in checks
        assert "model_injected" in checks
        assert len(result.findings) == 3


# ── CLI flag parsing ──────────────────────────────────────────────────


class TestCLIFlags:
    def test_inference_baseline_flag(self):
        from mcpnuke.cli import parse_args

        args = parse_args([
            "--targets", "http://example.com/sse",
            "--inference-baseline", "models.json",
        ])
        assert args.inference_baseline == "models.json"

    def test_save_inference_baseline_flag(self):
        from mcpnuke.cli import parse_args

        args = parse_args([
            "--targets", "http://example.com/sse",
            "--save-inference-baseline", "snapshot.json",
        ])
        assert args.save_inference_baseline == "snapshot.json"

    def test_defaults_none(self):
        from mcpnuke.cli import parse_args

        args = parse_args(["--targets", "http://example.com/sse"])
        assert args.inference_baseline is None
        assert args.save_inference_baseline is None
