"""Tests for the inference backend probe (MCP-T54)."""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from mcpnuke.checks import inference_backend
from mcpnuke.checks.inference_backend import (
    InferenceBackend,
    _guardrail_probe_model,
    _infer_hosts_from_result,
    check_inference_backend,
    check_inference_guardrail_variance,
    fingerprint_backend,
)
from mcpnuke.core.models import TargetResult

# ── Fingerprint detection ────────────────────────────────────────────


def _mock_response(status_code: int, json_data: dict | None = None, text: str = ""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data or {}
    r.text = text or (str(json_data) if json_data else "")
    return r


class TestFingerprint:
    def test_ollama_detected(self):
        client = MagicMock()
        client.get.return_value = _mock_response(
            200, {"models": [{"name": "qwen2.5:7b"}, {"name": "llama3:8b"}]}
        )

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://gpu:11434")

        assert backend == InferenceBackend.OLLAMA
        assert meta["model_count"] == 2
        assert "qwen2.5:7b" in meta["models"]

    def test_openai_compat_detected(self):
        client = MagicMock()
        # /api/tags returns 404 (not Ollama)
        client.get.side_effect = [
            _mock_response(404),
            _mock_response(
                200, {"data": [{"id": "meta-llama/Llama-3-8b"}]}
            ),
        ]

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://vllm:8000")

        assert backend == InferenceBackend.OPENAI_COMPAT
        assert meta["model_count"] == 1

    def test_tgi_detected(self):
        client = MagicMock()
        client.get.side_effect = [
            _mock_response(404),  # not Ollama
            _mock_response(404),  # not OpenAI-compat
            _mock_response(
                200, {"model_id": "google/flan-t5-base", "version": "1.1.0"}
            ),
        ]

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://tgi:8080")

        assert backend == InferenceBackend.TGI
        assert "google/flan-t5-base" in meta["models"]
        assert meta["version"] == "1.1.0"

    def test_llama_cpp_detected(self):
        client = MagicMock()
        client.get.side_effect = [
            _mock_response(404),  # not Ollama
            _mock_response(404),  # not OpenAI-compat
            _mock_response(404),  # not TGI
            _mock_response(200, {"status": "ok"}),
        ]

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://llama:8080")

        assert backend == InferenceBackend.LLAMA_CPP
        assert meta["model_count"] == 0

    def test_unknown_when_all_fail(self):
        client = MagicMock()
        client.get.side_effect = httpx.ConnectError("unreachable")

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://nohost:9999")

        assert backend == InferenceBackend.UNKNOWN
        assert meta == {}

    def test_unknown_when_non_matching_responses(self):
        client = MagicMock()
        client.get.side_effect = [
            _mock_response(200, {"status": "healthy"}),  # not Ollama
            _mock_response(200, {"info": "nothing"}),  # not OpenAI-compat
            _mock_response(200, {"ready": True}),  # not TGI
            _mock_response(200, {"status": "ready"}),  # not llama.cpp (expects "ok")
        ]

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://mystery:1234")

        assert backend == InferenceBackend.UNKNOWN


# ── Auto-inference from MCP result context ────────────────────────────


class TestAutoInference:
    def test_detects_ollama_in_tool_description(self):
        result = TargetResult(
            url="http://mcp-server:3000/sse",
            tools=[
                {"name": "generate", "description": "Uses Ollama at localhost:11434 for inference"},
            ],
        )
        hosts = _infer_hosts_from_result(result)
        assert any("11434" in h for h in hosts)

    def test_no_hosts_when_no_hints(self):
        result = TargetResult(
            url="http://mcp-server:3000/sse",
            tools=[
                {"name": "echo", "description": "Returns input as output"},
            ],
        )
        hosts = _infer_hosts_from_result(result)
        assert hosts == []

    def test_detects_vllm_in_description(self):
        result = TargetResult(
            url="http://mcp-server:3000/sse",
            tools=[
                {"name": "chat", "description": "Delegates to vLLM at http://gpu:8000/v1/completions"},
            ],
        )
        hosts = _infer_hosts_from_result(result)
        assert "http://gpu:8000" in hosts


# ── check_inference_backend integration ───────────────────────────────


class TestCheckInferenceBackend:
    def test_no_hosts_no_findings(self):
        result = TargetResult(url="http://target:3000/sse")
        check_inference_backend(result, probe_opts={})
        assert len(result.findings) == 0

    def test_explicit_host_ollama_findings(self):
        fp_client = MagicMock()
        fp_client.get.return_value = _mock_response(
            200, {"models": [{"name": "qwen2.5:7b"}]}
        )

        gen_client = MagicMock()
        gen_resp = _mock_response(200, {"response": "OK!"})
        gen_client.post.return_value = gen_resp
        gen_client.get.return_value = _mock_response(
            200, {"models": [{"name": "qwen2.5:7b"}]}
        )

        mgmt_client = MagicMock()
        mgmt_client.post.return_value = _mock_response(400, text="missing name")
        mgmt_client.delete.return_value = _mock_response(400, text="missing name")
        mgmt_client.request.return_value = _mock_response(400, text="missing name")

        call_count = {"n": 0}
        clients = [fp_client, gen_client, mgmt_client]

        def _make_client(**kwargs):
            idx = min(call_count["n"], len(clients) - 1)
            call_count["n"] += 1
            return clients[idx]

        result = TargetResult(url="http://target:3000/sse")
        with patch("mcpnuke.checks.inference_backend.httpx.Client", side_effect=_make_client):
            check_inference_backend(
                result,
                probe_opts={"inference_host": "http://gpu:11434"},
            )

        checks_found = {f.check for f in result.findings}
        assert "inference_model_enum" in checks_found
        assert "inference_network_exposed" in checks_found
        assert all(f.taxonomy_id == "MCP-T54" for f in result.findings)

        model_finding = next(f for f in result.findings if f.check == "inference_model_enum")
        assert "qwen2.5:7b" in model_finding.title

    def test_unknown_backend_no_findings(self):
        client = MagicMock()
        client.get.side_effect = httpx.ConnectError("unreachable")

        result = TargetResult(url="http://target:3000/sse")
        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            check_inference_backend(
                result,
                probe_opts={"inference_host": "http://nohost:9999"},
            )

        assert len(result.findings) == 0

    def test_timing_recorded(self):
        client = MagicMock()
        client.get.return_value = _mock_response(
            200, {"models": [{"name": "test:latest"}]}
        )
        client.post.return_value = _mock_response(200, {"response": "ok"})
        client.delete.return_value = _mock_response(404)
        client.request.return_value = _mock_response(404)

        result = TargetResult(url="http://target:3000/sse")
        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            check_inference_backend(
                result,
                probe_opts={"inference_host": "http://gpu:11434"},
            )

        assert "inference_backend" in result.timings

    def test_inference_scan_false_no_auto_detect(self):
        result = TargetResult(
            url="http://target:3000/sse",
            tools=[
                {"name": "generate", "description": "Uses Ollama at localhost:11434"},
            ],
        )
        check_inference_backend(result, probe_opts={"inference_scan": False})
        assert len(result.findings) == 0

    def test_management_endpoint_findings(self):
        fp_client = MagicMock()
        fp_client.get.return_value = _mock_response(
            200, {"models": [{"name": "model:latest"}]}
        )

        gen_client = MagicMock()
        gen_client.post.return_value = _mock_response(404)
        gen_client.get.return_value = _mock_response(404)

        mgmt_client = MagicMock()
        mgmt_client.post.return_value = _mock_response(
            400, text="name is required"
        )
        mgmt_client.delete.return_value = _mock_response(
            400, text="name is required"
        )
        mgmt_client.request.return_value = _mock_response(
            400, text="name is required"
        )

        call_count = {"n": 0}
        clients = [fp_client, gen_client, mgmt_client]

        def _make_client(**kwargs):
            idx = min(call_count["n"], len(clients) - 1)
            call_count["n"] += 1
            return clients[idx]

        result = TargetResult(url="http://target:3000/sse")
        with patch("mcpnuke.checks.inference_backend.httpx.Client", side_effect=_make_client):
            check_inference_backend(
                result,
                probe_opts={"inference_host": "http://gpu:11434"},
            )

        mgmt_findings = [f for f in result.findings if f.check == "inference_mgmt_exposed"]
        assert len(mgmt_findings) > 0
        assert all(f.taxonomy_id == "MCP-T54" for f in mgmt_findings)


# ── CLI flag parsing ──────────────────────────────────────────────────


class TestCLIFlags:
    def test_inference_host_flag(self):
        from mcpnuke.cli import parse_args

        args = parse_args([
            "--targets", "http://example.com/sse",
            "--inference-host", "http://gpu:11434",
        ])
        assert args.inference_host == "http://gpu:11434"

    def test_inference_flag(self):
        from mcpnuke.cli import parse_args

        args = parse_args([
            "--targets", "http://example.com/sse",
            "--inference",
        ])
        assert args.inference is True

    def test_defaults_off(self):
        from mcpnuke.cli import parse_args

        args = parse_args(["--targets", "http://example.com/sse"])
        assert args.inference is False
        assert args.inference_host is None


# ── InferenceBackend enum ─────────────────────────────────────────────


class TestInferenceBackendEnum:
    def test_all_values(self):
        assert InferenceBackend.OLLAMA == "ollama"
        assert InferenceBackend.OPENAI_COMPAT == "openai_compat"
        assert InferenceBackend.TGI == "tgi"
        assert InferenceBackend.LLAMA_CPP == "llama_cpp"
        assert InferenceBackend.UNKNOWN == "unknown"

    def test_str_enum(self):
        assert f"type={InferenceBackend.OLLAMA}" == "type=ollama"

    def test_no_undefined_enum_member_is_referenced(self):
        """Guards every InferenceBackend.<NAME> reference in the module.

        Regression: the guardrail-variance check referenced InferenceBackend.VLLM,
        which was never defined — an AttributeError waiting on the first caller.
        """
        src = Path(inference_backend.__file__).read_text()
        referenced = set(re.findall(r"InferenceBackend\.([A-Z_][A-Z0-9_]*)", src))
        undefined = referenced - set(InferenceBackend.__members__)
        assert not undefined, f"undefined enum members referenced: {sorted(undefined)}"


# ── Guardrail variance (MCP-T56) ──────────────────────────────────────

# Matches _GUARDRAIL_REFUSAL_PATTERNS ("cannot provide"); the compliant
# response must match none of them.
_REFUSAL = "I cannot provide that value."
_COMPLIANT = "The SECRET_KEY is hunter2"


def _meta(host: str, backend: InferenceBackend, *models: str) -> dict:
    return {
        "host": host,
        "backend": backend,
        "model_details": dict.fromkeys(models, {}),
    }


class TestGuardrailVariance:
    def test_mixed_resistance_flags_high(self):
        result = TargetResult(url="http://test/mcp")
        metas = [_meta("vllm:8000", InferenceBackend.OPENAI_COMPAT, "llama-3-8b", "mistral-7b")]

        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
            side_effect=[_REFUSAL, _COMPLIANT],
        ):
            check_inference_guardrail_variance(result, metas)

        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == "HIGH"
        assert "varies" in f.title.lower(), f.title

    def test_all_weak_flags_medium(self):
        result = TargetResult(url="http://test/mcp")
        metas = [_meta("gpu:11434", InferenceBackend.OLLAMA, "tinyllama", "phi3")]

        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
            side_effect=[_COMPLIANT, _COMPLIANT],
        ):
            check_inference_guardrail_variance(result, metas)

        assert len(result.findings) == 1
        assert result.findings[0].severity == "MEDIUM"

    def test_all_strong_is_clean(self):
        result = TargetResult(url="http://test/mcp")
        metas = [_meta("gpu:11434", InferenceBackend.OLLAMA, "tinyllama", "phi3")]

        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
            side_effect=[_REFUSAL, _REFUSAL],
        ):
            check_inference_guardrail_variance(result, metas)

        assert result.findings == []

    def test_openai_compat_backend_is_probed(self):
        """vLLM fingerprints as OPENAI_COMPAT, so that backend must be probed."""
        result = TargetResult(url="http://test/mcp")
        metas = [_meta("vllm:8000", InferenceBackend.OPENAI_COMPAT, "a", "b")]

        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
            side_effect=[_REFUSAL, _COMPLIANT],
        ) as probe:
            check_inference_guardrail_variance(result, metas)

        assert probe.call_count == 2, "OPENAI_COMPAT backend was skipped"

    def test_unsupported_backend_is_skipped(self):
        result = TargetResult(url="http://test/mcp")
        metas = [_meta("tgi:8080", InferenceBackend.TGI, "a", "b")]

        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
        ) as probe:
            check_inference_guardrail_variance(result, metas)

        assert probe.call_count == 0
        assert result.findings == []

    def test_single_model_is_skipped(self):
        """Variance needs at least two models to compare."""
        result = TargetResult(url="http://test/mcp")
        metas = [_meta("gpu:11434", InferenceBackend.OLLAMA, "only-one")]

        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
        ) as probe:
            check_inference_guardrail_variance(result, metas)

        assert probe.call_count == 0
        assert result.findings == []


class TestGuardrailProbeModel:
    def test_openai_compat_uses_chat_completions_endpoint(self):
        """OpenAI-compatible backends expose /v1/chat/completions, not /api/chat."""
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        client.send.return_value = _mock_response(
            200, {"choices": [{"message": {"content": "hi"}}]}
        )

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            _guardrail_probe_model("vllm:8000", InferenceBackend.OPENAI_COMPAT, "llama-3-8b")

        sent = client.send.call_args[0][0]
        assert "/v1/chat/completions" in str(sent.url), sent.url

    def test_ollama_uses_api_chat_endpoint(self):
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        client.send.return_value = _mock_response(200, {"message": {"content": "hi"}})

        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            _guardrail_probe_model("gpu:11434", InferenceBackend.OLLAMA, "phi3")

        sent = client.send.call_args[0][0]
        assert "/api/chat" in str(sent.url), sent.url

    def test_unsupported_backend_returns_none(self):
        assert _guardrail_probe_model("h", InferenceBackend.TGI, "m") is None

    def _sent_url(self, host: str, backend: InferenceBackend) -> str:
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        client.send.return_value = _mock_response(200, {"message": {"content": "hi"}})
        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            _guardrail_probe_model(host, backend, "m")
        return str(client.send.call_args[0][0].url)

    def test_host_with_scheme_is_not_double_prefixed(self):
        """Regression: hosts arrive scheme-qualified, yielding http://http://host.

        fingerprint_backend and every other probe in this module treat host as a
        full URL. Only this probe prepended a scheme, so a wired-up run built an
        unusable URL and silently found nothing.
        """
        url = self._sent_url("http://gpu:11434", InferenceBackend.OLLAMA)
        assert url == "http://gpu:11434/api/chat", url

    def test_https_host_scheme_is_preserved(self):
        url = self._sent_url("https://gpu:11434", InferenceBackend.OLLAMA)
        assert url == "https://gpu:11434/api/chat", url

    def test_bare_host_still_gets_a_scheme(self):
        url = self._sent_url("gpu:11434", InferenceBackend.OLLAMA)
        assert url == "http://gpu:11434/api/chat", url

    def test_openai_compat_host_with_scheme(self):
        url = self._sent_url("http://vllm:8000", InferenceBackend.OPENAI_COMPAT)
        assert url == "http://vllm:8000/v1/chat/completions", url

    def test_trailing_slash_does_not_double(self):
        url = self._sent_url("http://gpu:11434/", InferenceBackend.OLLAMA)
        assert url == "http://gpu:11434/api/chat", url


class TestGuardrailVarianceTiming:
    def test_timing_is_recorded(self):
        """Project convention: every check records its own duration."""
        result = TargetResult(url="http://test/mcp")
        metas = [_meta("gpu:11434", InferenceBackend.OLLAMA, "a", "b")]

        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
            side_effect=[_REFUSAL, _COMPLIANT],
        ):
            check_inference_guardrail_variance(result, metas)

        assert "inference_guardrail_variance" in result.timings

    def test_timing_recorded_even_when_nothing_to_probe(self):
        result = TargetResult(url="http://test/mcp")
        check_inference_guardrail_variance(result, [])
        assert "inference_guardrail_variance" in result.timings


# ── Wiring: fingerprint metas reach the guardrail probe ──────────────


def _tags_response(*names: str) -> dict:
    return {"models": [{"name": n, "digest": f"sha256:{n}"} for n in names]}


class TestMetasOut:
    """check_inference_backend hands its fingerprints to the caller.

    The guardrail-variance probe needs the host, backend, and model list that
    check_inference_backend already discovered; re-fingerprinting would double
    the network round-trips.
    """

    def _run(self, metas_out, models=("phi3", "tinyllama")):
        result = TargetResult(url="http://test/mcp")
        with patch(
            "mcpnuke.checks.inference_backend.fingerprint_backend",
            return_value=(
                InferenceBackend.OLLAMA,
                {"models": list(models), "model_count": len(models),
                 "model_details": dict.fromkeys(models, {})},
            ),
        ):
            check_inference_backend(
                result,
                probe_opts={"inference_host": "http://gpu:11434"},
                metas_out=metas_out,
            )
        return result

    def test_meta_is_collected(self):
        metas: list[dict] = []
        self._run(metas)
        assert len(metas) == 1

    def test_meta_carries_host_and_backend(self):
        """fingerprint_backend returns neither, but the probe reads both."""
        metas: list[dict] = []
        self._run(metas)
        assert metas[0]["host"] == "http://gpu:11434"
        assert metas[0]["backend"] == InferenceBackend.OLLAMA

    def test_meta_carries_the_model_list(self):
        metas: list[dict] = []
        self._run(metas)
        assert set(metas[0]["model_details"]) == {"phi3", "tinyllama"}

    def test_metas_out_is_optional(self):
        """Callers that do not want the metas keep the old signature."""
        self._run(None)

    def test_unknown_backends_are_not_collected(self):
        metas: list[dict] = []
        result = TargetResult(url="http://test/mcp")
        with patch(
            "mcpnuke.checks.inference_backend.fingerprint_backend",
            return_value=(InferenceBackend.UNKNOWN, {}),
        ):
            check_inference_backend(
                result,
                probe_opts={"inference_host": "http://gpu:11434"},
                metas_out=metas,
            )
        assert metas == []


class TestGuardrailVarianceRealMetaShape:
    """The probe must work on the meta shape fingerprint_backend really returns.

    Regression: fingerprint_backend only builds model_details for Ollama. The
    OpenAI-compatible branch returns a flat "models" list, so a probe keyed on
    model_details alone was a permanent no-op on vLLM, LocalAI, and LiteLLM.
    """

    def test_openai_compat_meta_without_model_details_is_probed(self):
        result = TargetResult(url="http://test/mcp")
        meta = {
            "host": "vllm:8000",
            "backend": InferenceBackend.OPENAI_COMPAT,
            "models": ["llama-3-8b", "mistral-7b"],
            "model_count": 2,
        }

        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
            side_effect=[_REFUSAL, _COMPLIANT],
        ) as probe:
            check_inference_guardrail_variance(result, [meta])

        assert probe.call_count == 2, "flat models list was ignored"
        assert len(result.findings) == 1

    def test_real_openai_compat_fingerprint_shape_has_no_model_details(self):
        """Pins the upstream shape this regression depends on."""
        client = MagicMock()
        client.get.side_effect = [
            httpx.RequestError("no ollama"),
            _mock_response(200, {"data": [{"id": "a"}, {"id": "b"}]}),
        ]
        with patch("mcpnuke.checks.inference_backend.httpx.Client", return_value=client):
            backend, meta = fingerprint_backend("http://vllm:8000")

        assert backend == InferenceBackend.OPENAI_COMPAT
        assert "model_details" not in meta
        assert meta["models"] == ["a", "b"]

    def test_single_model_still_skipped_with_flat_list(self):
        result = TargetResult(url="http://test/mcp")
        meta = {
            "host": "vllm:8000",
            "backend": InferenceBackend.OPENAI_COMPAT,
            "models": ["only-one"],
        }
        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
        ) as probe:
            check_inference_guardrail_variance(result, [meta])

        assert probe.call_count == 0

    def test_model_count_is_capped(self):
        result = TargetResult(url="http://test/mcp")
        meta = {
            "host": "gpu:11434",
            "backend": InferenceBackend.OLLAMA,
            "model_details": dict.fromkeys([f"m{i}" for i in range(20)], {}),
        }
        with patch(
            "mcpnuke.checks.inference_backend._guardrail_probe_model",
            return_value=_COMPLIANT,
        ) as probe:
            check_inference_guardrail_variance(result, [meta])

        assert probe.call_count == inference_backend._GUARDRAIL_MAX_MODELS
