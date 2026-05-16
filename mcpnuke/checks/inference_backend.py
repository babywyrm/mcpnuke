"""Inference backend discovery and audit (MCP-T54).

Probes for unauthenticated LLM inference backends (Ollama, vLLM,
LocalAI, llama.cpp, TGI) that are network-accessible behind or
alongside MCP servers. Checks model enumeration, unauthenticated
generation, and management endpoint exposure.

Activated via --inference or --inference-host; never runs by default.
"""

from __future__ import annotations

import re
from enum import StrEnum

import httpx

from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult

_TIMEOUT = 3.0
_GEN_TIMEOUT = 15.0

_TAXONOMY_ID = "MCP-T54"

_INFERENCE_HINT_PATTERNS = [
    re.compile(r"ollama", re.IGNORECASE),
    re.compile(r"localhost:\s*11434"),
    re.compile(r"127\.0\.0\.1:\s*11434"),
    re.compile(r"/api/generate\b"),
    re.compile(r"/v1/completions\b"),
    re.compile(r"/v1/chat/completions\b"),
    re.compile(r"\bvllm\b", re.IGNORECASE),
    re.compile(r"\blocalai\b", re.IGNORECASE),
    re.compile(r"\bllama\.cpp\b", re.IGNORECASE),
    re.compile(r"\btext-generation-inference\b", re.IGNORECASE),
]

_DEFAULT_PORTS = {
    "ollama": 11434,
    "openai_compat": 8000,
    "tgi": 8080,
    "llama_cpp": 8080,
}


class InferenceBackend(StrEnum):
    OLLAMA = "ollama"
    OPENAI_COMPAT = "openai_compat"
    TGI = "tgi"
    LLAMA_CPP = "llama_cpp"
    UNKNOWN = "unknown"


def fingerprint_backend(
    host: str, *, verify: bool = False,
) -> tuple[InferenceBackend, dict]:
    """Probe a host to identify the inference backend type.

    Returns (backend_type, metadata_dict). metadata_dict may contain
    'models', 'version', 'model_id', etc. depending on backend.
    """
    host = host.rstrip("/")
    client = httpx.Client(verify=verify, timeout=_TIMEOUT, follow_redirects=True)
    try:
        # Ollama: GET /api/tags → {"models": [...]}
        try:
            r = client.get(f"{host}/api/tags")
            if r.status_code == 200:
                data = r.json()
                if "models" in data:
                    models = [m.get("name", "") for m in data["models"]]
                    return InferenceBackend.OLLAMA, {
                        "models": models,
                        "model_count": len(models),
                    }
        except Exception:
            pass

        # OpenAI-compatible (vLLM, LocalAI, LiteLLM): GET /v1/models
        try:
            r = client.get(f"{host}/v1/models")
            if r.status_code == 200:
                data = r.json()
                if "data" in data:
                    models = [m.get("id", "") for m in data["data"]]
                    return InferenceBackend.OPENAI_COMPAT, {
                        "models": models,
                        "model_count": len(models),
                    }
        except Exception:
            pass

        # TGI: GET /info → {"model_id": ...}
        try:
            r = client.get(f"{host}/info")
            if r.status_code == 200:
                data = r.json()
                if "model_id" in data:
                    return InferenceBackend.TGI, {
                        "models": [data["model_id"]],
                        "model_count": 1,
                        "version": data.get("version", ""),
                    }
        except Exception:
            pass

        # llama.cpp: GET /health → {"status": "ok"}
        try:
            r = client.get(f"{host}/health")
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "ok":
                    return InferenceBackend.LLAMA_CPP, {
                        "models": [],
                        "model_count": 0,
                    }
        except Exception:
            pass

    finally:
        client.close()

    return InferenceBackend.UNKNOWN, {}


def _infer_hosts_from_result(result: TargetResult) -> list[str]:
    """Extract candidate inference backend URLs from MCP server metadata."""
    candidates: set[str] = set()
    searchable = ""

    for tool in result.tools:
        searchable += " " + tool.get("name", "")
        searchable += " " + tool.get("description", "")
        schema = tool.get("inputSchema", {})
        searchable += " " + str(schema)

    searchable += " " + str(result.server_info)
    searchable += " " + result.error

    for finding in result.findings:
        searchable += " " + finding.detail
        searchable += " " + finding.evidence

    for pat in _INFERENCE_HINT_PATTERNS:
        if pat.search(searchable):
            break
    else:
        return []

    port_matches = re.findall(
        r"https?://[\w.\-]+:\d+", searchable
    )
    for url in port_matches:
        candidates.add(url.rstrip("/"))

    host_from_target = re.match(r"https?://([^/:]+)", result.url)
    if host_from_target:
        target_host = host_from_target.group(1)
        for port in _DEFAULT_PORTS.values():
            candidates.add(f"http://{target_host}:{port}")
        candidates.add(f"http://localhost:11434")

    return sorted(candidates)


# Ollama management endpoints that should not be exposed
_OLLAMA_MGMT_ENDPOINTS = [
    ("POST", "/api/pull", "Model pull — download arbitrary models"),
    ("DELETE", "/api/delete", "Model delete — remove loaded models"),
    ("POST", "/api/copy", "Model copy — duplicate/rename models"),
    ("POST", "/api/create", "Model create — create custom models from Modelfile"),
    ("POST", "/api/push", "Model push — upload models to registry"),
]

# OpenAI-compat management endpoints
_OPENAI_MGMT_ENDPOINTS = [
    ("POST", "/models/apply", "LocalAI model apply — load arbitrary models"),
    ("GET", "/model/info", "LiteLLM model info — list configured models and keys"),
]


def _check_unauthenticated_generation(
    host: str,
    backend: InferenceBackend,
    result: TargetResult,
    verify: bool = False,
) -> None:
    """Attempt a benign generation request without auth."""
    client = httpx.Client(verify=verify, timeout=_GEN_TIMEOUT, follow_redirects=True)
    try:
        if backend == InferenceBackend.OLLAMA:
            r = client.post(
                f"{host}/api/generate",
                json={"model": "dummy", "prompt": "Say OK.", "stream": False},
            )
            if r.status_code == 200 and r.json().get("response"):
                result.add(
                    "inference_no_auth", "CRITICAL",
                    f"Unauthenticated inference on {backend.value} backend",
                    f"Generated text without any authentication at {host}. "
                    f"Anyone on the network can use this GPU for arbitrary inference.",
                    evidence=r.json().get("response", "")[:200],
                    taxonomy_id=_TAXONOMY_ID,
                )
                return
            # Model not found is fine — try with first available model
            try:
                tags = client.get(f"{host}/api/tags").json()
                models = tags.get("models", [])
                if models:
                    model_name = models[0].get("name", "")
                    r = client.post(
                        f"{host}/api/generate",
                        json={"model": model_name, "prompt": "Say OK.", "stream": False},
                    )
                    if r.status_code == 200 and r.json().get("response"):
                        result.add(
                            "inference_no_auth", "CRITICAL",
                            f"Unauthenticated inference on {backend.value} backend",
                            f"Generated text with model '{model_name}' at {host} "
                            f"without any authentication.",
                            evidence=r.json().get("response", "")[:200],
                            taxonomy_id=_TAXONOMY_ID,
                        )
            except Exception:
                pass

        elif backend == InferenceBackend.OPENAI_COMPAT:
            r = client.post(
                f"{host}/v1/completions",
                json={"model": "default", "prompt": "Say OK.", "max_tokens": 8},
            )
            if r.status_code == 200:
                result.add(
                    "inference_no_auth", "CRITICAL",
                    f"Unauthenticated inference on {backend.value} backend",
                    f"Completions API responded without authentication at {host}.",
                    evidence=r.text[:200],
                    taxonomy_id=_TAXONOMY_ID,
                )

        elif backend == InferenceBackend.TGI:
            r = client.post(
                f"{host}/generate",
                json={"inputs": "Say OK.", "parameters": {"max_new_tokens": 8}},
            )
            if r.status_code == 200:
                result.add(
                    "inference_no_auth", "CRITICAL",
                    f"Unauthenticated inference on {backend.value} backend",
                    f"TGI generate endpoint responded without authentication at {host}.",
                    evidence=r.text[:200],
                    taxonomy_id=_TAXONOMY_ID,
                )

        elif backend == InferenceBackend.LLAMA_CPP:
            r = client.post(
                f"{host}/completion",
                json={"prompt": "Say OK.", "n_predict": 8},
            )
            if r.status_code == 200:
                result.add(
                    "inference_no_auth", "CRITICAL",
                    f"Unauthenticated inference on {backend.value} backend",
                    f"llama.cpp completion endpoint responded without authentication at {host}.",
                    evidence=r.text[:200],
                    taxonomy_id=_TAXONOMY_ID,
                )
    except Exception:
        pass
    finally:
        client.close()


def _check_management_endpoints(
    host: str,
    backend: InferenceBackend,
    result: TargetResult,
    verify: bool = False,
) -> None:
    """Probe for exposed management/destructive endpoints."""
    endpoints = []
    if backend == InferenceBackend.OLLAMA:
        endpoints = _OLLAMA_MGMT_ENDPOINTS
    elif backend == InferenceBackend.OPENAI_COMPAT:
        endpoints = _OPENAI_MGMT_ENDPOINTS

    if not endpoints:
        return

    client = httpx.Client(verify=verify, timeout=_TIMEOUT, follow_redirects=True)
    try:
        for method, path, description in endpoints:
            url = f"{host}{path}"
            try:
                if method == "POST":
                    r = client.post(url, json={})
                elif method == "DELETE":
                    r = client.delete(url, json={"name": "nonexistent-probe-model"})
                else:
                    r = client.request(method, url)

                # A response other than connection error or 404 means the
                # endpoint exists and accepts requests (even if it returns
                # 400 for missing params — that's still exposed)
                if r.status_code not in (404, 405, 501):
                    result.add(
                        "inference_mgmt_exposed", "HIGH",
                        f"Inference management endpoint exposed: {method} {path}",
                        f"{description}. Endpoint at {url} returned HTTP {r.status_code}. "
                        f"An attacker could manipulate the model layer directly.",
                        evidence=r.text[:200],
                        taxonomy_id=_TAXONOMY_ID,
                    )
            except Exception:
                pass
    finally:
        client.close()


def check_inference_backend(
    result: TargetResult,
    probe_opts: dict | None = None,
) -> None:
    """Probe for unauthenticated inference backends (MCP-T54).

    Activated by --inference-host (explicit) or --inference (auto-detect
    from MCP server context). Never runs by default.
    """
    opts = probe_opts or {}
    explicit_host = opts.get("inference_host")
    auto_scan = opts.get("inference_scan", False)
    verify = opts.get("tls_verify", False)

    hosts_to_probe: list[str] = []
    if explicit_host:
        hosts_to_probe.append(explicit_host.rstrip("/"))
    if auto_scan:
        inferred = _infer_hosts_from_result(result)
        for h in inferred:
            if h not in hosts_to_probe:
                hosts_to_probe.append(h)

    if not hosts_to_probe:
        return

    with time_check("inference_backend", result):
        for host in hosts_to_probe:
            backend, meta = fingerprint_backend(host, verify=verify)
            if backend == InferenceBackend.UNKNOWN:
                continue

            models = meta.get("models", [])
            model_list = ", ".join(models[:10])
            if len(models) > 10:
                model_list += f" (+{len(models) - 10} more)"

            result.add(
                "inference_model_enum", "HIGH",
                f"{meta.get('model_count', 0)} model(s) enumerated on {backend.value} at {host}: {model_list}",
                f"Unauthenticated model enumeration — anyone on the network can list "
                f"available models without credentials.",
                evidence=f"backend={backend.value} host={host} models={model_list}",
                taxonomy_id=_TAXONOMY_ID,
            )

            result.add(
                "inference_network_exposed", "HIGH",
                f"Inference backend network-accessible: {host}",
                f"{backend.value} backend at {host} is reachable over the network "
                f"without authentication. Any client on the network can interact "
                f"with the inference API directly, bypassing MCP-layer controls.",
                evidence=f"backend={backend.value} host={host}",
                taxonomy_id=_TAXONOMY_ID,
            )

            _check_unauthenticated_generation(host, backend, result, verify=verify)
            _check_management_endpoints(host, backend, result, verify=verify)
