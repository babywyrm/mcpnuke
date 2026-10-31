"""Both scan paths route the optional AI pass through one dispatcher."""

from unittest.mock import MagicMock, patch

from mcpnuke import scanner
from mcpnuke.core.models import TargetResult

_LLM = "mcpnuke.checks.llm_analysis.run_llm_analysis"
_ENSEMBLE = "mcpnuke.core.llm_ollama.run_ensemble_analysis"


def _dispatch(opts: dict) -> tuple[MagicMock, MagicMock]:
    with patch(_LLM) as llm, patch(_ENSEMBLE) as ensemble:
        scanner._run_ai_analysis(MagicMock(), TargetResult(url="http://t"), opts, lambda _m: None)
    return llm, ensemble


def test_no_backend_runs_nothing() -> None:
    llm, ensemble = _dispatch({})
    llm.assert_not_called()
    ensemble.assert_not_called()


def test_claude_uses_the_claude_model() -> None:
    llm, ensemble = _dispatch({"claude": True, "claude_model": "m1"})
    assert llm.call_args.kwargs["model"] == "m1"
    assert llm.call_args.kwargs.get("llm_backend") is None
    ensemble.assert_not_called()


def test_ollama_single_model_passes_an_ollama_backend() -> None:
    llm, _ = _dispatch({"ollama_analysis": "http://o:11434", "ollama_model": "q"})
    backend = llm.call_args.kwargs["llm_backend"]
    assert llm.call_args.kwargs["model"] == "q"
    assert type(backend).__name__ == "OllamaBackend"


def test_ollama_ensemble_splits_the_model_list() -> None:
    llm, ensemble = _dispatch({"ollama_analysis": "http://o", "ollama_ensemble": "a, b c"})
    assert ensemble.call_args.kwargs["models"] == ["a", "b", "c"]
    llm.assert_not_called()
