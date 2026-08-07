"""_finding_digest must coerce non-string evidence before slicing it.

tool_shadowing stores a structured dict in Finding.evidence. Phase 3/4 used
to crash with KeyError(slice(...)) when digesting that finding for the LLM.
"""

from types import SimpleNamespace

from mcpnuke.checks.llm_analysis import _finding_digest
from mcpnuke.core.models import Finding


def test_dict_evidence_is_serialized_not_sliced():
    finding = Finding(
        target="http://t",
        check="tool_shadowing",
        severity="HIGH",
        title="Confusable tool names: 'get_user_role' vs 'get_user_roles'",
        detail="near-duplicate",
        evidence={"tools": ["get_user_role", "get_user_roles"], "name_similarity": 0.957},  # type: ignore[arg-type]
    )
    digest = _finding_digest(finding)
    assert isinstance(digest["evidence"], str)
    assert "get_user_role" in digest["evidence"]


def test_none_evidence_becomes_empty_string():
    finding = SimpleNamespace(
        check="x",
        severity="LOW",
        title="t",
        detail="d",
        evidence=None,
        taxonomy_id="",
    )
    assert _finding_digest(finding)["evidence"] == ""
