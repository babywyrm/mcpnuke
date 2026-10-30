"""Per-ID coverage: fail, pass, or untested for each vendored threat."""

from mcpnuke.core.models import TargetResult
from mcpnuke.core.taxonomy import threat_ids
from mcpnuke.reporting.taxonomy_coverage import (
    build_taxonomy_coverage,
    check_taxonomy_catalog,
)

_TAXONOMY: dict = {
    "threats": [
        {"threat_id": "MCP-T01", "title": "One"},
        {"threat_id": "MCP-T02", "title": "Two"},
        {"threat_id": "MCP-T03", "title": "Three"},
    ],
    "lanes": [],
}
_CATALOG: dict[str, frozenset[str]] = {
    "quiet_check": frozenset({"MCP-T01"}),
    "loud_check": frozenset({"MCP-T02"}),
}


def _result() -> TargetResult:
    result = TargetResult(url="http://example/mcp")
    result.timings["quiet_check"] = 0.01
    result.add("loud_check", "HIGH", "hit", taxonomy_id="MCP-T02")
    return result


def test_a_finding_fails_its_id_and_a_quiet_ran_check_passes() -> None:
    report = build_taxonomy_coverage([_result()], taxonomy=_TAXONOMY, catalog=_CATALOG)
    by_id = {row["threat_id"]: row for row in report["threats"]}
    assert by_id["MCP-T02"]["status"] == "fail"
    assert by_id["MCP-T02"]["findings"] == 1
    assert by_id["MCP-T01"]["status"] == "pass"
    assert by_id["MCP-T01"]["findings"] == 0


def test_an_id_whose_check_did_not_run_is_untested() -> None:
    report = build_taxonomy_coverage([_result()], taxonomy=_TAXONOMY, catalog=_CATALOG)
    by_id = {row["threat_id"]: row for row in report["threats"]}
    assert by_id["MCP-T03"]["status"] == "untested"


def test_a_finding_beats_a_ran_check() -> None:
    result = _result()
    result.timings["loud_check"] = 0.02
    report = build_taxonomy_coverage([result], taxonomy=_TAXONOMY, catalog=_CATALOG)
    by_id = {row["threat_id"]: row for row in report["threats"]}
    assert by_id["MCP-T02"]["status"] == "fail"


def test_the_catalog_attributes_a_real_check() -> None:
    catalog = check_taxonomy_catalog()
    attributed = set().union(*catalog.values())
    assert "MCP-T26" in attributed
    assert attributed <= threat_ids()
