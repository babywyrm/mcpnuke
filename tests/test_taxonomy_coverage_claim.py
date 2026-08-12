"""The taxonomy coverage number in ROADMAP.md must match the code.

ROADMAP.md read 22/56 for months while the code covered 40 of 57 — wrong in
both the numerator and the denominator, frozen at the Tier 1 milestone. Nothing
caught it: the sibling repo that cites the same fact cites it independently, and
the cross-repo coherence checker gates versions and the check registry but
deliberately leaves counts like this one alone.

Counting this is easy to get wrong in three ways, so the definition is pinned
here rather than left to whoever next runs a grep:

1. `rg 'MCP-T\\d+' | sort -u | wc -l` overcounts, because ripgrep prefixes each
   match with a filename and the same ID in two modules counts twice.
2. Counting only inline `taxonomy_id="MCP-T.."` literals undercounts, because
   three modules pass a module-level constant, one of which is
   `_INTEGRITY_TAXONOMY_ID` — so a regex anchored on `_?TAXONOMY_ID` misses it.
3. Counting only `Finding.taxonomy_id` undercounts, because two checks record
   their threat as a `threat_id` key inside the evidence dict instead. See
   `test_two_checks_attribute_only_in_evidence` for why that distinction is
   worth keeping visible.

Coverage means: an ID some check attributes to a finding by either mechanism,
over the IDs defined in the `lanes.yaml` this package bundles. It says nothing
about whether an ID names the threat the check actually probes — ROADMAP.md
records where those disagree.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_LANES = _ROOT / "mcpnuke" / "data" / "taxonomy" / "lanes.yaml"
_ROADMAP = _ROOT / "ROADMAP.md"

_CLAIM_RE = re.compile(r"Taxonomy coverage \| \*\*(\d+)/(\d+) IDs \((\d+)%\)\*\*")
_CONST_RE = re.compile(r'^(\w*TAXONOMY\w*)\s*=\s*"(MCP-T\d+)"', re.M)
_LITERAL_RE = re.compile(r'taxonomy_id\s*=\s*"(MCP-T\d+)"')
_EVIDENCE_RE = re.compile(r'"threat_id":\s*"(MCP-T\d+)"')


def _defined_ids() -> set[str]:
    """Every threat_id in the bundled taxonomy, at any nesting depth."""
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            threat_id = node.get("threat_id")
            if isinstance(threat_id, str):
                found.add(threat_id)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(yaml.safe_load(_LANES.read_text()))
    return found


def _sources() -> list[str]:
    return [path.read_text() for path in (_ROOT / "mcpnuke").rglob("*.py")]


def _structural_ids() -> set[str]:
    """IDs that reach `Finding.taxonomy_id`, written inline or via a constant.

    This is the set downstream consumers can act on: lane attribution and the
    SARIF export read the field, not the evidence dict.
    """
    found: set[str] = set()
    for text in _sources():
        found.update(_LITERAL_RE.findall(text))
        for name, value in _CONST_RE.findall(text):
            if re.search(rf"taxonomy_id\s*=\s*{name}\b", text):
                found.add(value)
    return found


def _evidence_ids() -> set[str]:
    found: set[str] = set()
    for text in _sources():
        found.update(_EVIDENCE_RE.findall(text))
    return found


def _covered_ids() -> set[str]:
    return _structural_ids() | _evidence_ids()


def test_roadmap_states_the_measured_coverage():
    claim = _CLAIM_RE.search(_ROADMAP.read_text())
    assert claim is not None, "ROADMAP.md lost its taxonomy coverage row"

    covered, total, percent = (int(group) for group in claim.groups())
    measured, defined = _covered_ids(), _defined_ids()

    assert covered == len(measured), (
        f"ROADMAP.md claims {covered} covered IDs, code attributes {len(measured)}"
    )
    assert total == len(defined), (
        f"ROADMAP.md claims {total} total IDs, lanes.yaml defines {len(defined)}"
    )
    assert percent == round(100 * len(measured) / len(defined))


def test_every_attributed_id_is_defined_in_the_bundled_taxonomy():
    """An ID no taxonomy defines cannot be attributed to a lane downstream."""
    undefined = _covered_ids() - _defined_ids()
    assert not undefined, f"attributed but not in lanes.yaml: {sorted(undefined)}"


def test_constant_resolution_finds_the_ids_no_literal_carries():
    """Guards the constant-resolving branch, which has silently missed IDs before.

    `_INTEGRITY_TAXONOMY_ID = "MCP-T55"` is the only source of T55, so if the
    resolver stops matching, coverage quietly drops by one and the claim above
    is what fails — with no hint as to why. Naming the ID here gives the hint.
    """
    inline_only: set[str] = set()
    for text in _sources():
        inline_only.update(_LITERAL_RE.findall(text))

    assert "MCP-T55" not in inline_only, "T55 is inline now; this guard is moot"
    assert "MCP-T55" in _structural_ids(), "constant resolution stopped working"


def test_two_checks_attribute_only_in_evidence():
    """Pins a known gap so a third instance has to be a decision, not an accident.

    `profile` (T06) and `dpop_enforcement` (T43) put their threat ID in the
    evidence dict and never set `taxonomy_id`, so both are invisible to lane
    attribution and to the SARIF export while still counting as covered. That is
    worth fixing; what is not acceptable is it spreading unnoticed.
    """
    evidence_only = _evidence_ids() - _structural_ids()
    assert evidence_only == {"MCP-T06", "MCP-T43"}, (
        "the set of evidence-only threat IDs changed; if a check was fixed to "
        "set taxonomy_id, narrow this assertion — if a new one was added, set "
        f"taxonomy_id instead. Got: {sorted(evidence_only)}"
    )
