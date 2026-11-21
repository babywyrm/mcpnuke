"""Every finding a check can emit lands in an OWASP category.

A finding with no taxonomy ID and no check-name fallback is reported as
"unmapped" by --owasp and --owasp-llm, and is invisible to --by-lane and
--taxonomy-coverage. Twenty-six checks shipped that way, some tagged at one
call site and not the next, so this walks every call site, not every check.

Only call sites with a literal check name are visible here.
"""

from __future__ import annotations

import ast
from pathlib import Path

from mcpnuke.reporting.owasp import CHECK_TO_OWASP, OWASP_MCP_TOP10

_PACKAGE: Path = Path(__file__).resolve().parent.parent / "mcpnuke"

# Scan health, not a threat: no endpoint, a rejected handshake, a truncated
# listing, a server that tolerates malformed JSON-RPC.
_NO_CATEGORY: frozenset[str] = frozenset(
    {"init", "transport", "enumeration", "protocol_robustness"}
)


def _call_sites() -> list[tuple[str, int, str, str | None, bool]]:
    """(file, line, check, severity, tagged) for each result.add-style call."""
    sites: list[tuple[str, int, str, str | None, bool]] = []
    for path in sorted(_PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name != "add" and not name.startswith("_add"):
                continue
            literals = [
                (i, a.value)
                for i, a in enumerate(node.args[:2])
                if isinstance(a, ast.Constant) and isinstance(a.value, str)
            ]
            if not literals:
                continue
            index, check = literals[0]
            if not check.replace("_", "").isalnum() or check != check.lower():
                continue
            severity_node = node.args[index + 1] if len(node.args) > index + 1 else None
            severity = (
                severity_node.value
                if isinstance(severity_node, ast.Constant) and isinstance(severity_node.value, str)
                else None
            )
            tagged = any(
                kw.arg is None
                or (
                    kw.arg == "taxonomy_id"
                    and not (isinstance(kw.value, ast.Constant) and kw.value.value == "")
                )
                for kw in node.keywords
            )
            rel = str(path.relative_to(_PACKAGE.parent))
            sites.append((rel, node.lineno, check, severity, tagged))
    return sites


def test_the_walk_sees_the_known_call_sites() -> None:
    checks = {check for _, _, check, _, _ in _call_sites()}
    assert {"tool_poisoning", "error_leakage", "init", "jwt_audience"} <= checks


def test_every_call_site_resolves_to_a_category() -> None:
    """INFO findings report a defense that held. Tagging them would make
    --taxonomy-coverage report the threat as failed."""
    orphans = [
        f"{rel}:{line} {check}"
        for rel, line, check, severity, tagged in _call_sites()
        if not tagged
        and severity != "INFO"
        and check not in CHECK_TO_OWASP
        and check not in _NO_CATEGORY
    ]
    assert orphans == []


def test_allowlists_name_real_checks() -> None:
    emitted = {check for _, _, check, _, _ in _call_sites()}
    assert emitted >= _NO_CATEGORY
    composites = {"attack_chain", "multi_vector"}
    stale = set(CHECK_TO_OWASP) - emitted - composites
    assert stale == set(), f"fallback entries for checks nothing emits: {sorted(stale)}"


def test_fallbacks_are_canonical_categories() -> None:
    assert set(CHECK_TO_OWASP.values()) <= set(OWASP_MCP_TOP10)
