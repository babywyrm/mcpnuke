"""Fixture PEM markers in tests must be named in .gitleaks.toml.

Gitleaks walks history. A scanner that detects private keys needs private-key
*markers* in its tests. Those strings are not secrets; they are the corpus.
If a new test file ships one and is not named in the allowlist, `./scripts/secret-scan.sh`
fails on a clean tree — which is how this gate went red tonight.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TOML = (_ROOT / ".gitleaks.toml").read_text()
_TESTS = _ROOT / "tests"


def test_every_pem_fixture_file_is_in_the_gitleaks_allowlist() -> None:
    missing: list[str] = []
    for path in sorted(_TESTS.glob("test_*.py")):
        text = path.read_text()
        pem_begin = "-" * 5 + "BEGIN"
        if pem_begin not in text or "PRIVATE KEY" not in text:
            continue
        rel = path.relative_to(_ROOT).as_posix()
        escaped = rel.replace(".", r"\.")
        if escaped not in _TOML and rel not in _TOML:
            missing.append(rel)
    assert missing == [], (
        "gitleaks allowlist is missing fixture PEM files: "
        f"{missing}. Add them to .gitleaks.toml with a reason."
    )
