"""How an identifier splits into words.

Lives here rather than in a check module because both the pattern rules and
the checks that apply them need the same answer. Two copies drifted once
already, in `code_execution`.
"""

from __future__ import annotations

import re

# Any run of non-alphanumerics, or the zero-width seam in camelCase.
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def normalize_identifier(text: str) -> str:
    """Return *text* as space-separated words.

    `run_command` becomes `run command`, so a `\\brun\\b` pattern matches it.
    `trigger-long-running-operation` becomes `trigger long running operation`,
    where `\\brun\\b` correctly does not match `running`.
    """
    return _TOKEN_SPLIT.sub(" ", text).strip()


def identifier_tokens(text: str) -> frozenset[str]:
    """Return the distinct lowercase words in *text*.

    The set form, for callers matching against a fixed vocabulary rather than
    a regex. `check_code_execution` had a private copy of this.
    """
    return frozenset(p.lower() for p in normalize_identifier(text).split())
