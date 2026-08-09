"""Code execution and remote access checks."""

import re

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.rules import CODE_EXEC_PATTERNS, RAC_PATTERNS
from mcpnuke.patterns.tokens import identifier_tokens, normalize_identifier

# All findings in this module are scoped to Lane 4 / Transport "A"
# (2026-04-26 by-lane reporting spec).
_add = lane_tagged(lane=4, transport="A")

# Parameter names that mean execution wherever they appear.
_ALWAYS_EXECUTION_PARAMS: frozenset[str] = frozenset({
    "command", "cmd", "script", "exec", "eval", "expression", "shell",
})

# Names that are execution-like only when the tool says it executes something.
# On their own these are ordinary: a `query` searches, a `code` is a country or
# status code, a `payload` is request data, a `statement` is a bank statement.
_CONTEXTUAL_EXECUTION_PARAMS: frozenset[str] = frozenset({
    "query", "code", "statement", "payload",
})

_EXECUTION_CONTEXT = re.compile(
    r"\b(sql|database|db|eval|evaluate|interpret|shell|subprocess|"
    r"execute|executes|execution|compiler?)\b",
    re.IGNORECASE,
)

# Token equality rather than substring containment, so `zipcode` is not `code`
# and `executive` is not `exec`. `country_code` and `sourceCode` both yield a
# `code` token and are then gated on execution context. The splitter is shared
# with the pattern rules — see mcpnuke/patterns/tokens.py.


def check_code_execution(result: TargetResult):
    with time_check("code_execution", result):
        for tool in result.tools:
            name = tool.get("name", "")
            combined = (
                name
                + " "
                + tool.get("description", "")
                + " "
                + str(tool.get("inputSchema", {}))
            )

            for pat in CODE_EXEC_PATTERNS:
                if re.search(pat, combined, re.IGNORECASE):
                    _add(result,
                        "code_execution",
                        "CRITICAL",
                        f"Code execution indicator in tool '{name}'",
                        f"Pattern: {pat}",
                        evidence=combined[:300],
                    )
                    break

            executes = bool(_EXECUTION_CONTEXT.search(combined))
            for pname in tool.get("inputSchema", {}).get("properties", {}):
                tokens = identifier_tokens(pname)
                if tokens & _ALWAYS_EXECUTION_PARAMS or (
                    executes and tokens & _CONTEXTUAL_EXECUTION_PARAMS
                ):
                    _add(result,
                        "code_execution",
                        "HIGH",
                        f"Tool '{name}' has execution-like param: '{pname}'",
                    )


def check_remote_access(result: TargetResult):
    with time_check("remote_access", result):
        for tool in result.tools:
            name = tool.get("name", "")
            # The name is normalized so anchored patterns see word boundaries
            # across snake_case and camelCase; the description is already prose.
            combined = normalize_identifier(name) + " " + tool.get("description", "")
            for category, (pattern, severity) in RAC_PATTERNS.items():
                if re.search(pattern, combined, re.IGNORECASE):
                    _add(result,
                        "remote_access",
                        severity,
                        f"Remote access [{category}]: '{name}'",
                        tool.get("description", "")[:200],
                        evidence=f"Pattern: {pattern}",
                    )
