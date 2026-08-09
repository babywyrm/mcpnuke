"""One definition of how an identifier splits into words.

Tool names arrive as snake_case, kebab-case, or camelCase. Anchored patterns
are applied to the normalized form, because `_` is a regex word character and
`\\brun\\b` would otherwise miss `run_command` — a true positive.
"""

from __future__ import annotations

from mcpnuke.patterns.tokens import identifier_tokens, normalize_identifier


class TestNormalizeIdentifier:
    def test_snake_case(self):
        assert normalize_identifier("run_command") == "run command"

    def test_kebab_case(self):
        assert normalize_identifier("get-resource-reference") == "get resource reference"

    def test_camel_case(self):
        assert normalize_identifier("getResourceReference") == "get Resource Reference"

    def test_single_word_is_unchanged(self):
        assert normalize_identifier("nc") == "nc"

    def test_compound_word_is_not_split(self):
        """`running` is one word. Splitting it would reintroduce the bug."""
        assert normalize_identifier("trigger-long-running-operation") == (
            "trigger long running operation"
        )

    def test_empty_string(self):
        assert normalize_identifier("") == ""

    def test_leading_and_trailing_separators_are_trimmed(self):
        assert normalize_identifier("__init__") == "init"


class TestIdentifierTokens:
    def test_returns_distinct_lowercase_words(self):
        assert identifier_tokens("getUserToken") == frozenset({"get", "user", "token"})

    def test_empty_string_has_no_tokens(self):
        assert identifier_tokens("") == frozenset()
