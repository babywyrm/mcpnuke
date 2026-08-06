"""A namespaced tool loses its verb before it is ever classified.

`_classify_tool` decides source and sink by splitting the tool name on
`[_\\-\\s]+` and intersecting the parts with keyword sets. A dot is not in that
class, so `vault.read_secret` splits to {'vault.read', 'secret'} and `read`
never appears — the tool is not a source, and no exfiltration path involving it
is reported.

Namespacing is the norm, not an edge case: all 139 tools on the Camazotz target
carry a dot. Sinks sometimes survived by accident, where the trailing segment
happened to be a keyword on its own (`notify.send_message` matched on
`message`), which is why the gap was not obvious from the output.
"""

from __future__ import annotations

from mcpnuke.checks.exfil_flow import _classify_tool

# Deliberately free of the words `_classify_tool` falls back on when the name
# yields nothing — return/retrieve/output/result for a source, and
# external/outbound/remote for a sink. Otherwise the description rescues the
# classification and the name parsing is never exercised.
_NEUTRAL: str = "Handles a stored record for the caller"


def _source(name: str, description: str = _NEUTRAL) -> bool:
    return _classify_tool({"name": name, "description": description})[0]


def _sink(name: str, description: str = _NEUTRAL) -> bool:
    return _classify_tool({"name": name, "description": description})[1]


class TestDottedNamesKeepTheirVerb:
    def test_a_namespaced_source_is_a_source(self):
        assert _source("vault.read_secret")

    def test_it_matches_the_unnamespaced_form(self):
        assert _source("vault.read_secret") == _source("read_secret")

    def test_a_namespaced_sink_is_a_sink(self):
        assert _sink("webhook.post_event")

    def test_a_deeply_namespaced_tool_still_classifies(self):
        assert _source("org.team.service.get_user")

    def test_the_verb_may_lead_the_namespace(self):
        assert _source("get.user_profile")


class TestTheCamazotzShape:
    """The names that motivated this, taken from the live target."""

    def test_chain_get_service_manifest_is_a_source(self):
        assert _source("chain.get_service_manifest")

    def test_comms_send_message_is_a_sink(self):
        assert _sink("comms.send_message")

    def test_subchain_read_env_inheritance_is_a_source(self):
        assert _source("subchain.read_env_inheritance")


class TestClassificationStaysNarrow:
    def test_an_unrelated_tool_is_neither(self):
        tool = {"name": "math.add_numbers", "description": "Add two numbers"}

        is_source, is_sink, _ = _classify_tool(tool)

        assert not is_source and not is_sink

    def test_a_dot_does_not_manufacture_a_keyword(self):
        """Splitting must not turn a non-keyword into one."""
        assert not _source("threadpool.spawn", "Start a worker")

    def test_an_empty_name_is_harmless(self):
        assert _classify_tool({"name": "", "description": ""}) == (False, False, False)
