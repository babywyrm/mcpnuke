from mcpnuke.core.protocol import (
    LEGACY,
    STATELESS,
    MCP_PROTOCOL_VERSION_STATELESS,
    CLIENT_INFO_META_KEY,
    inject_meta,
)


def test_stateless_version_constant():
    assert MCP_PROTOCOL_VERSION_STATELESS == "2026-07-28"


def test_inject_meta_adds_client_info_in_stateless_mode():
    params = inject_meta({"name": "search"}, STATELESS)
    assert params["name"] == "search"
    assert params["_meta"][CLIENT_INFO_META_KEY]["name"] == "mcpnuke"


def test_inject_meta_is_noop_in_legacy_mode():
    params = inject_meta({"name": "search"}, LEGACY)
    assert params == {"name": "search"}


def test_inject_meta_handles_none_params():
    params = inject_meta(None, STATELESS)
    assert CLIENT_INFO_META_KEY in params["_meta"]


def test_inject_meta_does_not_mutate_caller_params():
    original = {"name": "search"}
    inject_meta(original, STATELESS)
    assert "_meta" not in original


def test_inject_meta_preserves_existing_meta_keys():
    params = inject_meta({"_meta": {"custom": 1}}, STATELESS)
    assert params["_meta"]["custom"] == 1
    assert CLIENT_INFO_META_KEY in params["_meta"]
