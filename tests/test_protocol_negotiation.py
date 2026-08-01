from mcpnuke.core.models import TargetResult


def test_target_result_defaults_to_unknown_protocol_mode():
    assert TargetResult(url="http://t/mcp").protocol_mode == "unknown"
