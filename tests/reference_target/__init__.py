"""A hardened MCP server used to measure mcpnuke's false-positive rate."""

from tests.reference_target.server import ReferenceServer, start_reference_server

__all__ = ["ReferenceServer", "start_reference_server"]
