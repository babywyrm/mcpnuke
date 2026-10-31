"""Positive dogfood for the OWASP MCP Top 10. Not the hardened reference target."""

from tests.owasp_lab.server import OwaspLab, start_owasp_lab

__all__ = ["OwaspLab", "start_owasp_lab"]
