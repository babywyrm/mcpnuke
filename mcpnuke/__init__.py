"""
mcpnuke — MCP Red Teaming & Security Scanner

Security auditing for Model Context Protocol servers. Enumerates tools,
probes for injection and poisoning, detects rug pulls, and audits
Kubernetes MCP deployments.

Usage:
    mcpnuke --targets http://localhost:9090
    mcpnuke --port-range localhost:9001-9010 --verbose
    python -m mcpnuke --targets http://localhost:9090
"""

__version__ = "6.2.0"
