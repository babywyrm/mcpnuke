"""
mcprowler — MCP Red Teaming & Security Scanner

Security auditing for Model Context Protocol servers. Enumerates tools,
probes for injection and poisoning, detects rug pulls, and audits
Kubernetes MCP deployments.

Usage:
    mcprowler --targets http://localhost:9090
    mcprowler --port-range localhost:9001-9010 --verbose
    python -m mcprowler --targets http://localhost:9090
"""

__version__ = "5.0.0"
