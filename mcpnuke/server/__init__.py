"""mcpnuke-runner: a thin async HTTP service wrapping the mcpnuke library.

Exposes the scanner as a typed job API so sibling tools (e.g. the camazotz
portal) can launch scans and read structured findings without shelling out
to the CLI or parsing stdout. Install with the ``server`` extra:

    pip install "mcpnuke[server]"
    mcpnuke-runner            # serves on 0.0.0.0:8090

The service is intentionally stateless beyond an in-memory job table; it
holds no credentials and performs the same checks as the CLI.
"""

from mcpnuke.server.models import ScanDepth, ScanJob, ScanRequest

__all__ = ["ScanDepth", "ScanRequest", "ScanJob"]
