"""K8s namespace boundary chain probe.

Detects potential cross-namespace data movement chains in Kubernetes
environments. Complements static K8s checks with chain-aware analysis.
"""

from __future__ import annotations

import re

from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult

# Tools that suggest K8s API access
_K8S_TOOL_PATTERNS = re.compile(
    r"(list|get|create|delete|update).*(pod|secret|configmap|service|deployment|namespace)",
    re.IGNORECASE,
)

# Namespace parameter names
_NAMESPACE_PARAMS = {"namespace", "ns", "target_namespace", "target_ns"}


def _has_namespace_param(tool: dict) -> bool:
    """Check if tool accepts a namespace parameter."""
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    return any(p in _NAMESPACE_PARAMS for p in props)


def _is_k8s_tool(tool: dict) -> bool:
    """Check if tool appears to be K8s-related."""
    name = tool.get("name", "")
    desc = tool.get("description", "")
    return bool(_K8S_TOOL_PATTERNS.search(name) or _K8S_TOOL_PATTERNS.search(desc))


def k8s_chain_probe(result: TargetResult) -> None:
    """Probe for cross-namespace chain opportunities.

    Looks for tool combinations that could enable:
    - Reading secrets from one namespace
    - Creating pods/resources in another namespace
    - Service account token theft across boundaries
    """
    with time_check("k8s_chain_probe", result):
        k8s_tools = [t for t in result.tools if _is_k8s_tool(t)]
        if len(k8s_tools) < 2:
            return

        # Check for namespace-parameterized tools
        ns_tools = [t for t in k8s_tools if _has_namespace_param(t)]
        if len(ns_tools) < 2:
            return

        # Look for read + write combination
        read_tools = [t for t in ns_tools if re.search(r"list|get|read", t.get("name", ""), re.I)]
        write_tools = [t for t in ns_tools if re.search(r"create|update|delete|apply", t.get("name", ""), re.I)]

        if read_tools and write_tools:
            result.add(
                "k8s_chain_probe",
                "MEDIUM",
                "Cross-namespace chain opportunity detected",
                f"Found {len(read_tools)} read-capable and {len(write_tools)} write-capable "
                f"K8s tools with namespace parameters. A chain could read from one "
                f"namespace and write to another.",
                evidence=f"Read: {[t['name'] for t in read_tools]}, Write: {[t['name'] for t in write_tools]}",
            )
