"""Excessive permissions and schema risk checks."""

import re

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check
from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.rules import DANGEROUS_TOOL_PATTERNS
from mcpnuke.patterns.tokens import normalize_identifier

_WEAK_SIGNAL_THRESHOLD = 2
_add = lane_tagged(lane=1, transport="A")
_TAXONOMY_ID: str = "MCP-T20"


def check_excessive_permissions(result: TargetResult):
    with time_check("excessive_permissions", result):
        for tool in result.tools:
            # Normalize before lowercasing: the camelCase split needs the
            # original case, so `readFile` becomes "read File" and matches.
            # Descriptions stay raw — they are already prose, and normalizing
            # them would break literal alternatives like `__import__`.
            name = normalize_identifier(tool.get("name", "")).lower()
            desc = tool.get("description", "").lower()

            name_hits: list[tuple[str, str, str]] = []
            desc_only_hits: list[tuple[str, str, str]] = []

            for category, (pattern, severity) in DANGEROUS_TOOL_PATTERNS.items():
                if re.search(pattern, name, re.IGNORECASE):
                    name_hits.append((category, pattern, severity))
                elif re.search(pattern, desc, re.IGNORECASE):
                    desc_only_hits.append((category, pattern, severity))

            for category, pattern, severity in name_hits:
                _add(
                    result,
                    "excessive_permissions",
                    severity,
                    f"Dangerous capability [{category}]: '{tool['name']}'",
                    tool.get("description", "")[:200],
                    evidence=f"Pattern: {pattern}",
                    taxonomy_id=_TAXONOMY_ID,
                )

            if len(desc_only_hits) >= _WEAK_SIGNAL_THRESHOLD:
                for category, pattern, severity in desc_only_hits:
                    _add(
                        result,
                        "excessive_permissions",
                        severity,
                        f"Dangerous capability [{category}]: '{tool['name']}'",
                        tool.get("description", "")[:200],
                        evidence=f"Pattern: {pattern}",
                        taxonomy_id=_TAXONOMY_ID,
                    )

            schema = tool.get("inputSchema", {})
            if schema.get("type") == "object":
                props = schema.get("properties", {})
                if not props and not schema.get("required"):
                    _add(
                        result,
                        "excessive_permissions",
                        "MEDIUM",
                        f"Tool '{tool['name']}' has no input schema",
                        "Accepts arbitrary input with no validation",
                        taxonomy_id=_TAXONOMY_ID,
                    )
                for pname, pdef in props.items():
                    if not pdef.get("type"):
                        _add(
                            result,
                            "excessive_permissions",
                            "LOW",
                            f"Untyped param '{pname}' in '{tool['name']}'",
                            taxonomy_id=_TAXONOMY_ID,
                        )


def check_schema_risks(result: TargetResult):
    with time_check("schema_risks", result):
        for tool in result.tools:
            schema = tool.get("inputSchema", {})
            props = schema.get("properties", {})
            name = tool.get("name", "")
            for pname, pdef in props.items():
                if "command" in pname.lower():
                    result.add(
                        "schema_risk",
                        "CRITICAL",
                        f"Command parameter '{pname}' in tool '{name}'",
                    )
                if pdef.get("type") == "string" and not pdef.get("maxLength"):
                    result.add(
                        "schema_risk",
                        "MEDIUM",
                        f"Unbounded string param '{pname}' in tool '{name}'",
                        "No maxLength constraint — injection surface",
                    )
                if pdef.get("type") == "object" and not pdef.get(
                    "properties"
                ):
                    result.add(
                        "schema_risk",
                        "MEDIUM",
                        f"Freeform object param '{pname}' in tool '{name}'",
                        "Accepts arbitrary nested structure",
                    )
