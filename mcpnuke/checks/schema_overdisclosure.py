"""Pre-auth tool schema over-disclosure (MCP-T50, Lane 5 / Transport A).

MCP requires ``tools/list`` to work without authentication — anyone can
enumerate a server's tool catalog. The vulnerability isn't the spec; it's
that most developers put too much in their tool descriptions. Anonymous
attackers harvest internal hostnames, credential patterns, env-var
references, and architectural details from descriptions and schema metadata
without ever invoking a single tool.

This check is the static-scan counterpart to camazotz
``anon_schema_harvest_lab`` (MCP-T50). It scans every tool's name,
description, parameter descriptions, defaults, and enum values for:

  - Credential-like patterns (``cztz-...``, ``CZTZ_...``, ``sk-...``,
    bearer tokens, JWTs, AWS keys, GitHub PATs, connection strings)
  - Internal hostnames (``*.internal``, ``*.corp``, ``*.local``, ``*.svc``,
    RFC1918 ranges)
  - Internal env-var references (uppercase keys like ``CZTZ_SECRET_*``,
    ``DATABASE_URL``, ``AWS_SECRET_*``)
  - Internal path hints (``/workspace/``, ``/opt/``, ``/var/lib/``)

This check overlaps with ``credential_in_schema`` but is broader: it flags
the soft over-disclosure (internal paths, hostnames, env-var names) that
isn't a credential leak but still hands attackers reconnaissance for free.
``credential_in_schema`` focuses narrowly on literal credential strings;
``schema_overdisclosure`` catches the broader pre-auth recon surface.
"""

from __future__ import annotations

import re

from mcpnuke.checks._lane_helpers import lane_tagged
from mcpnuke.checks.base import time_check, tool_text
from mcpnuke.core.models import TargetResult
from mcpnuke.patterns.credentials import RECON_CREDENTIALS, find_credential

_add = lane_tagged(lane=5, transport="A")


# Credential-like patterns. Where these overlap with credential_in_schema we
# still emit here so anonymous-recon findings stand on their own; severity
# tunes the de-dup expectations downstream. Lab token formats come first so a
# cztz token is reported as such rather than as a generic secret.
_CREDENTIAL_PATTERNS = RECON_CREDENTIALS

# Internal-looking hostnames and URLs (recon surface, not a credential)
_INTERNAL_HOST_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"https?://[\w.\-]+\.internal\b"), "internal_tld_host"),
    (re.compile(r"https?://[\w.\-]+\.corp\b"), "corp_tld_host"),
    (re.compile(r"https?://[\w.\-]+\.local\b"), "local_tld_host"),
    (re.compile(r"https?://[\w.\-]+\.svc(\.cluster\.local)?\b"), "k8s_svc_host"),
    (re.compile(r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}"), "rfc1918_10_host"),
    (re.compile(r"https?://192\.168\.\d{1,3}\.\d{1,3}"), "rfc1918_192_host"),
    (re.compile(r"https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"), "rfc1918_172_host"),
    (re.compile(r"https?://169\.254\.169\.254"), "imds_host"),
]

# Internal env-var references (uppercase keys describing infrastructure).
# We exclude SHELL_PATH, USERNAME, HOME etc. by requiring at least one
# infra-y term in the name.
_ENV_VAR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|CRED)[A-Z0-9_]*\b"), "infra_env_var"),
    (re.compile(r"\bDATABASE_URL\b"), "database_url_env"),
    (re.compile(r"\b(?:JWT|OIDC)_SECRET\b"), "auth_secret_env"),
    (re.compile(r"\bAWS_(?:SECRET|ACCESS)_KEY[A-Z_]*\b"), "aws_env"),
]

# Internal-looking paths
_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/workspace/[\w./-]+"), "workspace_path"),
    (re.compile(r"/opt/[\w./-]{3,}"), "opt_path"),
    (re.compile(r"/var/(?:lib|run|log|cache)/[\w./-]+"), "var_path"),
    (re.compile(r"/etc/(?:secrets|kubernetes|nginx|systemd)/[\w./-]+"), "etc_path"),
]


_tool_searchable_text = tool_text


def check_schema_overdisclosure(result: TargetResult) -> None:
    """Static scan of ``tools/list`` for pre-auth over-disclosure (MCP-T50)."""
    with time_check("schema_overdisclosure", result):
        for tool in result.tools:
            name = tool.get("name", "")
            text = _tool_searchable_text(tool)

            hit = find_credential(text, _CREDENTIAL_PATTERNS)
            if hit:
                label, matched = hit
                _add(
                    result,
                    "schema_overdisclosure",
                    "CRITICAL",
                    f"Anonymous credential disclosure in tool '{name}'",
                    f"Credential pattern ({label}) is visible to anonymous "
                    "callers via tools/list (MCP-T50). Pre-auth recon "
                    "surface — no authentication needed.",
                    evidence=matched[:200],
                    taxonomy_id="MCP-T50",
                )

            for pattern, label in _INTERNAL_HOST_PATTERNS:
                m = pattern.search(text)
                if m:
                    _add(
                        result,
                        "schema_overdisclosure",
                        "HIGH",
                        f"Internal hostname disclosed in tool '{name}'",
                        f"Internal host pattern ({label}) is anonymously "
                        "visible via tools/list (MCP-T50). Reveals network "
                        "topology to pre-auth attackers.",
                        evidence=m.group()[:200],
                        taxonomy_id="MCP-T50",
                    )
                    break

            for pattern, label in _ENV_VAR_PATTERNS:
                m = pattern.search(text)
                if m:
                    _add(
                        result,
                        "schema_overdisclosure",
                        "MEDIUM",
                        f"Infrastructure env-var name disclosed in tool '{name}'",
                        f"Env-var reference ({label}) hints at the server's "
                        "credential namespace. Anonymous recon (MCP-T50).",
                        evidence=m.group()[:200],
                        taxonomy_id="MCP-T50",
                    )
                    break

            for pattern, label in _PATH_PATTERNS:
                m = pattern.search(text)
                if m:
                    _add(
                        result,
                        "schema_overdisclosure",
                        "LOW",
                        f"Internal path disclosed in tool '{name}'",
                        f"Internal filesystem path ({label}) appears in tool "
                        "schema, visible to anonymous callers (MCP-T50).",
                        evidence=m.group()[:200],
                        taxonomy_id="MCP-T50",
                    )
                    break
