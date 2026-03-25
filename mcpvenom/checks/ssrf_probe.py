"""Active SSRF detection via tool probing (MCP-T06).

For tools with URL/endpoint/host string params, sends SSRF test payloads
and analyzes responses for cloud metadata, internal service indicators,
or differential behavior between internal and external URLs.
"""

import re

from mcpvenom.core.models import TargetResult
from mcpvenom.checks.base import time_check
from mcpvenom.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke

URL_PARAM_PATTERNS = re.compile(
    r"(url|uri|endpoint|href|target|host|webhook|link|address|redirect|proxy|fetch|request|resource_url|source_url|dest|destination)",
    re.IGNORECASE,
)

SSRF_PAYLOADS = [
    ("imds_aws", "http://169.254.169.254/latest/meta-data/"),
    ("imds_decimal", "http://2852039166/latest/meta-data/"),
    ("imds_ipv6", "http://[::ffff:169.254.169.254]/latest/meta-data/"),
    ("imds_gcp", "http://metadata.google.internal/computeMetadata/v1/"),
    ("localhost", "http://127.0.0.1:80/"),
    ("localhost_ipv6", "http://[::1]:80/"),
    ("localhost_zero", "http://0:80/"),
]

CLOUD_METADATA_INDICATORS = [
    r"ami-[a-f0-9]+",
    r"instance-id",
    r"local-ipv4",
    r"security-credentials",
    r"iam/info",
    r"project-id",
    r"computeMetadata",
    r"access.?token",
    r"instance/service-accounts",
]

INTERNAL_INDICATORS = [
    r"<title>.*(?:dashboard|admin|consul|etcd|grafana|kibana|jenkins)",
    r"(?:kubernetes|k8s|docker|container)",
    r"(?:mongodb|redis|memcached|rabbitmq|elasticsearch).*(?:version|info|stats)",
]


def check_ssrf_probe(session, result: TargetResult, probe_opts: dict | None = None):
    opts = probe_opts or {}
    _log = opts.get("_log", lambda msg: None)
    with time_check("ssrf_probe", result):
        invokable = [t for t in result.tools if _should_invoke(t, opts)]
        _log(f"    [dim]    SSRF-probing {len(invokable)} tools[/dim]")
        tool_idx = 0
        for tool in result.tools:
            if not _should_invoke(tool, opts):
                continue
            name = tool.get("name", "")
            props = tool.get("inputSchema", {}).get("properties", {})

            url_params = [
                pname for pname, pdef in props.items()
                if pdef.get("type") in (None, "string") and URL_PARAM_PATTERNS.search(pname)
            ]

            if not url_params:
                continue

            base_args = _build_safe_args(tool)

            for pname in url_params:
                # Get baseline response with safe URL
                safe_args = {**base_args, pname: "http://example.com/test"}
                safe_resp = _call_tool(session, name, safe_args, timeout=8)
                safe_text = _response_text(safe_resp)

                for payload_name, payload_url in SSRF_PAYLOADS:
                    test_args = {**base_args, pname: payload_url}
                    resp = _call_tool(session, name, test_args, timeout=8)
                    text = _response_text(resp)
                    if not text:
                        continue

                    for pat in CLOUD_METADATA_INDICATORS:
                        if re.search(pat, text, re.IGNORECASE):
                            result.add(
                                "ssrf_probe",
                                "CRITICAL",
                                f"SSRF: cloud metadata accessible via tool '{name}'",
                                f"Payload: {payload_name} via param '{pname}'",
                                evidence=text[:400],
                            )
                            return

                    for pat in INTERNAL_INDICATORS:
                        if re.search(pat, text, re.IGNORECASE) and not re.search(pat, safe_text or "", re.IGNORECASE):
                            result.add(
                                "ssrf_probe",
                                "HIGH",
                                f"SSRF: internal service accessed via tool '{name}'",
                                f"Payload: {payload_name} via param '{pname}'",
                                evidence=text[:400],
                            )
                            return

                    if safe_text and text and len(text) > 50 and text != safe_text:
                        len_ratio = len(text) / max(len(safe_text), 1)
                        if len_ratio > 2.0 or len_ratio < 0.3:
                            result.add(
                                "ssrf_probe",
                                "MEDIUM",
                                f"SSRF indicator: differential response for internal URL via '{name}'",
                                f"Payload: {payload_name}, response length ratio: {len_ratio:.1f}",
                            )

            # Static flag: tool has URL params at all
            if url_params:
                desc = tool.get("description", "").lower()
                if any(kw in desc for kw in ("fetch", "download", "request", "proxy", "redirect", "load")):
                    result.add(
                        "ssrf_probe",
                        "MEDIUM",
                        f"SSRF surface: tool '{name}' accepts URL params and fetches content",
                        f"URL params: {url_params}",
                    )
