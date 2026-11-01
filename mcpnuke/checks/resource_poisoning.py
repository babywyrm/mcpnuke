"""Resource poisoning: deep analysis of resource contents for obfuscated
injection payloads beyond the static regex pass."""

import base64
import re

from mcpnuke.checks.base import (
    time_check,
)
from mcpnuke.core.models import TargetResult
from mcpnuke.core.transports.base import MCPSessionProtocol
from mcpnuke.patterns.credentials import compile_patterns
from mcpnuke.patterns.probes import (
    CREDENTIAL_CONTENT_PATTERNS,
    CSS_HIDDEN_PATTERN,
    MD_IMAGE_EXFIL_PATTERN,
    has_invisible_unicode,
)


def check_resource_poisoning(session: MCPSessionProtocol, result: TargetResult) -> None:
    """Deep content analysis of resources for obfuscated injection payloads."""
    with time_check("resource_poisoning", result):
        from mcpnuke.patterns.rules import INJECTION_PATTERNS, POISON_PATTERNS

        for resource in result.resources:
            uri = resource.get("uri", "")
            try:
                resp = session.call("resources/read", {"uri": uri}, timeout=15)
                if not resp or "result" not in resp:
                    continue

                for content_block in resp["result"].get("contents", []):
                    text = content_block.get("text", "") or ""
                    blob = content_block.get("blob", "") or ""

                    if blob and not text:
                        try:
                            text = base64.b64decode(blob).decode("utf-8", errors="ignore")
                        except Exception:
                            continue

                    if not text:
                        continue

                    # --- Base64-encoded injection payloads ---
                    for chunk in re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)[:5]:
                        try:
                            decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                            for pat in INJECTION_PATTERNS + POISON_PATTERNS:
                                if re.search(pat, decoded, re.IGNORECASE):
                                    result.add(
                                        "resource_poisoning",
                                        "CRITICAL",
                                        f"Base64-encoded injection in resource '{uri}'",
                                        f"Decoded content matches: {pat}",
                                        evidence=decoded[:300],
                                    )
                                    break
                        except Exception:
                            pass

                    # --- Data URI payloads ---
                    for du in re.findall(r"data:[a-z]+/[a-z0-9+.-]+(?:;base64)?,\S+", text, re.IGNORECASE):
                        result.add(
                            "resource_poisoning",
                            "HIGH",
                            f"Embedded data URI in resource '{uri}'",
                            "May contain executable or injected content",
                            evidence=du[:200],
                        )

                    # --- Steganographic invisible Unicode ---
                    inv = has_invisible_unicode(text)
                    if inv:
                        result.add(
                            "resource_poisoning",
                            "CRITICAL",
                            f"Steganographic content in resource '{uri}'",
                            f"{len(inv)} invisible Unicode chars — hidden instructions likely",
                            evidence=repr(text[:200]),
                        )

                    # --- CSS-hidden HTML (visually invisible to user, visible to LLM) ---
                    for h in CSS_HIDDEN_PATTERN.findall(text):
                        result.add(
                            "resource_poisoning",
                            "CRITICAL",
                            f"CSS-hidden HTML in resource '{uri}'",
                            "Visually hidden elements visible to LLM parsers",
                            evidence=h[:300],
                        )

                    # --- Markdown image exfiltration ---
                    exfil_kw = ("webhook", "ngrok", "burp", "requestbin", "pipedream", "interactsh")
                    for url in MD_IMAGE_EXFIL_PATTERN.findall(text):
                        if any(kw in url.lower() for kw in exfil_kw):
                            result.add(
                                "resource_poisoning",
                                "HIGH",
                                f"Markdown image exfiltration in resource '{uri}'",
                                f"Image src: {url}",
                            )

                    # --- Credential content (actual secrets in resource text) ---
                    # Case sensitivity now comes from the pattern itself: token
                    # prefixes like AKIA and ghp_ are case-specific by format,
                    # while the keyword patterns carry their own (?i).
                    for cred_pat, cred_type in compile_patterns(CREDENTIAL_CONTENT_PATTERNS):
                        m = cred_pat.search(text)
                        if m:
                            result.add(
                                "resource_poisoning",
                                "CRITICAL",
                                f"Credential exposed in resource '{uri}': {cred_type}",
                                f"Resource contains what appears to be a live {cred_type}",
                                evidence=m.group()[:200],
                            )

            except Exception:
                pass
