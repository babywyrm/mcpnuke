"""Prompt injection, tool poisoning, indirect injection checks."""

import re

from mcprowler.core.models import TargetResult
from mcprowler.checks.base import time_check
from mcprowler.patterns.rules import (
    INJECTION_PATTERNS,
    POISON_PATTERNS,
)


def check_prompt_injection(result: TargetResult):
    with time_check("prompt_injection", result):

        def _scan(text: str, location: str):
            for pat in INJECTION_PATTERNS:
                if re.search(pat, text, re.IGNORECASE):
                    result.add(
                        "prompt_injection",
                        "CRITICAL",
                        "Prompt injection payload detected",
                        f"Location: {location}",
                        evidence=f"Pattern: {pat}\nText: {text[:300]}",
                    )
                    return

        for tool in result.tools:
            name = tool.get("name", "")
            _scan(tool.get("description", ""), f"tool description: '{name}'")
            _scan(name, f"tool name: '{name}'")
            for prop, pdef in (
                tool.get("inputSchema", {}).get("properties", {}).items()
            ):
                _scan(
                    pdef.get("description", ""),
                    f"tool '{name}' param '{prop}'",
                )

        for r in result.resources:
            _scan(
                r.get("description", ""),
                f"resource '{r.get('uri','')}'",
            )
            _scan(r.get("name", ""), f"resource name '{r.get('uri','')}'")

        for p in result.prompts:
            _scan(
                p.get("description", ""),
                f"prompt '{p.get('name','')}'",
            )
            _scan(p.get("name", ""), "prompt name")


def check_tool_poisoning(result: TargetResult):
    with time_check("tool_poisoning", result):
        for tool in result.tools:
            name = tool.get("name", "")
            full = tool.get("description", "") + " " + str(
                tool.get("inputSchema", {})
            )

            for pat in POISON_PATTERNS:
                if re.search(pat, full, re.IGNORECASE | re.DOTALL):
                    result.add(
                        "tool_poisoning",
                        "CRITICAL",
                        f"Tool poisoning indicator in '{name}'",
                        f"Pattern: {pat}",
                        evidence=full[:400],
                    )
                    break

            for ch in tool.get("description", ""):
                if ord(ch) in range(0x200B, 0x2010) or ord(ch) == 0xFEFF:
                    result.add(
                        "tool_poisoning",
                        "CRITICAL",
                        f"Invisible Unicode in tool '{name}'",
                        "Possible hidden instructions via Unicode steganography",
                        evidence=repr(tool["description"][:200]),
                    )
                    break


def check_indirect_injection(session, result: TargetResult):
    with time_check("indirect_injection", result):
        for resource in result.resources:
            uri = resource.get("uri", "")
            try:
                resp = session.call(
                    "resources/read", {"uri": uri}, timeout=15
                )
                if not resp or "result" not in resp:
                    continue
                for content in resp["result"].get("contents", []):
                    text = content.get("text", "") or content.get("blob", "")
                    if not text:
                        continue
                    for pat in INJECTION_PATTERNS + POISON_PATTERNS:
                        if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                            result.add(
                                "indirect_injection",
                                "CRITICAL",
                                f"Indirect prompt injection in resource '{uri}'",
                                f"Pattern: {pat}",
                                evidence=text[:400],
                            )
                            break
                    for u in re.findall(r"https?://[^\s'\"<>]+", text):
                        if any(
                            kw in u
                            for kw in [
                                "webhook",
                                "ngrok",
                                "burp",
                                "requestbin",
                                "pipedream",
                                "canarytokens",
                                "interactsh",
                            ]
                        ):
                            result.add(
                                "indirect_injection",
                                "HIGH",
                                f"Exfiltration URL in resource '{uri}'",
                                evidence=u,
                            )
            except Exception:
                pass
