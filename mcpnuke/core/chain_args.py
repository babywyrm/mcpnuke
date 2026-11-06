"""Chain step arguments: placeholder substitution and step conditions.

A proposed chain names its arguments as templates, ``{{step0.output.id|b64}}``
or ``{{oast.url}}``, and may gate a step on a condition over earlier results.
Both are pure functions of prior step results, so they are testable without
a session or a model.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcpnuke.core.chain_replay import StepResult

# {{stepN.output}} or {{stepN.output.field|filter}} — placeholder template pattern.
_PLACEHOLDER_RE = re.compile(
    r"\{\{step(\d+)\.output(?:\.([a-zA-Z0-9_.\[\]]+))?(?:\|([a-zA-Z0-9_]+))?\}\}"
)

# {{oast.url}} — replaced with a per-run canary URL when a listener is active.
# A request for that URL is out-of-band proof the sink reached an address that
# appeared nowhere except this one replay.
_OAST_RE = re.compile(r"\{\{oast\.url\}\}")

def _parse_json_safe(text: str) -> Any:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    try:
        return json.loads(cleaned)
    except Exception:
        return text


def _extract_path(data: Any, path: str) -> Any:
    """Extract a nested value from dict/list or JSON string via dot/bracket path."""
    if not path:
        return data
    if isinstance(data, str):
        parsed = _parse_json_safe(data)
        if isinstance(parsed, (dict, list)):
            data = parsed
        else:
            return None

    tokens: list[str | int] = []
    for part in path.split("."):
        if not part:
            continue
        subparts = re.findall(r"([^\[\]]+)|\[(\d+)\]", part)
        for name, idx in subparts:
            if name:
                tokens.append(name)
            elif idx:
                tokens.append(int(idx))

    curr = data
    for token in tokens:
        if isinstance(token, str):
            if isinstance(curr, dict) and token in curr:
                curr = curr[token]
            else:
                return None
        elif isinstance(token, int):
            if isinstance(curr, list) and 0 <= token < len(curr):
                curr = curr[token]
            else:
                return None
        else:
            return None
    return curr


def _apply_filter(value: Any, filter_name: str) -> str:
    """Apply a transform filter to a value."""
    if filter_name == "json":
        if isinstance(value, str):
            return value
        try:
            return json.dumps(value, default=str)
        except Exception:
            return str(value)

    text = value if isinstance(value, str) else str(value)
    f = filter_name.lower().strip()
    if f == "b64":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    elif f == "b64decode":
        try:
            return base64.b64decode(text.encode("ascii")).decode("utf-8", errors="replace")
        except Exception:
            return text
    elif f == "urlencode":
        return urllib.parse.quote(text, safe="")
    elif f == "urldecode":
        return urllib.parse.unquote(text)
    elif f == "strip":
        return text.strip()
    return text


def _substitute(
    value: str,
    prior: list[StepResult],
    tracked_fragments: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Replace {{stepN.output...}} placeholders with extracted/transformed prior step responses."""
    fragments: list[str] = []

    def replace(match: re.Match[str]) -> str:
        index_str = match.group(1)
        path = match.group(2)
        filter_name = match.group(3)
        index = int(index_str)
        if not (0 <= index < len(prior) and not prior[index].failed):
            return match.group(0)

        raw_output = prior[index].response_text
        extracted = _extract_path(raw_output, path) if path else raw_output
        if extracted is None:
            return match.group(0)

        if isinstance(extracted, str) and len(extracted.strip()) >= 4:
            fragments.append(extracted.strip())

        if filter_name:
            filtered = _apply_filter(extracted, filter_name)
        elif isinstance(extracted, str):
            filtered = extracted
        else:
            filtered = _apply_filter(extracted, "json")

        if isinstance(filtered, str) and len(filtered.strip()) >= 4:
            fragments.append(filtered.strip())

        return filtered

    res = _PLACEHOLDER_RE.sub(replace, value)
    if tracked_fragments is not None:
        tracked_fragments.extend(fragments)
    return res, fragments


def _resolve_args(
    template: dict,
    prior: list[StepResult],
    oast_url: str = "",
    tracked_fragments: list[str] | None = None,
) -> dict:
    resolved: dict = {}
    for key, value in template.items():
        if isinstance(value, str):
            substituted, _ = _substitute(value, prior, tracked_fragments)
            if oast_url:
                substituted = _OAST_RE.sub(oast_url, substituted)
            resolved[key] = substituted
        else:
            resolved[key] = value
    return resolved
