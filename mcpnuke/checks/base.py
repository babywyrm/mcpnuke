"""Base utilities for checks."""

import json
import time

from mcpnuke.core.models import TargetResult


def tool_text(tool: dict) -> str:
    """Build the searchable surface of a tool definition.

    Name, description, and the whole inputSchema — which carries parameter
    descriptions, defaults, enums, and examples, all of it attacker-visible via
    ``tools/list``. Fields are newline-separated so a pattern cannot match
    across a field boundary by accident.
    """
    parts: list[str] = [
        str(tool.get("name", "")),
        str(tool.get("description", "")),
    ]
    schema = tool.get("inputSchema", {})
    if schema:
        parts.append(json.dumps(schema, default=str))
    return "\n".join(parts)


def response_is_error(resp: dict | None) -> bool:
    """True when the server refused or failed the call.

    ``_call_tool`` returns the response whenever the JSON-RPC round trip
    completes, so a refusal arrives as a value, not an exception. Treating any
    non-None response as success turned "permission denied" into confirmed
    exfiltration once already — this is that fix, in one place instead of two
    private copies.
    """
    if resp is None:
        return True
    if resp.get("error"):
        return True
    result = resp.get("result")
    return isinstance(result, dict) and bool(result.get("isError"))


def time_check(name: str, result: TargetResult):
    """Context manager to record check timing."""

    class _T:
        def __enter__(self):
            self.t0 = time.time()
            return self

        def __exit__(self, *_):
            result.timings[name] = time.time() - self.t0

    return _T()
