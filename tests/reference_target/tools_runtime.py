"""Hardened tool handlers for the reference target.

Each handler is the negative of a check mcpnuke implements. Two rules run
through all of them:

1. **Never echo caller input.** A server that reflects its arguments will grow
   an injection finding it does not deserve, and we would be measuring our own
   echo rather than the scanner.
2. **Refuse without explaining.** Refusals name the policy, not the input.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_DOCS: dict[str, str] = {
    "overview.txt": (
        "This is the reference target. It exists so mcpnuke can measure how "
        "quiet it stays against a server that is not vulnerable."
    ),
    "install.txt": "Install with: uv sync --all-extras",
    "faq.txt": "Q: Is this server intentionally vulnerable? A: No. That is DVMCP.",
}

_ALLOWED_FETCH_HOSTS: frozenset[str] = frozenset({"docs.example.com", "www.example.com"})

_MAX_TITLE: int = 120
_MAX_BODY: int = 4000

_tickets: list[dict] = []


def _ok(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _refuse(reason: str) -> dict:
    return {"content": [{"type": "text", "text": reason}], "isError": True}


def _docs_search(arguments: dict) -> dict:
    query = arguments.get("query")
    if not isinstance(query, str) or not query.strip():
        return _refuse("A non-empty 'query' string is required.")
    needle = query.strip().lower()
    hits = [name for name, body in _DOCS.items() if needle in body.lower()]
    if not hits:
        # Deliberately does not repeat the query.
        return _ok("No documents matched the search.")
    return _ok("Matching documents: " + ", ".join(sorted(hits)))


def _file_read(arguments: dict) -> dict:
    name = arguments.get("name")
    if not isinstance(name, str) or not name:
        return _refuse("A 'name' string is required.")
    # Allowlist by exact key rather than by path arithmetic: there is no path to
    # traverse, so traversal cannot succeed by construction.
    body = _DOCS.get(name)
    if body is None:
        return _refuse("No such document in the documentation directory.")
    return _ok(body)


def _host_is_public(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() in _ALLOWED_FETCH_HOSTS
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def _http_fetch(arguments: dict) -> dict:
    url = arguments.get("url")
    if not isinstance(url, str) or not url:
        return _refuse("A 'url' string is required.")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return _refuse("Only http and https URLs are permitted.")
    host = (parsed.hostname or "").lower()
    if not host or host not in _ALLOWED_FETCH_HOSTS or not _host_is_public(host):
        return _refuse("That host is not on the fetch allowlist.")
    # No real egress: a test must never depend on, or touch, the network.
    return _ok("Fetched 200 OK from an approved documentation host.")


def _ticket_create(arguments: dict) -> dict:
    title = arguments.get("title")
    body = arguments.get("body")
    if not isinstance(title, str) or not isinstance(body, str):
        return _refuse("Both 'title' and 'body' must be strings.")
    if not title.strip() or not body.strip():
        return _refuse("Both 'title' and 'body' must be non-empty.")
    if len(title) > _MAX_TITLE or len(body) > _MAX_BODY:
        return _refuse("Ticket exceeds the permitted field lengths.")
    ticket_id = len(_tickets) + 1
    _tickets.append({"id": ticket_id, "title": title, "body": body})
    # Returns the identifier only; the caller's text is never reflected.
    return _ok(f"Created ticket #{ticket_id}.")


_HANDLERS = {
    "docs.search": _docs_search,
    "file.read": _file_read,
    "http.fetch": _http_fetch,
    "ticket.create": _ticket_create,
}


def call_tool(name: str, arguments: dict) -> dict:
    handler = _HANDLERS.get(name)
    if handler is None:
        return _refuse("No such tool.")
    try:
        return handler(arguments)
    except Exception:
        # Never surface a traceback, a module path, or a dependency version.
        return _refuse("The tool could not complete the request.")
