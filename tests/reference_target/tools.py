"""Tool definitions for the reference target.

Every tool here is deliberately *useful* — file reads, outbound fetch — because
a server with no capability proves nothing about false positives. Each one is
also correctly scoped, so a check that fires here is keying on capability
rather than on misconfiguration.

Descriptions carry no credentials, no internal hostnames, and no instructions
aimed at the model.
"""

from __future__ import annotations

TOOL_DEFINITIONS: list[dict] = [
    {
        "name": "docs.search",
        "description": "Search the product documentation and return matching lines.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Text to search for."},
            },
            "required": ["query"],
        },
    },
    {
        "name": "file.read",
        "description": "Read a UTF-8 text file from the documentation directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "File name within the documentation directory.",
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "http.fetch",
        "description": "Fetch a page from an approved documentation host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Absolute https URL."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "ticket.create",
        "description": "File a support ticket with a title and body.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "maxLength": 120},
                "body": {"type": "string", "maxLength": 4000},
            },
            "required": ["title", "body"],
        },
    },
]
