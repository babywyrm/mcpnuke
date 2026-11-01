---
name: mcpnuke-add-transport
description: >-
  Add a new transport type to mcpnuke alongside SSE, HTTP, and ToolServer.
  Use when adding support for a new MCP transport protocol like DPoP, mTLS,
  or a custom gateway.
---

# Add a New mcpnuke Transport

## Current Transport Architecture

```
detect_transport(url)
  ├── SSE probe → MCPSession
  ├── HTTP POST probe → HTTPSession
  ├── SSE+POST combos → MCPSession
  └── ToolServer probe → ToolServerSession
```

All session types implement the same interface:
- `wait_ready(timeout) → bool`
- `call(method, params, timeout, retries) → dict | None`
- `notify(method, params)`
- `close()`
- Properties: `base`, `sse_url`, `post_url`

## Steps to Add a Transport

### 1. Create the session class

In a new module `mcpnuke/core/transports/<name>.py`, add the class, and
re-export it from `mcpnuke/core/session.py`:

```python
class YourSession:
    def __init__(self, base, post_url, timeout=25.0, **kwargs):
        self.base = base
        self.sse_url = ""
        self.post_url = post_url
        self.timeout = timeout
        # Your transport-specific setup

    def wait_ready(self, timeout=10.0) -> bool:
        return True

    def call(self, method, params=None, timeout=None, retries=2) -> dict | None:
        # Translate MCP JSON-RPC calls to your transport
        pass

    def notify(self, method, params=None):
        pass

    def close(self):
        pass
```

### 2. Add detection logic

Create a detector function:

```python
def _detect_your_transport(base, hint, timeout, auth_token, **kwargs):
    # Probe for your transport
    # Return YourSession if detected, None otherwise
    pass
```

### 3. Wire into detect_transport

Add your detector as a fallback in `detect_transport()`, after existing transports:

```python
# After ToolServer detection
your_session = _detect_your_transport(base, hint, ...)
if your_session:
    return your_session
```

### 4. Add CLI flags (if needed)

In `mcpnuke/cli.py`, add arguments:

```python
p.add_argument("--your-flag", help="...")
```

Thread through `__main__.py` → `scanner.py` → `detect_transport()`.

### 5. Add verbose logging

Use the `log` callable in `detect_transport`:

```python
if verbose:
    _log(f"  [dim]Trying YourTransport detection...[/dim]")
```

### 6. Update scanner labels

In `mcpnuke/scanner.py` `scan_target()`, add label detection:

```python
if isinstance(session, YourSession):
    transport_label = "YourTransport"
```

### 7. Test

Add transport detection tests to `tests/test_cli.py` or a new test file.

## Reference: Existing Transports

| Transport | Class | Detection Method |
|-----------|-------|-----------------|
| SSE | `MCPSession` | GET returns `text/event-stream` |
| HTTP | `HTTPSession` | POST initialize returns JSON-RPC |
| ToolServer | `ToolServerSession` | POST `/execute` returns tool response |
