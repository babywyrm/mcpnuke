# Security Policy

mcpnuke is an offensive security tool. This document covers two things:
reporting vulnerabilities **in mcpnuke itself**, and using mcpnuke
**against targets you are authorized to test**.

## Reporting a vulnerability in mcpnuke

Please do not open a public issue for security problems.

Use GitHub's private vulnerability reporting on
[the repository's Security tab](https://github.com/babywyrm/mcpnuke/security/advisories/new).
That channel is private until an advisory is published.

Include, where you can:

- affected version (`mcpnuke --version`) and Python version
- the command line you ran and the transport involved
- what happened versus what you expected
- a minimal reproduction — a fake MCP server or a redacted transcript is ideal

**Response expectations.** This is a single-maintainer project, so triage is
best-effort rather than contractual: acknowledgement within about a week, and a
fix or a documented decision before any advisory is published. If a report is
declined, you will get the reasoning rather than silence.

### What counts as a vulnerability here

Highest priority, because they break the trust boundary the tool sits on:

- **Scanner-side code execution** — a malicious MCP server that can execute
  code, write files, or escape the process on the machine running mcpnuke
- **Credential leakage** — auth tokens, OIDC secrets, or DPoP proofs written to
  reports, logs, SARIF, or generated policy where the user did not ask for them
- **Safety-control bypass** — `--no-invoke` or `--safe-mode` calling a tool it
  promised not to call, since operators rely on those against production
- **Unintended egress** — mcpnuke contacting a host the user never named,
  outside an explicitly enabled `--oast` listener

Also in scope, at lower severity: dependency vulnerabilities that are reachable
from a normal scan, and TLS verification that does not behave as documented.

**Not vulnerabilities:** false positives or false negatives in checks (open a
normal issue — those are correctness bugs and we want them), findings that
mcpnuke correctly reports about a deliberately vulnerable lab, or crashes on
malformed input that only affect the local run. Bug reports about detection
quality are genuinely welcome; they just are not handled through this channel.

## Authorized use

mcpnuke actively probes targets. Default behavior calls tools, sends injection
and SSRF payloads, and attempts multi-step chains. On a real server, that can
create data, trigger outbound requests, or move data between systems.

**Only scan systems you own or have written authorization to test.**
Unauthorized scanning is likely illegal in your jurisdiction regardless of
intent, and the finding quality is not worth the exposure.

### Controls for production and third-party targets

| Flag | Effect |
|------|--------|
| `--no-invoke` | Static-only. Enumerates and analyzes metadata; never calls a tool. |
| `--safe-mode` | Calls tools, but refuses ones classified dangerous (delete, send, exec, write, webhook, egress, exfil). |
| `--fast` | Samples the most security-relevant tools instead of the full inventory. |

`--no-invoke` is the safest starting point against anything you do not control.
Add invocation only once you know the blast radius.

`--oast` starts a local callback listener and plants its URL in payloads. It is
how mcpnuke proves data actually left a target, and it is off by default —
enable it deliberately, and understand that a confirmed callback means the
target really did make an outbound request.

## Handling scan output

Scan results describe exploitable paths and may quote credentials the target
leaked. Treat reports, SARIF files, and generated policy as sensitive:

- do not commit them to public repositories
- redact before filing an issue against mcpnuke or a third-party server
- the repository's `.gitignore` already excludes scan JSON for this reason

When reporting findings to a third party, follow their disclosure process.
