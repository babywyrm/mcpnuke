# CI/CD Pipeline Integration

Run mcpnuke as a security gate in your CI/CD pipeline. Fail builds on
CRITICAL findings, generate nullfield policy, and track regressions.

mcpnuke's own CI (`tests.yml`) dogfoods the CLI against the in-repo
reference target (`tests/test_cli_dogfood.py`). The reusable workflow
below is for scanning *your* MCP server; it is `workflow_call` only.

---

## GitHub Actions (Recommended)

### Option A: Use the reusable workflow

```yaml
# .github/workflows/security.yml
name: MCP Security
on:
  pull_request:
    branches: [main]

jobs:
  scan:
    uses: babywyrm/mcpnuke/.github/workflows/mcp-security-scan.yml@main
    with:
      target: http://mcp-staging.internal:8080/mcp
      scan-mode: static        # static | claude | full
      fail-on: critical        # critical | high | medium | any
      generate-policy: true
    secrets:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      MCP_AUTH_TOKEN: ${{ secrets.MCP_AUTH_TOKEN }}
```

**What it does:**
1. Installs mcpnuke in the runner
2. Downloads the previous baseline (if exists)
3. Scans the target MCP server
4. Compares against baseline for regressions
5. Generates nullfield policy artifact
6. Comments findings on the PR
7. Fails the PR if findings exceed threshold
8. Saves new baseline on main branch merges

### Option B: Inline workflow

```yaml
# .github/workflows/mcp-scan.yml
name: MCP Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install mcpnuke
        run: pip install mcpnuke

      - name: Scan
        run: |
          mcpnuke --targets ${{ vars.MCP_TARGET }} \
            --fast --no-invoke \
            --fail-on high \
            --generate-policy policy.yaml \
            --json report.json \
            --sarif results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-scan
          path: |
            report.json
            results.sarif
            policy.yaml
```

---

## GitLab CI

```yaml
# .gitlab-ci.yml
mcp-security-scan:
  stage: test
  image: python:3.12-slim
  script:
    - pip install mcpnuke
    - mcpnuke --targets $MCP_TARGET
        --fast --no-invoke
        --fail-on high
        --generate-policy policy.yaml
        --json report.json
        --sarif results.sarif
  artifacts:
    paths:
      - report.json
      - results.sarif
      - policy.yaml
    reports:
      sast: results.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## Generic CI (Jenkins, CircleCI, etc.)

```bash
#!/bin/bash
# ci-scan.sh — run in any CI environment

set -e

pip install mcpnuke

# Scan with --fail-on controlling exit code (no shell parsing needed)
mcpnuke --targets "$MCP_TARGET" \
  --fast --no-invoke \
  --fail-on high \
  --generate-policy policy.yaml \
  --json report.json \
  --sarif results.sarif

# Exit 0 = clean, 1 = findings >= HIGH, 2 = scanner error
echo "Scan complete. See report.json and results.sarif."
```

---

## Scan Modes for CI

| Mode | Flag | Time | Cost | When to Use |
|------|------|------|------|-------------|
| Static | `--fast --no-invoke` | <1s | $0 | Every PR (default) |
| AI-enhanced | `--fast --no-invoke --claude` | ~25s | ~$0.05 | Weekly deep scan |
| Full behavioral | `--fast` | 90s+ | ~$0.20 | Pre-release gate |

**Recommendation:** Run static on every PR (instant, free). Run Claude-enhanced
weekly or on release branches. Run full behavioral only before production deploys.

---

## Baseline Management

```bash
# Save baseline after a clean main branch scan
mcpnuke --targets $TARGET --fast --no-invoke \
  --save-baseline baseline.json

# On PRs, compare against baseline
mcpnuke --targets $TARGET --fast --no-invoke \
  --baseline baseline.json

# New findings not in the baseline = regressions
# Resolved findings = improvements
```

Store `baseline.json` as a CI artifact or commit it to the repo.

### Priority-action / policy goldens (Slice D)

Unit CI also runs offline fixtures under `tests/fixtures/scans/` via
`tests/test_lab_baselines.py`. These are **not** differential baselines —
they freeze the contracts that proved chains outrank capability spam and that
`--generate-policy` still emits DENY(sink)+HOLD(source*). Regenerate fixtures
from Camazotz/DVMCP scans when intentionally changing those contracts; do not
point them at golden-image VMs.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MCP_TARGET` | Yes | URL of the MCP server to scan |
| `ANTHROPIC_API_KEY` | No | For `--claude` mode only |
| `MCP_AUTH_TOKEN` | No | Bearer token for authenticated MCP servers |

---

## Policy Artifact

When `--generate-policy` is used, the output `policy.yaml` is a
ready-to-apply NullfieldPolicy. In a GitOps workflow:

```bash
# CI generates the policy
mcpnuke --targets $TARGET --generate-policy suggested-policy.yaml

# Developer reviews and applies
kubectl apply -f suggested-policy.yaml

# Or commit to repo for GitOps
cp suggested-policy.yaml deploy/nullfield/policy.yaml
git add deploy/nullfield/policy.yaml
git commit -m "security: apply mcpnuke-recommended policy"
```

---

## Cross-Project Coverage Reports

Use `--coverage-report` in CI to publish a per-lane coverage diff against
a running camazotz instance (typically a staging deployment exposing
`/api/lanes` schema v1). Vocabulary follows
[ADR 0001](https://github.com/babywyrm/camazotz/blob/main/docs/adr/0001-five-transport-taxonomy.md)
(transports A–E).

```bash
mcpnuke --targets "$MCP_TARGET" \
  --fast --no-invoke \
  --coverage-report "$CAMAZOTZ_URL" \
  --json report.json
```

**Exit code semantics for `--coverage-report`:** the flag is
**diagnostic-only** and does **not** influence mcpnuke's exit code.
Uncovered lanes, schema mismatches, and even HTTP failures fetching
`<CAMAZOTZ_URL>/api/lanes` are printed in red but the scan still exits
based purely on finding severity:

| Code | Meaning |
|------|---------|
| `0` | Clean scan — no findings at or above `--fail-on` threshold (default: HIGH) |
| `1` | At least one finding at or above threshold |
| `2` | Scanner error (target unreachable, invalid args, unhandled exception) |

If you want a CI gate that fails when camazotz declares lanes mcpnuke
isn't covering yet, post-process the `--json` report or the printed
"widest gap" line — don't rely on the exit code to encode that signal.

**`--claude` in coverage workflows:** `--claude` still **fails loud**
when `ANTHROPIC_API_KEY` is unset (exit `2` *before* any scan runs). If
your CI matrix lacks the key, drop `--claude` rather than expecting
silent degradation; mcpnuke will not run a `[cloud-stub]`-style fallback.

---

## mcpnuke-runner (Kubernetes / Camazotz)

`mcpnuke-runner` is a lightweight sidecar that runs scheduled or on-demand
scans within Kubernetes, integrating with the camazotz scan queue.

### Architecture

```
camazotz API → mcpnuke-runner Pod → mcpnuke scan → POST results back
```

The runner polls `camazotz /api/scan-queue` every N seconds, picks up
pending scan jobs (target URL + profile + options), executes mcpnuke,
and posts structured JSON results back.

### Deployment (Helm)

```yaml
# values.yaml snippet
mcpnukeRunner:
  enabled: true
  image: ghcr.io/babywyrm/mcpnuke:latest
  pollIntervalSeconds: 30
  defaultScanMode: static          # static | ai | full
  failOn: high                     # --fail-on threshold for result tagging
  sarifUpload: true                # attach SARIF to results payload
  resources:
    requests: { cpu: 100m, memory: 128Mi }
    limits:   { cpu: 500m, memory: 512Mi }
```

```bash
# Deploy or upgrade
helm upgrade --install camazotz ./deploy/helm/camazotz \
  --set mcpnukeRunner.enabled=true \
  --set mcpnukeRunner.failOn=high
```

### Environment Variables (runner pod)

| Variable | Default | Description |
|----------|---------|-------------|
| `CAMAZOTZ_URL` | required | camazotz API base URL |
| `CAMAZOTZ_API_KEY` | required | API key for posting results |
| `MCPNUKE_FAIL_ON` | `high` | Severity threshold for tagging a job as failed |
| `MCPNUKE_SARIF` | `false` | Attach SARIF 2.1.0 to results payload |
| `ANTHROPIC_API_KEY` | optional | Enable `--claude` AI-enhanced scans |
| `POLL_INTERVAL` | `30` | Seconds between queue polls |

### Running a manual scan via runner API

```bash
# Trigger an on-demand scan through camazotz
curl -X POST https://camazotz.example.com/api/scan-queue \
  -H "Authorization: Bearer $CAMAZOTZ_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://mcp-server:8080/mcp",
    "profile": "profiles/camazotz.json",
    "scan_mode": "static",
    "fail_on": "high"
  }'
```

### Reading runner logs

```bash
kubectl logs -n camazotz deploy/mcpnuke-runner -f
```

Structured log lines include `scan_id`, `target`, `findings_count`,
`severity_counts`, `exit_code`, and `duration_ms`.

