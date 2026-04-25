# CI/CD Pipeline Integration

Run mcpnuke as a security gate in your CI/CD pipeline. Fail builds on
CRITICAL findings, generate nullfield policy, and track regressions.

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
            --generate-policy policy.yaml \
            --json report.json

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-scan
          path: |
            report.json
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
        --generate-policy policy.yaml
        --json report.json
  artifacts:
    paths:
      - report.json
      - policy.yaml
    reports:
      codequality: report.json
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

# Scan (static, fast)
mcpnuke --targets "$MCP_TARGET" \
  --fast --no-invoke \
  --generate-policy policy.yaml \
  --json report.json

# Check for CRITICAL findings
CRITICAL=$(python3 -c "
import json
d = json.load(open('report.json'))
print(sum(1 for f in d['targets'][0]['findings'] if f['severity']=='CRITICAL'))
")

echo "Critical findings: $CRITICAL"

if [ "$CRITICAL" -gt 0 ]; then
  echo "FAIL: $CRITICAL critical findings detected"
  exit 1
fi

echo "PASS: No critical findings"
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
