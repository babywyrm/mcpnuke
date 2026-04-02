# mcpnuke Quickstart Scenarios

Practical command recipes for common workflows.

## 0) Setup

```bash
git clone https://github.com/babywyrm/mcpnuke.git
cd mcpnuke
./quickstart.sh
```

## 1) Camazotz (Regular Flow)

Use this when you want realistic, high-signal scans with full behavioral coverage.

```bash
./scan \
  --targets "http://192.168.1.114:30080/mcp" \
  --fast \
  --claude \
  --probe-calls 5 \
  --claude-max-tools 8 \
  --claude-phase2-workers 2 \
  --verbose \
  --json "camazotz-nuc-fast-ai-regular.json"
```

## 2) Camazotz (Deterministic Benchmarking)

Use this for tighter run-to-run comparisons. `--deterministic` forces stable ordering and single-thread deep probe / AI phase-2 execution.

```bash
./scan \
  --targets "http://192.168.1.114:30080/mcp" \
  --fast \
  --claude \
  --probe-calls 5 \
  --claude-max-tools 8 \
  --claude-phase2-workers 2 \
  --deterministic \
  --verbose \
  --json "camazotz-nuc-fast-ai-deterministic.json"
```

## 3) Camazotz (Bedrock Variation)

Optional backend variation when validating AWS Bedrock integration.

```bash
./scan \
  --targets "http://192.168.1.114:30080/mcp" \
  --fast \
  --claude \
  --bedrock \
  --bedrock-region us-east-1 \
  --claude-max-tools 8 \
  --claude-phase2-workers 2 \
  --verbose \
  --json "camazotz-nuc-fast-ai-bedrock.json"
```

## 4) DVMCP Bring-Up + Scan

Start local DVMCP challenge targets, then scan all 10 challenge ports.

```bash
./tests/dvmcp_reset.sh --setup-only

./scan \
  --targets \
  "http://localhost:9001/sse" "http://localhost:9002/sse" "http://localhost:9003/sse" \
  "http://localhost:9004/sse" "http://localhost:9005/sse" "http://localhost:9006/sse" \
  "http://localhost:9007/sse" "http://localhost:9008/sse" "http://localhost:9009/sse" \
  "http://localhost:9010/sse" \
  --fast \
  --deterministic \
  --verbose \
  --json "dvmcp-local-fast-deterministic.json"
```

## 5) Static-Only Safety Pass

Use for production endpoints where invoking tools is not acceptable.

```bash
./scan --targets "https://target.example/mcp" --no-invoke --verbose --json "static-only.json"
```

## 6) Repeatability Loop (Manual)

For consistency checks, reset target state between runs and compare:

- `total_findings`
- `risk_score`
- severity mix
- attack-chain count
- per-check drift

Recommended:

- benchmarking: use `--deterministic`
- adversarial realism: use regular flow (non-deterministic)

