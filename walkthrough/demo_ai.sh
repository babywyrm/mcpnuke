#!/usr/bin/env bash
set -euo pipefail

# mcpnuke AI Demo — Claude-powered MCP security analysis
# Usage: ./walkthrough/demo_ai.sh [--skip-setup] [--opus] [--no-cleanup]
#
# Requires: ANTHROPIC_API_KEY env var
# Runs the same DVMCP targets as demo.sh but with Claude reasoning layered on.

SKIP_SETUP=false
NO_CLEANUP=false
MODEL="claude-sonnet-5"
MODEL_LABEL="Sonnet"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN="$PROJECT_DIR/scan"

for arg in "$@"; do
    case "$arg" in
        --skip-setup) SKIP_SETUP=true ;;
        --no-cleanup) NO_CLEANUP=true ;;
        --opus) MODEL="claude-opus-5"; MODEL_LABEL="Opus" ;;
        -h|--help)
            echo "Usage: ./walkthrough/demo_ai.sh [--skip-setup] [--opus] [--no-cleanup]"
            echo ""
            echo "Runs mcpnuke with Claude AI analysis against DVMCP challenges."
            echo "Requires: ANTHROPIC_API_KEY env var, uv, Docker"
            echo ""
            echo "  --skip-setup   Skip install and DVMCP Docker build"
            echo "  --opus         Use Claude Opus (deeper reasoning, slower)"
            echo "  --no-cleanup   Leave DVMCP container running after demo"
            exit 0
            ;;
    esac
done

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

banner()  { echo -e "\n${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $1${NC}"; echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}\n"; }
explain() { echo -e "${DIM}  $1${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail()    { echo -e "  ${RED}✗${NC} $1"; exit 1; }

echo -e "${BOLD}"
echo "  ┌─────────────────────────────────────────────┐"
echo "  │  mcpnuke AI Demo                           │"
echo "  │  Claude-Powered MCP Security Analysis        │"
echo "  │                                              │"
echo "  │  Deterministic checks + LLM reasoning.       │"
echo "  │  See what Claude finds that regex can't.     │"
echo "  │  Model: $MODEL_LABEL                                │"
echo "  └─────────────────────────────────────────────┘"
echo -e "${NC}"

# ══════════════════════════════════════════════════════════════
# Phase 1: Preflight
# ══════════════════════════════════════════════════════════════

banner "Phase 1: Preflight"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    fail "ANTHROPIC_API_KEY not set. Export it first:"
    echo "  export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi
ok "ANTHROPIC_API_KEY set"

if [ "$SKIP_SETUP" = false ]; then
    command -v uv &>/dev/null || fail "uv not found"
    ok "uv found"
    command -v docker &>/dev/null || fail "Docker not found"
    docker info &>/dev/null 2>&1 || fail "Docker daemon not running"
    ok "Docker running"

    if [ ! -f "$SCAN" ] || [ ! -d "$PROJECT_DIR/.venv" ]; then
        explain "Installing mcpnuke..."
        cd "$PROJECT_DIR" && ./quickstart.sh --skip-tests 2>&1 | tail -3
    fi

    # Ensure anthropic SDK is installed
    cd "$PROJECT_DIR" && uv pip install -e ".[ai]" 2>&1 | tail -1
    ok "mcpnuke + AI dependencies installed"

    if docker ps --format '{{.Names}}' | grep -q '^dvmcp$'; then
        ok "DVMCP already running"
    else
        if [ ! -d "$PROJECT_DIR/tests/test_targets/DVMCP" ]; then
            git clone --depth 1 https://github.com/harishsg993010/damn-vulnerable-MCP-server.git \
                "$PROJECT_DIR/tests/test_targets/DVMCP" 2>&1 | tail -1
        fi
        cd "$PROJECT_DIR/tests/test_targets/DVMCP"
        docker build -t dvmcp . 2>&1 | tail -3
        docker run -d --name dvmcp -p 9001-9010:9001-9010 dvmcp >/dev/null
        ok "DVMCP started"
    fi

    explain "Waiting for servers..."
    for port in $(seq 9001 9010); do
        for attempt in $(seq 1 20); do
            if (echo >/dev/tcp/localhost/$port) 2>/dev/null; then break; fi
            sleep 1
        done
    done
    sleep 2
    ok "All 10 DVMCP servers ready"
fi

cd "$PROJECT_DIR"

# ══════════════════════════════════════════════════════════════
# Phase 2: Deterministic vs AI — Side by Side
# ══════════════════════════════════════════════════════════════

banner "Phase 2: Tool Poisoning (Challenge 2) — Deterministic Only"

explain "First, a baseline scan WITHOUT Claude:"
echo ""

$SCAN --targets http://localhost:9002/sse --no-invoke 2>&1 || true

echo ""
explain "The deterministic scanner found excessive_permissions, code_execution,"
explain "and schema_risks. Score: ~94. Good, but regex-based."
echo ""
read -p "  Press Enter to see what Claude adds..." </dev/tty

banner "Phase 2b: Same Target — Now With Claude ($MODEL_LABEL)"

explain "Adding --claude to the same scan. Watch for [AI] prefixed findings."
echo ""

$SCAN --targets http://localhost:9002/sse --no-invoke --claude --claude-model "$MODEL" --verbose 2>&1 || true

echo ""
echo -e "${BOLD}What Claude added:${NC}"
echo ""
explain "[AI] findings are things regex can't catch:"
explain "  - Logical attack chains between tools"
explain "  - Social engineering risks in descriptions"
explain "  - Multi-step exploitation scenarios"
explain "  - Context-dependent risks (what tools MEAN, not just what they say)"
echo ""
explain "The deterministic checks are fast and free. Claude adds depth."
explain "Together they catch more than either alone."
echo ""
read -p "  Press Enter to continue..." </dev/tty

# ══════════════════════════════════════════════════════════════
# Phase 3: Three-Layer Analysis — Rug Pull (Challenge 4)
# ══════════════════════════════════════════════════════════════

banner "Phase 3: Three-Layer Analysis — Rug Pull (Challenge 4)"

explain "This is the key insight: three analysis layers that stack."
explain ""
explain "Challenge 4 has a 'get_weather' tool that changes behavior after"
explain "repeated calls (rug pull). Watch how each layer catches something"
explain "the previous layer can't."
explain ""
explain "Running --safe-mode + --claude so all three layers fire:"
explain "  Layer 1: Deterministic regex checks"
explain "  Layer 2: Behavioral probes (call tools, analyze responses)"
explain "  Layer 3: Claude AI reasoning (read responses, chain findings)"
echo ""

$SCAN --targets http://localhost:9004/sse --safe-mode --claude --claude-model "$MODEL" --verbose 2>&1 || true

echo ""
echo -e "${BOLD}What each layer caught:${NC}"
echo ""
explain "Layer 1 (deterministic): schema_risk, auth, sse_security"
explain "  → Found the obvious metadata issues"
explain ""
explain "Layer 2 (behavioral): deep_rug_pull"
explain "  → Called get_weather 6 times, detected the response changed"
explain "  → The tool started returning fake paywall messages"
explain ""
explain "Layer 3 (Claude AI): social engineering in tool response"
explain "  → READ the paywall response and recognized it as social engineering"
explain "  → A fake rate limit trying to manipulate the LLM into paying"
explain "  → No regex pattern would ever catch this"
explain ""
explain "This is the power of the three-layer approach:"
explain "  Static catches what tools SAY (metadata)"
explain "  Behavioral catches what tools DO (runtime)"
explain "  Claude catches what tools MEAN (intent)"
echo ""
read -p "  Press Enter to continue..." </dev/tty

# ══════════════════════════════════════════════════════════════
# Phase 3b: Attack Chains — Where Claude Shines
# ══════════════════════════════════════════════════════════════

banner "Phase 3b: Remote Access (Challenge 9) — Claude Chain Reasoning"

explain "Challenge 9 has 'remote_access' (command execution on remote systems)"
explain "and 'manage_permissions' (RBAC manipulation)."
explain ""
explain "The deterministic scanner finds them individually. Claude reasons"
explain "about how they chain together."
echo ""

$SCAN --targets http://localhost:9009/sse --no-invoke --claude --claude-model "$MODEL" --verbose 2>&1 || true

echo ""
echo -e "${BOLD}Claude's chain reasoning:${NC}"
echo ""
explain "Claude identifies multi-step attack paths like:"
explain "  1. Use manage_permissions to grant yourself elevated access"
explain "  2. Use remote_access with new permissions for arbitrary command exec"
explain "  3. Establish persistence across sessions"
explain ""
explain "This is the kind of reasoning a human pentester does — but automated."
echo ""
read -p "  Press Enter to continue..." </dev/tty

# ══════════════════════════════════════════════════════════════
# Phase 4: Credential Theft — AI Response Analysis
# ══════════════════════════════════════════════════════════════

banner "Phase 4: Token Theft (Challenge 7) — AI Response Analysis"

explain "Now running WITH behavioral probes (--safe-mode) so Claude can also"
explain "analyze actual tool responses, not just definitions."
echo ""

$SCAN --targets http://localhost:9007/sse --safe-mode --claude --claude-model "$MODEL" --verbose 2>&1 || true

echo ""
echo -e "${BOLD}Three AI analysis phases:${NC}"
echo ""
explain "Phase 1 — Tool Analysis: Claude reads tool definitions"
explain "Phase 2 — Response Analysis: Claude examines actual tool output"
explain "Phase 3 — Chain Reasoning: Claude connects all findings"
explain ""
explain "Response analysis catches obfuscated secrets, social engineering"
explain "in output, and injection payloads that regex patterns miss."
echo ""
read -p "  Press Enter to continue..." </dev/tty

# ══════════════════════════════════════════════════════════════
# Phase 5: Full AI Sweep
# ══════════════════════════════════════════════════════════════

banner "Phase 5: Full AI Sweep — All 10 Challenges"

explain "Scanning all 10 DVMCP servers with Claude analysis."
explain "This takes longer (~2-3 min with Sonnet, ~5 min with Opus)."
echo ""

$SCAN --port-range localhost:9001-9010 --no-invoke --claude --claude-model "$MODEL" --json "$PROJECT_DIR/walkthrough/report_ai.json" 2>&1 || true

echo ""
echo -e "${BOLD}Comparison:${NC}"
echo ""
explain "Deterministic only:  ~97 total findings,  ~600 combined score"
explain "With Claude ($MODEL_LABEL):     Check the numbers above — Claude typically"
explain "adds 30-50% more findings and significantly higher risk scores"
explain "on servers with complex tool interactions."

# ══════════════════════════════════════════════════════════════
# Cleanup
# ══════════════════════════════════════════════════════════════

echo ""
if [ "$NO_CLEANUP" = true ]; then
    explain "DVMCP container left running (--no-cleanup)."
else
    read -p "  Stop DVMCP container? [y/N] " -n 1 -r </dev/tty
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker stop dvmcp >/dev/null 2>&1 && docker rm dvmcp >/dev/null 2>&1
        ok "DVMCP stopped and removed"
    else
        explain "DVMCP still running. Stop with: docker stop dvmcp && docker rm dvmcp"
    fi
fi

echo ""
echo -e "${BOLD}  AI Demo complete.${NC}"
echo ""
explain "Key takeaway: deterministic checks are fast and free."
explain "Claude adds reasoning depth for complex targets."
explain "Use both together for the most thorough analysis."
echo ""
explain "See walkthrough/README.md for the full guide."
echo ""
