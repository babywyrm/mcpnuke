#!/usr/bin/env bash
set -euo pipefail

# mcpvenom DVMCP demo — zero to findings in 60 seconds
# Usage: ./walkthrough/demo.sh [--skip-setup] [--no-cleanup]

SKIP_SETUP=false
NO_CLEANUP=false
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN="$PROJECT_DIR/scan"

for arg in "$@"; do
    case "$arg" in
        --skip-setup) SKIP_SETUP=true ;;
        --no-cleanup) NO_CLEANUP=true ;;
        -h|--help)
            echo "Usage: ./walkthrough/demo.sh [--skip-setup] [--no-cleanup]"
            echo ""
            echo "Runs mcpvenom against all 10 DVMCP challenges with annotated output."
            echo "Requires: uv, Docker"
            echo ""
            echo "  --skip-setup   Skip mcpvenom install and DVMCP Docker build"
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
echo "  │  mcpvenom DVMCP Demo                        │"
echo "  │  MCP Red Teaming — Live Walkthrough         │"
echo "  │                                             │"
echo "  │  10 vulnerable MCP servers. 1 scanner.      │"
echo "  │  See what mcpvenom finds and why it matters.│"
echo "  └─────────────────────────────────────────────┘"
echo -e "${NC}"

# ══════════════════════════════════════════════════════════════
# Phase 1: Setup
# ══════════════════════════════════════════════════════════════

if [ "$SKIP_SETUP" = false ]; then
    banner "Phase 1: Setup"

    # Check prerequisites
    command -v uv &>/dev/null || fail "uv not found. Install: https://docs.astral.sh/uv/"
    ok "uv found"
    command -v docker &>/dev/null || fail "Docker not found"
    docker info &>/dev/null 2>&1 || fail "Docker daemon not running"
    ok "Docker running"

    # Install mcpvenom if needed
    if [ ! -f "$SCAN" ] || [ ! -d "$PROJECT_DIR/.venv" ]; then
        explain "Installing mcpvenom..."
        cd "$PROJECT_DIR" && ./quickstart.sh --skip-tests 2>&1 | tail -3
    else
        ok "mcpvenom already installed"
    fi

    # Start DVMCP if not running
    if docker ps --format '{{.Names}}' | grep -q '^dvmcp$'; then
        ok "DVMCP already running"
    else
        explain "Building DVMCP Docker image..."
        if [ -d "$PROJECT_DIR/tests/test_targets/DVMCP" ]; then
            cd "$PROJECT_DIR/tests/test_targets/DVMCP"
        else
            explain "Cloning DVMCP..."
            git clone --depth 1 https://github.com/harishsg993010/damn-vulnerable-MCP-server.git \
                "$PROJECT_DIR/tests/test_targets/DVMCP" 2>&1 | tail -1
            cd "$PROJECT_DIR/tests/test_targets/DVMCP"
        fi
        docker build -t dvmcp . 2>&1 | tail -3
        ok "DVMCP image built"

        explain "Starting 10 vulnerable MCP servers on ports 9001-9010..."
        docker run -d --name dvmcp -p 9001-9010:9001-9010 dvmcp >/dev/null
        ok "DVMCP container started"
    fi

    # Wait for servers to be ready (TCP check — SSE endpoints hang on GET)
    explain "Waiting for all 10 servers..."
    for port in $(seq 9001 9010); do
        for attempt in $(seq 1 20); do
            if (echo >/dev/tcp/localhost/$port) 2>/dev/null; then
                break
            fi
            sleep 1
        done
    done
    sleep 2
    ok "All 10 DVMCP servers are up"
fi

cd "$PROJECT_DIR"

# ══════════════════════════════════════════════════════════════
# Phase 2: Your First Scan — Challenge 1 (Prompt Injection)
# ══════════════════════════════════════════════════════════════

banner "Phase 2: Your First Scan — Challenge 1 (Prompt Injection)"

explain "Scanning a single MCP server in static-only mode."
explain "This only analyzes metadata — no tools are actually called."
explain ""
explain "Command: ./scan --targets http://localhost:9001/sse --no-invoke"
echo ""

$SCAN --targets http://localhost:9001/sse --no-invoke 2>&1 || true

echo ""
echo -e "${BOLD}What mcpvenom found:${NC}"
echo ""
explain "auth HIGH — The server accepted an MCP initialize request with no"
explain "credentials at all. Anyone on the network can connect and enumerate tools."
explain ""
explain "sse_security HIGH — The SSE event stream is open without authentication."
explain "An attacker can subscribe and see all server events."
explain ""
explain "schema_risk MEDIUM — The 'username' parameter in 'get_user_info' has no"
explain "maxLength constraint. Unbounded strings are injection surfaces."
explain ""
explain "actuator_probe MEDIUM — /openapi.json is exposed, giving attackers a"
explain "complete map of the server's API surface."
echo ""
explain "Risk score: 26 (HIGH overall). Two HIGH findings drive the score."
explain "Score formula: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1"
echo ""
read -p "  Press Enter to continue..." </dev/tty

# ══════════════════════════════════════════════════════════════
# Phase 3: Dangerous Tools — Challenges 2-3
# ══════════════════════════════════════════════════════════════

banner "Phase 3: Dangerous Tools — Challenges 2-3"

explain "Challenge 2 has 'execute_command' and 'read_file' — tools that"
explain "should never be exposed without strict controls."
explain "Challenge 3 has 'file_manager' with read/write/delete on the filesystem."
explain ""
explain "Static checks catch what tools SAY they can do — before calling them."
echo ""

$SCAN --targets http://localhost:9002/sse http://localhost:9003/sse --no-invoke 2>&1 || true

echo ""
echo -e "${BOLD}Key findings:${NC}"
echo ""
explain "excessive_permissions CRITICAL — Tools named 'execute_command' and"
explain "'read_file' match dangerous capability patterns (shell, filesystem)."
explain "This is MCP-T03: tools with more power than users should have."
explain ""
explain "code_execution CRITICAL — The tool has a 'command' parameter and its"
explain "description mentions execution. Classic RCE surface."
explain ""
explain "schema_risk CRITICAL — A parameter literally named 'command' in the"
explain "input schema. The server is advertising code execution as a feature."
echo ""
read -p "  Press Enter to continue..." </dev/tty

# ══════════════════════════════════════════════════════════════
# Phase 4: Credential Theft — Challenges 5, 7
# ══════════════════════════════════════════════════════════════

banner "Phase 4: Credential Theft — Challenges 5, 7"

explain "Challenge 5 has tools with user role checking."
explain "Challenge 7 has 'authenticate' and 'verify_token' — tools that"
explain "accept passwords and tokens as parameters."
echo ""

$SCAN --targets http://localhost:9005/sse http://localhost:9007/sse --no-invoke 2>&1 || true

echo ""
echo -e "${BOLD}Key findings:${NC}"
echo ""
explain "token_theft CRITICAL — The 'authenticate' tool accepts a 'password'"
explain "parameter. Any content that reaches the LLM context could trick it"
explain "into passing real credentials through this tool. (MCP-T07)"
explain ""
explain "token_theft HIGH — 'verify_token' accepts a 'token' parameter."
explain "Combined with prompt injection, an attacker could exfiltrate session tokens."
echo ""
read -p "  Press Enter to continue..." </dev/tty

# ══════════════════════════════════════════════════════════════
# Phase 5: Attack Chains — Challenges 9-10
# ══════════════════════════════════════════════════════════════

banner "Phase 5: Attack Chains — Challenges 9-10"

explain "Challenge 9 has 'remote_access' (command injection) + 'manage_permissions'."
explain "Challenge 10 combines multiple vulnerability classes."
explain ""
explain "mcpvenom detects when findings CHAIN together into compound attacks."
echo ""

$SCAN --targets http://localhost:9009/sse http://localhost:9010/sse --no-invoke 2>&1 || true

echo ""
echo -e "${BOLD}Key findings:${NC}"
echo ""
explain "multi_vector CRITICAL — Multiple dangerous check categories are active"
explain "on the same server. This multiplies the risk: an attacker has multiple"
explain "entry points and can pivot between them."
explain ""
explain "attack_chain CRITICAL — Linked vulnerability pairs detected:"
explain "  code_execution → token_theft: RCE used to steal credentials"
explain "  actuator_probe → token_theft: leaked config enables token forgery"
explain ""
explain "Risk score 134 on port 9009 — the highest in DVMCP. Compare to"
explain "port 9001's score of 26. Attack chains multiply severity."
echo ""
read -p "  Press Enter to continue..." </dev/tty

# ══════════════════════════════════════════════════════════════
# Phase 6: Full Sweep — All 10 Challenges
# ══════════════════════════════════════════════════════════════

banner "Phase 6: Full Sweep — All 10 Challenges"

explain "Scanning all 10 DVMCP servers at once."
explain "JSON report saved to walkthrough/report.json."
echo ""

$SCAN --port-range localhost:9001-9010 --no-invoke --json "$PROJECT_DIR/walkthrough/report.json" 2>&1 || true

echo ""
echo -e "${BOLD}Summary:${NC}"
echo ""
explain "All 10 servers scanned. Every one has findings."
explain "The JSON report at walkthrough/report.json contains the full"
explain "structured output — use it for CI integration, dashboards,"
explain "or feeding into your own analysis tools."
explain ""
explain "Exit code 1 means CRITICAL or HIGH findings were detected."
explain "Use this in CI pipelines to gate MCP server deployments."

# ══════════════════════════════════════════════════════════════
# Phase 7: Taxonomy Scoreboard
# ══════════════════════════════════════════════════════════════

banner "Phase 7: MCP Threat Taxonomy Coverage"

echo -e "${BOLD}  DVMCP Challenge → MCP Threat Taxonomy Mapping${NC}"
echo ""
echo "  Challenge  Port   Taxonomy   What mcpvenom detects"
echo "  ─────────  ────   ────────   ─────────────────────────────────────"
echo "  1          9001   MCP-T01    Prompt injection in tool metadata"
echo "  2          9002   MCP-T02    Tool poisoning, hidden instructions"
echo "  3          9003   MCP-T03    Excessive permissions, confused deputy"
echo "  4          9004   MCP-T05    Rug pull, tool mutation after calls"
echo "  5          9005   MCP-T05    Tool shadowing, name collisions"
echo "  6          9006   MCP-T02    Indirect injection via data sources"
echo "  7          9007   MCP-T07    Token theft, credential parameters"
echo "  8          9008   MCP-T06    Code execution, eval on user input"
echo "  9          9009   MCP-T06    Remote access, command injection"
echo "  10         9010   Multi      Multi-vector, chained vulnerabilities"
echo ""
explain "Full taxonomy reference:"
explain "https://github.com/babywyrm/sysadmin/tree/master/mcp/redteam"

# ══════════════════════════════════════════════════════════════
# Cleanup
# ══════════════════════════════════════════════════════════════

echo ""
if [ "$NO_CLEANUP" = true ]; then
    echo -e "${DIM}  DVMCP container left running (--no-cleanup).${NC}"
    echo -e "${DIM}  Stop with: docker stop dvmcp && docker rm dvmcp${NC}"
else
    echo ""
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
echo -e "${BOLD}  Demo complete. See walkthrough/README.md for the full guide.${NC}"
echo ""
