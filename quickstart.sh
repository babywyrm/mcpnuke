#!/usr/bin/env bash
set -euo pipefail

# mcpvenom quickstart — sets up venv, installs deps, runs tests, shows usage
# Usage: ./quickstart.sh [--skip-tests] [--with-dvmcp]

SKIP_TESTS=false
WITH_DVMCP=false

for arg in "$@"; do
    case "$arg" in
        --skip-tests)  SKIP_TESTS=true ;;
        --with-dvmcp)  WITH_DVMCP=true ;;
        -h|--help)
            echo "Usage: ./quickstart.sh [--skip-tests] [--with-dvmcp]"
            echo ""
            echo "Options:"
            echo "  --skip-tests   Skip running the test suite"
            echo "  --with-dvmcp   Clone and set up DVMCP challenge servers"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (try --help)"
            exit 1
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

banner() { echo -e "\n${CYAN}${BOLD}▶ $1${NC}"; }
ok()     { echo -e "  ${GREEN}✓${NC} $1"; }
warn()   { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail()   { echo -e "  ${RED}✗${NC} $1"; exit 1; }

echo -e "${BOLD}"
echo "  ┌──────────────────────────────────────┐"
echo "  │  mcpvenom — quickstart             │"
echo "  │  MCP Red Teaming & Security Scanner  │"
echo "  └──────────────────────────────────────┘"
echo -e "${NC}"

# ── Check prerequisites ──────────────────────────────────────────────────

banner "Checking prerequisites"

if command -v uv &>/dev/null; then
    ok "uv $(uv --version 2>/dev/null | head -1)"
    PKG_MGR="uv"
elif command -v pip &>/dev/null; then
    ok "pip $(pip --version 2>/dev/null | awk '{print $2}')"
    PKG_MGR="pip"
else
    fail "Neither uv nor pip found. Install uv: https://docs.astral.sh/uv/getting-started/installation/"
fi

PYTHON_CMD=""
for py in python3.13 python3.12 python3.11 python3; do
    if command -v "$py" &>/dev/null; then
        ver=$("$py" --version 2>&1 | awk '{print $2}')
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON_CMD="$py"
            ok "Python $ver ($py)"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    fail "Python >= 3.11 required. Found: $(python3 --version 2>&1 || echo 'none')"
fi

# ── Create virtual environment ───────────────────────────────────────────

banner "Setting up virtual environment"

if [ "$PKG_MGR" = "uv" ]; then
    if [ ! -d ".venv" ]; then
        uv venv --python "$PYTHON_CMD" .venv
        ok "Created .venv"
    else
        ok "Existing .venv found"
    fi
else
    if [ ! -d ".venv" ]; then
        "$PYTHON_CMD" -m venv .venv
        ok "Created .venv"
    else
        ok "Existing .venv found"
    fi
fi

# Activate for the rest of this script (needed for pytest, etc.)
# shellcheck disable=SC1091
source .venv/bin/activate
ok "Activated .venv ($(python --version))"

# ── Install mcpvenom ───────────────────────────────────────────────────

banner "Installing mcpvenom + all dependencies"

if [ "$PKG_MGR" = "uv" ]; then
    uv sync --all-extras 2>&1 | tail -5
    ok "mcpvenom installed (uv sync --all-extras)"
else
    pip install -e ".[dev,ai,k8s]" 2>&1 | tail -3
    ok "mcpvenom installed (pip editable)"
fi

# Verify CLI entry point
ok "CLI wrapper: ./scan"
if [ -f "./scan" ]; then
    chmod +x ./scan
fi

# ── Run tests ────────────────────────────────────────────────────────────

if [ "$SKIP_TESTS" = false ]; then
    banner "Running test suite"
    if python -m pytest tests/ -v --tb=short -q 2>&1; then
        ok "All tests passed"
    else
        warn "Some tests failed — check output above"
    fi
else
    banner "Skipping tests (--skip-tests)"
fi

# ── Optional: DVMCP setup ───────────────────────────────────────────────

if [ "$WITH_DVMCP" = true ]; then
    banner "Setting up DVMCP challenge servers"

    DVMCP_DIR="tests/test_targets/DVMCP"
    if [ -d "$DVMCP_DIR" ]; then
        ok "DVMCP already cloned at $DVMCP_DIR"
    else
        echo -e "  ${DIM}Cloning DVMCP...${NC}"
        git clone --depth 1 https://github.com/harishsg993010/damn-vulnerable-MCP-server.git "$DVMCP_DIR"
        ok "Cloned DVMCP to $DVMCP_DIR"
    fi

    echo -e "  ${DIM}To start DVMCP servers:${NC}"
    echo -e "    cd $DVMCP_DIR && pip install -r requirements.txt"
    echo -e "    # Then start individual challenges on ports 9001-9010"
    echo ""
    echo -e "  ${DIM}To run live DVMCP tests:${NC}"
    echo -e "    DVMCP_LIVE=1 pytest tests/test_dvmcp.py -v"
fi

# ── Print usage ──────────────────────────────────────────────────────────

banner "Ready to go!"

echo ""
echo -e "  ${BOLD}Quick commands (no activation needed):${NC}"
echo ""
echo -e "  ${GREEN}# Scan a target${NC}"
echo "  ./scan --targets http://localhost:9090"
echo "  uv run mcpvenom --targets http://localhost:9090"
echo ""
echo -e "  ${GREEN}# Scan DVMCP challenges (ports 9001-9010)${NC}"
echo "  ./scan --port-range localhost:9001-9010 --verbose"
echo ""
echo -e "  ${GREEN}# Static-only mode (safe for prod)${NC}"
echo "  ./scan --targets http://prod-server:8080 --no-invoke"
echo ""
echo -e "  ${GREEN}# JSON report output${NC}"
echo "  ./scan --targets http://localhost:9090 --json report.json"
echo ""
echo -e "  ${GREEN}# Run tests${NC}"
echo "  uv run pytest tests/ -v"
echo ""
echo -e "  ${GREEN}# Run DVMCP challenge tests (offline)${NC}"
echo "  uv run pytest tests/test_dvmcp.py -v"
echo ""
echo -e "  ${DIM}uv run handles the venv automatically — no activation needed.${NC}"
echo -e "  ${DIM}./scan is a shortcut that does the same thing.${NC}"
echo ""
echo -e "  ${DIM}See README.md for full documentation.${NC}"
echo ""
