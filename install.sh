#!/usr/bin/env bash
#
# mcpnuke installer — for people who want the tool, not the repo.
#
#   curl -LsSf https://raw.githubusercontent.com/babywyrm/mcpnuke/main/install.sh | bash
#
# For working *on* mcpnuke, clone the repo and run ./quickstart.sh instead;
# that sets up a dev venv with all the extras and runs the test suite.
#
# mcpnuke is an application rather than a library, so every method here gives
# it an isolated environment. That is what stops the scanner's dependency
# pins arguing with whatever else a user has in their Python.

set -euo pipefail

PACKAGE="mcpnuke"

DRY_RUN=false
EXTRAS=""
VERSION=""
FROM_SPEC=""
METHOD=""

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
fail()   { echo -e "  ${RED}✗${NC} $1" >&2; exit 1; }

usage() {
    cat <<'EOF'
install.sh — install the mcpnuke MCP security scanner

Usage:
  install.sh [options]

Options:
  --extras <list>   Optional extras to install, e.g. all, ai, k8s, server
  --version <ver>   Install an exact version instead of the latest
  --from <spec>     Install from an explicit source: a local wheel, a git
                    URL, any pip requirement. Overrides --version.
  --method <name>   Force one of: uv, pipx, pip. Default is auto-detect.
  --dry-run         Print the plan and exit without changing anything
  -h, --help        Show this message

Examples:
  install.sh
  install.sh --extras all
  install.sh --version 6.15.0
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --extras)   EXTRAS="${2:-}";    shift 2 ;;
        --version)  VERSION="${2:-}";   shift 2 ;;
        --from)     FROM_SPEC="${2:-}"; shift 2 ;;
        --method)   METHOD="${2:-}";    shift 2 ;;
        --dry-run)  DRY_RUN=true;       shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "Unknown option: $1 (try --help)" >&2; exit 1 ;;
    esac
done

# A pin and an explicit source contradict each other. Honouring one silently
# would install something the user did not ask for.
if [ -n "$FROM_SPEC" ] && [ -n "$VERSION" ]; then
    fail "--from and --version cannot be combined; --from already names an exact source"
fi

# ── Resolve what to install ──────────────────────────────────────────────

if [ -n "$FROM_SPEC" ]; then
    SPEC="$FROM_SPEC"
else
    SPEC="$PACKAGE"
    [ -n "$EXTRAS" ] && SPEC="${SPEC}[${EXTRAS}]"
    [ -n "$VERSION" ] && SPEC="${SPEC}==${VERSION}"
fi

# ── Resolve how to install it ────────────────────────────────────────────

have() { command -v "$1" >/dev/null 2>&1; }

PIP_CMD=""
if have pip3; then
    PIP_CMD="pip3"
elif have pip; then
    PIP_CMD="pip"
fi

if [ -z "$METHOD" ]; then
    # Ordered by how well each isolates the install, and by what a user is
    # likely to already have working. Plain pip is last because it is the
    # one that can disturb an existing environment.
    if have uv; then
        METHOD="uv"
    elif have pipx; then
        METHOD="pipx"
    elif [ -n "$PIP_CMD" ]; then
        METHOD="pip"
    else
        fail "No installer found. Install uv (https://docs.astral.sh/uv/), pipx, or pip and re-run."
    fi
fi

case "$METHOD" in
    uv)
        have uv || fail "--method uv, but uv is not installed"
        CMD=(uv tool install "$SPEC")
        ;;
    pipx)
        have pipx || fail "--method pipx, but pipx is not installed"
        CMD=(pipx install "$SPEC")
        ;;
    pip)
        [ -n "$PIP_CMD" ] || fail "--method pip, but neither pip3 nor pip is installed"
        CMD=("$PIP_CMD" install --user "$SPEC")
        ;;
    *)
        fail "Unknown --method '$METHOD' (expected uv, pipx or pip)"
        ;;
esac

# ── Report the plan ──────────────────────────────────────────────────────

banner "Installing mcpnuke"
echo -e "  ${DIM}method:${NC} $METHOD"
echo -e "  ${DIM}source:${NC} $SPEC"
echo ""
echo "  ${CMD[*]}"

if [ "$METHOD" = "pip" ]; then
    warn "pip --user shares your ambient Python; uv or pipx would isolate it"
fi

if [ "$DRY_RUN" = true ]; then
    echo ""
    ok "dry run — nothing was installed"
    exit 0
fi

# ── Install ──────────────────────────────────────────────────────────────

echo ""
"${CMD[@]}"

# ── Verify ───────────────────────────────────────────────────────────────

banner "Verifying"

if have mcpnuke; then
    ok "$(mcpnuke --version 2>&1 | head -1)"
    echo ""
    echo -e "  ${BOLD}Next:${NC}"
    echo "    mcpnuke --doctor"
    echo "    mcpnuke --targets http://localhost:9090"
    echo ""
    echo -e "  ${DIM}Scanning a host you are not authorised to test is illegal.${NC}"
else
    # A successful install whose bin directory is not on PATH is the single
    # most common way this appears broken, so it gets a real explanation
    # rather than a failure.
    warn "installed, but 'mcpnuke' is not on your PATH yet"
    case "$METHOD" in
        uv)   echo -e "  ${DIM}Run:${NC} uv tool update-shell   ${DIM}then reopen your shell${NC}" ;;
        pipx) echo -e "  ${DIM}Run:${NC} pipx ensurepath        ${DIM}then reopen your shell${NC}" ;;
        pip)  echo -e "  ${DIM}Add your user base bin directory to PATH:${NC} python3 -m site --user-base" ;;
    esac
fi
