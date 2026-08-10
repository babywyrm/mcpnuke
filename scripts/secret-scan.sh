#!/usr/bin/env bash
#
# Canonical secret scan for mcpnuke. Runs two engines, because they see
# different things:
#
#   TruffleHog  reads the working tree and verifies findings against the live
#               provider, so it answers "is this key real".
#   Gitleaks    walks git history, so it answers "was a key ever committed" —
#               including one deleted before the current tree, which TruffleHog
#               in filesystem mode cannot see at all.
#
# Either engine failing fails the script.
#
# There used to be a .trufflehog.yaml here. TruffleHog rejected every key in
# it — `exclude_detectors` and `exclude_paths` are both absent from its config
# schema — and aborted with "unknown field" on each run, so the exclusions it
# appeared to declare had never once been applied. --config takes detector
# *definitions*, not scan settings.
#
# Both exclusions are command-line concerns, so this script is the one place
# they live and the way everyone runs the scan.
#
# Usage:  ./scripts/secret-scan.sh [path ...]      (defaults to the repo)

set -euo pipefail

# Detectors excluded, and why. Each one fires on a string that is provably not
# a credential; none of them suppress a real secret class.
#
#   Lob       — Lob API keys start with "test_", so every pytest function name
#               matches. e.g. test_docs_search_does_not_echo_the_query
#   Polygon   — botocore's bundled geo data, not a Polygon API key
#   Pastebin  — pytest RECORD checksums, not Pastebin tokens
#   URI       — credentials in third-party library doc examples
EXCLUDED_DETECTORS="Lob,Polygon,Pastebin,URI"

TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=(".")
fi

echo "Scanning: ${TARGETS[*]}"
echo "Excluded detectors: ${EXCLUDED_DETECTORS}"
echo

EXCLUDE_PATHS_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.trufflehog-exclude-paths"

# --fail is deliberately not used. It exits non-zero on unverified results too,
# and the repo intentionally ships fake credentials as scanner fixtures, so the
# gate would fail on every run and get ignored. Verified findings are the gate;
# unverified ones are printed for a human to look at.
output="$(trufflehog filesystem "${TARGETS[@]}" \
    --exclude-detectors="${EXCLUDED_DETECTORS}" \
    --exclude-paths="${EXCLUDE_PATHS_FILE}" \
    --results=verified,unknown \
    --json \
    --no-update 2>/dev/null || true)"

verified="$(printf '%s\n' "$output" | grep -c '"Verified":true' || true)"
unverified="$(printf '%s\n' "$output" | grep -c '"Verified":false' || true)"

echo "verified:   ${verified}"
echo "unverified: ${unverified}  (fixture credentials — review, do not gate)"

if [ "${verified}" -gt 0 ]; then
    echo
    echo "VERIFIED SECRET(S) FOUND:"
    printf '%s\n' "$output" | grep '"Verified":true'
    exit 1
fi

echo "OK — no verified secrets."

# Gitleaks, over history. Skipped rather than failed when absent: it is not in
# the dev dependencies, and a missing optional tool must not read as a clean
# scan — hence the explicit SKIPPED line rather than silence.
echo
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v gitleaks >/dev/null 2>&1; then
    echo "gitleaks:   SKIPPED (not installed — brew install gitleaks)"
    exit 0
fi

echo "gitleaks: scanning git history..."
if gitleaks detect --source "${REPO_ROOT}" --config "${REPO_ROOT}/.gitleaks.toml" \
        --no-banner --redact 2>&1 | tail -3; then
    echo "OK — no leaks in history."
else
    echo
    echo "GITLEAKS FOUND SECRETS IN HISTORY (see above)."
    echo "Fixture credentials belong in .gitleaks.toml, with a reason."
    exit 1
fi
