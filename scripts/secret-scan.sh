#!/usr/bin/env bash
#
# Canonical secret scan for mcpnuke.
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
