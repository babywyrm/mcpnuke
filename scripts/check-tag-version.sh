#!/usr/bin/env bash
#
# Refuse to publish when the git tag and the packaged version disagree.
#
#   check-tag-version.sh <tag> <version>
#
# A PyPI upload is permanent: the version number cannot be replaced or
# reused, so shipping 6.15.0 under a v6.16.0 tag burns 6.16.0 for good. This
# runs before the build, in the publish workflow.
#
# tests/test_version_consistency.py already keeps __init__.py, pyproject.toml
# and the changelog in agreement. None of them can see the tag, which is the
# one input that only exists at release time.

set -euo pipefail

TAG="${1:-}"
VERSION="${2:-}"

if [ -z "$TAG" ]; then
    echo "error: no tag given (a workflow that loses its ref must not be read as agreement)" >&2
    exit 1
fi

if [ -z "$VERSION" ]; then
    echo "error: no version given" >&2
    exit 1
fi

# Accept refs/tags/v1.2.3, v1.2.3 and 1.2.3 — different workflow contexts
# hand over different shapes of the same thing.
TAG="${TAG#refs/tags/}"
TAG="${TAG#v}"

# PyPI rejects local version identifiers, and does so only after the tag has
# been pushed.
case "$VERSION" in
    *+*)
        echo "error: '$VERSION' is a local version identifier; PyPI will reject it" >&2
        exit 1
        ;;
esac

# Exact string equality, deliberately. A prefix or substring comparison would
# accept v6.15.0-rc1 for 6.15.0, which is a different release.
if [ "$TAG" != "$VERSION" ]; then
    echo "error: tag '$TAG' does not match packaged version '$VERSION'" >&2
    echo "       bump pyproject.toml and mcpnuke/__init__.py, or move the tag" >&2
    exit 1
fi

echo "OK — tag and packaged version agree on $VERSION"
