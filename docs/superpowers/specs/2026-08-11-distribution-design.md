# Distribution: installer, publish workflow, packaging fixes

**Status:** Implemented 2026-08-11, shipped in 6.16.0
**Date:** 2026-08-11
**Follows:** `2026-08-10-stdio-transport-awareness-design.md`

## Outcome

Everything below shipped as designed, verified against a real clean-room
install: wheel built from the committed tree, installed into an empty venv
with no extras, `twine check --strict` passed on both artifacts, both console
scripts checked, and a full scan run end to end from the installed binary.

One addition the design did not anticipate. The upload job is gated on a
`PYPI_PUBLISH` repository variable as well as the tag, because the first
`vX.Y.Z` tag was pushed before the PyPI trusted publisher was registered.
Without the gate that tag queues a job which cannot start — the `pypi`
environment does not exist yet — and the release reads as failed even though
the build under it was green. Setting the variable to `true` arms the upload
once PyPI is configured.

## Problem

mcpnuke is source-only. Installing it means cloning the repo. Every roadmap
entry about adoption is blocked behind that, and it is the last **Gap** in the
capability table.

The gap is smaller than it looks. Measured before writing any of this:

| Check | Result |
|-------|--------|
| `uv build` | Builds sdist + wheel at 6.15.0 |
| Wheel contents | 106 entries; `py.typed`, `data/*.txt`, `taxonomy/lanes.yaml` and all 7 k8s manifests present |
| Clean-venv install | Succeeds, pulls 11 runtime deps |
| `mcpnuke --version` / `--help` | Work |
| Full scan from installed wheel | Works — scanned the stdio reference target end to end |
| PyPI name `mcpnuke` | Unclaimed (404 on the JSON API) |

So packaging is healthy and the name is available. What is missing is
delivery: an installer, a publish pipeline, and one real bug.

### The bug

`[project.scripts]` installs **two** console scripts, but only one of them
works in a base install:

```
$ mcpnuke-runner
ModuleNotFoundError: No module named 'pydantic'
```

`mcpnuke-runner` points at `mcpnuke.server.app:run`, and both
`mcpnuke/server/__init__.py` and `app.py` import pydantic/fastapi at module
top level. Those live in the optional `server` extra. A PyPI user's second
command therefore prints a traceback.

This matters more than it would from source: `pip install mcpnuke` is where
first impressions are formed, and a traceback reads as "broken", not "needs
an extra".

## Decisions

### 1. The runner shim lives outside `mcpnuke.server`

Catching the `ImportError` inside `mcpnuke/server/app.py` cannot work —
importing `mcpnuke.server` at all executes its `__init__`, which imports
`models`, which imports pydantic. The shim must sit above that boundary.

New module `mcpnuke/_runner_entry.py`, with `mcpnuke-runner` repointed at it.
Underscore-private because it exists purely for packaging.

It re-raises anything that is not a missing optional dependency. A shim that
swallows every `ImportError` would turn a real bug inside the server package
into the same friendly "install the extra" message and hide it.

Exit code **2**, matching how the CLI already reports usage errors, rather
than 1, which means "findings at or above the fail-on threshold".

### 2. `uv tool` first, then `pipx`, then `pip --user`

mcpnuke is an application, not a library. All three of these give it an
isolated environment, which is what stops a scanner's `httpx` pin fighting
with whatever else is in a user's Python.

Order is by what the user is likely to already have working, with the
project's own toolchain first. Plain `pip install` into the ambient
interpreter is the last resort and warns, because that is the one that
breaks other things.

### 3. The installer takes a source override, so it is testable before PyPI exists

The obvious installer runs `uv tool install mcpnuke`. That cannot be tested
until the package is published — which is exactly the sort of thing that
gets tested for the first time by a user.

`--from <spec>` passes any pip requirement through: a local wheel, a git ref,
a pinned version. The tests use it to install the wheel we just built, so the
real install path is exercised locally today.

`--dry-run` prints the resolved plan without executing it, so the method
selection can be tested with no network at all.

### 4. Trusted publishing (OIDC), not an API token

`pypa/gh-action-pypi-publish` with `id-token: write` and no stored secret.
A long-lived PyPI token in repo secrets is a credential that can be exfiltrated
by anything that can run a workflow; OIDC issues a short-lived one per run.

For a security tool, publishing via a mechanism we would flag on someone
else's repo is not defensible.

### 5. The tag must match the packaged version

`tests/test_version_consistency.py` already keeps `__init__.py`,
`pyproject.toml` and the changelog in agreement. It cannot know about the git
tag, and a `v6.16.0` tag that ships 6.15.0 is unrecoverable — PyPI does not
allow re-uploading a version.

The publish job fails before building if `refs/tags/vX.Y.Z` disagrees with
the built artifact.

## Non-goals

- **Publishing today.** The workflow ships ready; the tag push is a separate,
  deliberate act.
- Homebrew tap, Docker image on a registry, distro packages.
- Changing `quickstart.sh`, which is developer setup from a clone and stays
  as it is. `install.sh` is for people who want the tool, not the repo.

## Test plan

| Test | Asserts |
|------|---------|
| `tests/test_runner_entry.py` | Missing extra gives a message naming `mcpnuke[server]` and exit 2, not a traceback; an unrelated ImportError still propagates; a working import calls through to `run()` |
| `tests/test_install_script.py` | `--dry-run` picks uv → pipx → pip by availability; `--from` is honoured; `--help` exits 0; shellcheck is clean if installed |
| `tests/test_packaging.py` | Every `[project.scripts]` target is importable without an extra; the console script names match what the docs tell people to run |
| Live install, gated `MCPNUKE_INSTALL_LIVE=1` | `install.sh --from <local wheel>` produces a working `mcpnuke` binary |

Network-dependent installs are gated behind an env var, following
`DVMCP_LIVE` and `MCPNUKE_OSS_TARGETS`. Default CI stays hermetic.
