## Summary

<!-- What changed and why. Link the issue if there is one. -->

## Test plan

- [ ] `uv run pytest tests/ -v` — full suite green
- [ ] `uv run ruff check .` — zero
- [ ] `uv run mypy mcpnuke/` — at or under the CI ceiling
- [ ] Docs updated (README / docs/checks.md totals if the check inventory changed)
- [ ] `CHANGELOG.md` entry under `## [Unreleased]`
- [ ] Validated against a real target — which one:
- [ ] No secrets, live credentials, or real target data in this PR

<!-- New check? See the check-authoring recipe in CONTRIBUTING.md:
     failing test first, time_check wrapper, taxonomy ID, docs entry. -->
