# Release Candidate Readiness

This document is the review entry point for the current release candidate. It
summarizes the evidence that must be current before calling the release
candidate ready, while keeping full SRS `ODS-VER-008` acceptance separate.

## Readiness Criteria

- `scripts/check.sh` passes on the candidate commit.
- `scripts/engineering-mvp-evidence.sh` completes with its legacy-named bounded
  local preflight profile.
- `docs/engineering-mvp-scope.md` remains the release-candidate scope boundary.
- `docs/implemented-feature-scope.md` remains the code-aligned source of truth
  for retained implemented slices that exceed a minimal static-zone trim.
- `docs/mvp-gap-register.md` separates release-candidate evidence from
  remaining SRS acceptance gaps.
- `docs/evidence-command-catalog.md` owns the command inventory consumed by
  evidence snapshot tooling.
- `docs/verification-ledger.md` records SRS/Alpha/release acceptance state
  without making deferred long evidence a release-candidate blocker unless it
  is promoted into the release claim.
- `docs/implementation-plan.md` records milestone direction without owning
  feature or evidence status.
- `docs/operator-deployment-guide.md` and `config/oxidedns.example.toml` remain
  valid operator-facing startup material.

## Evidence Profile

Release-candidate readiness depends on the bounded local commands below:

```sh
./scripts/check.sh
scripts/engineering-mvp-evidence.sh
```

The legacy-named evidence snapshot runner captures only the narrow local command
set listed in `docs/evidence-command-catalog.md`. It uses per-command timeouts
and records broader release/operations commands in `deferred-not-run.txt`
instead of executing them.

## Explicit Non-Goals

Release-candidate readiness is not full SRS `ODS-VER-008` release acceptance.
It does not claim completed 30-day soak execution, signed release artifact
production, package/image reproducibility, external independent-builder
sign-off, or external operator acceptance until those artifacts exist. The
v0.2.0 static-binary reproducible-build comparison is retained in
`docs/reproducible-build-v0.2.0.md`. Completed benchmark and 24-hour fuzz
evidence may be retained and cited by the release, but any missing release
artifact must remain explicit in `docs/mvp-gap-register.md` and the release
notes.

## Stop Conditions

Do not call the release candidate ready when any of the following are true:

- `scripts/check.sh` fails.
- `scripts/engineering-mvp-evidence.sh` fails under its bounded default profile.
- Required release-candidate evidence is missing or only exists as an unchecked
  handoff placeholder.
- Documentation claims full SRS acceptance without release-specific evidence
  and owner sign-off.
- `docs/mvp-gap-register.md` no longer identifies remaining SRS acceptance gaps.
