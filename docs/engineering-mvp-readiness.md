# Engineering MVP Readiness

This document is the review entry point for the local Engineering MVP. It
summarizes the evidence that must be current before calling the Engineering MVP
ready, while keeping full SRS `ODS-VER-008` acceptance separate.

## Readiness Criteria

- `scripts/check.sh` passes on the candidate commit.
- `scripts/engineering-mvp-evidence.sh` completes with its default bounded
  local evidence profile.
- `docs/engineering-mvp-scope.md` remains the milestone boundary.
- `docs/mvp-gap-register.md` separates current Engineering MVP evidence from
  broader SRS acceptance gaps.
- `docs/evidence-command-catalog.md` owns the command inventory consumed by
  evidence snapshot tooling.
- `docs/verification-ledger.md` records SRS/Alpha/release acceptance state
  without making deferred long evidence an Engineering MVP blocker.
- `docs/implementation-plan.md` records milestone direction without owning
  feature or evidence status.
- `docs/operator-deployment-guide.md` and `config/oxidedns.example.toml` remain
  valid operator-facing startup material.

## Evidence Profile

Engineering MVP readiness depends on the bounded local commands below:

```sh
./scripts/check.sh
scripts/engineering-mvp-evidence.sh
```

The evidence snapshot runner captures only the narrow local command set listed
in `docs/evidence-command-catalog.md`. It uses per-command timeouts and records
broader release/operations commands in `deferred-not-run.txt` instead of
executing them.

## Explicit Non-Goals

The Engineering MVP is not full SRS `ODS-VER-008` release acceptance. It does
not require completed 24-hour fuzz campaigns, 30-day soak execution, Reference
Hardware/Profile benchmark campaigns, production-depth `info` verbosity
profiling, independent reproducible-build comparison, signed release artifact
production, or external operator acceptance.

## Stop Conditions

Do not call the Engineering MVP ready when any of the following are true:

- `scripts/check.sh` fails.
- `scripts/engineering-mvp-evidence.sh` fails under its bounded default profile.
- The readiness evidence requires one of the explicit non-goals above.
- Documentation claims full SRS acceptance without release-specific evidence.
- `docs/mvp-gap-register.md` no longer identifies remaining SRS acceptance gaps.
