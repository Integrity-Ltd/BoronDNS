# Release Candidate Scope

This document defines the current release-candidate scope for BoronDNS. It is
not the SRS `BDS-VER-008` release-acceptance gate.

## In Scope

- A deployable secondary-authoritative DNS server for the core operational path.
- Deterministic unit and integration tests that run in the normal local check
  profile.
- Short runtime smoke and interop captures that prove the implemented behavior
  is wired through the binary.
- Configuration, CLI, logging, health, metrics, shutdown, dependency, unused
  code, unsafe-boundary, and traceability checks.
- Documentation that records current implementation evidence and the remaining
  release-acceptance gaps without claiming final SRS acceptance.
- Implemented post-Alpha protocol slices listed in
  `docs/implemented-feature-scope.md`. These are not removed from
  release-candidate scope merely because they exceed a minimal static-zone
  secondary-server trim.

The retained post-Alpha slices are code-backed scope, not planning notes.
`scripts/check-srs-review-disposition.py` verifies those slices against current
source paths, implementation markers, representative test markers, evidence
paths, and SRS owner identifiers. If a retained slice is removed from code, the
implemented-feature scope, review disposition, gap register, and this boundary
must change in the same patch.

## Release Closeout

The bounded local preflight must not claim completed long-running evidence
unless release artifacts exist. The following are release closeout or formal
SRS acceptance activities tracked in `docs/mvp-gap-register.md`:

- Several independent 24-hour fuzz campaigns across the release-selected
  parser and untrusted-input targets.
- Risk-based extended-runtime/resource evidence; no fixed 30-day campaign is
  required.
- Reference Hardware/Profile benchmark campaigns.
- Production-depth `info` verbosity profiling under release traffic.
- External operator acceptance.
- External independent-builder sign-off, package/image reproducibility evidence,
  and signed release artifact production beyond the completed v0.2.0
  static-binary comparison in `docs/reproducible-build-v0.2.0.md`.

Setup scripts, schemas, runbooks, and handoff directories for those activities
may exist in this repository for release/operations use. They are not
release-candidate evidence until the generated artifacts are retained and cited
by the gap register, release notes, or verification ledger.

## Check Profile

`scripts/check.sh` is the local release-candidate quality gate. It may validate
script syntax and dry-run campaign wiring, but it must not execute the
long-running activities or generate long-running handoff evidence listed above.

`scripts/engineering-mvp-evidence.sh` is the legacy-named bounded local
evidence snapshot for the release-candidate preflight profile. By default it
runs only the narrow local evidence commands listed in
`docs/evidence-command-catalog.md`, applies a per-command timeout, and records
broader release/operations commands as deferred rather than executing them.
