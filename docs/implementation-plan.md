# OxideDNS Implementation Plan

This plan records implementation direction and points to the milestone
boundaries for the current OxideDNS SRS v0.9.1. It is intentionally not the
detailed evidence ledger, not the operator runbook, and not a substitute for the
normative SRS.

## Milestone Boundary

The project tracks two related but separate targets:

- **Release candidate**: the deployable and reviewable secondary DNS server
  that exercises the core operational path with deterministic tests, short
  smoke/runtime evidence, checked traceability, retained benchmark and fuzz
  evidence where available, and the implemented post-Alpha feature slices
  retained by `docs/implemented-feature-scope.md`.
- **SRS acceptance execution**: the later `ODS-VER-008` compliance gate run,
  including long-duration campaigns, full release evidence, and external
  operator acceptance.

The release candidate must not claim completed long-running evidence unless the
release artifacts exist. Handoff and runbook artifacts for long fuzz campaigns,
Reference Hardware/Profile benchmarks, 30-day soak, production-depth logging
profiles, external operator acceptance, independent reproducible-build
comparison, and signed release artifacts may remain in the repository, but they
are not release evidence until the generated artifacts are retained and cited by
the gap register, release notes, or verification ledger.

The detailed release-candidate boundary is owned by
`docs/engineering-mvp-scope.md` and checked by the legacy-named
`scripts/check-engineering-mvp-scope.py`. This plan can summarize that
boundary, but it must not become a competing source of truth.

## Release Candidate Target

The near-term implementation target is the current release candidate, not a
minimal Alpha trim. External review feedback that recommends deferring
implemented protocol features is treated as prioritization advice only; the
project keeps implemented, tested slices in scope and separates them from later
release-acceptance evidence.

At plan level, release-candidate scope is the deployable
secondary-authoritative server, its static configuration and operating
interfaces, its current retained implemented protocol slices, and the bounded
local verification profile. The exact retained feature slices, source
ownership, representative evidence, and nearby non-claims are owned by
`docs/implemented-feature-scope.md`. Current evidence state and remaining
formal-acceptance gaps are owned by `docs/verification-ledger.md`,
`docs/mvp-gap-register.md`, and `docs/appendix-a-traceability-matrix.md`.

Release-candidate runtime scope excludes eBPF/XDP, OxideDNS server AF_XDP,
io_uring, NSD-style packed arena storage, and a hot response-cache backend.
Those remain post-MVP optimization tracks. The current `oxide-gun` AF_XDP
backend is load-generator scope only.

## SRS Acceptance Execution Target

The later `ODS-VER-008` acceptance execution target is owned by the SRS,
`docs/mvp-gap-register.md`, `docs/test-plan.md`, and
`docs/release-evidence-guide.md`. This plan does not duplicate the acceptance
checklist. At this level the implementation-plan rule is that formal acceptance
work may require additional retained evidence without narrowing the
release-candidate feature boundary unless the SRS or code changes.

## Historical Alpha Reference

The SRS Alpha gate remains useful as historical context, but it is no longer the
active feature boundary. The release candidate includes implemented post-Alpha
slices listed in `docs/implemented-feature-scope.md`.

SRS `ODS-VER-007` still records the historical Alpha-vs-formal-SRS-MVP split.
That split must not be read as the current implementation boundary. Several
items that were historically outside the Alpha gate are now implemented
release-candidate slices; their current status and remaining release-acceptance
gaps are recorded in the owner documents named above.

## Ownership Rules

This plan deliberately stays at feature-slice granularity. In particular, it is
not the canonical inventory of every evidence script, artifact environment
variable, release-gate command, test case, or requirement-range traceability
row. When implementation status changes:

- put normative behavior changes in `docs/OxideDNS-Secondary-SRS-v0.9.1.md`;
- put implementation structure and unsafe-boundary changes in
  `docs/architecture.md`;
- put operator commands and deployment examples in
  `docs/operator-deployment-guide.md`;
- put active open decisions and release blockers in `docs/mvp-gap-register.md`;
- put evidence state by requirement family in `docs/verification-ledger.md`;
- put detailed requirement-range evidence in
  `docs/appendix-a-traceability-matrix.md`;
- put review-disposition rationale in `docs/srs-review-disposition.md`;
- put project-decision audit trail in `docs/project-decision-register.md`;
- put release evidence snapshot and handoff mechanics in
  `docs/release-evidence-guide.md`.

The implementation direction is to keep implemented feature slices wired exactly
as bounded in `docs/implemented-feature-scope.md`, preserve the Appendix C.6
future-optimization boundaries for XDP/eBPF, io_uring, packed arena storage, and
response caching, and update the owning evidence documents before changing
status.
