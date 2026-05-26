# OxideDNS Specification Documents

This directory contains the OxideDNS / OxideDNS-Secondary project
specification, planning, and evidence documents.

The current normative Software Requirements Specification is
`OxideDNS-Secondary-SRS-v0.9.md`, currently carrying the v0.9.1 requirement
set.

## Current Requirements and Design

- `OxideDNS-Secondary-SRS-v0.9.md`: current normative Software Requirements
  Specification, updated through the v0.9.1 requirement set.
- `architecture.md`: current module map, implementation decisions, deferred
  acceleration/storage tracks, unsafe-boundary posture, and release-governance
  scaffold.
- `interface-compatibility-policy.md`: semantic-versioned interface compatibility
  policy.
- `interface-stability-baseline.tsv`: current interface baseline checked by
  `scripts/check-interface-compatibility.py`.
- `unsafe-boundaries.tsv`: registered first-party unsafe-code boundaries.
- `unsafe-prone-dependencies.tsv`: dependency gate for low-level crates that
  would require an active unsafe-boundary row.

## Operator and Developer Guides

- `devops-getting-started.md`: clone, build, validate, and first local run guide.
- `operator-deployment-guide.md`: practical deployment and operations guide.
- `manual-bind-interop.md`: manual BIND interop smoke procedure.
- `dns-client-benchmark.md`: bounded local client benchmark and large-catalog
  benchmark guide.
- `oxide-gun.md`: OxideGun load-generator and XDP lab notes.
- `catalog-zone-mvp-rfc9432.md`: RFC 9432 catalog-zone implementation notes and
  MVP/E2E test shape.

## Engineering MVP and Evidence

- `engineering-mvp-scope.md`: local Engineering MVP boundary, including the
  exclusion of completed long-running evidence from this milestone and the
  implemented post-Alpha protocol slices that remain in scope.
- `engineering-mvp-readiness.md`: local Engineering MVP readiness review entry
  point and stop-condition checklist.
- `implementation-plan.md`: Engineering MVP and SRS acceptance implementation
  plan.
- `mvp-gap-register.md`: short active queue of release blockers and evidence
  gaps.
- `verification-ledger.md`: lightweight Engineering MVP and SRS verification
  evidence ledger.
- `test-plan.md`: verification cadence, harness, and regression-policy plan.
- `appendix-a-traceability-matrix.md`: working traceability matrix.
- `dnssec-conformance-matrix.tsv`: passive DNSSEC conformance matrix.
- `zsm-engineering-mvp-matrix.tsv`: checked short-evidence matrix for Zone State
  Machine requirements.
- `rfc-compliance-assertions.md`: ODS-VER-014 structured RFC compliance
  assertion register.
- `rrl-release-thresholds.md`: RRL threshold baseline and release-review
  notes.
- `srs-review-disposition.md`: disposition register for the external SRS review,
  including accepted protocol fixes, rejected scope-trim suggestions, and known
  implementation-alignment gaps.

## Release Scaffolding

- `release-notes-template.md`: release-note structure and acceptance checklist
  shape.

## Archived Historical Inputs

These files are retained for provenance only. They are not current requirements
and are not maintained against v0.9.1:

- `OxideDNS-Secondary-SRS-v0.1.md`: previous SRS baseline.
- `OxideDNS-Secondary-SBVR-v0.1.md`: SBVR Structured English companion from the
  v0.1 baseline.
- `OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md`: executive summary for the
  v0.1 baseline.

The planning and evidence documents are companion working artifacts. They remain
subordinate to the current SRS v0.9.1 requirement set when scope or behavioral
wording differs.

Known implementation-alignment gaps are recorded in `implementation-plan.md`,
`mvp-gap-register.md`, and the traceability matrices. In particular, the v0.9.1
SRS cleanup corrected response DO-bit handling to RFC 6840 query-bit copy
semantics; older evidence that describes augmentation-derived response DO-bit
behaviour is legacy evidence until the implementation and interop scripts are
updated.
