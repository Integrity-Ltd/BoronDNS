# OxideDNS Specification Documents

This directory contains the OxideDNS / OxideDNS-Secondary project
specification, planning, and evidence documents.

The current normative Software Requirements Specification is
`OxideDNS-Secondary-SRS-v0.9.1.md`.

The documentation set intentionally separates three things:

- **Normative requirements** in the current SRS.
- **Current Engineering MVP scope** in the scope, readiness, implementation, and
  gap documents.
- **Later release-acceptance evidence** such as long fuzz campaigns, reference
  hardware benchmarks, soak execution, signed release evidence, and external
  operator acceptance.

Implemented protocol families must not be removed from Engineering MVP scope
only because they exceed a minimal static-zone secondary-server cut. The exact
retained slices, code owners, and nearby non-claims live in
`docs/implemented-feature-scope.md`; remaining work for those features is
tracked as release evidence or, when one exists, an explicit implementation
gap.

## Document Ownership Rules

Use this ownership map when editing docs. It is meant to prevent status text,
evidence claims, and requirement wording from being copied into several places
and slowly diverging.

| Question | Owning document | Other documents should |
| --- | --- | --- |
| What is required behavior? | `OxideDNS-Secondary-SRS-v0.9.1.md` | Link to the requirement ID instead of restating normative wording. |
| What is the local Engineering MVP boundary? | `engineering-mvp-scope.md` | Refer to this boundary when explaining why long-running evidence is deferred. |
| Is the Engineering MVP ready to claim? | `engineering-mvp-readiness.md` | Link to the readiness checklist instead of inventing local stop conditions. |
| What is still open? | `mvp-gap-register.md` | Keep only short active gaps here; put detailed evidence in the ledger or Appendix A. |
| What evidence exists by requirement family? | `verification-ledger.md` | Keep coarse status here; put per-requirement/range detail in Appendix A. |
| What requirement ranges map to evidence? | `appendix-a-traceability-matrix.md` | Keep the detailed traceability rows here; do not duplicate them in the gap register. |
| How is the implementation structured? | `architecture.md` | Keep internal module and unsafe-boundary detail out of the SRS unless it is observable behavior. |
| Where are deferred optimization tracks detailed? | `future-optimization-tracks.md` | Keep future XDP, packed-store, and response-cache design constraints here; let SRS Appendix C.6 record the formal scope boundary. |
| How does an operator run it? | `operator-deployment-guide.md` | Keep deployment commands and operational examples here, not in the SRS. |
| Where are operator SLOs published? | `operational-slos.md` | Keep informative SLO targets here and link from the operator guide; do not duplicate the SLO table in the SRS. |
| How is release evidence captured? | `release-evidence-guide.md` | Keep snapshot options and handoff mechanics here; link from operator docs instead of duplicating the runbook. |
| What is the formal benchmark environment? | `reference-verification-profile.md` | Keep hardware, query-mix, and benchmark-artifact details here; keep only requirement targets and ownership pointers in the SRS. |
| How was the external review handled? | `srs-review-disposition.md` | Record review disposition here; promote only checked protocol or scope changes into the owning docs. |
| Which extra implemented features are retained? | `implemented-feature-scope.md` | Keep the exact retained slice and nearby non-claims here; summarize or link elsewhere. |
| Where are project decisions recorded? | `project-decision-register.md` | Keep the decision audit trail here; let SRS Appendix C.5 point to it instead of embedding the full table. |

## Current Requirements and Design

- `OxideDNS-Secondary-SRS-v0.9.1.md`: current normative Software Requirements
  Specification, updated through the v0.9.1 requirement set.
- `architecture.md`: current module map, implementation decisions, deferred
  acceleration/storage tracks, unsafe-boundary posture, and release-governance
  posture.
- `future-optimization-tracks.md`: deferred XDP/eBPF, packed-zone-store, and
  response-cache tracks referenced by SRS Appendix C.6.
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
- `debian12-beta-vm-profile.md`: Debian 12 container-in-VM beta handover
  profile linked from the Operator Deployment Guide.
- `operational-slos.md`: informative SLO publication linked from the Operator
  Deployment Guide.
- `manual-bind-interop.md`: manual BIND interop smoke procedure.
- `dns-client-benchmark.md`: bounded local client benchmark and large-catalog
  benchmark guide.
- `reference-verification-profile.md`: formal release benchmark hardware,
  query-mix, and artifact-retention profile referenced by SRS Appendix E.
- `oxide-gun.md`: OxideGun load-generator and XDP lab notes.
- `catalog-zone-rfc9432.md`: RFC 9432 catalog-zone implementation notes,
  Engineering MVP boundary, and E2E test shape.

## Engineering MVP and Evidence

- `engineering-mvp-scope.md`: local Engineering MVP boundary, including the
  exclusion of completed long-running evidence from this milestone and the
  implemented post-Alpha protocol slices that remain in scope.
- `implemented-feature-scope.md`: code-aligned retained slices, current source
  ownership, evidence ownership, and nearby non-claims for implemented
  post-Alpha features.
- `engineering-mvp-readiness.md`: local Engineering MVP readiness review entry
  point and stop-condition checklist.
- `implementation-plan.md`: Engineering MVP and SRS acceptance implementation
  plan.
- `mvp-gap-register.md`: short active queue of release blockers and evidence
  gaps.
- `evidence-command-catalog.md`: command inventory consumed by release evidence
  snapshot tooling.
- `release-evidence-guide.md`: release snapshot options, handoff directories,
  and release/operations evidence runbook.
- `verification-ledger.md`: lightweight Engineering MVP and SRS verification
  evidence ledger.
- `test-plan.md`: verification cadence, harness, and regression-policy plan.
- `appendix-a-traceability-matrix.md`: working traceability matrix.
- `dnssec-conformance-matrix.tsv`: passive DNSSEC conformance matrix.
- `zsm-engineering-mvp-matrix.tsv`: checked short-evidence matrix for Zone State
  Machine requirements.
- `rfc-compliance-assertions.md`: ODS-VER-014 structured RFC compliance
  assertion register.
- `project-decision-register.md`: project decision audit trail consumed by
  release handoff for Appendix C.5 decision review.
- `rrl-release-thresholds.md`: RRL threshold baseline and release-review
  notes.
- `srs-review-disposition.md`: disposition register for the external SRS review,
  including accepted protocol fixes, rejected scope-trim suggestions, and the
  current rationale for retained post-Alpha features.

## Release Scaffolding

- `release-notes-template.md`: release-note structure and acceptance checklist
  shape.

## Archived Historical Inputs

These files are retained under `docs/archive/` for provenance only. They are not
current requirements and are not maintained against v0.9.1:

- `archive/OxideDNS-Secondary-SRS-v0.1.md`: previous SRS baseline.
- `archive/OxideDNS-Secondary-SBVR-v0.1.md`: SBVR Structured English companion
  from the v0.1 baseline.
- `archive/OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md`: executive summary
  for the v0.1 baseline.

The planning and evidence documents are companion working artifacts. They remain
subordinate to the current SRS v0.9.1 requirement set when scope or behavioral
wording differs.

Current implementation and evidence status is recorded in
`implementation-plan.md`, `mvp-gap-register.md`, and the traceability matrices.
The v0.9.1 SRS cleanup corrected response DO-bit handling to RFC 6840 query-bit
copy semantics, and current unit/runtime evidence now follows that rule.
