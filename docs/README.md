# BoronDNS Specification Documents

This directory contains the BoronDNS / BoronDNS-Secondary project
specification, planning, and evidence documents.

The current normative Software Requirements Specification is
`BoronDNS-Secondary-SRS-v0.9.1.md`.

The documentation set intentionally separates three things:

- **Normative requirements** in the current SRS.
- **Current release-candidate scope** in the scope and readiness documents, with
  retained feature slices and remaining gaps in their own owner documents.
- **Formal release-acceptance closeout** such as long fuzz campaigns, reference
  hardware benchmarks, soak execution, signed release evidence, and external
  operator acceptance.

Implemented protocol families must not be removed from release-candidate scope
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
| What is required behavior? | `BoronDNS-Secondary-SRS-v0.9.1.md` | Link to the requirement ID instead of restating normative wording. |
| What is the current release-candidate boundary? | `engineering-mvp-scope.md` | Refer to this boundary when explaining why long-running evidence is deferred from local preflight. |
| Is the release candidate ready to claim? | `engineering-mvp-readiness.md` | Link to the readiness checklist instead of inventing local stop conditions. |
| What is still open for SRS acceptance? | `mvp-gap-register.md` | Keep only short active closeout gaps here; put detailed evidence in the ledger or Appendix A. |
| What evidence exists by requirement family? | `verification-ledger.md` | Keep coarse status here; put per-requirement/range detail in Appendix A. |
| What requirement ranges map to evidence? | `appendix-a-traceability-matrix.md` | Keep the detailed traceability rows here; do not duplicate them in the gap register. |
| How are RFC traceability rules maintained? | `rfc-traceability-policy.md` | Keep RFC mapping conventions, status vocabulary, and out-of-scope clause handling here; keep current structured compliance rows in `rfc-compliance-assertions.md`. |
| How is the implementation structured? | `architecture.md` | Keep internal module and unsafe-boundary detail out of the SRS unless it is observable behavior. |
| Where is RR catalogue implementation detail kept? | `rr-type-catalogue.md` | Keep code paths, tests, and out-of-catalogue examples here; let the SRS own the normative type list. |
| Where are deferred optimization tracks detailed? | `future-optimization-tracks.md` | Keep future XDP, packed-store, and response-cache design constraints here; let SRS Appendix C.6 record the formal scope boundary. |
| Where is the next data-plane design detailed? | `memory-io-data-plane-design.md` | Keep packed `ZoneImage`, packet-I/O, metric, benchmark, and tuning details here; summarize only the deferred-track boundary elsewhere. |
| Where is ZoneImage implementation status tracked? | `zone-image-implementation-status.md` | Keep checklist state, remaining layout work, and old query-layout retirement status here; keep detailed design rationale in `memory-io-data-plane-design.md`. |
| What are the exact ZoneImage capacity limits? | `zone-image-capacity-limits.md` | Keep encoded, DNS-format, transfer-ingest, and reload-memory limits here; keep benchmark rationale in `zone-image-large-zone-design.md`. |
| How were the July 2026 denial, memory, and class-index proposals resolved? | `zone-image-proposal-disposition-2026-07.md` | Keep the measured accepted/rejected/alternative-implemented decisions and reproduction command here. |
| How will the retained ZoneSnapshot be narrowed? | `zone-snapshot-narrowing-design.md` | Keep responsibility separation, migration stages, and the signed-registry replay gate here; keep current implementation status in the ZoneImage tracker. |
| How were Tibor's remaining July ZoneImage audit items closed? | `zone-image-action-items-2026-07.md` | Keep the code disposition, matched performance evidence, and remaining non-claims here. |
| How does the synthetic large-zone primary remain deterministic and bounded? | `boron-gen-design.md` | Keep BoronGen generation, NSEC3, protocol-scope, and resource-safety contracts here. |
| How is BoronGen run and validated under a cgroup limit? | `boron-gen.md` | Keep CLI examples, profiles, bounded-harness controls, and evidence interpretation here. |
| What evidence qualified BoronGen for large-scale internal testing? | `boron-gen-validation-2026-07.md` | Keep the July functional, scale, containment, fuzz-disposition, and final 32 GiB results here. |
| What did the July two-host 750 GiB campaign establish? | `boron-gen-two-host-campaign-2026-07.md` | Keep the frozen campaign triage, accepted size curve, 60M capacity boundary, and rerun requirements here. |
| What is the health and metrics HTTP contract? | `health-metrics-interface.md` | Keep concrete paths, bodies, headers, and rate-limit behavior here; let the SRS own requirement IDs and stable behavior. |
| What is the richer optional JSON observability API? | `observability-api.md` | Keep observability paths, response shapes, reduced-metrics behavior, and config knobs here. |
| How does an operator run it? | `operator-deployment-guide.md` | Keep deployment commands and operational examples here, not in the SRS. |
| Where are operator SLOs published? | `operational-slos.md` | Keep informative SLO targets here and link from the operator guide; do not duplicate the SLO table in the SRS. |
| How is release evidence captured? | `release-evidence-guide.md` | Keep snapshot options and handoff mechanics here; link from operator docs instead of duplicating the runbook. |
| What is the formal benchmark environment? | `reference-verification-profile.md` | Keep hardware, query-mix, and benchmark-artifact details here; keep only requirement targets and ownership pointers in the SRS. |
| How was the external review handled? | `srs-review-disposition.md` | Record review disposition here; promote only checked protocol or scope changes into the owning docs. |
| Which extra implemented features are retained? | `implemented-feature-scope.md` | Keep the exact retained slice and nearby non-claims here; summarize or link elsewhere. |
| Where are project decisions recorded? | `project-decision-register.md` | Keep the decision audit trail here; let SRS Appendix C.5 point to it instead of embedding the full table. |

## Current Requirements and Design

- `BoronDNS-Secondary-SRS-v0.9.1.md`: current normative Software Requirements
  Specification, updated through the v0.9.1 requirement set.
- `architecture.md`: current module map, implementation decisions, deferred
  acceleration/storage tracks, unsafe-boundary posture, and release-governance
  posture.
- `future-optimization-tracks.md`: deferred XDP/eBPF, packed-zone-store, and
  response-cache tracks referenced by SRS Appendix C.6.
- `memory-io-data-plane-design.md`: implementation-ready design for the
  deferred packed `ZoneImage`, response-composition, metric, comparison,
  tuning, and packet-I/O optimization track.
- `zone-image-implementation-status.md`: checklist tracker for implemented,
  partial, and remaining `ZoneImage` work, including retirement of the old
  query-time memory layout.
- `zone-image-large-zone-design.md`: measured rationale for selective global
  `u64` fields and rejection of range sharding.
- `zone-image-capacity-limits.md`: exact encoded, DNS-format, transfer-ingest,
  and practical reload limits for one immutable zone image.
- `zone-image-proposal-disposition-2026-07.md`: measured disposition of indexed
  denial lookup, compression/interning, and IN-only class-index specialization.
- `zone-snapshot-narrowing-design.md`: design boundary for separating transfer,
  catalog, control, builder, and offline-oracle responsibilities before
  reducing the retained source snapshot.
- `zone-image-action-items-2026-07.md`: closure report for the July capacity,
  robustness, observability, documentation, and performance follow-up.
- `boron-gen-design.md`: deterministic on-the-fly primary design for bounded
  large-zone, catalog, AXFR, and synthetic ordered-NSEC3 testing.
- `boron-gen.md`: BoronGen profiles, commands, bounded local load harness,
  containment outcomes, and validation workflow.
- `boron-gen-validation-2026-07.md`: retained BoronGen functional, scale,
  capacity, containment, fuzz-disposition, and final 32 GiB validation results.
- `health-metrics-interface.md`: concrete health and metrics HTTP path, body,
  header, gzip, and rate-limit contract for `BDS-IF-HEALTH`.
- `observability-api.md`: optional in-process JSON observability API for richer
  read-only runtime, zone, transfer, catalog, resource, time-sync, and
  certificate status.
- `rr-type-catalogue.md`: code-aligned RR catalogue implementation notes for
  known-type validation, response compression, and unknown-RR boundaries.
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
- `BoronGun-SRS-v0.1.md`: normative requirements for the BoronGun support
  tool (RRL-focused load generator with AF_XDP backend).
- `boron-gun-mvp-plan.md`: phased path from the current prototype toward a
  useful MVP aligned with the SRS.
- `boron-gun.md`: BoronGun load-generator and XDP lab notes (operational usage).
- `boron-gen.md`: BoronGen deterministic synthetic-primary usage and safety
  notes for large catalog, AXFR, and NSEC3 load tests.
- `two-host-fuzz-soak-campaign.md`: prepared two-host fuzz, sanitizer, soak,
  and XDP evidence campaign runbook for the local physical hosts.
- `catalog-zone-rfc9432.md`: RFC 9432 catalog-zone implementation notes,
  release-candidate boundary, opt-in member-transfer extensions, and E2E test
  shape.

## Release Scope and Evidence

- `engineering-mvp-scope.md`: current release-candidate boundary, including the
  separation of local preflight from release closeout and the implemented
  post-Alpha protocol slices that remain in scope.
- `implemented-feature-scope.md`: code-aligned retained slices, current source
  ownership, evidence ownership, and nearby non-claims for implemented
  post-Alpha features.
- `engineering-mvp-readiness.md`: release-candidate readiness review entry
  point and stop-condition checklist.
- `implementation-plan.md`: milestone direction and ownership pointers, without
  duplicating the detailed feature inventory, current status, or
  release-acceptance checklist.
- `mvp-gap-register.md`: short active queue of SRS acceptance blockers and
  evidence gaps.
- `evidence-command-catalog.md`: command inventory consumed by release evidence
  snapshot tooling.
- `release-evidence-guide.md`: release snapshot options, handoff directories,
  and release/operations evidence runbook.
- `verification-ledger.md`: lightweight release-candidate and SRS verification
  evidence ledger.
- `test-plan.md`: verification cadence, harness, and regression-policy plan.
- `appendix-a-traceability-matrix.md`: working traceability matrix.
- `rfc-traceability-policy.md`: RFC traceability conventions, status
  vocabulary, and out-of-scope clause handling policy.
- `dnssec-conformance-matrix.tsv`: passive DNSSEC conformance matrix.
- `zsm-engineering-mvp-matrix.tsv`: checked short-evidence matrix for Zone State
  Machine requirements.
- `rfc-compliance-assertions.md`: BDS-VER-014 structured RFC compliance
  assertion register.
- `project-decision-register.md`: project decision audit trail consumed by
  release handoff for Appendix C.5 decision review.
- `rrl-release-thresholds.md`: RRL threshold baseline and release-review
  notes.
- `srs-review-disposition.md`: disposition register for the external SRS review,
  including accepted protocol fixes, rejected scope-trim suggestions, and the
  current rationale for retained post-Alpha features.

## Release Templates

- `release-notes-template.md`: release-note structure and acceptance checklist
  shape.
- `release-notes-v0.2.0-draft.md`: source-aligned draft release material for
  the v0.2.0 preparation branch, including version posture and remaining
  tag-time evidence steps.

## Archived Historical Inputs

These files are retained under `docs/archive/` for provenance only. They are not
current requirements and are not maintained against v0.9.1:

- `archive/BoronDNS-Secondary-SRS-v0.1.md`: previous SRS baseline.
- `archive/BoronDNS-Secondary-SBVR-v0.1.md`: SBVR Structured English companion
  from the v0.1 baseline.
- `archive/BoronDNS-Secondary-SRS-v0.1-Executive-Summary.md`: executive summary
  for the v0.1 baseline.

The planning and evidence documents are companion working artifacts. They remain
subordinate to the current SRS v0.9.1 requirement set when scope or behavioral
wording differs.

Current implementation and evidence status is recorded in the gap register,
verification ledger, implemented-feature scope, and traceability matrices. The
implementation plan stays at milestone level so those owner documents do not
compete with each other.

## Documentation Growth Control

Before adding a new document or repeating status text in an existing document,
choose the owning document from the table above. If no owner fits, add the owner
row here in the same patch as the new document. Avoid copying requirement text,
evidence status, command inventories, or feature-scope tables into multiple
documents; link to the owner and keep only the local context needed by the
reader.

The current large documents are intentionally split by role:

- the SRS owns normative requirements and identifier stability;
- Appendix A owns detailed requirement-range traceability outside the SRS body;
- the verification ledger owns coarse evidence state;
- the gap register owns the short active queue;
- implemented-feature scope owns code-backed retained feature boundaries;
- the operator and DevOps guides own executable deployment instructions.

When a review finding exposes drift, edit the owner first, then update any short
summaries that point to it. A summary that needs more than a short paragraph is a
sign that the detail belongs in the owner document instead.
