# OxideDNS Specification Documents

This directory contains the OxideDNS / OxideDNS-Secondary project
specification, planning, and evidence documents.

The current normative Software Requirements Specification is
`OxideDNS-Secondary-SRS-v0.9.md`, currently carrying the v0.9.1 requirement
set.

## Files

- `OxideDNS-Secondary-SRS-v0.9.md`: current normative Software Requirements Specification, updated through v0.9.1.
- `OxideDNS-Secondary-SRS-v0.1.md`: archived previous SRS baseline retained for history only; not a source of current requirements.
- `OxideDNS-Secondary-SBVR-v0.1.md`: archived SBVR Structured English companion from the v0.1 baseline; not maintained against v0.9.1.
- `OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md`: archived executive summary for the v0.1 baseline.
- `devops-getting-started.md`: clone, build, validate, and first local run guide.
- `operator-deployment-guide.md`: practical MVP deployment and operations guide.
- `dns-client-benchmark.md`: bounded local UDP client benchmark guide.
- `architecture.md`: architecture and release-governance scaffold for current MVP decisions.
- `test-plan.md`: verification cadence, harness, and regression-policy plan.
- `verification-ledger.md`: lightweight Alpha/MVP verification evidence ledger scaffold.
- `engineering-mvp-scope.md`: local Engineering MVP boundary, especially the
  exclusion of completed long-running evidence from this milestone.
- `engineering-mvp-readiness.md`: local Engineering MVP readiness review entry
  point and stop-condition checklist.
- `zsm-engineering-mvp-matrix.tsv`: checked short-evidence matrix for Zone
  State Machine requirements.
- `implementation-plan.md`: Engineering MVP and SRS acceptance implementation plan.
- `mvp-gap-register.md`: short active queue of release blockers and evidence gaps.
- `appendix-a-traceability-matrix.md`: first-pass working traceability matrix.
- `rfc-compliance-assertions.md`: ODS-VER-014 structured RFC compliance assertion register.
- `srs-review-disposition.md`: disposition register for the external SRS review,
  including accepted protocol fixes, rejected scope-trim suggestions, and known
  implementation-alignment gaps.

The planning and evidence documents are companion working artifacts. They remain
subordinate to the current SRS v0.9.1 requirement set when scope or behavioral
wording differs.

Known implementation-alignment gaps are recorded in `implementation-plan.md`,
`mvp-gap-register.md`, and the traceability matrices. In particular, the v0.9.1
SRS cleanup corrected response DO-bit handling to RFC 6840 query-bit copy
semantics; older evidence that describes augmentation-derived response DO-bit
behaviour is legacy evidence until the implementation and interop scripts are
updated.
