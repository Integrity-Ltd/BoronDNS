# OxideDNS Specification Documents

This directory contains the documents provided by Tibor Dravecz for the OxideDNS /
OxideDNS-Secondary project.

The current normative Software Requirements Specification is SRS v0.7 from the
email titled `OxideDNS Secondary SRS v.0.7`, dated 2026-05-25. The older SDS,
SBVR, executive summary, and SRS v0.1 material remain source context. If
documents disagree substantially, implementation work should follow SRS v0.7
and update companion documents afterward.

## Files

- `OxideDNS-Secondary-SRS-v0.7.md`: current normative Software Requirements Specification.
- `OxideDNS-Secondary-SRS-v0.1.md`: previous SRS baseline retained for history.
- `OxideDNS-Secondary-SBVR-v0.1.md`: SBVR Structured English companion specification.
- `OxideDNS-Secondary-SRS-v0.1-Executive-Summary.md`: executive summary.
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

The planning and evidence documents are companion working artifacts. They remain
subordinate to SRS v0.7 when scope or behavioral wording differs.
