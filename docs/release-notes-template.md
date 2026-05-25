# OxideDNS Release Notes Template

Use this template for each release candidate. Replace every `TBD` value before
running `scripts/check-release-notes.sh`.

## Release Identity

- Version: TBD
- Release candidate commit: TBD
- Release date UTC: TBD
- Evidence snapshot: TBD

## Verification Summary

| Requirement category | Verified | Deferred | Failed |
| --- | ---: | ---: | ---: |
| ODS-FR | TBD | TBD | TBD |
| ODS-NFR | TBD | TBD | TBD |
| ODS-IF | TBD | TBD | TBD |
| ODS-INV | TBD | TBD | TBD |
| ODS-NEG | TBD | TBD | TBD |

## Regression Delta

- New Failed results compared to previous same-major release: TBD
- New Deferred results compared to previous same-major release: TBD
- Performance/resource regression threshold: 10 percent unless overridden by
  `regression.performance_threshold_pct`.
- Regression baseline window: last five release measurements on the Reference
  Hardware Profile, or initial baseline for the first release of a major
  version.

| Requirement or metric | Baseline value | Candidate value | Delta percent | Status | Root cause | Fix or accepted rationale | Owner | Target remediation release |
| --- | ---: | ---: | ---: | --- | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

Regression triage status: TBD

## Interop Primary Versions

List each successful real-primary interop run used for release evidence. Include
the retained `interop-primary-versions/.../primary-version.txt` path from the
evidence snapshot.

| Primary | Version string | OS or container package context | Configuration profile | Transport/security | Evidence artifact |
| --- | --- | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD |

## Failed Requirement Decisions

If any ODS-FR, ODS-NFR, ODS-IF, ODS-INV, or ODS-NEG requirement is Failed,
record the explicit project decision, rationale, owner, and target remediation
release here. If none failed, write `No Failed release-blocking requirements`.

TBD

## Appendix C.5 Decision Review

Copy the pending-decision register from
`release-handoff/appendix-c5-decision-register.tsv`. Every `Pending` item must
be resolved for this release or explicitly deferred with an owner and target
release before MVP acceptance is claimed.

| Item | Flagged at | Recommendation | Decision for this release | Owner | Target release | Evidence or rationale |
| --- | --- | --- | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD | TBD |

## RFC Compliance Assertions

Allowed compliance status values are `Fully Compliant`, `Partially Compliant`,
`Not Compliant`, and `Informative Only`. Copy the structured list from
`docs/rfc-compliance-assertions.md`, update evidence pointers to this release's
retained evidence snapshot, and keep the primary documentation sync pointer
aligned with the Operator Deployment Guide.

| RFC number | RFC title | Compliance status | Scope qualifier | Unresolved compliance gaps | Target resolution release | SRS revision | Evidence pointer | Primary documentation sync |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | docs/operator-deployment-guide.md#rfc-compliance-assertions |

## Interface Changes

List interface additions, deprecations, and breaking changes for configuration,
CLI, metrics, logs, health endpoints, and network behavior.

TBD

## Maintainability Measurements

- First-party Rust source line count: TBD
- Rationale for exceeding LOC target: TBD
- Coverage summary: TBD

## Security and Dependency Review

- Dependency audit result: TBD
- Vulnerability disclosure changes: TBD
- Vulnerability disclosure policy reviewed: TBD
- Release signing mechanism and verification instructions: TBD
- Security audit findings and remediation actions: TBD

## Long-Running Evidence Handoff

- Fuzz campaign handoff or completed artifacts: TBD
- Info verbosity profile handoff or completed artifacts: TBD
- Reference Hardware/Profile benchmark handoff or completed artifacts: TBD
- Soak handoff or completed 30-day report: TBD
- Release/operations owner for delegated long-running evidence: TBD
- Deferred execution rationale, if any: TBD

## Release/Operations Handoff

- Release handoff artifact: TBD
- Scheduled CI/manual-run plan: TBD
- Release readiness checklist: TBD
- External operator acceptance artifact: TBD
- Signing runbook or completed signing manifest: TBD

## Verification Responsibility Sign-off

| Role | Responsible person or party | Scope | Sign-off |
| --- | --- | --- | --- |
| Architecture Owner | TBD | Release verification result review | TBD |
| Test/verification owner | TBD | Verification evidence completeness | TBD |
| External operator, MVP only | TBD | Production-representative acceptance scope | TBD |
