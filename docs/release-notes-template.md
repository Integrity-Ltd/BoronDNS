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

## RFC Compliance Assertions

| RFC | Scope | Assertion status | Evidence pointer | Out-of-scope rationale |
| --- | --- | --- | --- | --- |
| TBD | TBD | TBD | TBD | TBD |

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

## Verification Responsibility Sign-off

| Role | Responsible person or party | Scope | Sign-off |
| --- | --- | --- | --- |
| Architecture Owner | TBD | Release verification result review | TBD |
| Test/verification owner | TBD | Verification evidence completeness | TBD |
| External operator, MVP only | TBD | Production-representative acceptance scope | TBD |
