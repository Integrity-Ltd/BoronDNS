# OxideDNS v0.2.0 Release Notes

Release date: 2026-06-14

Release tag target: `v0.2.0`.

Evidence snapshot: `target/evidence/20260613T235555Z`.

Snapshot commit: `7cb6ac5fce040ad6b667381067e9e280386b0465`.

Status vocabulary used below:

- Verified: checked by repository gate, release evidence snapshot, retained docs,
  or release-local inspection.
- Deferred: intentionally not claimed for this release and handed off with an
  owner path or later acceptance gate.
- Failed: a requirement decision or regression that would block this release;
  no Failed release blockers are accepted for v0.2.0.

## Verification Summary

| Category | Representative scope | Status | Evidence pointer |
| --- | --- | --- | --- |
| ODS-FR | Query, AXFR/IXFR, NOTIFY, TSIG, XoT, catalog-zone, DNSSEC serve-only, EDNS, Cookie, RRL, and CHAOS-class behavior covered by source tests and interop scripts | Verified for checked-in gates and selected current-primary matrix; Deferred for XoT, production-depth, and long-running acceptance artifacts | `scripts/check.sh`; `docs/verification-ledger.md`; `docs/primary-interop-matrix-v0.2.0.md`; `target/evidence/20260613T235555Z/`; `target/evidence/primary-matrix-20260614T010049Z/` |
| ODS-NFR | Maintainability, security review inputs, observability, static-binary reproducibility, resource evidence handoff, and release security posture | Verified for local gates and static-binary reproducibility; Deferred for production reference benchmark, package/image reproducibility, artifact signing, and long soak | `target/evidence/20260613T235555Z/coverage-evidence/coverage-summary.env`; `target/evidence/20260613T235555Z/unsafe-dependency-evidence/geiger-summary.env`; `docs/reproducible-build-v0.2.0.md` |
| ODS-IF | CLI, config, health, metrics, logging, process, and interface compatibility baseline | Verified | `target/evidence/20260613T235555Z/cli-evidence/`; `target/evidence/20260613T235555Z/interface-compatibility/current-interface-baseline.tsv` |
| ODS-INV | Runtime invariants, fail-closed transfer publication, no dynamic code loading, and panic discipline for untrusted input | Verified by source gates and focused regression tests | `scripts/check.sh`; `target/evidence/20260613T235555Z/logs/` |
| ODS-NEG | Explicitly excluded surfaces, including inbound ordinary DoT/DoH/DoQ and unsupported config aliases | Verified by docs/source alignment checks | `docs/implemented-feature-scope.md`; `docs/operator-deployment-guide.md` |
| ODS-VER | Release evidence, RFC compliance assertions, regression policy, version consistency, and role handoff | Verified for v0.2.0 release publication; Deferred for formal production acceptance rows named below | `target/evidence/20260613T235555Z/release-handoff/evidence-attachment-map.tsv` |

Coverage summary: overall line coverage was 91.384415 percent against a
70.000000 percent minimum, with 37,962 covered lines of 41,541 measured lines.
Parser-related release evidence retained the 85.000000 percent minimum.

First-party Rust source line count: 74,322 lines under `crates/*/src/*.rs`;
68,700 lines for `oxidedns-core`, `oxidedns-server`, and `oxidedns-cli`.
Rationale for exceeding LOC target: v0.2.0 keeps DNS protocol, transfer,
catalog-zone, TSIG/XoT, health/metrics, config, CLI, and evidence tooling in
tree so release claims remain directly traceable. Further server module
decomposition remains a maintainability candidate, not a release blocker.

Reproducible-build handoff or completed bit-identical comparison: Verified for
the static musl binaries. `docs/reproducible-build-v0.2.0.md` records
`target/evidence/reproducible-build-20260614T013236Z`, where two clean release
builds in separate target directories produced matching `x86_64-unknown-linux-musl`
`oxidedns` and `oxide-gun` binaries. Installer/archive normalization, Docker
image archive reproducibility, artifact signing, and external independent-builder
sign-off remain separate release-governance work.

## Regression Delta

Performance/resource regression threshold: `regression.performance_threshold_pct`
is 10 percent for release triage.

Regression baseline window: initial v0.2.0 release baseline. There is no prior
accepted v0.2.x release baseline, so release-to-release regression comparison is
classified as an initial baseline.

| Requirement or metric | Baseline value | Candidate value | Delta percent | Regression triage status | Root cause | Fix or accepted rationale | Target remediation release |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Workspace version consistency | no v0.2.0 tag baseline | all workspace, internal, eBPF, and lockfile versions are `0.2.0` | 0 | Verified | release prep | version-consistency gate passes | none |
| Overall line coverage | 70.000000 percent minimum | 91.384415 percent | +30.549164 | Verified | test coverage retained | accepted as above threshold | none |
| Parser/XoT-file coverage | 85.000000 percent minimum | threshold retained by coverage evidence | 0 | Verified | release coverage policy | accepted as above threshold | none |
| Production reference benchmark | no completed v0.2.0 release baseline | handoff package only | not measured | Deferred | production-depth benchmark not run in snapshot | benchmark handoff retained for later execution | next production benchmark cycle |
| Long soak | no completed 30-day v0.2.0 soak | handoff package only | not measured | Deferred | 30-day evidence not run in snapshot | soak handoff retained for later execution | next long-running evidence cycle |
| Release blocker failures | none accepted | none accepted | 0 | Verified | no Failed blockers retained | release can proceed with named deferrals | none |

## Interop Primary Versions

Status: Verified for the selected local current-primary matrix.

The v0.2.0 local release evidence in
`target/evidence/primary-matrix-20260614T010049Z` passed 12 of 12 selected
interop cases. `docs/primary-interop-matrix-v0.2.0.md` records the command,
scope, tested versions, case table, and retained artifact layout.

| Primary | Version | Runtime source | Selected capabilities |
| --- | --- | --- | --- |
| BIND 9 | 9.20.23 stable | Arch Linux host package | AXFR; TSIG AXFR; NOTIFY refresh; IXFR refresh |
| NSD | 4.14.2 | Alpine Linux v3.24 container package | AXFR; TSIG AXFR; NOTIFY refresh |
| Knot DNS | 3.5.3 | Alpine Linux v3.24 container package | AXFR; TSIG AXFR; NOTIFY refresh; IXFR refresh |
| PowerDNS Authoritative | 5.0.5 | `powerdns/pdns-auth-50:latest`, Debian 13 container | PostgreSQL catalog zone with TSIG transfer |

The original release snapshot directory
`target/evidence/20260613T235555Z/interop-primary-versions/INDEX.tsv` still
contains only the snapshot header. The selected matrix above is the current
retained local primary-version evidence. XoT and broader production acceptance
remain separate deferred rows.

## Failed Requirement Decisions

No Failed requirement decision is accepted for v0.2.0.

| Decision | Status | Release action |
| --- | --- | --- |
| Any release blocker classified Failed | Verified absent | Do not tag if a Failed blocker appears before publication |
| Production-depth benchmark, long soak, XoT release matrix, package/image reproducibility, artifact signing | Deferred | Named in handoff sections rather than claimed as completed |

## Appendix C.5 Decision Review

Decision for this release: resolved Appendix C.5 decisions are accepted as
documented in `target/evidence/20260613T235555Z/release-handoff/appendix-c5-decision-register.tsv`.

| Item | Decision for this release | Target release | Evidence or rationale |
| --- | --- | --- | --- |
| Out-of-zone glue tolerance compatibility option | Resolved: strict out-of-zone owner rejection remains; fail-closed publication validation is required | v0.2.0 | Candidate tolerance was removed because accepted transfer data must compile and serve end-to-end |
| External secret store client integration | Resolved: plaintext filesystem `SecretStore` snapshot projection is in scope; direct Vault/KMS/PKCS#11/HSM clients are excluded | v0.2.0 | Static config keeps policy; dynamic secrets reload through filesystem-backed snapshots |
| Property-based testing in Alpha scope | Pending quality-improvement candidate | later quality pass | Non-normative improvement tracked in Test Plan |
| Server module decomposition | Pending maintainability candidate | later maintainability pass | `server/lib.rs` decomposition remains useful but not a release blocker |
| 1 percent idle CPU bound for 1000 zones | Pending formal Reference Hardware/Profile acceptance target | later reference-profile acceptance | Local tooling can sample idle CPU; formal profile confirmation is deferred |

## RFC Compliance Assertions

Primary documentation sync:
`docs/rfc-compliance-assertions.md`;
`docs/operator-deployment-guide.md#rfc-compliance-assertions`.

Status vocabulary: Fully Compliant, Partially Compliant, Not Compliant,
Informative Only. No row is asserted Fully Compliant or Not Compliant for
v0.2.0; most implemented DNS protocol rows remain Partially Compliant until
formal retained release evidence is complete.

| RFC number | RFC title | Compliance status | Scope qualifier | Unresolved compliance gaps | Target resolution milestone | SRS revision | Evidence pointer |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RFC 1034 | Domain Names: Concepts and Facilities | Partially Compliant | secondary authoritative server clauses | Full retained release traceability remains open | Formal SRS acceptance | SRS v0.9.1 | `docs/appendix-a-traceability-matrix.md`; `docs/verification-ledger.md` |
| RFC 1035 | Domain Names: Implementation and Specification | Partially Compliant | DNS wire format, RR format, authoritative response, TCP framing, bounded CHAOS handling | Full retained release traceability remains open | Formal SRS acceptance | SRS v0.9.1 | `scripts/check.sh`; `scripts/interop-chaos-queries.sh` |
| RFC 5936 | DNS Zone Transfer Protocol (AXFR) | Partially Compliant | AXFR client-side clauses | Broader fault-injection, multi-primary, and production-depth artifacts remain open | Formal SRS acceptance | SRS v0.9.1 | `scripts/interop-bind-axfr.sh`; `docs/primary-interop-matrix-v0.2.0.md`; `docs/appendix-a-traceability-matrix.md` |
| RFC 1995 | Incremental Zone Transfer in DNS | Partially Compliant | IXFR client-side clauses | Additional real-primary IXFR matrix remains open | Formal SRS acceptance | SRS v0.9.1 | `scripts/interop-bind-ixfr-refresh.sh`; `scripts/interop-knot-ixfr-refresh-docker.sh` |
| RFC 1996 | DNS NOTIFY | Partially Compliant | NOTIFY receiver-side clauses | Signed-NOTIFY fault matrix and retained refresh-trigger artifacts remain open | Formal SRS acceptance | SRS v0.9.1 | `scripts/interop-notify-negative.sh` |
| RFC 8945 | Secret Key Transaction Authentication for DNS | Partially Compliant | TSIG request/response, transfer, and NOTIFY authentication | Full TSIG truncation and transfer-stream release evidence remain open | Formal SRS acceptance | SRS v0.9.1 | `scripts/interop-bind-tsig-axfr.sh`; `docs/verification-ledger.md` |
| RFC 9103 | DNS Zone Transfer over TLS | Partially Compliant | XoT client-side transfer clauses only | Broader real-primary XoT matrix remains open | Formal SRS acceptance | SRS v0.9.1 | `scripts/interop-knot-xot-docker.sh`; `scripts/audit-xot-revocation.sh` |
| RFC 9432 | DNS Catalog Zones | Partially Compliant | catalog consumer behavior and explicit OxideDNS member-transfer extension profile | Broader release-level catalog evidence remains open | Formal SRS acceptance | SRS v0.9.1 | `docs/catalog-zone-rfc9432.md`; catalog interop scripts |
| RFC 7314 | EDNS EXPIRE Option | Informative Only | excluded experimental zone-expire signalling | Not implemented by design | N/A | SRS v0.9.1 | `docs/OxideDNS-Secondary-SRS-v0.9.1.md` |
| RFC 4033 | DNS Security Introduction and Requirements | Informative Only | DNSSEC architecture context | None; context citation only | N/A | SRS v0.9.1 | `docs/OxideDNS-Secondary-SRS-v0.9.1.md` |

## Interface Changes

Interface compatibility evidence:
`target/evidence/20260613T235555Z/interface-compatibility/interface-compatibility-summary.env`.

Previous accepted interface baseline: none for v0.2.0.

Current interface baseline:
`target/evidence/20260613T235555Z/interface-compatibility/current-interface-baseline.tsv`.

Interface additions: v0.2.0 includes `--config`/`OXIDEDNS_CONFIG` config-path
selection and reloadable filesystem-backed secret references for TSIG/XoT
material.

Interface deprecations: none.

Interface breaking changes: none against a previous accepted v0.2.x baseline.

Major-version approval rationale: not applicable; this is a pre-1.0 minor
release with an initial interface baseline.

## Security and Dependency Review

Dependency audit result: repository `cargo deny` gate passed in the release
snapshot; current duplicate dependency warnings are informational and do not
represent accepted advisory, ban, license, or source failures.

Unsafe dependency enumeration and scanner caveats: cargo-geiger evidence is
partial. The snapshot records 201 package rows, 201 unique packages, 95 packages
with unsafe items, 15,687 total unsafe items, 204 not-scanned files, 209 warning
lines, and `geiger_completeness_status=partial`.

Vulnerability disclosure changes: no v0.2.0-specific vulnerability disclosure
process change.

Vulnerability disclosure policy reviewed: Verified against `SECURITY.md`.

Release signing mechanism and verification instructions: Deferred to the
signing handoff. Static binary reproducibility is verified in
`docs/reproducible-build-v0.2.0.md`; public artifact signatures are not yet
claimed. The preferred mechanism remains Sigstore/Cosign with detached OpenPGP
allowed as fallback.

Security audit findings and remediation actions: no accepted Failed blocker is
recorded for this release. Security review ownership is still an explicit
release handoff row.

## Long-Running Evidence Handoff

Fuzz campaign handoff or completed artifacts: a first ASan-backed two-host
24-hour fuzz record exists in `docs/two-host-fuzz-soak-campaign.md`; broader
long-running campaign execution remains Deferred.

Info verbosity profile handoff or completed artifacts:
`target/evidence/20260613T235555Z/info-verbosity-handoff/`.

Reference Hardware/Profile benchmark handoff or completed artifacts:
`target/evidence/20260613T235555Z/benchmark-handoff/`.

Soak handoff or completed 30-day report:
`target/evidence/20260613T235555Z/soak-handoff/`.

Release/operations owner for delegated long-running evidence:
`unassigned-release-engineer` / `unassigned-external-operator` until a named
operator signs the production acceptance rows.

Deferred execution rationale: these are production-depth or long-duration
acceptance artifacts; v0.2.0 publishes the cleaned implementation, gates, and
handoff package without claiming completed production acceptance.

## Release/Operations Handoff

Release handoff artifact:
`target/evidence/20260613T235555Z/release-handoff/evidence-attachment-map.tsv`.

Scheduled CI/manual-run plan:
`target/evidence/20260613T235555Z/release-handoff/scheduled-ci-plan.md`.

Release readiness checklist:
`target/evidence/20260613T235555Z/release-handoff/release-readiness-checklist.md`.

External operator acceptance artifact:
`target/evidence/20260613T235555Z/release-handoff/external-operator-acceptance.md`.

Signing runbook or completed signing manifest:
`target/evidence/20260613T235555Z/release-handoff/signing-runbook.md`.

## Verification Responsibility Sign-off

| Role | Owner | Sign-off state | Scope |
| --- | --- | --- | --- |
| Architecture Owner | DT | Verified | Release verification result review |
| Release engineer | unassigned-release-engineer | Deferred | Gate execution, evidence snapshot, release notes, signing handoff |
| Test/verification owner | unassigned-release-engineer | Deferred | Verification evidence completeness and regression triage |
| Operations owner | unassigned-release-engineer | Deferred | Long-running fuzz, benchmark, and soak scheduling |
| External operator | unassigned-external-operator | Deferred | Production-representative formal acceptance |
| Security reviewer | unassigned-security-reviewer | Deferred | Security policy review, dependency audit review, and vulnerability exceptions |
