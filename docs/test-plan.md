# OxideDNS Test Plan

This Test Plan is the sibling document required by SRS v0.7 section 7.6. It
records the current verification harnesses, their SRS method classifications,
and their execution cadence. It is intentionally a living plan: individual test
case inventories will become more granular as Appendix A expands from
family-level traceability to per-requirement traceability.

## Scope

- Normative source: `docs/OxideDNS-Secondary-SRS-v0.7.md`.
- Working evidence ledger: `docs/verification-ledger.md`.
- Family traceability matrix: `docs/appendix-a-traceability-matrix.md`.
- Release evidence snapshot: `scripts/release-evidence-snapshot.sh`.

Every concrete test case or evidence command in this plan must reference SRS
requirement identifiers directly or through the ledger/matrix row that owns the
family-level requirement range.

## Cadence Classes

The project uses the SRS v0.7 ODS-VER-011 cadence vocabulary exactly:

- **Continuous**: build-blocking checks for every main-branch candidate.
- **Periodic**: scheduled checks independent of a specific commit.
- **Gate**: release-acceptance checks whose results support release approval.

## Method Cadence Map

| Verification method | Cadence | Current harness or evidence command | Requirement coverage owner |
| --- | --- | --- | --- |
| Static analysis | Continuous | `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `scripts/audit-invariants.sh`; `scripts/audit-safe-rust.sh`; `scripts/audit-unused-code.sh`; `scripts/audit-spoof-evidence.py`; `scripts/audit-log-fields.py`; `scripts/audit-log-lazy-formatting.py`; `scripts/audit-dnssec-passive.sh`; `scripts/audit-xot-revocation.sh`; `cargo deny check` | `docs/verification-ledger.md`; `docs/appendix-a-traceability-matrix.md` |
| Unit test | Continuous | `cargo test --workspace`; `scripts/capture-coverage-evidence.sh` for `cargo-llvm-cov` threshold evidence | Rust test names and ledger rows |
| Property-based test | Continuous | Targeted randomized tests inside `cargo test --workspace`; promote dedicated property suites here when introduced | Rust test names and ledger rows |
| Integration test | Continuous | Runtime tests inside `cargo test --workspace`; CLI process tests in `crates/oxidedns-cli/tests` | Rust test names and ledger rows |
| Conformance test | Continuous and Gate | DNS wire-format, EDNS, TSIG, DNSSEC-passive, signal, CLI, health, metrics, and config tests inside `cargo test --workspace`; retained via release snapshot at Gate | Rust test names, release snapshot logs, and ledger rows |
| Short-cadence Fuzz test | Continuous | `cargo check --manifest-path fuzz/Cargo.toml`; optional `scripts/fuzz-campaign.sh --duration <seconds>` runs not exceeding one hour per parser | `fuzz/README.md`; release snapshot logs |
| Dependency security audit | Continuous | `cargo deny check` | `docs/verification-ledger.md` dependency audit row |
| Long-cadence Fuzz test | Periodic | `scripts/fuzz-campaign.sh --duration 86400` per parser target; local MVP requires setup, later release/operations execution retains the full campaign artifacts | retained fuzz campaign artifacts |
| Performance test | Periodic and Gate | `scripts/perf-smoke.sh` and `scripts/capture-resource-evidence.sh` for current smoke evidence; `scripts/capture-benchmark-handoff.sh` creates the local MVP setup/report path for later Reference Hardware/Profile execution; `scripts/check-perf-regression.py` checks rolling-history comparisons | retained performance/resource logs, benchmark handoff or completed benchmark report, and regression baseline |
| Differential test | Periodic | Monthly comparison against current stable BIND 9, NSD, and Knot DNS primary releases; current interop scripts provide the starting harness | retained interop outputs |
| Interoperability test | Gate | BIND, NSD, and Knot scripts listed in `docs/mvp-gap-register.md`; primary versions retained by `scripts/interop-version-evidence.sh` and `scripts/evidence-artifacts.sh` | `ODS-VER-003`, `ODS-VER-004`, `ODS-VER-013` |
| Soak test | Periodic and Gate | `scripts/capture-soak-handoff.sh` creates the local MVP setup/report path; later release/operations execution runs the 30-day production-representative soak with weekly snapshot reports | soak handoff and completed soak report artifacts |
| Operational test | Gate | Operator Deployment Guide execution, release evidence snapshot review, deployment/rollback exercise, external operator acceptance | release notes and operator acceptance records |
| Security audit | Gate | Third-party or independent review at major release boundaries and after vulnerability-disclosure events | release notes and security audit report |
| External operator acceptance | Gate | Production-representative external deployment and signed scope statement for MVP acceptance | MVP release notes |

## Continuous Execution

`scripts/check.sh` enacts the current Continuous cadence. It is the local
stand-in for CI until a hosted CI definition is added. The command must remain
build-blocking for:

- Test Plan shape validation: `scripts/check-test-plan.sh`;
- verification ledger consistency: `python3 scripts/check-verification-ledger.py`;
- static audits: invariant, passive DNSSEC, XoT revocation, safe-Rust where
  release-review cost allows;
- Rust formatting, clippy, workspace tests, and coverage threshold evidence;
- dependency advisory/license/source checks through `cargo deny check`.

## Periodic Execution

Periodic evidence is not yet fully automated. Until scheduled CI is added, the
release engineer records each periodic run manually in the release evidence
snapshot and release notes.

| Periodic evidence | Required cadence | Current command or artifact | MVP gap |
| --- | --- | --- | --- |
| Long fuzz campaign | Weekly during release acceptance execution; at least 24 hours per parser before final signoff | `scripts/fuzz-campaign.sh --duration 86400` | local MVP needs runnable setup and retained campaign summary format |
| Performance regression run | Weekly on Reference Hardware Profile | `scripts/capture-benchmark-handoff.sh` provides `benchmark-report-template.md`, metric/resource TSV schemas, baseline-history template, runbook, and operator sign-off scaffold; later execution fills those artifacts and runs `scripts/check-perf-regression.py --candidate <file> --history <history>` | release/operations owners later fill the report during Reference Hardware/Profile benchmark execution |
| Soak snapshot | Weekly while later soak execution is active | `scripts/capture-soak-handoff.sh` provides `soak-report-template.md`, TSV sample schemas, weekly summary template, and operator sign-off scaffold | release/operations owners later fill the report during the 30-day run |
| Differential primary comparison | Monthly | BIND/NSD/Knot interop scripts | add differential assertions beyond pass/fail interop |

## Gate Execution

Release Gate evidence is captured with `scripts/release-evidence-snapshot.sh`.
Set `OXIDEDNS_EVIDENCE_RUN_INTEROP=1` for release candidates that need retained
interop artifacts, `OXIDEDNS_EVIDENCE_RUN_FUZZ=1` for release-cadence fuzz evidence,
`OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` for retained RRL campaign evidence, and
`OXIDEDNS_RELEASE_NOTES=<path>` to run the release-notes gate against the snapshot.
Use `OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS` for iteration-count campaigns or
`OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_DURATION` for wall-clock duration campaigns.

Gate review must not treat skipped interop, fuzz, performance, soak, security
audit, or external-operator steps as passing evidence for final SRS acceptance.
For the local project MVP, long-running steps may be marked as delegated when
the runnable harness, artifact format, and release/operations handoff are
present.

`scripts/capture-benchmark-handoff.sh` is intentionally a setup artifact. It
creates the benchmark runbook, report template, performance/resource TSV
schemas, requirement traceability map, rolling-baseline history template, and
operator sign-off scaffold for later Reference Hardware/Profile execution. A
generated handoff directory proves the local MVP setup exists; it does not
prove that production benchmarks have been executed.

`scripts/capture-soak-handoff.sh` is intentionally a setup artifact. It creates
the report template, RSS/file-descriptor/metrics/event TSV schemas, requirement
traceability map, and operator sign-off scaffold for the later ODS-NFR-REL-003
30-day soak. A generated handoff directory proves the local MVP setup exists; it
does not prove that the long-running soak has been executed.

When `OXIDEDNS_PERF_BASELINE` points at a whitespace-delimited history file with
rows shaped as `release metric value`, `scripts/release-evidence-snapshot.sh`
runs the smoke-metric regression comparison. `OXIDEDNS_PERF_REGRESSION_THRESHOLD_PCT`
overrides the default 10 percent threshold.

## Regression Policy

This policy implements ODS-VER-012.

- A functional regression exists when a requirement previously marked
  **Verified** in the traceability matrix fails its current verification.
- A performance/resource regression exists when an `ODS-NFR-PERF-*` or
  `ODS-NFR-RES-*` metric that previously met target degrades by more than
  `regression.performance_threshold_pct`.
- `regression.performance_threshold_pct` defaults to **10**.
- The performance/resource comparison baseline is the median of the last five
  release measurements for the same metric on the Reference Hardware Profile.
- The first release of a major version establishes the initial baseline.
- New requirements introduced in a release cannot regress because they have no
  prior verification result; they are classified as Verified, Deferred, or
  Failed against their new acceptance criterion.

Every detected regression must be triaged before release. The release notes
must record root cause, owner, remediation release, and whether the regression
was fixed or explicitly accepted with rationale. A release with an untriaged
regression must not proceed.

## Release Notes Inputs

`docs/release-notes-template.md` is the required release-note structure. The
release-note gate checks that the release notes include:

- per-requirement-category counts for Verified, Deferred, and Failed;
- new Failed and Deferred results compared to the previous same-major release;
- retained primary version/configuration artifact paths for interop evidence;
- failed-requirement project decisions and remediation targets;
- RFC compliance assertions;
- verification responsibility sign-off;
- for the MVP gate, external operator acceptance signature, accepting operator
  identity, and accepted scope statement.
