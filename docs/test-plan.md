# OxideDNS Test Plan

This Test Plan is the sibling document required by SRS v0.9.1 section 7.6. It
records the current verification harnesses, their SRS method classifications,
and their execution cadence. It is intentionally a living plan: the test
inventory stays at evidence-command and requirement-family level until release
acceptance requires per-requirement rows. Appendix A, the verification ledger,
and release evidence snapshots own that expansion.

## Scope

- Normative source: `docs/OxideDNS-Secondary-SRS-v0.9.1.md`.
- Working evidence ledger: `docs/verification-ledger.md`.
- Family traceability matrix: `docs/appendix-a-traceability-matrix.md`.
- Release evidence snapshot: `scripts/release-evidence-snapshot.sh`.
- Release/operations handoff: `scripts/capture-release-handoff.sh`.

Every concrete test case or evidence command in this plan must reference SRS
requirement identifiers directly or through the ledger/matrix row that owns the
family-level requirement range.

## Cadence Classes

The project uses the SRS v0.9.1 ODS-VER-011 cadence vocabulary exactly:

- **Continuous**: build-blocking checks for every main-branch candidate.
- **Periodic**: scheduled checks independent of a specific commit.
- **Gate**: release-acceptance checks whose results support release approval.

For the private Engineering MVP profile, only the Continuous class is enacted
as local automation through `scripts/check.sh`. Periodic and Gate rows below are
documented release/operations obligations with runnable commands, handoff
artifacts, and evidence formats; they are not treated as completed evidence
until their corresponding retained runs exist.

## Method Cadence Map

| Verification method | Cadence | Current harness or evidence command | Requirement coverage owner |
| --- | --- | --- | --- |
| Static analysis | Continuous | `cargo fmt --all --check`; `scripts/check-shell-scripts.sh` (`shfmt -w` plus `shellcheck`); `cargo clippy --workspace --all-targets -- -D warnings`; `scripts/audit-invariants.sh`; `scripts/audit-safe-rust.sh`; `scripts/check-unsafe-boundaries.py`; `scripts/check-unsafe-prone-dependencies.py`; `scripts/check-interface-compatibility.py`; `scripts/check-functional-requirement-references.py`; `scripts/audit-unused-code.sh`; `scripts/audit-spoof-evidence.py`; `scripts/audit-log-fields.py`; `scripts/audit-log-lazy-formatting.py`; `scripts/audit-dnssec-passive.sh`; `scripts/audit-xot-revocation.sh`; `cargo deny check`; release-review `scripts/capture-unsafe-dependency-evidence.sh` | `docs/verification-ledger.md`; `docs/appendix-a-traceability-matrix.md` |
| Unit test | Continuous | `cargo test --workspace`; `scripts/capture-coverage-evidence.sh` for `cargo-llvm-cov` threshold evidence | Rust test names and ledger rows |
| Property-based test | Continuous | Targeted randomized tests inside `cargo test --workspace`; promote dedicated property suites here when introduced | Rust test names and ledger rows |
| Integration test | Continuous | Runtime tests inside `cargo test --workspace`; CLI process tests in `crates/oxidedns-cli/tests` | Rust test names and ledger rows |
| Conformance test | Continuous and Gate | DNS wire-format, EDNS, TSIG, DNSSEC-passive, signal, CLI, health, metrics, and config tests inside `cargo test --workspace`; retained via release snapshot at Gate | Rust test names, release snapshot logs, and ledger rows |
| Short-cadence Fuzz test | Continuous | `cargo check --manifest-path fuzz/Cargo.toml`; optional `scripts/fuzz-campaign.sh --duration <seconds>` runs not exceeding one hour per parser | `fuzz/README.md`; release snapshot logs |
| Dependency security audit | Continuous | `cargo deny check` | `docs/verification-ledger.md` dependency audit row |
| Long-cadence Fuzz test | Periodic | `scripts/fuzz-campaign.sh --duration 86400` per parser target; Engineering MVP setup records `campaign-summary.tsv`, later release/operations execution retains the full campaign artifacts | retained fuzz campaign summary, logs, and artifacts |
| Performance test | Periodic and Gate | `scripts/perf-smoke.sh` and `scripts/capture-resource-evidence.sh` for current smoke evidence; `scripts/capture-benchmark-handoff.sh` creates the Engineering MVP setup/report path for later Reference Hardware/Profile execution; `scripts/check-perf-regression.py` checks rolling-history comparisons | retained performance/resource logs, benchmark handoff or completed benchmark report, and regression baseline |
| Differential test | Periodic | Monthly comparison against current stable BIND 9, NSD, and Knot DNS primary releases; current interop scripts provide the starting harness | retained interop outputs |
| Interoperability test | Gate | BIND, NSD, and Knot scripts listed in `docs/evidence-command-catalog.md`, with current gaps tracked in `docs/mvp-gap-register.md`; human-operated BIND smoke run documented in `docs/manual-bind-interop.md`; primary versions retained by `scripts/interop-version-evidence.sh` and `scripts/evidence-artifacts.sh` | `ODS-VER-003`, `ODS-VER-004`, `ODS-VER-013` |
| Soak test | Periodic and Gate | `scripts/capture-soak-handoff.sh` creates the Engineering MVP setup/report path; later release/operations execution runs the 30-day production-representative soak with weekly snapshot reports | soak handoff and completed soak report artifacts |
| Operational test | Gate | Operator Deployment Guide execution, release evidence snapshot review, `scripts/capture-info-verbosity-handoff.sh` setup or completed profile, `scripts/capture-interface-compatibility-evidence.sh` baseline or completed release diff, deployment/rollback exercise, external operator acceptance | release notes, interface compatibility evidence, info verbosity profile, and operator acceptance records |
| Security audit | Gate | Third-party or independent review at major release boundaries and after vulnerability-disclosure events | release notes and security audit report |
| External operator acceptance | Gate | Production-representative external deployment and signed scope statement for formal SRS MVP release acceptance | formal SRS MVP release notes |

## Continuous Execution

`scripts/check.sh` enacts the current Continuous cadence. It is the local
stand-in for hosted continuous CI until a main-branch candidate workflow is
enabled. The command must remain build-blocking for:

- Test Plan shape validation: `scripts/check-test-plan.sh`;
- verification ledger consistency: `python3 scripts/check-verification-ledger.py`;
- functional requirement source-comment coverage:
  `python3 scripts/check-functional-requirement-references.py`;
- static audits: invariant, passive DNSSEC, XoT revocation, safe-Rust where
  release-review cost allows, and unsafe-boundary registry consistency;
- Rust formatting, shell formatting/linting, clippy, workspace tests, and
  coverage threshold evidence;
- dependency advisory/license/source checks through `cargo deny check`;
- transitive unsafe enumeration and first-party package unsafe-count checks
  through `scripts/capture-unsafe-dependency-evidence.sh`.

Hosted continuous CI for every main-branch candidate is intentionally deferred
while the repository remains private. This avoids spending GitHub Actions
minutes on heavyweight evidence tooling before a public-release gate exists;
`scripts/check.sh` is the current local continuous verification entry point.

This does not prohibit explicit release packaging automation. The repository
contains a tag-push/workflow-dispatch release workflow. It acts as artifact publication automation for a named release by building and smoking the
`x86_64-unknown-linux-musl` installer archive, raw static binary, and Docker
image archive; it is not the standing Continuous gate unless the release
process records its retained logs as the accepted release-gate automation
evidence.

Manual real-primary smoke evidence is intentionally outside `scripts/check.sh`
because it depends on Docker or host BIND availability. For developer/operator
confidence after an Engineering MVP build, run `scripts/interop-bind-axfr-docker.sh`
and retain artifacts with `OXIDEDNS_BIND_DOCKER_AXFR_ARTIFACT_DIR`, as described
in `docs/manual-bind-interop.md`. For RFC 9432 catalog-zone confidence, run
`scripts/interop-bind-catalog-zone-docker.sh` and retain artifacts with
`OXIDEDNS_BIND_CATALOG_DOCKER_ARTIFACT_DIR`; that harness mutates the BIND
catalog while OxideDNS remains running and verifies live member add/remove
behavior end to end. For BIND 9 XoT catalog-zone confidence, run
`scripts/interop-bind-xot-catalog-zone-docker.sh` and retain artifacts with
`OXIDEDNS_BIND_XOT_CATALOG_DOCKER_ARTIFACT_DIR`; that harness verifies ALPN
`dot`, TSIG over XoT, denied plain TCP transfer, and live catalog member
add/remove. For the intended PowerDNS plus PostgreSQL primary shape, run
`scripts/interop-powerdns-postgres-catalog-tsig-docker.sh` and retain artifacts
with `OXIDEDNS_POWERDNS_CATALOG_TSIG_ARTIFACT_DIR`; that harness uses PowerDNS
producer catalog metadata, PostgreSQL/gpgsql storage, TSIG-only catalog/member
transfers, live catalog assignment add/remove, and an in-place member-zone
record update while OxideDNS remains running.

## Periodic Execution

Periodic evidence is not yet fully automated. Until scheduled CI is added, the
release engineer records each periodic run manually in the release evidence
snapshot and release notes.

The cadence column below is a formal release-acceptance cadence, not an
Engineering MVP execution requirement and not a standing calendar commitment
until a release-acceptance cycle begins. In the private Engineering MVP profile,
these rows remain handoff obligations unless completed artifacts are retained.

| Periodic evidence | Release acceptance cadence | Current command or artifact | Open acceptance work |
| --- | --- | --- | --- |
| Long fuzz campaign | Weekly during release acceptance execution; at least 24 hours per parser before final signoff | `scripts/fuzz-campaign.sh --duration 86400` with retained `campaign-summary.tsv` | release/operations owners later fill the summary during 24-hour parser campaigns |
| Performance regression run | Weekly on Reference Hardware Profile | `scripts/capture-benchmark-handoff.sh` provides `benchmark-report-template.md`, metric/resource TSV schemas, baseline-history template, runbook, and operator sign-off template; later execution fills those artifacts and runs `scripts/check-perf-regression.py --candidate <file> --history <history>` | release/operations owners later fill the report during Reference Hardware/Profile benchmark execution |
| Reproducible-build comparison | Gate before formal SRS MVP or public artifact signing | `scripts/capture-reproducible-build-handoff.sh` provides fixed build inputs, runbook, artifact manifest schema, comparison schema, release-note snippet, and release-engineer sign-off template; later execution fills those artifacts after two independent clean builds | release/operations owners later fill the comparison before claiming ODS-NFR-MAINT-005 |
| Soak snapshot | Weekly while later soak execution is active | `scripts/capture-soak-handoff.sh` provides `soak-report-template.md`, TSV sample schemas, weekly summary template, and operator sign-off template | release/operations owners later fill the report during the 30-day run |
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
For Engineering MVP, long-running steps may be marked as delegated when
the runnable harness, artifact format, and release/operations handoff are
present.

`scripts/capture-release-handoff.sh` is intentionally a setup artifact. It
creates the release attachment map, scheduled CI/manual-run plan, signing
runbook, release-note fill plan, external-operator acceptance template, and
release-readiness checklist for later SRS acceptance execution. A generated
handoff directory proves the Engineering MVP governance setup exists; it does not
prove that release acceptance or external-operator sign-off has been completed.

`scripts/capture-info-verbosity-handoff.sh` is intentionally a setup artifact.
It creates the runbook, report template, log-volume/structured-field/metrics
TSV schemas, requirement traceability map, release-note snippet, and operator
sign-off template for later production-depth profiling of `info` verbosity
under release traffic. A generated handoff directory proves the Engineering MVP
setup exists; it does not prove that production-depth profiling has been
executed.

`scripts/capture-interface-compatibility-evidence.sh` records the current
interface baseline and policy for ODS-NFR-MAINT-006. When a previous accepted
baseline is provided, it also runs the release-to-release compatibility diff.
Without that previous baseline it is setup evidence only and must not be treated
as a completed compatibility-diff review.

`scripts/capture-benchmark-handoff.sh` is intentionally a setup artifact. It
creates the benchmark runbook, report template, performance/resource TSV
schemas, requirement traceability map, rolling-baseline history template, and
operator sign-off template for later Reference Hardware/Profile execution. A
generated handoff directory proves the Engineering MVP setup exists; it does
not prove that production benchmarks have been executed.

`scripts/capture-soak-handoff.sh` is intentionally a setup artifact. It creates
the report template, RSS/file-descriptor/metrics/event TSV schemas, requirement
traceability map, and operator sign-off template for the later ODS-NFR-REL-003
30-day soak. A generated handoff directory proves the Engineering MVP setup
exists; it does not prove that the long-running soak has been executed.

`scripts/capture-reproducible-build-handoff.sh` is intentionally a setup
artifact. It creates fixed build inputs, a runbook, artifact-manifest and
comparison TSV schemas, requirement traceability, release-note snippet, and
release-engineer sign-off template for the later independent bit-identical build
comparison. A generated handoff directory proves the Engineering MVP setup
exists; it does not prove ODS-NFR-MAINT-005 until completed manifests from two
independent builders match.

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

- per-requirement-category counts for Verified, Deferred, and Failed, including
  the `ODS-VER` verification-requirement category;
- new Failed and Deferred results compared to the previous same-major release;
- retained primary version/configuration artifact paths for interop evidence;
- failed-requirement project decisions and remediation targets;
- RFC compliance assertions;
- verification responsibility sign-off;
- for the formal SRS MVP release gate, external operator acceptance signature, accepting operator
  identity, and accepted scope statement.
