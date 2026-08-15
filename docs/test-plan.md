# BoronDNS Test Plan

This Test Plan is the sibling document required by SRS v0.9.1 section 7.6. It
records the current verification harnesses, their SRS method classifications,
and their execution cadence. It is intentionally a living plan: the test
inventory stays at evidence-command and requirement-family level until release
acceptance requires per-requirement rows. Appendix A, the verification ledger,
and release evidence snapshots own that expansion.

## Scope

- Normative source: `docs/BoronDNS-Secondary-SRS-v0.9.1.md`.
- Working evidence ledger: `docs/verification-ledger.md`.
- Family traceability matrix: `docs/appendix-a-traceability-matrix.md`.
- Release evidence snapshot: `scripts/release-evidence-snapshot.sh`.
- Release/operations handoff: `scripts/capture-release-handoff.sh`.

Every concrete test case or evidence command in this plan must reference SRS
requirement identifiers directly or through the ledger/matrix row that owns the
family-level requirement range.

## Cadence Classes

The project uses the SRS v0.9.1 BDS-VER-011 cadence vocabulary exactly:

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
| Static analysis | Continuous plus release review | `cargo fmt --all --check`; `cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check`; `scripts/check-shell-scripts.sh` (non-mutating `shfmt -d` plus `shellcheck`); `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings`; `scripts/check-github-actions.sh`; `scripts/audit-invariants.sh`; `scripts/audit-safe-rust.sh`; `scripts/check-unsafe-boundaries.py`; `scripts/check-unsafe-prone-dependencies.py`; `scripts/check-interface-compatibility.py`; `scripts/check-functional-requirement-references.py`; `scripts/audit-unused-code.sh`; `scripts/audit-spoof-evidence.py`; `scripts/audit-log-fields.py`; `scripts/audit-log-lazy-formatting.py`; `scripts/audit-dnssec-passive.sh`; `scripts/audit-xot-revocation.sh`; `cargo deny check`; release-review `scripts/capture-unsafe-dependency-evidence.sh` | `docs/verification-ledger.md`; `docs/appendix-a-traceability-matrix.md` |
| Unit test | Continuous | Default-feature `cargo test --workspace -- --test-threads=1` plus `cargo test --workspace --all-targets --all-features -- --test-threads=1` so the feature-gated server AF_XDP and BoronGun XDP adapter suites remain blocking; `scripts/capture-coverage-evidence.sh` for `cargo-llvm-cov` threshold evidence | Rust test names and ledger rows |
| Property-based test | Continuous | Targeted randomized tests inside `cargo test --workspace`; promote dedicated property suites here when introduced | Rust test names and ledger rows |
| Integration test | Continuous | Runtime tests inside `cargo test --workspace`; CLI process tests in `crates/borondns-cli/tests` | Rust test names and ledger rows |
| Conformance test | Continuous and Gate | DNS wire-format, EDNS, TSIG, DNSSEC-passive, signal, CLI, health, metrics, and config tests inside `cargo test --workspace`; retained via release snapshot at Gate | Rust test names, release snapshot logs, and ledger rows |
| Short-cadence Fuzz test | Continuous | `cargo check --manifest-path fuzz/Cargo.toml`; fuzz-crate formatting and warning-free Clippy gates; optional `scripts/fuzz-campaign.sh --duration <seconds>` runs not exceeding one hour per parser | `fuzz/README.md`; release snapshot logs |
| Dependency security audit | Continuous | `cargo deny check` | `docs/verification-ledger.md` dependency audit row |
| Long-cadence Fuzz test | Periodic | `scripts/fuzz-campaign.sh --duration 86400` per parser target; `docs/two-host-fuzz-soak-campaign.md` and `scripts/fuzz-soak-two-host-campaign.sh plan --duration 86400` prepare the local two-host split; Engineering MVP setup records `campaign-summary.tsv`, later release/operations execution retains the full campaign artifacts | retained fuzz campaign summary, logs, and artifacts |
| Performance test | Periodic and Gate | `scripts/perf-smoke.sh` and `scripts/capture-resource-evidence.sh` for current smoke evidence; `scripts/capture-benchmark-handoff.sh` creates the Engineering MVP setup/report path for later Reference Hardware/Profile execution; `scripts/check-perf-regression.py` checks rolling-history comparisons | retained performance/resource logs, benchmark handoff or completed benchmark report, and regression baseline |
| Differential test | Periodic | Monthly comparison against current stable BIND 9, NSD, and Knot DNS primary releases; current interop scripts provide the starting harness | retained interop outputs |
| Interoperability test | Gate | BIND, NSD, and Knot scripts listed in `docs/evidence-command-catalog.md`, with current gaps tracked in `docs/mvp-gap-register.md`; human-operated BIND smoke run documented in `docs/manual-bind-interop.md`; primary versions retained by `scripts/interop-version-evidence.sh` and `scripts/evidence-artifacts.sh` | `BDS-VER-003`, `BDS-VER-004`, `BDS-VER-013` |
| Soak test / extended-runtime test | Periodic and Gate when selected | `scripts/capture-soak-handoff.sh` creates a duration-neutral setup/report path; the release plan selects fuzz/resource rounds, allocator stress, targeted load, and any optional longer soak according to changed risk | retained resource samples and completed extended-runtime report artifacts |
| Operational test | Gate | Operator Deployment Guide execution, release evidence snapshot review, `scripts/capture-info-verbosity-handoff.sh` setup or completed profile, `scripts/capture-interface-compatibility-evidence.sh` baseline or completed release diff, deployment/rollback exercise, and optional external operator review | release notes, interface compatibility evidence, info verbosity profile, and any external review record |
| Optional independent security review | Gate when selected | Third-party or independent review may be selected for a defined release or vulnerability scope | release notes and review report when available |
| Optional external operator review | Gate when selected | Production-representative external deployment may supplement project-owned acceptance evidence | release notes and reviewed scope when available |

The `scripts/audit-invariants.sh` BDS-INV-004 gate self-tests its filesystem
mutation scanner before inspecting runtime source. Its fixtures cover Cargo
dependency renames followed by source-level crate/module aliases, fixed-point
type and function-value aliases, typed `Default::default()` `OpenOptions`,
parenthesized or cast function values, `const`/`static` function bindings, and
moved or assigned `OpenOptions`, `DirBuilder`, and `File` capabilities. The
multi-hop fixtures exercise each added binding form. Negative fixtures retain
generic network writers, unrelated typed defaults, and provably read-only
`OpenOptions`/`rustix` opens as allowed surfaces.

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
- first-party safe-Rust and audited unsafe-boundary checks through
  `scripts/audit-safe-rust.sh` and `scripts/check-unsafe-boundaries.py`.

Transitive unsafe dependency enumeration through
`scripts/capture-unsafe-dependency-evidence.sh` is retained as release-review
evidence because it depends on `cargo-geiger` scanner behavior and can be
slow or partial. It is not part of the default Engineering MVP evidence
profile.

Hosted continuous CI for every main-branch candidate is intentionally deferred
while the repository remains private. This avoids spending GitHub Actions
minutes on heavyweight evidence tooling before a public-release gate exists;
`scripts/check.sh` is the current local continuous verification entry point.

`scripts/test-operations-harnesses.sh` is the focused fault-injection gate for
campaign and interop lifecycle helpers. Its Docker-image setup fixtures use a
monotonic clock and verify that lock acquisition, descriptor-bound temporary
tree creation, identity-bound cleanup, broker release, and all STOP,
SIGTERM-ignore, and SIGKILL/reap paths share one absolute setup deadline. The
timing assertions include a narrow scheduler tolerance but do not grant each
cleanup phase a fresh timeout. Where a setup operation authenticates an earlier
operation cutoff and a later cleanup cutoff, ordinary mutations stop at the
first cutoff while the non-replaceable broker authority remains available only
for bounded cleanup through the second. The same gate replaces automatic-tree
family lock pathnames during creation and requires the abstract family
authority to prevent split-brain publication while exact rollback leaves a
discoverable tree/journal or quarantine instead of deleting through a mutable
pathname. Automatic-tree journal/recovery scans and stale-status staging scans
stream directory entries under the absolute operation deadline, sort only a
bounded set, and fail-retain when the explicit entry cap is exceeded. Flood and
expired-deadline fixtures require prompt nonzero exit without deleting any
preexisting entry or publishing a replacement. Expired cleanup attempts leave
the ready journal byte-identical.
Deadline-supervisor fixtures also delay procfs enumeration before its first
entry and lower a test-only proc inventory cap, proving that process-group
membership checks cannot extend the configured termination tail. Collection
metadata fixtures cover oversized sparse status/commit files, FIFO commits,
post-open pathname swaps, and a live transaction flooded beyond its 64-entry
recovery cap; each must fail promptly and retain unrelated or indeterminate
state.
Restarted processes treat same-UID disk journals and collection markers as
evidence only and prove that forged, schema-valid state cannot authorize
delete, overwrite, restore, or promotion. Live collection tests retain marker
and transaction descriptors, keep marker decision payloads in immutable process
state, and reject both post-creation pathname swaps and in-place marker rewrites
paired with object swaps. They also interrupt an all-absent bundle before its
first promotion and require same-process recovery to restore all three absent
destinations, covering dynamic output assignment from live marker state.
Privileged-cleanup fixtures prove that sudo still
retains a current-UID-owned fuzz tree instead of recursively deleting it, and
that a root-owned mode-0777 post-stat swap or named access ACL forces the same
whole-tree retention. Retained-cleanup fixtures require a prepublished exact
original/quarantine identity journal, verify a crash-left `prepared` journal
only when its original is absent and exact quarantine identity/type match, and
reject a forged sibling inode. The
deadline supervisor blocks INT/TERM/HUP/CHLD before `posix_spawn`, consumes
them with `signalfd`, observes exit with pidfd `waitid(WNOWAIT)`, tears down the
process group, and only then reaps. Its descriptor-bound stdout-capture fixture
TERMs the real outer Bash caller and proves that owner pidfds tear down nested
command-substitution descendants before the deadline. Early-failure fixtures
also require invalid owner overrides and capture output-name collisions to
preserve caller traps byte-for-byte and launch no child. Descriptor-exhaustion
fixtures cover the partial process-substitution window, requiring a nonzero
capture result, unchanged caller output and traps, and no orphaned child.
Metadata-codec fixtures reject implementation-local and syntactically unsafe
dynamic output names before caller state is unset or metadata is read. Retained
journal fixtures also reject symlink parent namespaces and require journal,
original, and quarantine checks relative to one descriptor-bound real parent.
Sampler fixtures
also cross-bind every process-detail row to its exact host epoch, reject
per-epoch duplicate PIDs and aggregate mismatches, and retain same-PID reuse
across later epochs as valid evidence.

The repository also contains a tag-push/workflow-dispatch release workflow. It
runs `scripts/check.sh` as a blocking Continuous gate, then acts as artifact publication automation
for a named release by building and smoking the
`x86_64-unknown-linux-musl` installer archive, raw static `borondns` binary,
raw static XDP-enabled `boron-gun` binary, and Docker image archive; it is not
the standing Continuous gate unless the release
process records its retained logs as the accepted release-gate automation
evidence.

Manual real-primary smoke evidence is intentionally outside `scripts/check.sh`
because it depends on Docker or host BIND availability. For developer/operator
confidence after an Engineering MVP build, run `scripts/interop-bind-axfr-docker.sh`
and retain artifacts with `BORONDNS_BIND_DOCKER_AXFR_ARTIFACT_DIR`, as described
in `docs/manual-bind-interop.md`. For RFC 9432 catalog-zone confidence, run
`scripts/interop-bind-catalog-zone-docker.sh` and retain artifacts with
`BORONDNS_BIND_CATALOG_DOCKER_ARTIFACT_DIR`; that harness mutates the BIND
catalog while BoronDNS remains running and verifies live member add/remove
behavior end to end. For BIND 9 XoT catalog-zone confidence, run
`scripts/interop-bind-xot-catalog-zone-docker.sh` and retain artifacts with
`BORONDNS_BIND_XOT_CATALOG_DOCKER_ARTIFACT_DIR`; that harness verifies ALPN
`dot`, TSIG over XoT, denied plain TCP transfer, and live catalog member
add/remove. For the intended PowerDNS plus PostgreSQL primary shape, run
`scripts/interop-powerdns-postgres-catalog-tsig-docker.sh` and retain artifacts
with `BORONDNS_POWERDNS_CATALOG_TSIG_ARTIFACT_DIR`; that harness uses PowerDNS
producer catalog metadata, PostgreSQL/gpgsql storage, TSIG-only catalog/member
transfers, live catalog assignment add/remove, and an in-place member-zone
record update while BoronDNS remains running.

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
| Reproducible-build comparison | Hard gate before public artifact signing | The tagged workflow runs `scripts/reproducible-build-compare.sh` for its exact current commit and authenticates the validated manifests into the signing job; `docs/reproducible-build-v0.2.0.md` records earlier v0.2.0 evidence and `scripts/capture-reproducible-build-handoff.sh` provides release-engineer sign-off templates | release/operations owners still fill package/image, public-signature verification, and external sign-off evidence before claiming broader artifact acceptance |
| Extended-runtime snapshot | At a declared cadence while the selected run is active | `scripts/capture-soak-handoff.sh` provides `soak-report-template.md`, TSV sample schemas, summary template, and operator sign-off template | release/operations owners fill the report for the declared run duration |
| Differential primary comparison | Monthly | BIND/NSD/Knot interop scripts | add differential assertions beyond pass/fail interop |

## Gate Execution

Release Gate evidence is captured with `scripts/release-evidence-snapshot.sh`.
Set `BORONDNS_EVIDENCE_RUN_INTEROP=1` for release candidates that need retained
interop artifacts, `BORONDNS_EVIDENCE_RUN_FUZZ=1` for release-cadence fuzz evidence,
`BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` for retained RRL campaign evidence, and
`BORONDNS_RELEASE_NOTES=<path>` to run the release-notes gate against the snapshot.
Use `BORONDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS` for iteration-count campaigns or
`BORONDNS_EVIDENCE_RRL_CAMPAIGN_DURATION` for wall-clock duration campaigns.

Gate review must not treat skipped interop, fuzz, performance, soak, security
audit, or external-operator steps as passing evidence for final SRS acceptance.
For Engineering MVP, long-running steps may be marked as delegated when
the runnable harness, artifact format, and release/operations handoff are
present.

For releases that change the `ZoneImage` data plane, packet composer, or UDP/TCP
serving path, retain `scripts/zone-image-evidence-gate.sh` output as the
ZoneImage release gate. A local loopback run is acceptable for Engineering
release stabilization evidence; formal performance acceptance must use the
Reference Hardware/Profile or a physical non-loopback run with
`BORONDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true`.

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
interface baseline and policy for BDS-NFR-MAINT-006. When a previous accepted
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
traceability map, and operator sign-off template for the later BDS-NFR-REL-003
extended-runtime campaign. A generated handoff directory proves the setup
exists; it does not prove that the long-running soak has been executed.

`scripts/capture-reproducible-build-handoff.sh` is intentionally a setup
artifact. It creates fixed build inputs, a runbook, artifact-manifest and
comparison TSV schemas, requirement traceability, release-note snippet, and
release-engineer sign-off template. `scripts/reproducible-build-compare.sh`
now produces completed local static-binary manifests and comparison TSVs. The
tagged workflow validates the current-commit result before signing and carries
those records under a separate authenticated internal manifest; the handoff
remains for external sign-off and package/image follow-up.

When `BORONDNS_PERF_BASELINE` points at a whitespace-delimited history file with
rows shaped as `release metric value`, `scripts/release-evidence-snapshot.sh`
runs the smoke-metric regression comparison. `BORONDNS_PERF_REGRESSION_THRESHOLD_PCT`
overrides the default 10 percent threshold.

## Regression Policy

This policy implements BDS-VER-012.

- A functional regression exists when a requirement previously marked
  **Verified** in the traceability matrix fails its current verification.
- A performance/resource regression exists when a `BDS-NFR-PERF-*` or
  `BDS-NFR-RES-*` metric that previously met target degrades by more than
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
  the `BDS-VER` verification-requirement category;
- new Failed and Deferred results compared to the previous same-major release;
- retained primary version/configuration artifact paths for interop evidence;
- failed-requirement project decisions and remediation targets;
- RFC compliance assertions;
- verification responsibility sign-off;
- when an optional external operator review is available, reviewer identity,
  reviewed scope, and conclusions as supporting evidence.
