# BoronDNS Test Plan

This plan maps the SRS verification methods to runnable checks and explains when
to run them. Use [the evidence guide](release-evidence-guide.md) for capture and
retention, the [verification ledger](verification-ledger.md) for results, and
[Appendix A](appendix-a-traceability-matrix.md) for requirement traceability.
The governing requirements are in
[SRS section 7](BoronDNS-Secondary-SRS-v1.0.0.md).

## Cadence Classes

The `BDS-VER-011` classes describe when evidence is needed:

- **Continuous**: local checks required for a main-branch candidate.
- **Periodic**: scheduled runs during an active release-acceptance cycle.
- **Gate**: checks selected for a release decision.

`scripts/check.sh` implements Continuous locally and on the project's SSH
verification hosts. GitHub Actions builds and publishes tagged releases; it
does not run that full gate. No hosted periodic schedule is currently configured.

## Method Cadence Map

| Verification method | Cadence | Current harness | Evidence or requirement owner |
| --- | --- | --- | --- |
| Static analysis | Continuous | Rust and fuzz formatting/Clippy, shell lint, workflow lint, MSRV check, source/unsafe-boundary audits, interface and documentation checks in `scripts/check.sh` | Verification ledger and Appendix A |
| Unit test | Continuous | Default and all-feature workspace tests, plus coverage capture | Rust tests and `scripts/capture-coverage-evidence.sh` |
| Property-based test | Continuous | Targeted randomized tests inside the Rust suites | Rust test names and ledger rows |
| Integration test | Continuous | Server runtime and CLI process tests | Server and CLI test suites |
| Conformance test | Continuous and Gate | Wire format, EDNS, TSIG, passive DNSSEC, CLI, configuration, signals, health and metrics tests; selected interop scripts | Rust tests, interop reports, ledger |
| Short-cadence Fuzz test | Continuous | Fuzz compile, format, Clippy, and campaign dry-run checks; short executions selected separately | `fuzz/README.md` |
| Dependency security audit | Continuous | `cargo deny` for workspace and the two separate eBPF manifests | Dependency audit ledger row |
| Long-cadence Fuzz test | Periodic and Gate when selected | `scripts/fuzz-campaign.sh --duration 86400`; two-host campaign harness | Campaign summary, logs, crashes, and resource samples |
| Performance test | Periodic and Gate | `scripts/perf-smoke.sh`, resource capture, workload-specific benchmarks, regression comparison | Benchmark report and baseline |
| Differential test | Periodic | Comparisons against BIND, NSD, and Knot; interop scripts provide the starting harness | Retained comparative assertions and primary versions |
| Interoperability test | Gate | Primary matrix and protocol scripts in `docs/evidence-command-catalog.md` | `BDS-VER-003`, `BDS-VER-004`, `BDS-VER-013` |
| Soak test / extended-runtime test | Periodic and Gate when selected | Fuzz/resource rounds, allocator stress, sustained load, optional longer soak | Resource samples and declared run duration |
| Operational test | Gate | Install/upgrade/removal, startup, rollback, health, logging, interface comparison, release verification | Package tests and operator evidence |
| Optional independent security review | Gate when selected | Review of a declared release or changed attack surface | Review report and finding dispositions |
| Optional external operator review | Gate when available | Production-representative deployment review | Reviewer, scope, and conclusions |

## Continuous Execution

Run the maintained gate rather than copying its command list into a second
automation script:

```sh
scripts/check.sh
```

The gate includes these Rust checks:

```sh
rustup run 1.95.0 cargo check --workspace --all-targets --locked
cargo fmt --all --check
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
cargo test --workspace --all-targets --all-features -- --test-threads=1
```

The MSRV check uses the declared Rust 1.95.0 minimum. Normal builds use the
pinned repository toolchain. All-feature tests keep the server AF_XDP and
BoronGun XDP code covered even though those backends are opt-in.

Source checks include `scripts/check-unsafe-boundaries.py`,
`scripts/check-unsafe-prone-dependencies.py`,
`scripts/check-interface-compatibility.py`, and
`scripts/check-functional-requirement-references.py`. The invariant scanner
self-tests its alias and filesystem-capability handling before auditing runtime
source. Coverage and short resource checks also run in the gate.

`scripts/test-operations-harnesses.sh` covers process deadlines, cancellation,
resource sampling, lock ownership, collection consistency, and recovery from
interrupted operations. It includes fault injection for pathname replacement,
forged recovery metadata, descriptor exhaustion, and retained-state cleanup.
The fixtures and their exact assertions belong in that script, rather than
being duplicated as an evolving test inventory here.

`scripts/capture-unsafe-dependency-evidence.sh` provides transitive unsafe
enumeration for release review. Its scanner caveats need manual interpretation;
it is not part of the default bounded evidence profile.

Real-primary smoke tests require Docker or a configured primary and run
separately. Start with [Manual BIND Interop](manual-bind-interop.md), or select
the relevant catalog, XoT, TSIG, and IXFR commands from the
[evidence catalog](evidence-command-catalog.md). Retain primary versions,
configuration, logs, and results.

For wildcard/NSEC3 canonicalization changes, run the signed-zone regression on
the verification host:

```sh
ulimit -n 65536
python3 tests/interop/nsec3_wildcard_validation.py --binary /absolute/path/to/borondns
```

It needs BIND's `named`, `dnssec-keygen`, `dnssec-signzone`, `dig` and `delv`.
Run as an unprivileged user. On AppArmor hosts, pass `--work-parent` with a
test-user-writable directory under `/var/cache/bind`; keep host confinement
enabled. The test generates a signed zone, transfers it to BoronDNS and validates
direct and alias-derived wildcard answers against an explicit test trust anchor.
Its private evidence directory retains the zone, wire output, validator logs and
binary hash. Default mode checks compact serving after AXFR. Add `--ixfr` to
re-sign an updated primary and require a journal-backed dirty overlay before
validation. Add `--opt-out` for omitted-delegation and empty-nonterminal cases;
the primary and secondary must have matching validator classifications, including
legitimate insecure answers. This is bounded scenario coverage, not general
DNSSEC compliance certification.
Synthetic RRSIGs in Rust selection fixtures do not replace this validation.

`scripts/test-invariant-audit.py` exercises the source audit against isolated
mutations: unauthorized filesystem writes, unsafe lifecycle-token handling,
lost DNAME continuation or chain accounting, and refresh-result ownership and
acknowledgement ordering. These structural checks complement the runtime tests;
they are not a Rust control-flow proof.

## Periodic Execution

The release engineer schedules and records these runs. The weekly/monthly
intervals below are the `BDS-VER-011` release acceptance cadence during an active
acceptance cycle, not a standing calendar commitment. A run's existence in this
plan is not evidence that it has happened.

| Evidence | Cadence during acceptance | Command or guide |
| --- | --- | --- |
| Long fuzz campaign | At least weekly; at least 24 hours per selected parser for final sign-off | `scripts/fuzz-campaign.sh --duration 86400`; [two-host campaign](two-host-fuzz-soak-campaign.md) |
| Performance regression | Weekly on the Reference Hardware Profile | Benchmark harnesses; `scripts/check-perf-regression.py` |
| Extended runtime | Continuous sampling during the selected run, with weekly reports if it lasts that long | `scripts/capture-soak-handoff.sh`; [large-surface soak](large-surface-soak.md) |
| Differential primary comparison | At least monthly | BIND/NSD/Knot harnesses with comparative assertions |

Retain `campaign-summary.tsv`, logs, resource samples, and any failure artifacts
for fuzz runs. There is no fixed 30-day soak requirement. Select additional
stress or load scenarios for the changed code and document the duration.

## Gate Execution

Before tagging, run the local quality gate and the clean-container packaging
rehearsal against the selected commit. The tag-push/workflow-dispatch release
workflow is artifact publication automation: it verifies source and tag
provenance, rebuilds and checks packages, signs a checksum manifest, and
publishes the artifacts. It does not invoke `scripts/check.sh`.

```sh
scripts/check.sh
scripts/release-preflight-container.sh
```

To retain a broad local evidence set:

```sh
scripts/release-evidence-snapshot.sh
```

Set `BORONDNS_EVIDENCE_RUN_INTEROP=1`,
`BORONDNS_EVIDENCE_RUN_FUZZ=1`, or
`BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` for the additional campaigns needed.
RRL duration/count and performance-baseline options are described in the
[evidence guide](release-evidence-guide.md).

For changes to `ZoneImage`, packet composition, or UDP/TCP serving, retain
`scripts/zone-image-evidence-gate.sh` results. Loopback is useful for functional
and tuning checks. Performance claims about a real network require the Reference
Hardware/Profile or an appropriate physical non-loopback run; the harness can
enforce this with `BORONDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true`.

`scripts/reproducible-build-compare.sh` supplies the static-binary comparison.
The tagged workflow repeats it for the exact commit and checks that the packaged
binaries match. DEB and RPM builds are compared separately. Archive/image
reproducibility and an independent builder's agreement need their own evidence.

The following helpers prepare report formats for work that is selected:

| Evidence | Helper |
| --- | --- |
| Interface baseline or release comparison | `scripts/capture-interface-compatibility-evidence.sh` |
| Production-depth logging | `scripts/capture-info-verbosity-handoff.sh` |
| Reference benchmark | `scripts/capture-benchmark-handoff.sh` |
| Extended runtime | `scripts/capture-soak-handoff.sh` |
| Independent build comparison | `scripts/capture-reproducible-build-handoff.sh` |
| Release decisions and review | `scripts/capture-release-handoff.sh` |

A generated template is not a passed test. A skipped optional run should remain
identified as unrun; a missing required result blocks the corresponding claim.
Review open findings in [the acceptance register](release-acceptance-gap-register.md).

## Regression Policy

This policy implements `BDS-VER-012`.

- A functional regression is a failure of a requirement previously marked
  **Verified**.
- A performance/resource regression is a previously accepted metric that
  degrades by more than `regression.performance_threshold_pct`, which
  defaults to **10**.
- The comparison uses the median of the last five release measurements for the
  same metric on the Reference Hardware Profile.
- The first release of a major version establishes the initial baseline.
- New requirements have no previous result; classify them as Verified, Deferred,
  or Failed against their own acceptance criteria.

Record each regression's cause, owner, disposition, and remediation target in
canonical release evidence. A release with an untriaged regression must not
proceed. Public notes must explain material operator-facing effects; detailed
tables can remain in linked evidence.

## Release Notes Inputs

Public notes identify the version, artifacts, support posture, material
limitations, interface changes, and verification instructions. They may link to
canonical requirement and interoperability evidence instead of reproducing it.

[Release Notes Template](release-notes-template.md) is the optional detailed
dossier accepted by `scripts/check-release-notes.sh`. It contains requirement
counts and changes, regression decisions, primary versions, RFC assertions,
interface changes, security evidence, and review responsibility. Supply
`BORONDNS_RELEASE_NOTES=<path>` to check that dossier during a snapshot.

The tag workflow generates concise publication notes and does not call the
dossier checker. Optional external review is supporting evidence when available,
not a prerequisite for every release.
