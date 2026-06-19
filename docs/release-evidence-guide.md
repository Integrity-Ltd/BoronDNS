# Release Evidence Guide

Status: release and operations evidence runbook for formal SRS acceptance.

This guide owns the mechanics of `scripts/release-evidence-snapshot.sh` and the
handoff directories used by later release/operations runs. It is separate from
the Operator Deployment Guide so day-one deployment instructions stay focused on
running OxideDNS.

The release candidate does not claim completed long-running evidence unless the
release artifacts exist. A generated handoff directory proves that the setup and
artifact shape exist; it does not prove that the benchmark, soak,
reproducible-build comparison, production-depth logging profile, release-signing
review, or external operator acceptance has been completed.

## Snapshot Profiles

`scripts/engineering-mvp-evidence.sh` writes the legacy-named bounded local
preflight evidence profile under `target/evidence/engineering-mvp/<timestamp>/`.
It runs
security-policy, CLI, log, signal, health/metrics, malformed-query,
portability, resource, coverage, interface-compatibility, unused-code, and
functional-requirement-reference checks. It does not run transitive unsafe
dependency enumeration, fuzz build/campaign commands, invariant audits,
real-primary interop scripts, or `scripts/perf-smoke.sh` in the default bounded
profile; those commands are recorded as deferred release/operations work.

`scripts/release-evidence-snapshot.sh` writes release-candidate command logs
under `target/evidence/<timestamp>/`. By default it captures:

- repository check output;
- fuzz compile check output;
- cargo-deny output;
- tool versions;
- git state;
- the current verification command list;
- Test Plan shape check output;
- architectural, read-only-runtime, safe-Rust, spoofing, log-field,
  maintainability, XoT revocation, and passive-DNSSEC audit output;
- portability evidence under `portability-evidence/`;
- unused/dead-code audit artifacts under `unused-code-audit/`;
- resource smoke artifacts under `resource-evidence/`;
- `cargo-llvm-cov` threshold artifacts under `coverage-evidence/`;
- `cargo geiger` unsafe dependency enumeration under
  `unsafe-dependency-evidence/`;
- production-depth info verbosity setup under `info-verbosity-handoff/`;
- interface compatibility baseline and optional release-diff output under
  `interface-compatibility/`;
- Reference Hardware/Profile benchmark setup/report files under
  `benchmark-handoff/`;
- long-run soak setup/report files under `soak-handoff/`;
- reproducible-build setup files under `reproducible-build-handoff/`;
- release-governance setup files under `release-handoff/`.
- CycloneDX release SBOM evidence under `sbom-evidence/`.
- bounded `perf-smoke.sh` metrics and focused local protocol smoke artifacts
  for negative responses, NOTIFY rejection, TCP truncation retry, EDNS behavior,
  DNS Cookies, IXFR NOTIMP fallback, passive DNSSEC/NSEC3 serving, and RRL UDP
  limiting.

Those focused default smoke scripts are not the broader real-primary interop
matrix. The broad BIND, NSD, Knot, PowerDNS/PostgreSQL, packet-torture, XoT,
and long RRL campaign command set remains opt-in through
`OXIDEDNS_EVIDENCE_RUN_INTEROP=1` or `OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1`.

The unsafe dependency evidence records scanner caveats and must be reviewed
before it is treated as complete. The info-verbosity, interface-compatibility,
benchmark, soak, reproducible-build, and release-governance handoffs are
release/operations template sets for delegated runs unless their
release-specific inputs are supplied.

## Optional Evidence Runs

Set `OXIDEDNS_EVIDENCE_RUN_FUZZ=1` to run the fuzz campaign helper inside the
snapshot and retain its `campaign-summary.tsv`.

Set `OXIDEDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` to run the retained RRL evidence
campaign under the snapshot. Use `OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS` or
`OXIDEDNS_EVIDENCE_RRL_CAMPAIGN_DURATION` to choose iteration-count or wall-clock
duration mode.

Set `OXIDEDNS_EVIDENCE_RUN_INTEROP=1` to run the broader interop commands listed
in `docs/evidence-command-catalog.md` as part of the snapshot. Successful
real-primary interop runs write `primary-version.txt` under their
`target/interop/...` workdir. The snapshot copies new files into
`interop-primary-versions/` with an index so each pass/fail result can be tied
to the tested primary implementation version, OS or container package context,
configuration artifacts, transport, and security mode. A skipped script is
missing evidence, not passing evidence.

Use `scripts/interop-primary-matrix.sh` for a retained aggregate pass across the
selected BIND, NSD, Knot, and PowerDNS/PostgreSQL primary scenarios. It writes
`primary-matrix-summary.tsv` and per-primary artifact subdirectories under
`target/evidence/primary-matrix-...` by default, or under
`OXIDEDNS_PRIMARY_MATRIX_ARTIFACT_DIR` when set.

Set `OXIDEDNS_RELEASE_NOTES` to a completed release-notes markdown file to run
the release-note gate and verify that retained primary-version artifact paths
are published in the notes.

Set `OXIDEDNS_PERF_BASELINE` to a whitespace-delimited history file with rows
shaped as `release metric value` to compare retained `perf-smoke-metrics.env`
values against the rolling baseline.
`OXIDEDNS_PERF_REGRESSION_THRESHOLD_PCT` overrides the default 10 percent
regression threshold.

## Handoff Directories

Use the standalone handoff scripts when a release/operations owner needs only
one evidence package instead of a full snapshot.

| Handoff | Command | Purpose |
| --- | --- | --- |
| Benchmark | `scripts/capture-benchmark-handoff.sh` | Creates the Reference Hardware/Profile benchmark runbook, report template, metric/resource TSV schemas, baseline-history template, requirement traceability map, release-note snippet, and operator sign-off template. |
| Info verbosity | `scripts/capture-info-verbosity-handoff.sh` | Creates the production-depth `info` verbosity profile runbook, report template, log-volume/structured-field/metrics TSV schemas, requirement traceability map, release-note snippet, and operator sign-off template. |
| Soak | `scripts/capture-soak-handoff.sh` | Creates the 30-day soak report template, RSS/file-descriptor/metrics/event TSV schemas, weekly summary template, requirement traceability map, and operator sign-off template. |
| Release governance | `scripts/capture-release-handoff.sh` | Creates the evidence attachment map, role ownership TSV, scheduled CI/manual-run plan, signing runbook, release-note fill plan, external-operator acceptance template, and release-readiness checklist. |

## Large-Surface Soak Evidence

Use `scripts/large-surface-soak-campaign.sh` to run the broad scenario-cycle
soak on the two SSH hosts. The runner repeatedly executes retained BIND, NSD,
Knot, PowerDNS/PostgreSQL, XoT, TSIG, catalog-zone, extended-catalog,
DNSSEC/EDNS/DNS-Cookie/RRL, bad-transfer, and negative-query scenarios while
sampling host resources and retaining per-scenario artifacts.

The default release-campaign duration is `2592000` seconds, matching a 30-day
wall-clock soak window. Its evidence complements the single resident-process
RSS/file-descriptor soak represented by `scripts/capture-soak-handoff.sh`: the
large-surface soak maximizes protocol and primary-interop churn, while the
resident-process soak remains the stricter memory-growth lane for
ODS-NFR-REL-003.

See `docs/large-surface-soak.md` for launch, status, collection, and evidence
schema details.

## Reproducible Build Evidence

Use `scripts/reproducible-build-compare.sh` to run the local static-binary
comparison. The script builds `oxidedns` and `oxide-gun` twice in separate clean
target directories for `x86_64-unknown-linux-musl`, fixes the embedded
`OXIDEDNS_BUILD_*` metadata plus `SOURCE_DATE_EPOCH`, and writes
`artifact-manifest.tsv`, `comparison.tsv`, and `reproducible-build-summary.env`
under `target/evidence/reproducible-build-...`.

The comparison intentionally uses the concrete rustup Cargo and rustc binaries
instead of the local `cargo` shim so build-script environment values reach the
compiled binary. A passing comparison verifies the raw static binaries only; it
does not sign artifacts or claim installer archive or Docker image archive
reproducibility.

## Package and Docker Smoke Evidence

Use `scripts/package-installer.sh` to build the release installer archive,
standalone `oxidedns` and `oxide-gun` binaries, package manifest, static-link
reports, and SHA-256 files. Use `scripts/test-installer-docker.sh` to smoke the
installer in Ubuntu, including install, update, config validation,
`oxide-gun --self-test`, and startup.

Use `scripts/package-docker-image.sh` to build and export the Docker image
archive, image manifest, inspect JSON, and SHA-256 file. Use
`scripts/test-docker-image.sh` to smoke the image with a read-only root
filesystem, dropped capabilities, `no-new-privileges`, health endpoints, and
metrics.

Use `scripts/package-sbom.sh` to generate CycloneDX JSON SBOMs and SHA-256
files for the two shipped release binaries. The Cargo SBOM pass uses
`cargo-cyclonedx` against the workspace lockfile, the musl release target, and
the shipped feature set `oxidedns-cli/af-xdp,oxide-gun/xdp`. It also writes
`target/dist/oxidedns-<version>-x86_64-unknown-linux-musl-sbom-manifest.tsv`
with the source, feature set, tool version, path, and hash for each SBOM.

Set `OXIDEDNS_SBOM_DOCKER=1` after `scripts/package-docker-image.sh` to require
Syft and add a CycloneDX JSON SBOM for the release Docker image. Tagged GitHub
release builds run this required Docker SBOM mode and attach the binary SBOMs,
Docker image SBOM, their SHA-256 files, and the SBOM manifest to the release.
Local release snapshots use `OXIDEDNS_SBOM_DOCKER=0` by default so they retain
binary SBOM evidence without requiring a local Docker daemon.

The v0.2.0 retained package/image smoke bundle is recorded in
`docs/package-docker-smoke-v0.2.0.md` and lives under
`target/evidence/package-docker-smoke-20260616T173146Z`. A passing smoke bundle
verifies package/image creation and runtime smoke behavior only; archive
reproducibility, Docker image archive reproducibility, public artifact signing,
and independent-builder sign-off remain separate release-governance work.

For the formal SRS MVP release gate, release notes must also include the
external operator acceptance signature, accepting operator identity, and
accepted scope statement required by `ODS-VER-008` and `ODS-VER-015`.

## Primary Interop Evidence

The Operator Deployment Guide lists the day-one primary interoperability scripts
operators are most likely to run directly. The full command inventory consumed
by the release snapshot is `docs/evidence-command-catalog.md`; that file is the
source for the broader `OXIDEDNS_EVIDENCE_RUN_INTEROP=1` command set.

Retain each successful real-primary run's `primary-version.txt`, redacted
configuration, relevant packet/log artifacts, and traceability TSVs when the
script produces them. Release notes must publish the primary versions and
configuration modes used for accepted interop evidence.

## XoT Release Evidence

For the selected v0.2.0 XoT breadth run, retain the outputs from:

- `scripts/interop-knot-xot-docker.sh`
- `scripts/interop-knot-xot-tsig-docker.sh`
- `scripts/interop-bind-xot-catalog-zone-docker.sh`

The current retained bundle is recorded in `docs/xot-release-evidence-v0.2.0.md`
and lives under `target/evidence/xot-release-20260614T014700Z`. The bundle
keeps per-case status/log files, `primary-version.txt`, ALPN probes,
certificate summaries, readiness/metrics/query artifacts, and per-case
traceability TSVs. TSIG and RNDC-bearing artifacts must be retained only in
redacted form, and the retained bundle should pass a direct scan for fixture
secret values before it is cited in release notes.
