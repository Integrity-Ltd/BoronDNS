# Release Evidence Guide

Status: release and operations evidence runbook for formal SRS acceptance.

This guide owns the mechanics of `scripts/release-evidence-snapshot.sh` and the
handoff directories used by later release/operations runs. It is separate from
the Operator Deployment Guide so day-one deployment instructions stay focused on
running BoronDNS.

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
`BORONDNS_EVIDENCE_RUN_INTEROP=1` or `BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1`.

The unsafe dependency evidence records scanner caveats and must be reviewed
before it is treated as complete. The info-verbosity, interface-compatibility,
benchmark, soak, reproducible-build, and release-governance handoffs are
release/operations template sets for delegated runs unless their
release-specific inputs are supplied.

## Optional Evidence Runs

Set `BORONDNS_EVIDENCE_RUN_FUZZ=1` to run the fuzz campaign helper inside the
snapshot and retain its `campaign-summary.tsv`.

Set `BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` to run the retained RRL evidence
campaign under the snapshot. Use `BORONDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS` or
`BORONDNS_EVIDENCE_RRL_CAMPAIGN_DURATION` to choose iteration-count or wall-clock
duration mode.

Set `BORONDNS_EVIDENCE_RUN_INTEROP=1` to run the broader interop commands listed
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
`BORONDNS_PRIMARY_MATRIX_ARTIFACT_DIR` when set.

Set `BORONDNS_RELEASE_NOTES` to a completed release-notes markdown file to run
the release-note gate and verify that retained primary-version artifact paths
are published in the notes.

Set `BORONDNS_PERF_BASELINE` to a whitespace-delimited history file with rows
shaped as `release metric value` to compare retained `perf-smoke-metrics.env`
values against the rolling baseline.
`BORONDNS_PERF_REGRESSION_THRESHOLD_PCT` overrides the default 10 percent
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
comparison. The script builds `borondns` and `oxide-gun` twice in separate clean
target directories for `x86_64-unknown-linux-musl`, fixes the embedded
`BORONDNS_BUILD_*` metadata plus `SOURCE_DATE_EPOCH`, and writes
`artifact-manifest.tsv`, `comparison.tsv`, and `reproducible-build-summary.env`
under `target/evidence/reproducible-build-...`.
The comparison refuses modified or untracked source by default. The explicit
`BORONDNS_REPRODUCIBLE_BUILD_ALLOW_DIRTY_NON_RELEASE=1` escape hatch exists only
for diagnostics: such a run exits nonzero and records
`reproducible_build_status=false` plus `release_eligible=false`, even when its two
artifact digests match. Dirty-source output is never release evidence.
The source commit and the complete non-ignored worktree status are captured at
preflight and must remain identical before and after locked metadata capture,
each build, artifact capture, and terminal evidence publication. Any boundary
drift fails the comparison before it can publish passing release evidence.
The tagged release workflow runs this comparison again for its exact checked-out
commit before preparing the signing handoff. It validates the two matching
binary pairs with `scripts/verify-release-reproducibility.py`; a missing,
ineligible, commit-mismatched, size-mismatched, or digest-mismatched record is a
hard failure before the privileged signing job can start. The independently
packaged raw `borondns` and `oxide-gun` binaries must then compare byte-for-byte
with both retained builds, so the result authenticates the bytes sent for
signing rather than an unrelated successful comparison.

The comparison intentionally uses the concrete rustup Cargo and rustc binaries
instead of the local `cargo` shim so build-script environment values reach the
compiled binary. A passing comparison verifies the raw static binaries only; it
does not sign artifacts or claim installer archive or Docker image archive
reproducibility.

## Package and Docker Smoke Evidence

Use `scripts/package-installer.sh` to build the release installer archive,
standalone `borondns` and `oxide-gun` binaries, package manifest, static-link
reports, and SHA-256 files. Use `scripts/test-installer-docker.sh` to smoke the
installer in Ubuntu, including install, update, config validation,
`oxide-gun --self-test`, and startup.

Both installer and Docker packaging fail closed when Git reports any modified
or untracked, non-ignored source. They revalidate the exact commit and complete
worktree status across build and publication boundaries. The
`BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1` override exists only for local
development diagnostics: affected manifests record `source_clean=0`,
`release_eligible=0`, and `dirty_source_override=1`, and Docker images carry
matching source-clean and release-eligibility labels. The override is rejected
under GitHub Actions and must never appear in the tagged release workflow.
Likewise, `BORONDNS_PACKAGE_ALLOW_DYNAMIC=1` is a local diagnostic override:
even on a clean tree it forces `release_eligible=0`, records
`dynamic_link_override=1`, and publishes only in the `-nonrelease-dynamic`
artifact and image-tag namespace. It is also rejected under GitHub Actions.

Installer, SBOM, and Docker package builders capture the device, inode, owner,
and directory type of every private run/staging root that may later be removed
recursively. Normal completion and failure rollback both revalidate that exact
identity immediately before cleanup. In a packaging-UID-writable namespace,
logical cleanup ends with an exact no-replace rename to a unique
`*.borondns-remove.*` quarantine. The builder reports that retained path and
its captured `device:inode:owner:type`, plus the immediate parent path and parent
identity. Recovery journals persist those four values in the indexed
`retained_removal_quarantine_N*` fields. The journal parent directory is bound
to `publication_recovery_root_identity`; retained objects beneath it also carry
root-relative object and parent paths. If a same-process retry later quarantines
that whole root, the diagnostic path is identity-revalidated and rebased while
the immutable journal remains resolvable through its current parent directory.
The original absolute fields remain historical evidence. The builder never
performs a later pathname `unlink` or `rmdir`; remove it only during
privileged or dedicated-UID reconciliation where the packaging UID cannot swap
the victim. If a same-UID process replaces either the private path or its
quarantine, packaging exits nonzero and preserves the replacement and displaced
recovery state for inspection; a failed post-move revalidation reports only the
unverified parent namespace and does not claim an exact retained identity.
Unique quarantine names and removal of the
obsolete source binding from live package state let later staging runs proceed
without adopting or overwriting retained objects.
An interrupted recovery-diagnostic write likewise retains its uniquely named
`.publication-recovery-incomplete-*` inode instead of attempting a raceable
cleanup unlink; stderr identifies the exact path, object identity, parent path,
and parent identity when post-write revalidation succeeds, or only the
unverified parent namespace when it does not.
Cargo-cyclonedx's fixed worktree outputs are identity-bound renamed into unique
`*.borondns-remove.*` paths under the already locked Git metadata root. This
keeps retained evidence outside Git source-status accounting without using a
copy-and-unlink fallback; an unsupported cross-filesystem layout fails closed
and retains the source pathname with the same object/parent identity evidence
when it can still be revalidated. A later invocation never imports a prior
stderr or journal record as mutation authority.
Transactional artifact publication applies the same object-identity binding to
regular-file backups and promoted files immediately before rollback removal,
restore, or committed backup cleanup. Docker packaging creates private run
roots only after preflight and gives one EXIT cleanup path sole ownership of
both its run root and installer-publication staging root on success, failure,
and signals.

Use `scripts/package-docker-image.sh` to build and export the Docker image
archive, image manifest, inspect JSON, and SHA-256 file. Use
`scripts/test-docker-image.sh` to smoke the image with a read-only root
filesystem, dropped capabilities, `no-new-privileges`, health endpoints, and
metrics.
Docker packaging rebuilds its image input in the isolated
`target/docker-installer-input/` directory. It must not reuse or overwrite the
installer archive and raw binaries in `target/dist/`, because those exact
publishable files have already passed the installer smoke test.
The image manifest records both the reviewed digest-pinned Alpine base reference
and its resolved `sha256` digest; retain those fields with the other release
evidence so the published image can be traced to the exact platform manifest.
The build also captures Docker's immutable image ID through `--iidfile`; inspect,
archive export, archive reload verification, and the required Syft scan all use
that ID. A mutable tag is checked against it before and after packaging, and tag
drift aborts publication rather than mixing evidence from two images.
Before an exported archive reaches the Docker daemon,
`scripts/verify-docker-archive.py` streams it under a single absolute
`CLOCK_BOOTTIME` deadline and hard upper bounds for member count, individual and
total expanded bytes, and retained JSON. Callers may lower those bounds through
the `BORONDNS_DOCKER_ARCHIVE_*` environment variables, but cannot raise the
compiled maxima. Links, special files, duplicate or non-canonical members,
digest mismatches, and archives exceeding any bound fail closed.

Use `scripts/package-sbom.sh` to generate CycloneDX JSON SBOMs and SHA-256
files for the two shipped release binaries. The Cargo SBOM pass uses
`cargo-cyclonedx` against the workspace lockfile, the musl release target, and
the shipped feature set `borondns-cli/af-xdp,oxide-gun/xdp`. It also writes
`target/dist/borondns-<version>-x86_64-unknown-linux-musl-sbom-manifest.tsv`
with the source, feature set, tool version, path, and hash for each SBOM.

Set `BORONDNS_SBOM_DOCKER=1` after `scripts/package-docker-image.sh` to require
Syft and add a CycloneDX JSON SBOM for the release Docker image. Tagged GitHub
release builds run this required Docker SBOM mode and attach the binary SBOMs,
Docker image SBOM, their SHA-256 files, and the SBOM manifest to the release.
The tagged workflow uses three exact GitHub-hosted jobs. A `contents: read`
verification runner executes Continuous and emits only its verified commit. A
new `contents: read` packaging runner checks out that exact commit and therefore
inherits no environment, background process, or mutable tool state from
Continuous. It passes the publishable files plus a public SHA-256 handoff
manifest and a separate internal manifest covering the reproducibility records
and their two validators. Both manifest SHA-256 values are carried as
authenticated job outputs and checked before any signing. The internal records
are signing inputs only; they do not expand the published release-asset surface
or the public handoff manifest.
The workflow relies on the pinned download action's transport integrity plus
that independent manifest, rather than exposing an artifact-digest output that
the download action cannot compare against an expected value.
The release binaries are built on that fresh packaging runner in a freshly
recreated, release-only Cargo target directory, so ignored fingerprints or
executables from verification cannot be reused for packaging. The signing job installs the
commit-pinned Cosign action before downloading and fully verifying the handoff;
no executable or action step is allowed between verification and signing.
Only that short signing/publishing job receives `contents: write` and
`id-token: write`, and it neither checks out nor executes repository or built
code. The workflow keylessly signs every published asset, including the handoff
manifest, with Cosign and attaches `<asset>.sigstore.json`. Generated release
notes include a `cosign verify-blob` command constrained to the GitHub Actions
OIDC issuer and this repository's tagged `release-installer.yml` workflow
identity. Release acceptance must execute that command against every downloaded
asset/bundle pair and retain the verification output; the existence of workflow
YAML alone does not close the signing evidence gap.
GitHub release API mutations run through `scripts/release-api-supervisor.py`.
Each call receives one absolute operation deadline, blocks cancellation signals
before spawning a new process group, and waits for an explicit parent-authority
token before it may start `gh`. Cancellation or timeout terminates and reaps the
whole group; an API leader that exits while descendants remain is a failed
operation. This closes the shell's spawn-to-PID window for release mutations.
Release tags are an immutable provenance boundary: repository rules must protect
`v*` tags from force-update and deletion after creation. The publishing job peels
the remote tag to its commit immediately before release creation and again
immediately afterward. If the second lookup fails or differs from the event
commit, it deletes the just-created release and fails. That rollback is a final
race detector, not a substitute for protected immutable tags; an environment
that permits tag rewrites is not release-eligible.
The verification and packaging jobs resolve Cargo and rustc through the pinned
rustup toolchain, record their SHA-256 identities, and invoke the resolved
absolute paths. The package manifest records stable executable names plus those
digests; a competing PATH `cargo` cannot proxy a release build, and absolute
host paths do not make otherwise identical archives differ.
For installer acceptance, run verification before extraction or privilege:

```sh
tag=v0.2.0
asset="borondns-${tag#v}-x86_64-unknown-linux-musl.tar.xz"
cosign verify-blob \
  --bundle "$asset.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/Integrity-Ltd/borondns/.github/workflows/release-installer.yml@refs/tags/$tag" \
  "$asset"
```

The recorded tag, identity, bundle, asset digest, Cosign output, and time of
verification belong in the release evidence. A failed or cross-tag identity
must stop acceptance before `tar` or `sudo` is run.
Local release snapshots use `BORONDNS_SBOM_DOCKER=0` by default so they retain
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
source for the broader `BORONDNS_EVIDENCE_RUN_INTEROP=1` command set.

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
