# Release Evidence Guide

This guide explains how to collect release evidence, rehearse packaging, and
verify published artifacts. For installation, use the
[operator guide](operator-deployment-guide.md). For deciding which checks a
candidate needs, use the [test plan](test-plan.md) and
[readiness checklist](engineering-mvp-readiness.md).

A release record should identify the tested commit, commands, tool versions,
results, and retained artifacts. A runbook or generated report template is
preparation; a completed log or measurement establishes what was tested.
Historical evidence can support a later release when its relevance is explained.

## Choose an Evidence Profile

| Profile | Command | What it does |
| --- | --- | --- |
| Regular quality gate | `scripts/check.sh` | Runs the maintained local static checks, tests, and short runtime checks. |
| Bounded evidence snapshot | `scripts/engineering-mvp-evidence.sh` | Captures selected CLI, logging, signal, health, malformed-query, resource, portability, coverage, interface, security-policy, and source-reference checks with per-command timeouts. |
| Broad release snapshot | `scripts/release-evidence-snapshot.sh` | Runs the quality gate, captures additional audits and smoke tests, and creates report templates for selected release work. |
| Packaging rehearsal | `scripts/release-preflight-container.sh` | Builds and tests release packages from a clean commit in a tool container. |

The bounded snapshot uses the legacy-named
`target/evidence/engineering-mvp/<timestamp>/` directory. It does not run
transitive unsafe dependency enumeration, fuzz build/campaign commands, invariant
audits, real-primary interop scripts, or `scripts/perf-smoke.sh` in the default
bounded profile. Omitted commands are recorded in `deferred-not-run.txt`.

The broad snapshot writes to `target/evidence/<timestamp>/`, or under
`BORONDNS_EVIDENCE_DIR`. Its default run includes:

- the repository gate, fuzz compilation, dependency checks, and tool/git state;
- architectural, read-only-runtime, safe-Rust, spoofing, log-field,
  maintainability, XoT revocation, and passive-DNSSEC audit output;
- CLI, logs, signals, health/metrics, malformed-query, portability, resource,
  coverage, interface-compatibility, and unused-code evidence;
- `cargo geiger` output, including scanner caveats that need review;
- binary CycloneDX SBOMs;
- bounded `perf-smoke.sh` metrics and focused local protocol smoke artifacts
  for negative responses, NOTIFY rejection, TCP retry, EDNS, DNS Cookies,
  IXFR fallback, passive DNSSEC/NSEC3, and UDP RRL;
- handoff templates for benchmarks, info-verbosity profiling, extended runtime,
  reproducible builds, and release review.

Those focused default smoke scripts are not the broader real-primary interop
matrix. The full command inventory is in
[Evidence Command Catalog](evidence-command-catalog.md). Additional interop and
RRL campaign execution remains opt-in through
`BORONDNS_EVIDENCE_RUN_INTEROP=1` or
`BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1`.

## Select Additional Runs

| Setting | Effect |
| --- | --- |
| `BORONDNS_EVIDENCE_RUN_INTEROP=1` | Runs the broader primary/interoperability command set. |
| `BORONDNS_EVIDENCE_RUN_FUZZ=1` | Runs the fuzz helper and retains `campaign-summary.tsv`. |
| `BORONDNS_EVIDENCE_RUN_RRL_CAMPAIGN=1` | Runs the RRL evidence campaign. |
| `BORONDNS_EVIDENCE_RRL_CAMPAIGN_ITERATIONS` | Selects RRL iteration count; the default is 3. |
| `BORONDNS_EVIDENCE_RRL_CAMPAIGN_DURATION` | Selects wall-clock seconds instead of iteration count. |
| `BORONDNS_PERF_BASELINE` | Compares smoke metrics with a history file containing `release metric value` rows. |
| `BORONDNS_PERF_REGRESSION_THRESHOLD_PCT` | Overrides the default 10 percent smoke-regression threshold. |
| `BORONDNS_RELEASE_NOTES` | Checks a detailed release-evidence dossier against the snapshot. |

The detailed dossier is optional in the current public release process. The
tagged workflow generates shorter artifact notes and verification instructions.
See [Release Notes Template](release-notes-template.md) for the fuller format.

For primary interoperability, retain `primary-version.txt`, redacted
configuration, logs, packets where collected, and traceability output. The
snapshot indexes newly collected primary-version files under
`interop-primary-versions/`. Skipped scripts are missing evidence, not passes.
Use `scripts/interop-primary-matrix.sh` for an aggregate BIND, NSD, Knot, and
PowerDNS/PostgreSQL run; its default output is
`target/evidence/primary-matrix-...`, overridable with
`BORONDNS_PRIMARY_MATRIX_ARTIFACT_DIR`.

For extended testing, see the [two-host fuzz campaign](two-host-fuzz-soak-campaign.md)
and [large-surface soak guide](large-surface-soak.md).
`scripts/large-surface-soak-campaign.sh` cycles through transfer, catalog,
DNSSEC, EDNS, cookie, RRL, and failure scenarios while sampling host resources.
Choose its duration explicitly. It complements resident-process RSS/file-descriptor
sampling; no fixed 30-day run is required.

## Prepare a Single Evidence Package

These scripts create runbooks and report formats without running the campaign.

| Subject | Script |
| --- | --- |
| Reference Hardware/Profile benchmark | `scripts/capture-benchmark-handoff.sh` |
| Production-depth `info` log profiling | `scripts/capture-info-verbosity-handoff.sh` |
| Extended-runtime resource sampling | `scripts/capture-soak-handoff.sh` |
| Independent build comparison | `scripts/capture-reproducible-build-handoff.sh` |
| Release review, decisions, signing, and optional external review | `scripts/capture-release-handoff.sh` |

`scripts/capture-interface-compatibility-evidence.sh` also captures the current
interface baseline. It runs a release-to-release comparison only when a previous
baseline is supplied. Inspect the result before describing it as a passed
compatibility comparison.

## Rehearse Packaging Before Tagging

Run this from a clean, committed checkout:

```sh
scripts/release-preflight-container.sh
```

The launcher bundles the selected commit into a digest-pinned Ubuntu 24.04 tool
container. It uses a 32 GiB memory/swap limit by default; override it with
`BORONDNS_RELEASE_PREFLIGHT_MEMORY` when needed. The container uses host
networking and mounts the Docker socket plus a temporary workspace for nested
package tests. Docker-socket access carries host root authority, so this
rehearsal is for reviewed source.

The rehearsal covers release/version policy, publication recovery fault
injection, static-binary reproducibility, installer construction, Ubuntu/Alpine
installer smoke tests, DEB and RPM lifecycle tests, Docker image smoke testing,
SBOM generation, static-link checks, and handoff validation. The current plan
contains 12 unsigned files and 13 published assets after the manifest's Sigstore
bundle is added. It does not request OIDC credentials or publish to GitHub.

The individual commands are useful when a change affects only one part:

| Output or check | Commands |
| --- | --- |
| Installer and raw static binaries | `scripts/package-installer.sh`; `scripts/test-installer-docker.sh` |
| Debian/Ubuntu amd64 package | `scripts/package-deb.sh`; `scripts/test-deb-package-docker.sh` |
| Fedora/RHEL-compatible x86_64 package | `scripts/package-rpm.sh`; `scripts/test-rpm-package-docker.sh` |
| Alpine Docker image archive | `scripts/package-docker-image.sh`; `scripts/test-docker-image.sh` |
| Binary CycloneDX SBOMs | `scripts/package-sbom.sh` |
| Binary and Docker SBOMs | `BORONDNS_SBOM_DOCKER=1 scripts/package-sbom.sh` |

Release binaries use `x86_64-unknown-linux-musl` with
`borondns-cli/af-xdp,boron-gun/xdp`. The server's AF_XDP backend remains
experimental and opt-in. Docker packaging builds its inputs separately under
`target/docker-installer-input/` so it does not overwrite the installer assets
already tested in `target/dist/`.

## Reproducibility and Recovery

`scripts/reproducible-build-compare.sh` builds the two static binaries twice in
separate target directories with fixed build metadata and `SOURCE_DATE_EPOCH`.
It retains manifests, digest comparisons, and a summary under
`target/evidence/reproducible-build-...`. It rejects modified or untracked
source and checks that the source state stays unchanged across the run.

The tagged workflow repeats this comparison for its checked-out commit, validates
it with `scripts/verify-release-reproducibility.py`, and compares both retained
builds byte-for-byte with the packaged raw binaries before signing. It also
compares repeated DEB and RPM builds. These results do not establish identical
installer or Docker archives, or independent-builder agreement.

Packaging requires clean source. The diagnostic overrides
`BORONDNS_PACKAGE_ALLOW_DIRTY_NON_RELEASE=1`,
`BORONDNS_PACKAGE_ALLOW_DYNAMIC=1`, and
`BORONDNS_REPRODUCIBLE_BUILD_ALLOW_DIRTY_NON_RELEASE=1` produce explicitly
ineligible results. The packaging overrides are rejected under GitHub Actions.

Packaging tracks the identity of staging objects and retains uncertain recovery
state instead of deleting through a changed pathname. If a command reports a
`*.borondns-remove.*` quarantine or `.publication-recovery-incomplete-*` file,
retain the reported object/parent identities and logs. Reconcile it under
privileged or dedicated-UID control; a stale journal or path alone is not
authorization to remove files. See `scripts/package-common.sh` and
`scripts/test-package-publication-recovery.sh` for the implementation and tests.

Docker evidence binds the digest-pinned Alpine base and immutable image ID to
the exported archive and Syft scan. `scripts/verify-docker-archive.py` validates
archive contents, digests, size limits, and an absolute deadline before daemon
loading. The image smoke checks read-only root operation, dropped capabilities,
no-new-privileges, health, and metrics.

## What the Tag Workflow Executes

The [release workflow](../.github/workflows/release-installer.yml) runs
automatically for `v*` tag pushes. Manual dispatch is also available. Branch
pushes and pull requests do not trigger it.

| Job | Checks and authority |
| --- | --- |
| Verify source | Checks clean source, commit and toolchain identity; for tags, checks the Cargo version and trusted annotated-tag signature. Read-only repository access. |
| Package release | Uses a fresh checkout of that commit; builds reproducible static binaries and packages, runs package smoke/lifecycle checks, and creates SBOMs plus checksum manifests. Read-only repository access. |
| Sign and publish | Verifies the handoff, signs its public checksum manifest with Cosign, and publishes the release. This job alone has repository write and OIDC permissions. |

The workflow does **not** run `scripts/check.sh` or
`scripts/check-release-notes.sh`. Retain the local quality-gate result before
tagging. A green workflow proves its source, packaging, signing, and publication
checks passed; it does not establish complete SRS acceptance.

Automatic releases require an annotated tag signed by Tibor Dravecz's trusted
OpenPGP key:

```text
E72382CD34A6DBC21070BAB1A0F90CBE53C07CA9
```

The checked-in public key verifies the tag and its target commit. The private
key is not stored in Actions. Create a tag with
`git tag -s vVERSION COMMIT -m "BoronDNS VERSION"`; protect `v*` tags against
updates and deletion. The publisher checks the remote tag before and after
release creation and rolls back a newly created release if the second check
fails or the target changed.

Packaging passes a public checksum manifest and a separate internal manifest
for reproducibility evidence and validators. Their hashes are authenticated job
outputs. The signing job verifies both and signs only
`release-handoff.sha256`. The public release includes its bundle,
`release-handoff.sha256.sigstore.json`; individual artifact sidecars and
per-artifact signatures are not published. Local package scripts still generate
SHA-256 sidecars for direct checks.

The signing job does not check out the repository or run the shipped binaries.
It executes the authenticated validation and publishing helpers from the handoff,
along with the signing and GitHub tools. API mutations use the deadline
supervisor to stop and reap command descendants on timeout or cancellation.
These controls and their fault-injection coverage are checked by
`scripts/check-release-signing-policy.py`.

## Verify Published Artifacts

Download the release's checksum manifest, its Sigstore bundle, and all files
listed by the manifest into one directory. Verify before extracting or
installing anything:

```sh
tag=v1.0.0
cosign verify-blob \
  --bundle release-handoff.sha256.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/Integrity-Ltd/BoronDNS/.github/workflows/release-installer.yml@refs/tags/$tag" \
  release-handoff.sha256
sha256sum -c release-handoff.sha256
```

Use the tag whose artifacts you downloaded. Retain the tag, expected workflow
identity, verification output, artifact digests, and verification time. A failed
signature, wrong tag identity, or checksum mismatch blocks acceptance.

## Historical Evidence

Older reports describe their recorded versions and environments:

- [v0.2.0 reproducible static binaries](reproducible-build-v0.2.0.md)
- [v0.2.0 package and Docker smoke tests](package-docker-smoke-v0.2.0.md)
- [v0.2.0 XoT interoperability](xot-release-evidence-v0.2.0.md)

The XoT report covers Knot XoT, Knot XoT with TSIG, and BIND XoT catalog
scenarios. Retain certificates, ALPN results, primary versions, logs, and query
results with secrets redacted. Check fixture TSIG/RNDC secrets are absent before
sharing any bundle.
