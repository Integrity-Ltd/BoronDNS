# Evidence Command Catalog

Use this inventory to select a preflight or capture additional acceptance
evidence. It records commands, not results; see the
[verification ledger](verification-ledger.md) and
[gap register](release-acceptance-gap-register.md) for evidence status.

`scripts/release-evidence-snapshot.sh` copies all shell blocks below into its
snapshot manifest. When `BORONDNS_EVIDENCE_RUN_INTEROP=1` is set, it executes
the `scripts/` and `./` commands in the broader acceptance block, skipping
recursive snapshot commands. Bare `cargo` and environment-prefixed commands
in that block are manual instructions; the snapshot runner does not execute
them.

Run from the repository root on a build/test host with the prerequisites in
the chosen script. The broader block includes builds, containers, and network
tests; it is not a lightweight documentation check. Commands using `plan` or
`--dry-run` prepare a campaign but do not run it.

## Release-Candidate Preflight Profile

```sh
scripts/release-preflight-container.sh
scripts/engineering-mvp-evidence.sh
scripts/check-security-policy.sh
scripts/capture-cli-evidence.sh
scripts/capture-log-evidence.sh
scripts/capture-signal-evidence.sh
scripts/capture-health-metrics-evidence.sh
scripts/capture-malformed-query-evidence.sh
scripts/capture-portability-evidence.sh
scripts/capture-resource-evidence.sh
scripts/capture-coverage-evidence.sh
scripts/capture-interface-compatibility-evidence.sh
scripts/audit-unused-code.sh
scripts/check-functional-requirement-references.py
```

`engineering-mvp-evidence.sh` runs its bounded default checks with per-command
timeouts and records broader work in a deferred list. It does not invoke the
clean-container packaging rehearsal; run `release-preflight-container.sh`
separately before creating a signed release tag. That rehearsal builds the
release artifacts and uses the host Docker daemon. The broader unsafe-dependency
capture requires `cargo-geiger`.

## Broader SRS Acceptance Commands

```sh
./scripts/check.sh
scripts/check-security-policy.sh
scripts/capture-cli-evidence.sh
scripts/capture-log-evidence.sh
scripts/capture-signal-evidence.sh
scripts/capture-health-metrics-evidence.sh
scripts/capture-malformed-query-evidence.sh
scripts/capture-portability-evidence.sh
scripts/capture-resource-evidence.sh
scripts/capture-coverage-evidence.sh
scripts/capture-unsafe-dependency-evidence.sh
scripts/capture-info-verbosity-handoff.sh
scripts/capture-benchmark-handoff.sh
scripts/capture-soak-handoff.sh
scripts/reproducible-build-compare.sh
scripts/package-installer.sh
scripts/test-installer-docker.sh
scripts/package-docker-image.sh
scripts/test-docker-image.sh
scripts/package-sbom.sh
scripts/fuzz-soak-two-host-campaign.sh plan --duration 86400
scripts/large-surface-soak-campaign.sh plan --duration 86400
scripts/capture-release-handoff.sh
scripts/audit-invariants.sh
scripts/audit-readonly-runtime.sh
scripts/audit-log-fields.py
scripts/audit-log-lazy-formatting.py
scripts/audit-unused-code.sh
scripts/audit-xot-revocation.sh
scripts/capture-xot-failure-evidence.sh
scripts/audit-dnssec-passive.sh
scripts/audit-safe-rust.sh
scripts/check-unsafe-prone-dependencies.py
scripts/check-interface-compatibility.py
scripts/check-functional-requirement-references.py
scripts/audit-maintainability.sh
cargo check --manifest-path fuzz/Cargo.toml
RUSTUP_TOOLCHAIN=nightly cargo fuzz check dns_datagram
RUSTUP_TOOLCHAIN=nightly cargo fuzz check transfer_stream
RUSTUP_TOOLCHAIN=nightly cargo fuzz check tsig_message
RUSTUP_TOOLCHAIN=nightly cargo fuzz check notify_edns_datagram
scripts/fuzz-campaign.sh --dry-run --duration 1 --target dns_datagram
scripts/interop-primary-matrix.sh
scripts/interop-bind-axfr.sh
scripts/interop-bind-tsig-axfr.sh
scripts/interop-bind-notify-refresh.sh
scripts/interop-bind-ixfr-refresh.sh
scripts/interop-nsd-axfr-docker.sh
scripts/interop-nsd-tsig-axfr-docker.sh
scripts/interop-nsd-notify-refresh-docker.sh
scripts/interop-knot-axfr-docker.sh
scripts/interop-knot-tsig-axfr-docker.sh
scripts/interop-knot-notify-refresh-docker.sh
scripts/interop-knot-ixfr-refresh-docker.sh
scripts/interop-knot-xot-docker.sh
scripts/interop-knot-xot-tsig-docker.sh
scripts/interop-bind-catalog-zone-docker.sh
scripts/interop-bind-xot-catalog-zone-docker.sh
scripts/interop-powerdns-postgres-catalog-tsig-docker.sh
scripts/interop-knot-dnssec-docker.sh
scripts/interop-ixfr-notimp-fallback.sh
scripts/interop-unknown-rr.sh
scripts/interop-unknown-rr-bad-transfer.sh
scripts/interop-rrl-udp.sh
scripts/rrl-evidence-campaign.sh --iterations 3
scripts/interop-dns-cookie-dig.sh
scripts/interop-dnssec-serve.sh
scripts/interop-dnssec-nsec3-serve.sh
scripts/interop-negative-responses.sh
scripts/interop-notify-negative.sh
scripts/interop-tcp-truncation-retry.sh
scripts/interop-edns-behavior.sh
scripts/perf-smoke.sh
scripts/release-evidence-snapshot.sh
```

## Package lifecycle checks

These manual commands supplement the broader inventory when native packages
change. The snapshot runner does not execute this section automatically.

```sh
scripts/package-deb.sh
scripts/test-deb-package-docker.sh
scripts/package-rpm.sh
scripts/test-rpm-package-docker.sh
```
