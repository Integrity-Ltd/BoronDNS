# Evidence Command Catalog

This file lists command entry points used by the release-candidate preflight and
later SRS acceptance evidence flows. It is command inventory only; current
evidence state and remaining gaps stay in `docs/mvp-gap-register.md`,
`docs/verification-ledger.md`, and `docs/appendix-a-traceability-matrix.md`.

`scripts/release-evidence-snapshot.sh` copies all shell blocks below into its
snapshot manifest. When `OXIDEDNS_EVIDENCE_RUN_INTEROP=1` is set, it executes
only the commands in the broader SRS acceptance block, skipping recursive
snapshot commands.

## Release-Candidate Preflight Profile

```sh
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

`scripts/engineering-mvp-evidence.sh` runs only this narrow profile by default,
uses per-command timeouts, and writes broader release/operations commands to a
deferred list instead of executing them. Transitive unsafe dependency
enumeration through `scripts/capture-unsafe-dependency-evidence.sh` is kept in
the broader SRS acceptance profile because it depends on `cargo-geiger` and is
release-review evidence rather than a cheap release-candidate gate.

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
scripts/fuzz-soak-two-host-campaign.sh plan --duration 86400
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
