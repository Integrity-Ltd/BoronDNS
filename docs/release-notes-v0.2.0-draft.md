# BoronDNS v0.2.0 Release Notes Draft

Status: draft release material for the v0.2.0 preparation branch. This is not
the final release-acceptance note and does not claim that the formal SRS
`BDS-VER-008` gate is complete.

## Version Posture

- Planned release version: `0.2.0`.
- Current package version: `0.2.0`.
- The workspace package version, internal crate-dependency versions, eBPF
  support-crate versions, and package entries across all four checked-in
  lockfiles have been bumped to `0.2.0`: `./Cargo.lock`, `./fuzz/Cargo.lock`,
  `./crates/borondns-server-ebpf/Cargo.lock`, and
  `./crates/boron-gun-ebpf/Cargo.lock`.
- SRS document version remains `v0.9.1`; the v0.2.0 work is source-alignment,
  documentation, evidence, and release-readiness cleanup against that SRS.

## Release Scope Summary

The v0.2.0 preparation branch is intended to publish the cleaner
release-candidate shape now present in source and docs:

- top-level `--config` and `BORONDNS_CONFIG` config-path handling across
  validation, dump, `check-config`, and `serve` modes;
- reloadable plaintext filesystem-backed `SecretStore` snapshots for TSIG keys
  and named XoT profiles, with atomic snapshot replacement and fail-closed
  reload behavior;
- RFC 9432 catalog-zone handling with hidden catalog service by default,
  dynamic member reconciliation, split catalog/member transfer policy, opt-in
  member-transfer extensions, and private-address-only legacy unsigned member
  AXFR policy;
- strict transfer publication behavior after malformed or out-of-zone transfer
  data; bad transfer data must fail cleanly rather than panic the AXFR path;
- UDP and AF_XDP tuning controls plus retained benchmark documentation for the
  tuned server and BoronGun paths;
- first 24-hour ASan-backed two-host fuzz campaign evidence for the current
  parser-oriented fuzz targets.

## Evidence Already Available

- Repository gate: `./scripts/check.sh`.
- Documentation gates: hygiene, SRS review disposition, RFC compliance
  assertions, Appendix A traceability, operator guide shape, and interface
  compatibility checks.
- Coverage gate: `cargo llvm-cov` via the repository check script, including
  the parser/XoT-file threshold.
- Dependency gate: `cargo deny` via the repository check script; the current
  duplicate `getrandom` warning remains informational while advisories, bans,
  licenses, and sources pass.
- Benchmark record and runbook: `docs/dns-client-benchmark.md`.
- Fuzz/soak record and first ASan-backed two-host 24-hour fuzz evidence:
  `docs/two-host-fuzz-soak-campaign.md`.
- Release evidence runbook: `docs/release-evidence-guide.md`.
- Release security and signing policy: `SECURITY.md`.

## Required Before Tagging v0.2.0

- Fill the formal release-note template with the final commit, release date,
  evidence snapshot path, primary interop versions, signing details, and owner
  sign-off.
- Decide which SRS acceptance closeout rows are in scope for the v0.2.0 claim.
  Any row left open must be named as deferred or non-claimed in the final
  release notes.
- Run `scripts/release-evidence-snapshot.sh` for the release candidate and keep
  the generated evidence directory.
- Verify release artifact checksums and either Sigstore/Cosign or detached
  OpenPGP signature instructions.
- Decide whether any BoronDNS benchmark notes belong in the separate BoronDNS
  repository; they are out of scope for the BoronDNS v0.2.0 public docs unless
  they are reframed as external comparison material.
