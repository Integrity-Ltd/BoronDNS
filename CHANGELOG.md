# Changelog

All notable project-facing changes are recorded here. Formal release acceptance
notes still use `docs/release-notes-template.md` when a release candidate needs
full evidence pointers and sign-off.

## Unreleased

### Changed

- Adopted the BoronDNS product name across crates, binaries, configuration,
  environment variables, metrics, packaging, deployment assets,
  documentation, and repository metadata.
- Advanced the pre-1.0 workspace and eBPF support crates from `0.2.0` to
  `0.9.0` for the breaking BoronDNS release-candidate identity.
- Updated public-release preparation docs to align with current source-owned
  behavior for top-level `--config`, reloadable filesystem-backed TSIG/XoT
  secret snapshots, opt-in catalog member transfer extensions, legacy private
  unsigned member AXFR policy, UDP/XDP tuning knobs, and hot-path metric modes.
- Added a v0.2.0 draft release-note document that records the current release
  scope, package-version posture, retained evidence, and tag-time gates.
- Removed the unfinished out-of-zone A/AAAA glue transfer tolerance candidate;
  transfer owner validation remains strict, and transfer publication now fails
  closed instead of panicking if a parsed candidate snapshot cannot compile into
  the served zone image.

## 0.1.5 - 2026-06-09

### Added

- Added physical UDP/Knot comparison harnessing for detached multi-row sweeps,
  Knot reference rows, host/NIC/qdisc evidence capture, and transmit-side loss
  diagnostics.
- Added OxideGun and server AF_XDP/XDP controls for multi-queue binding,
  sparse queue steering, source-port weighting, reply redirects, requester
  diagnostics, and packet-I/O counters.
- Added observability API coverage and related operator/metrics documentation.

### Changed

- Tuned the standard UDP socket path with lower hot-path overhead, borrowed
  zone access, optional timestamp skipping, pacing/qdisc/tuning support, and
  expanded physical saturation profiles.
- Promoted the current UDP and AF_XDP benchmark evidence into the Knot
  comparison documentation, including rejected prototype notes where evidence
  did not justify keeping an approach.
- Bumped the workspace and eBPF support crates to version `0.1.5`.
- Built release-packaged `borondns` binaries with the server `af-xdp` feature
  enabled, matching the XDP-enabled `oxide-gun` release asset.

### Notes

- This release captures the current physical UDP comparison and AF_XDP
  diagnostic work. Formal production acceptance still depends on repeatable
  operations evidence, long-running fuzz/interop sweeps, signing, and external
  operator acceptance.

## 0.1.4 - 2026-06-02

### Changed

- Split the large `borondns-server` runtime file into focused modules for UDP,
  TCP, health/metrics, transfer I/O, transfer planning, rate limiting, DNS
  Cookies, configuration validation, runtime status, shutdown, errors, and
  tests without changing runtime ownership or packet-serving behavior.
- Updated maintainability evidence to count standalone test modules separately
  from production Rust and to track the current 34-module first-party workspace
  map.
- Registered the standard UDP socket/mmsg adapters and feature-gated server
  AF_XDP/eBPF adapters in the unsafe-boundary and unsafe-prone dependency
  registries.
- Bumped the workspace and eBPF support crates to version `0.1.4`.

### Fixed

- Added a hard cap on DNS compression-pointer indirection chains in both name
  parsing and skip-only record scanning to keep malformed packet handling
  bounded.
- Fixed benchmark script shellcheck hygiene for privileged perf capture while
  keeping stdout/stderr artifacts owned by the invoking user.

### Notes

- This is the final intended local pre-NIC/XDP stabilization release. Physical
  NIC AF_XDP/XDP performance evidence remains a separate lab-hardware phase.
- Formal SRS acceptance evidence such as long fuzz campaigns, full interop
  sweeps, reference-hardware benchmarks, soak, reproducible-build comparison,
  signing, and external operator acceptance remains delegated to the later
  release/operations gate.

## 0.1.3 - 2026-05-29

### Added

- Added the initial `oxide-gun` crate: a DNS load/probe tool with TOML
  configuration, process/drop receive modes, structured summary output, a local
  responder `--self-test` E2E path, and an explicit Linux AF_XDP backend behind
  the `xdp` Cargo feature for lab hosts.
- Added release packaging for the XDP-enabled `oxide-gun` binary, including a
  raw static binary asset, installer payload inclusion, SHA256 sidecars, and
  installer smoke coverage.

### Changed

- Promoted the immutable `ZoneImage` data plane through the server query path,
  publishing compiled images beside transferred zone snapshots with ArcSwap
  directory replacement and suffix-indexed zone lookup.
- Removed the live snapshot-serving rollback and shadow-validation paths from
  packet answering; runtime query serving now uses the ZoneImage packet path
  without cloning `ZoneSnapshot` or materializing `LookupResult` values on the
  hot path.
- Expanded ZoneImage coverage for DNSSEC proofs, QTYPE ANY, EDNS option cases,
  UDP truncation, DNAME/delegation stress cases, high-fanout zones, and retained
  in-process benchmark evidence.
- Updated benchmark and evidence scripts to treat packet serving as ZoneImage
  parity after rollback retirement while keeping plan/wire layout ratios as
  strict performance guardrails.

### Documentation

- Refreshed memory-layout, architecture, health/metrics, operator, interface,
  release-note, OxideGun, and test-plan documentation to describe the promoted
  ZoneImage layout, retired rollback/shadow surfaces, and release-packaged
  OxideGun tooling.

### Notes

- This is an Engineering release. Formal SRS release acceptance still requires
  release/operations evidence such as real hardware benchmark runs, long fuzz
  campaigns, soak, reproducible-build comparison, signing, and external operator
  acceptance.

## 0.1.2 - 2026-05-26

### Added

- Added CHAOS-class self-identification support with conservative REFUSED
  defaults, optional `[chaos]` configuration, metrics, debug logging, and
  UDP/TCP client E2E coverage.
- Added compressed Alpine Docker image archive packaging for tag releases,
  including manifest and SHA256 sidecars.
- Added BIND packet-torture interop coverage that transfers a broad valid RR
  corpus and compares served packet content against BIND behavior.
- Added PowerDNS Authoritative plus PostgreSQL catalog TSIG interop coverage,
  including live member add/remove and member-zone record update while BoronDNS
  remains running.
- Added Debian 12 beta VM container-operator notes for the release Docker image
  archive, including host-network, three-interface deployment guidance.
- Added a large catalog-zone benchmark harness with mixed zone sizes, randomized
  TCP/UDP clients, phase timing, optional perf capture, and opt-in zone-shape
  metrics.

### Changed

- Tuned the release profile with ThinLTO, single codegen unit, stripped symbols,
  and aborting panics for smaller/faster release artifacts.
- Reduced zone-store memory overhead with compact RRset RDATA storage, interned
  zone keys, and lower-allocation lookup helpers.
- Gated costly zone-shape diagnostics behind configuration so production
  metrics scrapes do not pay the full-zone scan cost.

## 0.1.1 - 2026-05-26

### Added

- Added DNAME edge-case handling, including YXDOMAIN on synthesized-name
  overflow and transfer-time rejection of multiple DNAME records at one owner.
- Added stricter referral glue handling so parent-side NS addresses are not
  emitted as child bailiwick glue.
- Added catalog-zone observability, including member-zone metrics and
  add/remove logs.
- Added strict transfer-publication validation follow-up for the out-of-zone
  glue compatibility candidate; the candidate was removed before being treated
  as supported behavior.
- Added mandatory TSIG validation for catalog zones.
- Added BIND XoT catalog-zone interop coverage.
- Added bounded EDNS Extended DNS Errors diagnostics for selected authoritative
  server states.

### Changed

- Updated the SRS alignment to v0.9 while preserving the BoronDNS naming and
  configuration model.
- Clarified health endpoint and configuration wording in the SRS.
- Restored canonical MIT and Apache-2.0 license texts.
- Added transfer policy configuration for stricter production deployments.

## 0.1.0 - 2026-05-25

### Added

- Initial Engineering MVP release of BoronDNS as a secondary-only authoritative
  DNS server.
- Included AXFR/IXFR acquisition, NOTIFY handling, TSIG, XoT transfer support,
  DNS-over-UDP/TCP serving, health/metrics endpoints, RRL, DNS Cookies, passive
  DNSSEC record serving, catalog-zone support, installer packaging, and the
  first release workflow.
