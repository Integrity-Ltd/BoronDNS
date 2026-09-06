# Changelog

Pre-1.0 versions were internal validation releases and are intentionally
omitted from this public release history.

## 1.0.1 - 2026-09-06

Changes since `v1.0.0`.

### Added

- Debian/Ubuntu `.deb` and Fedora/Rocky Linux `.rpm` release packages, with a
  systemd service and a dedicated runtime user. Package builds check Cargo,
  release-tag, and binary versions; lifecycle tests cover installation,
  upgrade, and removal.
- Contribution guidelines and GitHub issue and pull-request templates.

### Fixed

- CNAME/DNAME answer construction no longer repeats an RRset already included
  in the answer. Delegation lookup respects the first zone cut, including when
  deeper delegation data exists below it.
- NSEC3 hashing uses canonical DNS wire names, correcting names containing
  bytes escaped in their textual representation.
- Repeated IXFR additions of an existing record are treated as idempotent.
- The archive installer accepts trusted, root-owned symlinked system tools,
  handles an inactive systemd service returning exit status 4, and validates
  configuration with a clean environment.
- Release manifests and SBOMs include the shipped AF_XDP feature. The release
  API supervisor tolerates a nonblocking signal read with no pending signal.

### Changed

- Durable IXFR updates can persist a bounded RRset-change journal instead of
  rewriting the entire zone checkpoint for every update. Restart recovery
  validates and replays those changes; full checkpoints remain the fallback.
  See the [IXFR measurements](docs/ixfr-scaling-2026-08.md) for results and
  workload limits.
- Release downloads use one checksum manifest and its Sigstore bundle instead
  of separate checksum and signature files for every payload.
- Documentation is organized around installation, configuration, operation,
  development, and retained evidence. Release-handoff reports distinguish
  implemented behavior from deferred verification work.
- Development and release builds now pin Rust 1.98.1 instead of 1.96.1.

### Upgrade and rollback notes

- Verification scripts consuming release assets must use
  `release-handoff.sha256` and `release-handoff.sha256.sigstore.json`: verify
  the manifest's signature and release identity, then the downloaded payloads
  against that manifest.
- Version 1.0.0 does not replay the new `.bdj` IXFR journals. Downgrading while
  reusing the cache can restore an older `.bdz` checkpoint. Before a downgrade,
  stop the service and preserve the complete cache; use a separate empty cache
  and obtain fresh full transfers from reachable primaries before returning
  the downgraded server to service.

## 1.0.0 - Initial public-beta release

BoronDNS 1.0.0 is the initial public release of the authoritative secondary
DNS server, together with BoronGun and BoronGen. It includes AXFR/IXFR refresh,
XoT transfers, passive DNSSEC serving, catalog zones, DNS Cookies, RRL,
operational observability, signed release artifacts, and large-zone tooling.

This release has a public-beta support posture. The supported product boundary
and known limitations are defined by `docs/implemented-feature-scope.md`, the
operator guide, `SECURITY.md`, and the 1.0 release notes. Internal Rust crate
APIs and ABI are not stable public interfaces.
