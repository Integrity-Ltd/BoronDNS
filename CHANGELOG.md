# Changelog

All notable project-facing changes are recorded here. Formal release acceptance
notes still use `docs/release-notes-template.md` when a release candidate needs
full evidence pointers and sign-off.

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
  including live member add/remove and member-zone record update while OxideDNS
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
- Added optional out-of-zone A/AAAA glue tolerance for compatibility with
  primary servers that emit traditional glue outside the zone apex.
- Added mandatory TSIG validation for catalog zones.
- Added BIND XoT catalog-zone interop coverage.
- Added bounded EDNS Extended DNS Errors diagnostics for selected authoritative
  server states.

### Changed

- Updated the SRS alignment to v0.9 while preserving the OxideDNS naming and
  configuration model.
- Clarified health endpoint and configuration wording in the SRS.
- Restored canonical MIT and Apache-2.0 license texts.
- Added transfer policy configuration for stricter production deployments.

## 0.1.0 - 2026-05-25

### Added

- Initial Engineering MVP release of OxideDNS as a secondary-only authoritative
  DNS server.
- Included AXFR/IXFR acquisition, NOTIFY handling, TSIG, XoT transfer support,
  DNS-over-UDP/TCP serving, health/metrics endpoints, RRL, DNS Cookies, passive
  DNSSEC record serving, catalog-zone support, installer packaging, and the
  first release workflow.
