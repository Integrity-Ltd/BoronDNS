# Changelog

Pre-1.0 versions were internal validation releases and are intentionally
omitted from this public release history.

## 1.0.0 - Initial public-beta release

BoronDNS 1.0.0 is the initial public release of the authoritative secondary
DNS server, together with BoronGun and BoronGen. It includes AXFR/IXFR refresh,
XoT transfers, passive DNSSEC serving, catalog zones, DNS Cookies, RRL,
operational observability, signed release artifacts, and large-zone tooling.

This release has a public-beta support posture. The supported product boundary
and known limitations are defined by `docs/implemented-feature-scope.md`, the
operator guide, `SECURITY.md`, and the 1.0 release notes. Internal Rust crate
APIs and ABI are not stable public interfaces.
