# MVP Gap Register

This register keeps the active MVP work tied to reviewable evidence. The
implementation plan describes feature status in detail; this file is the shorter
queue for remaining release blockers.

## Protocol Coverage

| Area | Current Evidence | Remaining MVP Gap |
| --- | --- | --- |
| AXFR | Unit parser coverage; BIND, NSD, and Knot AXFR interop scripts; TSIG AXFR scripts for all three primaries | Expand release evidence into per-requirement traceability before acceptance review |
| IXFR | Unit parser/fault coverage; BIND true incremental IXFR refresh interop; fake-primary NOTIMP fallback/cooldown interop script | Additional real-primary IXFR behavior matrix where primary support permits it |
| NOTIFY | Unit/runtime coverage; BIND, NSD, and Knot NOTIFY refresh interop | Release traceability and broader negative interop evidence |
| XoT | Configuration and startup validation; in-process TLS transport, XoT+TSIG, mTLS client-certificate, certificate-name, untrusted-cert, expired-cert, ALPN-failure, and missing-client-cert tests; Knot XoT AXFR and XoT+TSIG interop scripts | Broader real-primary XoT evidence beyond Knot |
| DNSSEC Serving | Unit-level response augmentation for stored DNSSEC records; runtime fake-primary DNSSEC serve scripts for DO-sensitive RRSIG/NSEC/NSEC3/DNSKEY/NSEC3PARAM and truncation behavior; Knot signed-primary NSEC3 interop script | Release-level conformance matrix |
| RRL | Unit-level token bucket and metrics coverage; runtime UDP drop/slip script across all response categories with metrics checks; retained RRL evidence campaign helper | Release threshold decisions and longer-running campaign evidence |

## Non-Functional Evidence

| Area | Current Evidence | Remaining MVP Gap |
| --- | --- | --- |
| Fuzzing | `dns_datagram`, `transfer_stream`, `tsig_message`, and `notify_edns_datagram` compile checks; `scripts/fuzz-campaign.sh` and optional release-snapshot fuzz campaign capture | 24-hour campaigns per parser target with retained logs/artifacts |
| Safe Rust Audit | Workspace `unsafe_code = "forbid"` lint; `scripts/audit-safe-rust.sh` first-party unsafe construct scan | Release-review transitive dependency unsafe enumeration, for example with `cargo geiger` or equivalent |
| Dependency Audit | `cargo deny` in `scripts/check.sh`; `scripts/release-evidence-snapshot.sh` captures a release-review cargo-deny log | Release snapshot review and retained advisory/license/source artifacts |
| Performance | `scripts/perf-smoke.sh` provides a repeatable startup-to-ready, AXFR ingestion, metrics, and UDP direct-hit latency smoke harness | Release benchmark artifacts for throughput, latency, memory, transfer performance, and capacity against SRS NFR targets |
| Soak | No accepted soak artifact yet | 30-day production-representative soak without anomaly |
| Portability | Linux CI-style local checks | Linux distribution/container evidence and documented platform boundaries |
| Operator Docs | README, implementation plan, verification ledger, first-pass Appendix A traceability matrix, example config, Operator Deployment Guide, and release evidence snapshot helper | Expand Appendix A from family-level rows to the full per-requirement traceability matrix required by ODS-VER-009 |

## Current Verification Commands

```sh
./scripts/check.sh
scripts/audit-safe-rust.sh
cargo check --manifest-path fuzz/Cargo.toml
RUSTUP_TOOLCHAIN=nightly cargo fuzz check dns_datagram
RUSTUP_TOOLCHAIN=nightly cargo fuzz check transfer_stream
RUSTUP_TOOLCHAIN=nightly cargo fuzz check tsig_message
RUSTUP_TOOLCHAIN=nightly cargo fuzz check notify_edns_datagram
scripts/fuzz-campaign.sh --dry-run --duration 1 --target dns_datagram
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
scripts/interop-knot-xot-docker.sh
scripts/interop-knot-xot-tsig-docker.sh
scripts/interop-knot-dnssec-docker.sh
scripts/interop-ixfr-notimp-fallback.sh
scripts/interop-rrl-udp.sh
scripts/rrl-evidence-campaign.sh --iterations 3
scripts/interop-dnssec-serve.sh
scripts/interop-dnssec-nsec3-serve.sh
scripts/perf-smoke.sh
scripts/release-evidence-snapshot.sh
```
