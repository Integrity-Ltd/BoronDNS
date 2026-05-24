# MVP Gap Register

This register keeps the active MVP work tied to reviewable evidence. The
implementation plan describes feature status in detail; this file is the shorter
queue for remaining release blockers.

## Protocol Coverage

| Area | Current Evidence | Remaining MVP Gap |
| --- | --- | --- |
| AXFR | Unit parser coverage; BIND, NSD, and Knot AXFR interop scripts; TSIG AXFR scripts for all three primaries | Expand release evidence into per-requirement traceability before acceptance review |
| IXFR | Unit parser/fault coverage; fake-primary NOTIMP fallback/cooldown interop script | Real-primary IXFR behavior matrix where primary support permits it |
| NOTIFY | Unit/runtime coverage; BIND NOTIFY refresh interop | NSD and Knot NOTIFY refresh interop |
| XoT | Configuration and startup validation; in-process TLS transport tests; Knot XoT AXFR interop script | Wider TLS fault matrix, XoT+TSIG interop, and any additional real-primary XoT evidence |
| DNSSEC Serving | Unit-level response augmentation for stored DNSSEC records | Release-level conformance matrix for DNSSEC responses and truncation interactions |
| RRL | Unit-level token bucket and metrics coverage | Runtime/interop evidence under UDP load and release threshold decisions |

## Non-Functional Evidence

| Area | Current Evidence | Remaining MVP Gap |
| --- | --- | --- |
| Fuzzing | `dns_datagram`, `transfer_stream`, `tsig_message`, and `notify_edns_datagram` compile checks | 24-hour campaigns per parser target with retained logs/artifacts |
| Dependency Audit | `cargo deny` in `scripts/check.sh` | Release snapshot of advisory/license/source results |
| Performance | No accepted benchmark artifact yet | Throughput, latency, memory, and transfer performance evidence against SRS NFR targets |
| Soak | No accepted soak artifact yet | 30-day production-representative soak without anomaly |
| Portability | Linux CI-style local checks | Linux distribution/container evidence and documented platform boundaries |
| Operator Docs | README, implementation plan, verification ledger, and example config | Operator Deployment Guide and full Appendix A traceability matrix |

## Current Verification Commands

```sh
./scripts/check.sh
cargo check --manifest-path fuzz/Cargo.toml
RUSTUP_TOOLCHAIN=nightly cargo fuzz check dns_datagram
RUSTUP_TOOLCHAIN=nightly cargo fuzz check transfer_stream
RUSTUP_TOOLCHAIN=nightly cargo fuzz check tsig_message
RUSTUP_TOOLCHAIN=nightly cargo fuzz check notify_edns_datagram
scripts/interop-bind-axfr.sh
scripts/interop-bind-tsig-axfr.sh
scripts/interop-bind-notify-refresh.sh
scripts/interop-nsd-axfr-docker.sh
scripts/interop-nsd-tsig-axfr-docker.sh
scripts/interop-knot-axfr-docker.sh
scripts/interop-knot-tsig-axfr-docker.sh
scripts/interop-knot-xot-docker.sh
scripts/interop-ixfr-notimp-fallback.sh
```
