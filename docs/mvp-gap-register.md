# Engineering MVP and SRS Acceptance Gap Register

This register keeps active implementation work tied to reviewable evidence. The
implementation plan describes feature status in detail; this file is the shorter
queue for release blockers.

Terminology:

- **Engineering MVP** is the first deployable secondary DNS server with the core
  operational path and retained verification evidence.
- **SRS acceptance** is the later ODS-VER-008 gate. It requires full SRS
  conformance, the complete interop matrix, performance targets, 30-day soak,
  long-run fuzzing, dependency/CVE/release-signing evidence, documentation
  completion, and external operator acceptance.
- **Current normative SRS** is `docs/OxideDNS-Secondary-SRS-v0.7.md`.

Rows below deliberately separate current evidence from remaining acceptance
gaps. A row with substantial implementation evidence is not a claim of full SRS
compliance.

## Protocol Coverage

| Area | Current Evidence | Remaining Acceptance Gap |
| --- | --- | --- |
| AXFR | Unit parser coverage; BIND, NSD, and Knot AXFR interop scripts; TSIG AXFR scripts for all three primaries | Expand release evidence into per-requirement traceability before acceptance review |
| IXFR | Unit parser/fault coverage; BIND and Knot true incremental IXFR refresh interop; fake-primary NOTIMP fallback/cooldown interop script | Additional real-primary IXFR behavior matrix where primary support permits it |
| NOTIFY | Unit/runtime coverage; BIND, NSD, and Knot NOTIFY refresh interop | Release traceability and broader negative interop evidence |
| XoT | Configuration and startup validation; in-process TLS transport, XoT+TSIG, mTLS client-certificate, certificate-name, untrusted-cert, expired-cert, ALPN-failure, and missing-client-cert tests; structured XoT TLS establishment/ALPN-failure/session-close log tests with negotiated TLS version/cipher and byte counters; no-CRL/no-OCSP revocation-posture audit; Knot XoT AXFR and XoT+TSIG interop scripts | Broader real-primary XoT evidence beyond Knot and retained release log artifacts |
| DNSSEC Serving | Unit-level response augmentation for stored DNSSEC records; runtime fake-primary DNSSEC serve scripts for DO-sensitive RRSIG/NSEC/NSEC3/DNSKEY/NSEC3PARAM and truncation behavior; Knot signed-primary NSEC3 interop script | Release-level conformance matrix |
| RRL | Unit-level token bucket and metrics coverage; runtime UDP drop/slip script across all response categories with metrics checks; retained RRL evidence campaign helper | Release threshold decisions and longer-running campaign evidence |
| EDNS v0.7 Additions | EDNS parsing, OPT response foundations, payload-limit tests, non-EDNS 512-octet truncation/no-OPT unit evidence, configured NSID response tests for `ODS-FR-EDNS-016..017`, and fake-primary runtime evidence in `scripts/interop-dnssec-serve.sh` for non-EDNS truncation plus NSID empty/non-empty request handling exist | Retain per-requirement release artifacts before Alpha signoff |
| DNS Cookies | RFC 9018 version-1 server-cookie construction/validation, COOKIE option parsing, startup random runtime secret with redacted fingerprint logging, configurable disabled/lenient/strict policy and in-process secret rotation interval, strict BADCOOKIE extended-RCODE responses with debug logging, lenient refresh of invalid server cookies, same-client validation, timestamp/source/tamper rejection, malformed length FORMERR handling, UDP valid-cookie RRL exemption, global and per-source-prefix cookie-case counters, BADCOOKIE counters, bounded prefix cardinality, metrics exposition, and BIND `dig +cookie` runtime interop have unit/runtime tests | Add broader BIND/Knot deployment interop evidence and retained MVP release artifacts |

## Non-Functional Evidence

| Area | Current Evidence | Remaining Acceptance Gap |
| --- | --- | --- |
| Architectural Invariants | `scripts/audit-invariants.sh` records static inspection evidence for SRS v0.7 INV-001 through INV-009, including authoritative-only response composition, single-process operation, and no runtime code loading; `dns_update_opcode_gets_notimp_without_zone_mutation` covers DNS UPDATE rejection without zone mutation; `concurrent_snapshot_replacement_answers_from_one_zone_version` stress-checks CNAME-chain query responses during atomic snapshot replacement | Add read-only root filesystem runtime evidence and stronger panic-free query-path evidence |
| Fuzzing | `dns_datagram`, `transfer_stream`, `tsig_message`, and `notify_edns_datagram` compile checks; `scripts/fuzz-campaign.sh` and optional release-snapshot fuzz campaign capture | 24-hour campaigns per parser target with retained logs/artifacts |
| Safe Rust Audit | Workspace `unsafe_code = "forbid"` lint for first-party crates except the narrow audited POSIX signal-disposition FFI module required for `SIG_IGN`; `scripts/audit-safe-rust.sh` first-party unsafe construct scan | Release-review transitive dependency unsafe enumeration, for example with `cargo geiger` or equivalent, and retained review of the signal-disposition FFI boundary |
| Maintainability Evidence | `scripts/audit-maintainability.sh` records first-party Rust source line count, module map, and the current ODS-NFR-MAINT-001 over-target status | Architecture/release-note justification or refactor plan for the line-count target, plus reproducible-build and in-code requirement-reference evidence |
| Dependency Audit | `cargo deny` in `scripts/check.sh`; `scripts/release-evidence-snapshot.sh` captures a release-review cargo-deny log | Release snapshot review and retained advisory/license/source artifacts |
| Performance | `scripts/perf-smoke.sh` provides a repeatable startup-to-ready, AXFR ingestion, metrics, and UDP direct-hit latency smoke harness | Release benchmark artifacts for throughput, latency, memory, transfer performance, and capacity against SRS NFR targets |
| Soak | No accepted soak artifact yet | 30-day production-representative soak without anomaly |
| Portability | Linux CI-style local checks | Linux distribution/container evidence and documented platform boundaries |
| Interface/CLI | `serve`, `check-config`, `--validate-config`, redacted `--dump-config`, `--example-config`, `--version`/`-V`, `--help`/`-h`, config parsing, optional `[interfaces].notify` UDP/TCP listeners with DNS/NOTIFY handling and DNS-listener overlap rejection, JSON/logfmt logging, `ODS_<SECTION>_<KEY>` env overrides for the scalar server/health/limits/TSIG subset plus non-fatal unrecognised-`ODS_*` warnings, implemented suspicious-warning catalogue for DNS Cookies disabled, global RRL allowlists, large TSIG fudge, HMAC-SHA1 TSIG keys, long TCP idle timeouts, low AXFR/IXFR ingestion-size caps, XoT trust-anchor expiry within 30 days, and transferred SOA timers approaching the configured ZSM maximum effective interval, `/livez`, JSON `/readyz`, `/healthz` readiness alias, `/metrics`, gzip-capable and per-source-IP rate-limited metrics responses, SRS-named per-zone status metrics, config-warning count gauge, build-info gauge, query latency histogram, SIGTERM/SIGINT handling, SIGHUP ignore behavior, SIGHUP/SIGPIPE `SIG_IGN` disposition evidence on Linux, Linux no-extra-handler evidence for SIGHUP/SIGPIPE/SIGQUIT/SIGUSR1/SIGUSR2, and binary-level tests for config/usage/version/help/example-config exit codes plus config/startup/bind failure exit codes 2, 64, 71, 73, 74, and 78 | Complete SRS v0.7 Alpha alignment: broader sysexits mapping for less common runtime classes, canonical log fields, broader retained health/metrics/signal timing evidence, stdout/stderr broken-pipe runtime evidence, and release evidence for build-info label accuracy, latency histogram behavior, version/help/example-config output retention, and metrics rate limiting under production-representative scrape traffic |
| Verification Governance | `scripts/release-evidence-snapshot.sh` captures command logs and git/tool state | Add SRS v0.7 release notes gate (`ODS-VER-010`), method cadence/Test Plan mapping (`ODS-VER-011`), regression triage policy (`ODS-VER-012`), primary version recording (`ODS-VER-013`), RFC compliance assertion publication (`ODS-VER-014`), and responsibility allocation (`ODS-VER-015`) |
| Operator Docs | README, implementation plan, verification ledger, first-pass Appendix A traceability matrix, example config, Operator Deployment Guide, and release evidence snapshot helper | Expand Appendix A from family-level rows to the full per-requirement traceability matrix required by ODS-VER-009; add Architecture Document, Test Plan, SLO/operator guide sections, vulnerability disclosure policy, and signed-release process before MVP acceptance |

## Current Verification Commands

Engineering MVP evidence profile:

```sh
scripts/engineering-mvp-evidence.sh
```

Broader SRS acceptance evidence commands:

```sh
./scripts/check.sh
scripts/audit-invariants.sh
scripts/audit-xot-revocation.sh
scripts/audit-safe-rust.sh
scripts/audit-maintainability.sh
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
scripts/interop-knot-ixfr-refresh-docker.sh
scripts/interop-knot-xot-docker.sh
scripts/interop-knot-xot-tsig-docker.sh
scripts/interop-knot-dnssec-docker.sh
scripts/interop-ixfr-notimp-fallback.sh
scripts/interop-rrl-udp.sh
scripts/rrl-evidence-campaign.sh --iterations 3
scripts/interop-dns-cookie-dig.sh
scripts/interop-dnssec-serve.sh
scripts/interop-dnssec-nsec3-serve.sh
scripts/perf-smoke.sh
scripts/release-evidence-snapshot.sh
```
