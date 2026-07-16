# XoT Release Evidence - v0.2.0

This document records the local v0.2.0 retained XoT release-evidence bundle.

Evidence directory:
`target/evidence/xot-release-20260614T014700Z`

Failure-evidence addendum:
`target/evidence/xot-failure-20260616T170617Z`

Run scope:

- `scripts/interop-knot-xot-docker.sh`
- `scripts/interop-knot-xot-tsig-docker.sh`
- `scripts/interop-bind-xot-catalog-zone-docker.sh`
- `scripts/capture-xot-failure-evidence.sh`

Result: passed, 3 of 3 primary interop cases and 10 of 10 failure-evidence
cases completed without skips.

## Inputs

| Input | Value |
| --- | --- |
| Source commit | `4193049dc540feb7d9d97479fc6aede2b8cb3e09` |
| Dirty checkout | `no` |
| Host | `release-validation-host` |
| Kernel | `Linux release-validation-host 7.0.11-arch1-1 #1 SMP PREEMPT_DYNAMIC Tue, 02 Jun 2026 18:26:58 +0000 x86_64 GNU/Linux` |
| Docker | `Docker version 29.5.2, build 79eb04c7d8` |
| DiG | `DiG 9.20.23` |
| OpenSSL | `OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)` |

Failure-evidence input summary:

| Input | Value |
| --- | --- |
| Source commit | `1ca8d0d97b3824957c45bb259dbd1916c427351b` |
| Dirty checkout | `no` |
| Captured at UTC | `20260616T170617Z` |
| Host | `unknown` |
| Kernel | `Linux release-validation-host 7.0.11-arch1-1 #1 SMP PREEMPT_DYNAMIC Tue, 02 Jun 2026 18:26:58 +0000 x86_64 GNU/Linux` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Cargo | `cargo 1.96.0 (30a34c682 2026-05-25)` |
| OpenSSL | `OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)` |

## Case Summary

| Case | Primary | Version | Covered behavior | Result |
| --- | --- | --- | --- | --- |
| `knot-xot` | Knot DNS on Alpine Linux v3.24 | Knot DNS 3.5.3 | AXFR over TLS, ALPN `dot`, certificate validation, no cleartext fallback, TLS session logging, served A/CNAME/TCP SOA after publication | passed |
| `knot-xot-tsig` | Knot DNS on Alpine Linux v3.24 | Knot DNS 3.5.3 | TSIG-authenticated AXFR over TLS, unsigned XoT AXFR rejection, ALPN `dot`, certificate validation, no cleartext fallback, TLS session logging, TSIG/TLS secret redaction checks | passed |
| `bind-xot-catalog` | BIND 9 on Alpine Linux v3.24 | BIND 9.20.23 | RFC 9432 catalog transfer over XoT+TSIG, plain TCP transfer denial, ALPN `dot`, live member add/remove reconciliation | passed |

## Failure Case Summary

| Case | Covered behavior | Result |
| --- | --- | --- |
| `handshake-no-cleartext-fallback` | TLS handshake failure is reported as XoT failure and does not retry the primary over cleartext TCP. | passed |
| `certificate-name-mismatch` | Certificate name mismatch aborts before any DNS transfer query is sent. | passed |
| `missing-dot-alpn` | Missing negotiated `dot` ALPN aborts before any DNS transfer query is sent and emits the ALPN failure log event. | passed |
| `tls12-only-primary` | TLS 1.2-only primaries fail the TLS profile before AXFR is sent. | passed |
| `untrusted-certificate` | Untrusted XoT certificate aborts before any DNS transfer query is sent. | passed |
| `expired-certificate` | Expired XoT certificate aborts before any DNS transfer query is sent. | passed |
| `mtls-client-certificate` | Configured client certificate is presented and mTLS XoT AXFR publishes the transferred serial. | passed |
| `missing-mtls-client-certificate` | mTLS primary requiring a client certificate rejects the transfer before any DNS query is sent. | passed |
| `missing-trust-anchor-file` | Runtime validation rejects XoT trust anchor paths that cannot be read. | passed |
| `malformed-trust-anchor-file` | Runtime validation rejects malformed XoT trust anchor PEM files. | passed |

## Requirement Traceability

Retained traceability files under the evidence directories map the cases to:

- `BDS-FR-XOT-001`
- `BDS-FR-XOT-002`
- `BDS-FR-XOT-003`
- `BDS-FR-XOT-004`
- `BDS-FR-XOT-005`
- `BDS-FR-XOT-006`
- `BDS-FR-XOT-008`
- `BDS-FR-XOT-011`
- `BDS-NEG-016`
- `BDS-CFG-001`
- `BDS-FR-PROV-006`
- `BDS-VER-003`

## Retained Artifacts

The evidence directory retains:

- `xot-release-env.env`
- `xot-release-summary.env`
- per-case logs and status files
- per-primary `primary-version.txt`
- ALPN probe output
- server certificate summaries
- redacted XoT/TSIG configuration artifacts where TSIG or RNDC secrets are used
- BoronDNS readiness, metrics, transfer-answer, and session logs
- catalog add/remove zone files and member query outputs for the BIND catalog case
- per-case traceability TSVs
- `xot-failure-env.env`
- `xot-failure-summary.tsv`
- per-failure-case `cargo test -- --nocapture` logs

A direct scan of the retained bundle for the fixture TSIG and RNDC secret values
passed after the script redaction fix.

## Remaining Related Work

This evidence closes the selected local XoT release-breadth gap for Knot XoT,
Knot XoT+TSIG, BIND catalog-zone transfer over XoT+TSIG, and retained local
failure-class evidence for TLS profile, certificate, ALPN, mTLS, trust-anchor,
and no-cleartext-fallback behavior. It does not claim full formal XoT
acceptance for every deployment class. Remaining broader acceptance work
includes real-primary mTLS evidence, default-port evidence where required,
ClientHello/prohibited-suite inspection, and NSD XoT evidence if the selected
NSD version exposes TLS-protected transfer configuration.
