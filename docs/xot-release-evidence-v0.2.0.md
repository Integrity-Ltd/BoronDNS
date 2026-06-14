# XoT Release Evidence - v0.2.0

This document records the local v0.2.0 retained XoT release-evidence bundle.

Evidence directory:
`target/evidence/xot-release-20260614T014700Z`

Run scope:

- `scripts/interop-knot-xot-docker.sh`
- `scripts/interop-knot-xot-tsig-docker.sh`
- `scripts/interop-bind-xot-catalog-zone-docker.sh`

Result: passed, 3 of 3 cases completed without skips.

## Inputs

| Input | Value |
| --- | --- |
| Source commit | `4193049dc540feb7d9d97479fc6aede2b8cb3e09` |
| Dirty checkout | `no` |
| Host | `release-validation-host-arch` |
| Kernel | `Linux release-validation-host-arch 7.0.11-arch1-1 #1 SMP PREEMPT_DYNAMIC Tue, 02 Jun 2026 18:26:58 +0000 x86_64 GNU/Linux` |
| Docker | `Docker version 29.5.2, build 79eb04c7d8` |
| DiG | `DiG 9.20.23` |
| OpenSSL | `OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)` |

## Case Summary

| Case | Primary | Version | Covered behavior | Result |
| --- | --- | --- | --- | --- |
| `knot-xot` | Knot DNS on Alpine Linux v3.24 | Knot DNS 3.5.3 | AXFR over TLS, ALPN `dot`, certificate validation, no cleartext fallback, TLS session logging, served A/CNAME/TCP SOA after publication | passed |
| `knot-xot-tsig` | Knot DNS on Alpine Linux v3.24 | Knot DNS 3.5.3 | TSIG-authenticated AXFR over TLS, unsigned XoT AXFR rejection, ALPN `dot`, certificate validation, no cleartext fallback, TLS session logging, TSIG/TLS secret redaction checks | passed |
| `bind-xot-catalog` | BIND 9 on Alpine Linux v3.24 | BIND 9.20.23 | RFC 9432 catalog transfer over XoT+TSIG, plain TCP transfer denial, ALPN `dot`, live member add/remove reconciliation | passed |

## Requirement Traceability

Retained traceability files under the evidence directory map the cases to:

- `ODS-FR-XOT-001`
- `ODS-FR-XOT-002`
- `ODS-FR-XOT-003`
- `ODS-FR-XOT-004`
- `ODS-FR-XOT-005`
- `ODS-FR-XOT-006`
- `ODS-FR-XOT-008`
- `ODS-FR-XOT-011`
- `ODS-FR-PROV-006`
- `ODS-VER-003`

## Retained Artifacts

The evidence directory retains:

- `xot-release-env.env`
- `xot-release-summary.env`
- per-case logs and status files
- per-primary `primary-version.txt`
- ALPN probe output
- server certificate summaries
- redacted XoT/TSIG configuration artifacts where TSIG or RNDC secrets are used
- OxideDNS readiness, metrics, transfer-answer, and session logs
- catalog add/remove zone files and member query outputs for the BIND catalog case
- per-case traceability TSVs

A direct scan of the retained bundle for the fixture TSIG and RNDC secret values
passed after the script redaction fix.

## Remaining Related Work

This evidence closes the selected local XoT release-breadth gap for Knot XoT,
Knot XoT+TSIG, and BIND catalog-zone transfer over XoT+TSIG. It does not claim
full formal XoT acceptance for every failure class. Remaining broader acceptance
work includes malformed TLS/certificate/ALPN fault artifacts, real-primary mTLS
evidence, default-port evidence where required, ClientHello/prohibited-suite
inspection, and NSD XoT evidence if the selected NSD version exposes
TLS-protected transfer configuration.
