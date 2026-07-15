# RR Type Catalogue Implementation Notes

Status: implementation-supporting companion to SRS section 4.14.

The normative RR type requirement is `ODS-FR-RR-001` in
`docs/BoronDNS-Secondary-SRS-v0.9.1.md`. This document records how the current
code owns that catalogue so review-driven MVP trim suggestions do not silently
remove behavior that is already implemented and tested.

## Ownership

| Concern | Current owner |
| --- | --- |
| Known RR type numeric constants | `crates/borondns-core/src/dns.rs` `RecordType` |
| AXFR/IXFR transfer RDATA normalization | `crates/borondns-core/src/axfr.rs` `normalize_transfer_rdata` |
| Known-type transfer validation | `crates/borondns-core/src/axfr.rs` `validate_known_rdata` |
| Response RDATA compression policy | `crates/borondns-core/src/dns.rs` `encode_record_rdata` |
| Query-time additional-section semantics | `crates/borondns-core/src/zone.rs` target extraction helpers |
| Unknown RR transfer and serving | `crates/borondns-core/src/axfr.rs`; `crates/borondns-core/src/dns.rs` |

## Current Known-Type Set

The current type-aware set is:

| RR type | Code | Current code-aligned behavior |
| --- | ---: | --- |
| A | 1 | Validates fixed 4-octet RDATA. |
| NS | 2 | Normalizes compressed transfer RDATA names and may compress names when serving. |
| CNAME | 5 | Normalizes compressed transfer RDATA names, may compress names when serving, and participates in CNAME exclusivity checks. |
| SOA | 6 | Normalizes MNAME/RNAME transfer names, may compress MNAME/RNAME when serving, validates exact apex SOA, and uses RFC 1982 serial arithmetic where serial comparison is needed. REFRESH, RETRY, EXPIRE, and MINIMUM are carried as 32-bit timer fields from RFC 1035. |
| PTR | 12 | Normalizes compressed transfer RDATA names and may compress names when serving. |
| HINFO | 13 | Validates exactly two DNS character-string fields. |
| MX | 15 | Normalizes compressed EXCHANGE transfer names, may compress EXCHANGE when serving, and drives A/AAAA additional-section lookups. |
| TXT | 16 | Validates one or more DNS character-string fields while preserving field boundaries. |
| AAAA | 28 | Validates fixed 16-octet RDATA. |
| SRV | 33 | Validates uncompressed TARGET and drives A/AAAA additional-section lookups. |
| NAPTR | 35 | Validates ORDER/PREFERENCE, three character-string fields, and uncompressed REPLACEMENT. |
| DNAME | 39 | Validates uncompressed TARGET, enforces DNAME/CNAME coexistence constraints, and drives DNAME-to-CNAME response synthesis. |
| DS | 43 | Validates the fixed key-tag/algorithm/digest-type prefix and carries digest bytes opaquely. |
| RRSIG | 46 | Validates the uncompressed Signer's Name field and selects signatures by Type Covered for passive DNSSEC serving. |
| NSEC | 47 | Validates uncompressed Next Domain Name plus RFC 4034 type bit maps and serves transferred denial proofs. |
| DNSKEY | 48 | Validates the fixed prefix and RFC 4034 protocol field value 3 while preserving algorithm/key data opaquely. |
| NSEC3 | 50 | Validates NSEC3 salt/hash layout plus type bit maps and serves transferred denial proofs subject to the configured iteration cap. |
| NSEC3PARAM | 51 | Validates the NSEC3 parameter layout and drives the configured NSEC3 iteration-cap decision. |
| TLSA | 52 | Validates the fixed certificate-usage/selector/matching-type prefix and serves the association data opaquely. BoronDNS does not perform DANE validation. |
| SVCB | 64 | Validates uncompressed TargetName, AliasMode parameter absence, and sorted SvcParam keys; drives A/AAAA additional-section lookups. |
| HTTPS | 65 | Same wire-format validation and additional-section behavior as SVCB. |
| URI | 256 | Validates priority, weight, and non-empty raw URI target octets. The target is not a DNS character-string. |

## Out-Of-Catalogue Behavior

Types not listed in SRS section 4.14 are handled under `ODS-FR-URR-001` through
`ODS-FR-URR-009`, not as missing implementation. Current examples intentionally
remaining unknown include LOC, SSHFP, IPSECKEY, OPENPGPKEY, CSYNC, ZONEMD,
SMIMEA, CDS, CDNSKEY, CAA, HIP, and SPF type 99.

This is a code-aligned scope boundary:

- Unknown transfer RDATA is stored and served bit-for-bit.
- Unknown RDATA is not interpreted as compressed names.
- Reserved type values 0 and 65535 are rejected.
- Pseudo/meta/query types OPT, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, and ANY are
  rejected as zone-transfer content.
- Adding CAA, SSHFP, ZONEMD, CDS, CDNSKEY, or another type to the type-aware set
  requires code, SRS section 4.14, this document, and traceability updates in
  the same patch.

## Evidence Pointers

Current short evidence includes:

- `crates/borondns-core/src/axfr.rs` unit tests for transfer normalization,
  prohibited transfer content, known-type validation, DNSSEC algorithm opacity,
  URI raw target handling, and SVCB/HTTPS parameter validation.
- `crates/borondns-core/src/dns.rs` unit tests for response compression of
  permitted pre-RFC3597 RDATA names and opaque serving of unknown RDATA.
- `scripts/interop-unknown-rr.sh` and
  `scripts/interop-unknown-rr-bad-transfer.sh` for runtime unknown-RR and
  prohibited-transfer behavior.
- `scripts/interop-bind-packet-torture-docker.sh` for broad packet comparison
  against BIND, including known catalogue types and intentionally unknown CAA.

Release acceptance still needs retained per-type packet artifacts where
`docs/appendix-a-traceability-matrix.md` marks `ODS-FR-RR-001..ODS-FR-RR-007`
as partial.
