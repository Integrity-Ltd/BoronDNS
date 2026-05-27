# Implemented Feature Scope

This document is the code-aligned boundary for protocol families that exceed a
minimal static-zone secondary DNS MVP but are already implemented and tested in
OxideDNS. It exists to keep the Engineering MVP scope from drifting into either
direction: it prevents removing working features merely because they were
outside a smaller external-review trim, and it prevents nearby unimplemented
features from being implied by broad feature names.

`docs/srs-review-disposition.md` owns the external-review rationale.
`docs/engineering-mvp-scope.md` owns the local milestone boundary.
This file owns the retained implementation slices.

## Maintenance Rule

Each retained feature family below must name:

- the retained implementation slice;
- nearby behavior that is not claimed by the slice;
- current source ownership;
- representative evidence or test ownership.

`scripts/check-srs-review-disposition.py` checks this file against current
source paths, evidence paths, implementation markers, and representative test
markers. If code removes one of these slices, update this document, the review
disposition, the Engineering MVP scope, and the gap register in the same patch.

## Retained Slices

| Feature family | Retained implementation slice | Not claimed by this slice | Current source ownership | Representative evidence ownership |
| --- | --- | --- | --- | --- |
| IXFR and AXFR fallback | The transfer client can build an IXFR query from the held SOA, parse valid IXFR responses, apply accepted deltas, and fall back to AXFR when IXFR is unavailable or unsuitable. | Primary-server behavior, dynamic UPDATE, UDP IXFR, or serving IXFR to downstream secondaries. | `crates/oxidedns-core/src/axfr.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-bind-ixfr-refresh.sh`; `scripts/interop-knot-ixfr-refresh-docker.sh`; `scripts/interop-ixfr-notimp-fallback.sh` |
| XoT | Outbound zone-transfer transport uses rustls with configured trust anchors, SNI, ALPN `dot`, optional client certificates, and TSIG-over-XoT where configured. | Client-query DoT, DoH, DoQ, inbound XoT listeners, NOTIFY-over-TLS listeners, or cleartext fallback after TLS failure. | `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-knot-xot-docker.sh`; `scripts/interop-knot-xot-tsig-docker.sh`; `scripts/interop-bind-xot-catalog-zone-docker.sh`; `scripts/audit-xot-revocation.sh` |
| Passive DNSSEC serving | The answer path serves transferred DNSSEC RRsets and selected transferred denial proofs when DO=1, copies the query DO bit into the response OPT, and can omit high-iteration NSEC3 proofs with bounded EDE diagnostics. | Signing, validation, key management, RFC 5011 rollover, generated DNSSEC records, or synthesized denial-proof material. | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/zone.rs` | `scripts/interop-dnssec-serve.sh`; `scripts/interop-dnssec-nsec3-serve.sh`; `scripts/interop-knot-dnssec-docker.sh`; `scripts/audit-dnssec-passive.sh`; `docs/dnssec-conformance-matrix.tsv` |
| RRL | UDP responses are classified through process-local source-prefix buckets with configured thresholds, allowlists, slip/drop behavior, summary logging, and metrics. | Per-zone RRL, distributed/shared RRL state across processes, or an RFC-standard RRL profile. | `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-rrl-udp.sh`; `scripts/rrl-evidence-campaign.sh`; `docs/rrl-release-thresholds.md` |
| DNS Cookies | EDNS COOKIE parsing, server-cookie emission, and server-cookie verification are implemented for UDP source-address confirmation, with lenient or strict BADCOOKIE policy. | Durable client authentication, TSIG replacement, replay-proof identity, or mandatory cookies for all deployments. | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-dns-cookie-dig.sh` |
| RFC 9432 catalog zones | Configured catalog zones are transferred, parsed, reconciled into member-zone transfer plans subject to the configured member cap, hidden from external service by default, and observed through live add/remove logs plus `oxidedns_catalog_member_info`. | A management API, automatic discovery without catalog configuration, or catalog member metadata beyond the implemented RFC 9432 owner-name and PTR target handling. | `crates/oxidedns-core/src/catalog.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `docs/catalog-zone-mvp-rfc9432.md`; `scripts/interop-bind-catalog-zone-docker.sh`; `scripts/interop-powerdns-postgres-catalog-tsig-docker.sh`; `scripts/interop-bind-xot-catalog-zone-docker.sh` |
| EDNS response behavior | The query path owns OPT parsing and response emission for BADVERS, advertised UDP ceilings, DO-bit copy semantics, NSID, TCP keepalive, padding, unknown-option ignore, and non-EDNS truncation behavior. | EDNS Refresh, DNS Stateful Operations, recursive EDNS behavior, or transport protocols outside DNS over UDP/TCP. | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-edns-behavior.sh` |
| Bounded EDE diagnostics | Minimal EDE output is available for `Not Ready` and `Unsupported NSEC3 Iterations` only, behind the configured EDE mode. | A full EDE catalogue, resolver-policy explanations, stale-answer diagnostics, filtering diagnostics, or recursive validation errors. | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-dnssec-serve.sh`; `scripts/interop-dnssec-nsec3-serve.sh`; `docs/dnssec-conformance-matrix.tsv` |
| Opt-in CHAOS self-identification | CH/TXT `version.bind.`, `version.server.`, `hostname.bind.`, and `id.server.` responses are disabled by default and require explicit configured values or NSID fallback where applicable. | Automatic host disclosure, arbitrary CHAOS namespaces, non-TXT CHAOS support, or IN-class behavior changes. | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-chaos-queries.sh` |

## Formal Acceptance Posture

These slices are Engineering MVP scope because current code and tests own them.
They are not complete formal SRS release-acceptance claims until the relevant
rows in `docs/mvp-gap-register.md`, `docs/verification-ledger.md`, and
`docs/appendix-a-traceability-matrix.md` have retained release-grade evidence.
