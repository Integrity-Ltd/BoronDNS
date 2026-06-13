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
- the normative SRS requirement family that owns the observable behavior;
- current source ownership;
- representative evidence or test ownership.

`scripts/check-srs-review-disposition.py` checks this file against current
source paths, evidence paths, implementation markers, and representative test
markers. If code removes one of these slices, update this document, the review
disposition, the Engineering MVP scope, and the gap register in the same patch.

This document is intentionally code-owned. External review suggestions to trim
scope are reconciled in `docs/srs-review-disposition.md`, but this file remains
the authority on whether a slice is actually implemented, what exact behavior it
claims, and what adjacent behavior it does not claim.

## Review Baseline Alignment

The external review's suggested minimal MVP cut is treated as a floor for code
alignment, not a replacement for the current Engineering MVP. The table below
maps that baseline to current code and evidence so "trim the MVP" cannot be
read as removing behavior that already exists and is still in scope.

| Review baseline area | Current code-aligned status | Current source ownership | Representative evidence ownership |
| --- | --- | --- | --- |
| Secondary-only authoritative server; no recursion, forwarding, UPDATE, or primary role | Implemented as an authoritative-only answer path with invariant checks for forbidden resolver, forwarding, UPDATE, admin, and primary-serving surfaces. | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs`; `scripts/audit-invariants.sh` | `scripts/check.sh`; `docs/architecture.md`; `docs/engineering-mvp-readiness.md` |
| Static TOML configuration with explicit zones, primaries, and optional TSIG plus an optional reloadable secret-store root | Implemented through startup-only TOML parsing, `[[zones]]`, transfer primaries, startup TSIG key loading, redacted config dump, fail-closed `transfer.require_tsig` validation, and atomic reload of filesystem-backed TSIG/XoT secret snapshots from a configured root. | `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-core/src/tsig.rs`; `crates/oxidedns-server/src/secret_store.rs`; `crates/oxidedns-cli/src/main.rs`; `config/oxidedns.example.toml` | `docs/devops-getting-started.md`; `docs/operator-deployment-guide.md`; `scripts/check.sh` |
| UDP/TCP authoritative query serving with EDNS0 and TCP fallback | Implemented over UDP and TCP listeners, DNS-over-TCP framing, EDNS OPT parsing/emission, conservative UDP payload ceilings, TC truncation, and complete TCP retry behavior. | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/tcp.rs`; `crates/oxidedns-server/src/udp.rs` | `scripts/interop-edns-behavior.sh`; `scripts/interop-tcp-truncation-retry.sh` |
| AXFR initial load, SOA refresh/retry/expire state machine, NOTIFY, and TSIG-protected transfer/NOTIFY | Implemented as initial AXFR, SOA polling, scheduled refresh/retry/expire tracking, authorized NOTIFY refresh signalling, and TSIG signing/verification where configured. | `crates/oxidedns-core/src/axfr.rs`; `crates/oxidedns-core/src/tsig.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/transfer.rs` | `scripts/interop-bind-axfr.sh`; `scripts/interop-bind-notify-refresh.sh`; `scripts/interop-notify-negative.sh`; `docs/zsm-engineering-mvp-matrix.tsv` |
| Basic RR support, unknown RR pass-through, and passive DNSSEC records as transferred | Implemented known-type validation/serving for the baseline RR set and broader type-aware catalogue, bit-preserving unknown RR storage/serving, and passive DNSSEC serving without signing or validation. | `crates/oxidedns-core/src/axfr.rs`; `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/zone.rs`; `docs/rr-type-catalogue.md` | `scripts/interop-unknown-rr.sh`; `scripts/interop-dnssec-serve.sh`; `scripts/interop-dnssec-nsec3-serve.sh`; `scripts/interop-bind-packet-torture-docker.sh` |
| Minimal health, readiness, metrics, and structured logs | Implemented `/livez`, `/readyz`, `/healthz`, `/metrics`, Prometheus text exposition format 0.0.4, bounded JSON/logfmt structured logging, and build/version fields. | `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/health_metrics.rs`; `crates/oxidedns-cli/src/main.rs`; `docs/health-metrics-interface.md` | `scripts/capture-health-metrics-evidence.sh`; `scripts/check-interface-compatibility.py`; `scripts/audit-log-fields.py`; `scripts/audit-log-lazy-formatting.py` |

## Retained Slices

The table covers every code-backed slice that exceeds a static AXFR-only
secondary-server cut, not only the feature names explicitly called out by the
external review. That is why IXFR/AXFR fallback and broad EDNS response behavior
are retained here alongside catalog zones, XoT, DNS Cookies, RRL, bounded EDE,
passive DNSSEC serving, and opt-in CHAOS diagnostics.

| Feature family | Retained implementation slice | Not claimed by this slice | Normative SRS owner | Current source ownership | Representative evidence ownership |
| --- | --- | --- | --- | --- | --- |
| IXFR and AXFR fallback | The transfer client can build an IXFR query from the held SOA, parse valid IXFR responses, apply accepted deltas, and fall back to AXFR when IXFR is unavailable or unsuitable. | Primary-server behavior, dynamic UPDATE, UDP IXFR, or serving IXFR to downstream secondaries. | `ODS-FR-IXFR-001..019`; `ODS-FR-AXFR-001..026` | `crates/oxidedns-core/src/axfr.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/transfer.rs` | `crates/oxidedns-server/src/tests/transfer_protocol.rs`; `scripts/interop-bind-ixfr-refresh.sh`; `scripts/interop-knot-ixfr-refresh-docker.sh`; `scripts/interop-ixfr-notimp-fallback.sh` |
| XoT | Outbound zone-transfer transport uses rustls with a TLS 1.3-only client profile, configured trust anchors, SNI, ALPN `dot`, optional client certificates, TSIG-over-XoT where configured, and no cleartext fallback after TLS failure. | Client-query DoT, DoH, DoQ, inbound XoT listeners, NOTIFY-over-TLS listeners, or compatibility-mode TLS 1.2 XoT negotiation. | `ODS-FR-XOT-001..012` | `Cargo.toml`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/transfer.rs` | `crates/oxidedns-server/src/tests/refresh_xot_runtime.rs`; `scripts/interop-knot-xot-docker.sh`; `scripts/interop-knot-xot-tsig-docker.sh`; `scripts/interop-bind-xot-catalog-zone-docker.sh`; `scripts/audit-xot-revocation.sh` |
| Passive DNSSEC serving | The answer path serves transferred DNSSEC RRsets and selected transferred denial proofs when DO=1, copies the query DO bit into the response OPT, and can omit high-iteration NSEC3 proofs with bounded EDE diagnostics. | Signing, validation, key management, RFC 5011 rollover, generated DNSSEC records, or synthesized denial-proof material. | `ODS-FR-DNSSEC-001..014` | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/zone.rs` | `crates/oxidedns-core/src/dns_tests/any_negative_dnssec.rs`; `crates/oxidedns-core/src/dns_tests/edns_dnssec_cookie.rs`; `scripts/interop-dnssec-serve.sh`; `scripts/interop-dnssec-nsec3-serve.sh`; `scripts/interop-knot-dnssec-docker.sh`; `scripts/audit-dnssec-passive.sh`; `docs/dnssec-conformance-matrix.tsv` |
| RRL | UDP responses are classified through process-local source-prefix buckets with configured thresholds, allowlists, TSIG and valid-cookie exemptions, slip/drop behavior, summary logging, and metrics. | Per-zone RRL, distributed/shared RRL state across processes, or an RFC-standard RRL profile. | `ODS-FR-RRL-001..012`; valid-cookie exemption owned by `ODS-FR-COOKIE-009` | `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/health_metrics.rs`; `crates/oxidedns-server/src/rate_limit.rs`; `crates/oxidedns-server/src/udp.rs` | `crates/oxidedns-server/src/tests/metrics_rrl_udp.rs`; `scripts/interop-rrl-udp.sh`; `scripts/rrl-evidence-campaign.sh`; `docs/rrl-release-thresholds.md` |
| DNS Cookies | EDNS COOKIE parsing, RFC 9018 version-1 server-cookie emission, server-cookie verification, lenient or strict BADCOOKIE policy, configured shared Server Secrets, and current-plus-previous staged rollover are implemented for UDP source-address confirmation across single-instance and load-balanced/anycast deployments. | Durable client authentication, TSIG replacement, replay-proof identity, mandatory cookies for all deployments, or automatic runtime reload of DNS Cookie shared Server Secrets. | `ODS-FR-COOKIE-001..011` | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/dns_cookie.rs`; `crates/oxidedns-server/src/udp.rs` | `crates/oxidedns-core/src/dns_tests/edns_dnssec_cookie.rs`; `crates/oxidedns-server/src/tests/metrics_rrl_udp.rs`; `scripts/interop-dns-cookie-dig.sh` |
| RFC 9432 catalog zones | Configured catalog zones are transferred, parsed, reconciled into member-zone transfer plans subject to the configured member cap, hidden from external service by default, and observed through live add/remove logs plus `oxidedns_catalog_member_info`. When `member_transfer_extensions = true`, catalog member records may carry per-member transfer addresses, TSIG key-name references, transfer transport/port/server-name hints, and NOTIFY sources. | A management API, automatic discovery without catalog configuration, carrying raw TSIG/TLS secret material in catalog data, or accepting catalog-derived unsigned public-member AXFR plans. | `ODS-FR-PROV-001..014`; `ODS-IF-CONF-013`; `ODS-NFR-OBS-008` | `crates/oxidedns-core/src/catalog.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/transfer_plan.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/health_metrics.rs` | `crates/oxidedns-server/src/tests/catalog_and_plan.rs`; `docs/catalog-zone-rfc9432.md`; `scripts/interop-bind-catalog-zone-docker.sh`; `scripts/interop-powerdns-postgres-catalog-tsig-docker.sh`; `scripts/interop-bind-xot-catalog-zone-docker.sh` |
| EDNS response behavior | The query path owns OPT parsing and response emission for BADVERS, advertised UDP ceilings, DO-bit copy semantics, NSID, TCP keepalive, padding, unknown-option ignore, and non-EDNS truncation behavior. | EDNS EXPIRE (RFC 7314), DNS Stateful Operations, recursive EDNS behavior, or transport protocols outside DNS over UDP/TCP. | `ODS-FR-EDNS-001..017` | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `crates/oxidedns-core/src/dns_tests/edns_dnssec_cookie.rs`; `scripts/interop-edns-behavior.sh` |
| Bounded EDE diagnostics | Minimal EDE output is available for `Not Ready` and `Unsupported NSEC3 Iterations` only, behind the configured EDE mode. | A full EDE catalogue, resolver-policy explanations, stale-answer diagnostics, filtering diagnostics, or recursive validation errors. | `ODS-FR-EDNS-018`; `ODS-IF-CONF-017` | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs` | `crates/oxidedns-core/src/dns_tests/any_negative_dnssec.rs`; `crates/oxidedns-core/src/dns_tests/edns_dnssec_cookie.rs`; `scripts/interop-dnssec-serve.sh`; `scripts/interop-dnssec-nsec3-serve.sh`; `docs/dnssec-conformance-matrix.tsv` |
| Opt-in CHAOS self-identification | CH/TXT `version.bind.`, `version.server.`, `hostname.bind.`, and `id.server.` responses are disabled by default and require explicit configured values or NSID fallback where applicable. | Automatic host disclosure, arbitrary CHAOS namespaces, non-TXT CHAOS support, or IN-class behavior changes. | `ODS-FR-CHAS-001..006`; `ODS-IF-CONF-018` | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/health_metrics.rs` | `crates/oxidedns-core/src/dns_tests/message_parse_notify.rs`; `scripts/interop-chaos-queries.sh` |

## Formal Acceptance Posture

These slices are Engineering MVP scope because current code and tests own them.
They are not complete formal SRS release-acceptance claims until the relevant
rows in `docs/mvp-gap-register.md`, `docs/verification-ledger.md`, and
`docs/appendix-a-traceability-matrix.md` have retained release-grade evidence.

## Retained Support And Evidence Tooling

The external review also called out packaging, performance evidence, and
interop breadth as too much for a trimmed MVP. Those concerns are handled as
tooling boundaries: the following artifacts may remain in the repository
because they support deployment or evidence capture, but they do not expand the
OxideDNS server protocol surface unless a current SRS requirement says so.

| Tooling family | Retained tooling slice | Not claimed by this slice | Current source ownership | Representative evidence ownership |
| --- | --- | --- | --- | --- |
| Release installer and Docker image archives | The release path can build an `x86_64-unknown-linux-musl` installer `.tar.xz`, verify static linking for that default release target, produce raw static `oxidedns` and XDP-enabled `oxide-gun` binary assets, produce an Alpine-based Docker image archive `.tar.xz`, write SHA256 sidecars, and run local installer/container smoke checks. | A package repository, Docker registry publication, Kubernetes chart, multi-architecture release matrix, or signed-release acceptance evidence. Dynamic-link packaging is allowed only through an explicit non-release override and is not the portability artifact. | `scripts/package-installer.sh`; `scripts/package-docker-image.sh`; `.github/workflows/release-installer.yml` | `scripts/test-installer-docker.sh`; `scripts/test-docker-image.sh`; `docs/devops-getting-started.md`; `docs/release-evidence-guide.md` |
| OxideGun load generator | The workspace includes a support-tool DNS load generator with a portable UDP backend and an explicit Linux AF_XDP backend behind the `xdp` Cargo feature for lab hosts; the release installer includes an XDP-enabled static `oxide-gun` binary for lab evidence runs. | OxideDNS server XDP/eBPF support, a production packet-I/O backend, DNS protocol conformance authority, or automatic privileged deployment. | `crates/oxide-gun/src/main.rs`; `crates/oxide-gun/src/xdp_backend.rs`; `docs/unsafe-boundaries.tsv` | `docs/oxide-gun.md`; `scripts/oxide-gun-self-test.sh`; `scripts/oxide-gun-xdp-veth-smoke.sh`; `crates/oxide-gun/tests/cli.rs` |
| Benchmark and tuning harnesses | Local UDP/TCP DNS client benchmarks, large catalog-zone data generation, optional query-pipeline timing metrics, and response-cache candidate counters exist for evidence-driven tuning. | Formal Reference Hardware/Profile conformance, always-on high-cardinality metrics, a response-cache backend, or proof of equivalence to NSD, Knot DNS, BIND, or another authoritative server. | `scripts/benchmark-dns-clients.sh`; `scripts/benchmark-large-catalog-zones.sh`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs`; `crates/oxidedns-server/src/health_metrics.rs` | `docs/dns-client-benchmark.md`; `docs/future-optimization-tracks.md`; `scripts/capture-benchmark-handoff.sh`; `scripts/check-perf-regression.py` |
| Supplemental interop harnesses | BIND packet-torture comparison and PowerDNS/PostgreSQL catalog-TSIG interop scripts exercise broad record mixes, live catalog updates, TSIG-gated catalog transfer, and retained packet captures. | Mandatory execution in every local check, a replacement for the formal NSD/Knot/BIND release matrix, or a claim that PowerDNS is part of ODS-VER-003. | `scripts/interop-bind-packet-torture-docker.sh`; `scripts/interop-powerdns-postgres-catalog-tsig-docker.sh`; `docs/manual-bind-interop.md` | `docs/manual-bind-interop.md`; retained script artifact directories under `target/evidence/` when the scripts are run |
