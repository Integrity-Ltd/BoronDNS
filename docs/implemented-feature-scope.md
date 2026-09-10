# Implemented Feature Scope

This reference lists the implemented server features, their limits, and the
source/tests that support them. For configuration and use, start with the
[operator guide](operator-deployment-guide.md). Review history is in
[SRS Review Disposition](srs-review-disposition.md).

Update the relevant section when a feature changes. The source and test references
are checked by `scripts/check-srs-review-disposition.py`; they establish
implementation coverage, not a result for an untested release or platform.

## Core Server

The basic secondary-server functions are listed first. More specialized
protocol support follows under Protocol Features.

### Secondary-authoritative service

Implemented as an authoritative-only answer path with invariant checks for forbidden
resolver, forwarding, DNS UPDATE, record-editing, and primary-serving surfaces.
The opt-in [local zone commands](operator-commands.md) inspect installed zones and
schedule transfers; they cannot inject records or change runtime configuration.

<details>
<summary>Source and tests</summary>

Source:

- [crates/borondns-core/src/dns.rs](../crates/borondns-core/src/dns.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [scripts/audit-invariants.sh](../scripts/audit-invariants.sh)

Tests and supporting documentation:

- [scripts/check.sh](../scripts/check.sh)
- [docs/architecture.md](architecture.md)
- [docs/engineering-mvp-readiness.md](engineering-mvp-readiness.md)

</details>

### Configuration and secrets

Implemented through startup-only TOML parsing, `[[zones]]`, transfer primaries, startup
TSIG key loading, redacted config dump, fail-closed `transfer.require_tsig` validation,
and atomic reload of filesystem-backed TSIG/XoT secret snapshots from a configured root.

<details>
<summary>Source and tests</summary>

Source:

- [crates/borondns-core/src/config.rs](../crates/borondns-core/src/config.rs)
- [crates/borondns-core/src/tsig.rs](../crates/borondns-core/src/tsig.rs)
- [crates/borondns-server/src/secret_store.rs](../crates/borondns-server/src/secret_store.rs)
- [crates/borondns-cli/src/main.rs](../crates/borondns-cli/src/main.rs)
- [config/borondns.example.toml](../config/borondns.example.toml)

Tests and supporting documentation:

- [docs/devops-getting-started.md](devops-getting-started.md)
- [docs/operator-deployment-guide.md](operator-deployment-guide.md)
- [scripts/check.sh](../scripts/check.sh)

</details>

### UDP and TCP queries

Implemented over UDP and TCP listeners, DNS-over-TCP framing, EDNS OPT parsing/emission,
conservative UDP payload ceilings, TC truncation, and complete TCP retry behavior.

<details>
<summary>Source and tests</summary>

Source:

- [crates/borondns-core/src/dns.rs](../crates/borondns-core/src/dns.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/tcp.rs](../crates/borondns-server/src/tcp.rs)
- [crates/borondns-server/src/udp.rs](../crates/borondns-server/src/udp.rs)

Tests and supporting documentation:

- [scripts/interop-edns-behavior.sh](../scripts/interop-edns-behavior.sh)
- [scripts/interop-tcp-truncation-retry.sh](../scripts/interop-tcp-truncation-retry.sh)

</details>

### Zone acquisition and refresh

Implemented as initial AXFR, SOA polling, scheduled refresh/retry/expire tracking,
authorized NOTIFY refresh signalling, and TSIG signing/verification where configured.

<details>
<summary>Source and tests</summary>

Source:

- [crates/borondns-core/src/axfr.rs](../crates/borondns-core/src/axfr.rs)
- [crates/borondns-core/src/tsig.rs](../crates/borondns-core/src/tsig.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/transfer.rs](../crates/borondns-server/src/transfer.rs)

Tests and supporting documentation:

- [scripts/interop-bind-axfr.sh](../scripts/interop-bind-axfr.sh)
- [scripts/interop-bind-notify-refresh.sh](../scripts/interop-bind-notify-refresh.sh)
- [scripts/interop-notify-negative.sh](../scripts/interop-notify-negative.sh)
- [docs/zsm-engineering-mvp-matrix.tsv](zsm-engineering-mvp-matrix.tsv)

</details>

### Record types

Implemented known-type validation/serving for the baseline RR set and broader type-aware
catalogue, bit-preserving unknown RR storage/serving, and passive DNSSEC serving without
signing or validation.

<details>
<summary>Source and tests</summary>

Source:

- [crates/borondns-core/src/axfr.rs](../crates/borondns-core/src/axfr.rs)
- [crates/borondns-core/src/dns.rs](../crates/borondns-core/src/dns.rs)
- [crates/borondns-core/src/zone.rs](../crates/borondns-core/src/zone.rs)
- [docs/rr-type-catalogue.md](rr-type-catalogue.md)

Tests and supporting documentation:

- [scripts/interop-unknown-rr.sh](../scripts/interop-unknown-rr.sh)
- [scripts/interop-dnssec-serve.sh](../scripts/interop-dnssec-serve.sh)
- [scripts/interop-dnssec-nsec3-serve.sh](../scripts/interop-dnssec-nsec3-serve.sh)
- [scripts/interop-bind-packet-torture-docker.sh](../scripts/interop-bind-packet-torture-docker.sh)

</details>

### Health, metrics, and logs

Implemented `/livez`, `/readyz`, `/healthz`, `/metrics`, Prometheus text exposition
format 0.0.4, bounded JSON/logfmt structured logging, and build/version fields.

<details>
<summary>Source and tests</summary>

Source:

- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/health_metrics.rs](../crates/borondns-server/src/health_metrics.rs)
- [crates/borondns-cli/src/main.rs](../crates/borondns-cli/src/main.rs)
- [docs/health-metrics-interface.md](health-metrics-interface.md)

Tests and supporting documentation:

- [scripts/capture-health-metrics-evidence.sh](../scripts/capture-health-metrics-evidence.sh)
- [scripts/check-interface-compatibility.py](../scripts/check-interface-compatibility.py)
- [scripts/audit-log-fields.py](../scripts/audit-log-fields.py)
- [scripts/audit-log-lazy-formatting.py](../scripts/audit-log-lazy-formatting.py)

</details>


## Protocol Features

These features are implemented alongside the basic transfer and query path.
The limits below distinguish each supported use from similarly named
protocol features that the server does not provide.

### IXFR and AXFR fallback

The transfer client builds IXFR from the held SOA, validates RFC 1995 sequences, applies
RRset-granular deltas to structurally shared snapshots and denial indexes, atomically
publishes compact or sharded query state, and can fall back to AXFR when IXFR is
unavailable or unsuitable, including when the requested serial is outside the primary's
retained window.

Limits: Dynamic UPDATE, UDP IXFR, or serving IXFR to downstream secondaries. BoronGen's primary
mode is test tooling, not a BoronDNS production-server feature.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-IXFR-001..019`; `BDS-FR-AXFR-001..026`; `BDS-IF-CONF-019`

Source:

- [crates/borondns-core/src/axfr.rs](../crates/borondns-core/src/axfr.rs)
- [crates/borondns-core/src/zone.rs](../crates/borondns-core/src/zone.rs)
- [crates/borondns-core/src/zone_image.rs](../crates/borondns-core/src/zone_image.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/transfer.rs](../crates/borondns-server/src/transfer.rs)

Tests and supporting documentation:

- Core IXFR/overlay differential tests
- [crates/borondns-server/src/tests/transfer_protocol.rs](../crates/borondns-server/src/tests/transfer_protocol.rs)
- [fuzz/fuzz_targets/transfer_stream.rs](../fuzz/fuzz_targets/transfer_stream.rs)
- [scripts/interop-bind-ixfr-refresh.sh](../scripts/interop-bind-ixfr-refresh.sh)
- [scripts/interop-knot-ixfr-refresh-docker.sh](../scripts/interop-knot-ixfr-refresh-docker.sh)
- [scripts/interop-ixfr-notimp-fallback.sh](../scripts/interop-ixfr-notimp-fallback.sh)
- [docs/ixfr-scaling-2026-08.md](ixfr-scaling-2026-08.md)

</details>

### XoT

Outbound zone-transfer transport uses rustls with a TLS 1.3-only client profile,
configured trust anchors, SNI, ALPN `dot`, optional client certificates, TSIG-over-XoT
where configured, and no cleartext fallback after TLS failure.

Limits: Client-query DoT, DoH, DoQ, inbound XoT listeners, NOTIFY-over-TLS listeners, or
compatibility-mode TLS 1.2 XoT negotiation.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-XOT-001..012`

Source:

- [Cargo.toml](../Cargo.toml)
- [crates/borondns-core/src/config.rs](../crates/borondns-core/src/config.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/transfer.rs](../crates/borondns-server/src/transfer.rs)

Tests and supporting documentation:

- [crates/borondns-server/src/tests/refresh_xot_runtime.rs](../crates/borondns-server/src/tests/refresh_xot_runtime.rs)
- [scripts/interop-knot-xot-docker.sh](../scripts/interop-knot-xot-docker.sh)
- [scripts/interop-knot-xot-tsig-docker.sh](../scripts/interop-knot-xot-tsig-docker.sh)
- [scripts/interop-bind-xot-catalog-zone-docker.sh](../scripts/interop-bind-xot-catalog-zone-docker.sh)
- [scripts/audit-xot-revocation.sh](../scripts/audit-xot-revocation.sh)

</details>

### Passive DNSSEC serving

The answer path serves transferred DNSSEC RRsets and selected transferred denial proofs
when DO=1, copies the query DO bit into the response OPT, and fails closed with SERVFAIL
plus optional bounded EDE diagnostics when an NSEC3 proof exceeds the configured
iteration cap.

Limits: Signing, validation, key management, RFC 5011 rollover, generated DNSSEC records, or
synthesized denial-proof material.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-DNSSEC-001..014`

Source:

- [crates/borondns-core/src/dns.rs](../crates/borondns-core/src/dns.rs)
- [crates/borondns-core/src/zone.rs](../crates/borondns-core/src/zone.rs)

Tests and supporting documentation:

- [crates/borondns-core/src/dns_tests/any_negative_dnssec.rs](../crates/borondns-core/src/dns_tests/any_negative_dnssec.rs)
- [crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs](../crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs)
- [scripts/interop-dnssec-serve.sh](../scripts/interop-dnssec-serve.sh)
- [scripts/interop-dnssec-nsec3-serve.sh](../scripts/interop-dnssec-nsec3-serve.sh)
- [scripts/interop-knot-dnssec-docker.sh](../scripts/interop-knot-dnssec-docker.sh)
- [scripts/audit-dnssec-passive.sh](../scripts/audit-dnssec-passive.sh)
- [docs/dnssec-conformance-matrix.tsv](dnssec-conformance-matrix.tsv)

</details>

### RRL

UDP responses are classified through process-local source-prefix buckets with configured
thresholds, allowlists, TSIG and valid-cookie exemptions, slip/drop behavior, summary
logging, and metrics.

Limits: Per-zone RRL, distributed/shared RRL state across processes, or an RFC-standard RRL
profile.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-RRL-001..012`; valid-cookie exemption owned by `BDS-FR-COOKIE-009`

Source:

- [crates/borondns-core/src/config.rs](../crates/borondns-core/src/config.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/health_metrics.rs](../crates/borondns-server/src/health_metrics.rs)
- [crates/borondns-server/src/rate_limit.rs](../crates/borondns-server/src/rate_limit.rs)
- [crates/borondns-server/src/udp.rs](../crates/borondns-server/src/udp.rs)

Tests and supporting documentation:

- [crates/borondns-server/src/tests/metrics_rrl_udp.rs](../crates/borondns-server/src/tests/metrics_rrl_udp.rs)
- [scripts/interop-rrl-udp.sh](../scripts/interop-rrl-udp.sh)
- [scripts/rrl-evidence-campaign.sh](../scripts/rrl-evidence-campaign.sh)
- [docs/rrl-release-thresholds.md](rrl-release-thresholds.md)

</details>

### DNS Cookies

EDNS COOKIE parsing, RFC 9018 version-1 server-cookie emission, server-cookie
verification, lenient or strict BADCOOKIE policy, configured shared Server Secrets, and
current-plus-previous staged rollover are implemented for UDP source-address
confirmation across single-instance and load-balanced/anycast deployments.

Limits: Durable client authentication, TSIG replacement, replay-proof identity, mandatory
cookies for all deployments, or automatic runtime reload of DNS Cookie shared Server
Secrets.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-COOKIE-001..011`

Source:

- [crates/borondns-core/src/dns.rs](../crates/borondns-core/src/dns.rs)
- [crates/borondns-core/src/config.rs](../crates/borondns-core/src/config.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/dns_cookie.rs](../crates/borondns-server/src/dns_cookie.rs)
- [crates/borondns-server/src/udp.rs](../crates/borondns-server/src/udp.rs)

Tests and supporting documentation:

- [crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs](../crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs)
- [crates/borondns-server/src/tests/metrics_rrl_udp.rs](../crates/borondns-server/src/tests/metrics_rrl_udp.rs)
- [scripts/interop-dns-cookie-dig.sh](../scripts/interop-dns-cookie-dig.sh)

</details>

### RFC 9432 catalog zones

Configured catalog zones are transferred, parsed, reconciled into member-zone transfer
plans subject to the configured member cap, hidden from external service by default, and
observed through live add/remove logs plus `borondns_catalog_member_info`. Existing
instances win name clashes; later catalog instances are ignored rather than taking over,
and a member-node identifier change resets and re-adds the zone. When
`member_transfer_extensions = true`, catalog member records may carry per-member
transfer addresses, TSIG key-name references, transfer transport/port/server-name hints,
and NOTIFY sources.

Limits: A management API, automatic discovery without catalog configuration, carrying raw
TSIG/TLS secret material in catalog data, or accepting catalog-derived unsigned
public-member AXFR plans.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-PROV-001..014`; `BDS-IF-CONF-013`; `BDS-NFR-OBS-008`

Source:

- [crates/borondns-core/src/catalog.rs](../crates/borondns-core/src/catalog.rs)
- [crates/borondns-core/src/config.rs](../crates/borondns-core/src/config.rs)
- [crates/borondns-server/src/transfer_plan.rs](../crates/borondns-server/src/transfer_plan.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/health_metrics.rs](../crates/borondns-server/src/health_metrics.rs)

Tests and supporting documentation:

- [crates/borondns-server/src/tests/catalog_and_plan.rs](../crates/borondns-server/src/tests/catalog_and_plan.rs)
- [docs/catalog-zone-rfc9432.md](catalog-zone-rfc9432.md)
- [scripts/interop-bind-catalog-zone-docker.sh](../scripts/interop-bind-catalog-zone-docker.sh)
- [scripts/interop-powerdns-postgres-catalog-tsig-docker.sh](../scripts/interop-powerdns-postgres-catalog-tsig-docker.sh)
- [scripts/interop-bind-xot-catalog-zone-docker.sh](../scripts/interop-bind-xot-catalog-zone-docker.sh)

</details>

### EDNS response behavior

The query path owns OPT parsing and response emission for BADVERS, advertised UDP
ceilings, DO-bit copy semantics, NSID, TCP keepalive, unknown-option ignore, and
non-EDNS truncation behavior. Padding requests are recognised, but padding is never
emitted over plaintext UDP/TCP; the transport-gated composer can pad only encrypted
responses, and this release rejects nonzero padding configuration because it has no
encrypted client-query listener.

Limits: EDNS EXPIRE (RFC 7314), DNS Stateful Operations, encrypted client-query listeners,
recursive EDNS behavior, or transport protocols outside DNS over UDP/TCP.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-EDNS-001..017`

Source:

- [crates/borondns-core/src/dns.rs](../crates/borondns-core/src/dns.rs)
- [crates/borondns-core/src/config.rs](../crates/borondns-core/src/config.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)

Tests and supporting documentation:

- [crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs](../crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs)
- [scripts/interop-edns-behavior.sh](../scripts/interop-edns-behavior.sh)

</details>

### Bounded EDE diagnostics

Minimal EDE output is available for `Not Ready` and `Unsupported NSEC3 Iterations` only,
behind the configured EDE mode.

Limits: A full EDE catalogue, resolver-policy explanations, stale-answer diagnostics, filtering
diagnostics, or recursive validation errors.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-EDNS-018`; `BDS-IF-CONF-017`

Source:

- [crates/borondns-core/src/dns.rs](../crates/borondns-core/src/dns.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)

Tests and supporting documentation:

- [crates/borondns-core/src/dns_tests/any_negative_dnssec.rs](../crates/borondns-core/src/dns_tests/any_negative_dnssec.rs)
- [crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs](../crates/borondns-core/src/dns_tests/edns_dnssec_cookie.rs)
- [scripts/interop-dnssec-serve.sh](../scripts/interop-dnssec-serve.sh)
- [scripts/interop-dnssec-nsec3-serve.sh](../scripts/interop-dnssec-nsec3-serve.sh)
- [docs/dnssec-conformance-matrix.tsv](dnssec-conformance-matrix.tsv)

</details>

### Opt-in CHAOS self-identification

CH/TXT `version.bind.`, `version.server.`, `hostname.bind.`, and `id.server.` responses
are disabled by default and require explicit configured values or NSID fallback where
applicable.

Limits: Automatic host disclosure, arbitrary CHAOS namespaces, non-TXT CHAOS support, or
IN-class behavior changes.

<details>
<summary>Source, tests, and requirements</summary>

SRS: `BDS-FR-CHAS-001..006`; `BDS-IF-CONF-018`

Source:

- [crates/borondns-core/src/dns.rs](../crates/borondns-core/src/dns.rs)
- [crates/borondns-core/src/config.rs](../crates/borondns-core/src/config.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/health_metrics.rs](../crates/borondns-server/src/health_metrics.rs)

Tests and supporting documentation:

- [crates/borondns-core/src/dns_tests/message_parse_notify.rs](../crates/borondns-core/src/dns_tests/message_parse_notify.rs)
- [scripts/interop-chaos-queries.sh](../scripts/interop-chaos-queries.sh)

</details>


Release-specific results are recorded in the
[verification ledger](verification-ledger.md),
[traceability matrix](appendix-a-traceability-matrix.md), and
[acceptance register](release-acceptance-gap-register.md).

## Tools and Delivery

Packaging and test tools support deployment and verification. They do not
expand the BoronDNS server protocol surface: for example, BoronGen's generated
primary zones are test inputs, not a production primary-server mode.

### Release installer and Docker image archives

The release path can build an `x86_64-unknown-linux-musl` installer `.tar.xz`, verify
static linking for that default release target, produce raw static `borondns` and
XDP-enabled `boron-gun` binary assets, build Debian/Ubuntu `amd64` and
Fedora/RHEL-compatible `x86_64` packages, produce an Alpine-based Docker image archive
`.tar.xz`, generate CycloneDX SBOMs for the release binaries and Docker image, and
publish one authenticated checksum manifest with a keyless Sigstore bundle. Local
packaging scripts also write SHA-256 sidecars for direct checks.

Limits: A package repository, Docker registry publication, Kubernetes chart, multi-architecture
release matrix, or signed-release acceptance evidence. Dynamic-link packaging is allowed
only through an explicit non-release override and is not the portability artifact.

<details>
<summary>Source, tests, and requirements</summary>

Source:

- [scripts/package-installer.sh](../scripts/package-installer.sh)
- [scripts/package-deb.sh](../scripts/package-deb.sh)
- [scripts/package-rpm.sh](../scripts/package-rpm.sh)
- [scripts/package-docker-image.sh](../scripts/package-docker-image.sh)
- [scripts/package-sbom.sh](../scripts/package-sbom.sh)
- [.github/workflows/release-installer.yml](../.github/workflows/release-installer.yml)

Tests and supporting documentation:

- [scripts/test-installer-docker.sh](../scripts/test-installer-docker.sh)
- [scripts/test-deb-package-docker.sh](../scripts/test-deb-package-docker.sh)
- [scripts/test-rpm-package-docker.sh](../scripts/test-rpm-package-docker.sh)
- [scripts/test-docker-image.sh](../scripts/test-docker-image.sh)
- [docs/devops-getting-started.md](devops-getting-started.md)
- [docs/release-evidence-guide.md](release-evidence-guide.md)

</details>

### BoronDNS server AF_XDP backend

The official `borondns` release binary includes the feature-gated Linux AF_XDP
packet-I/O backend. It is within the shipped product scope as an experimental, opt-in
profile and activates only when `limits.udp_backend = "af_xdp"` and the required `[xdp]`
settings are supplied.

Limits: AF_XDP as the default or production-qualified packet-I/O path, automatic fallback from a
failed requested XDP mode, arbitrary runtime eBPF loading, or broad
physical-NIC/zero-copy compatibility. The standard UDP backend remains the supported
default.

<details>
<summary>Source, tests, and requirements</summary>

Source:

- [crates/borondns-server/src/af_xdp.rs](../crates/borondns-server/src/af_xdp.rs)
- [crates/borondns-server-ebpf/src/lib.rs](../crates/borondns-server-ebpf/src/lib.rs)
- [crates/borondns-server/src/udp.rs](../crates/borondns-server/src/udp.rs)
- [docs/unsafe-boundaries.tsv](unsafe-boundaries.tsv)

Tests and supporting documentation:

- Feature-gated server tests
- [scripts/borondns-af-xdp-veth-smoke.sh](../scripts/borondns-af-xdp-veth-smoke.sh)
- [docs/knot-comparison-benchmark.md](knot-comparison-benchmark.md)
- physical-NIC promotion evidence remains separate

</details>

### BoronGun load generator

The workspace includes a support-tool DNS load generator with a portable UDP backend and
an explicit Linux AF_XDP backend behind the `xdp` Cargo feature for lab hosts; the
release installer includes an XDP-enabled static `boron-gun` binary for lab evidence
runs.

Limits: A production traffic generator, DNS protocol conformance authority, automatic privileged
deployment, or evidence that the separate BoronDNS server AF_XDP backend is qualified on
untested hardware.

<details>
<summary>Source, tests, and requirements</summary>

Source:

- [crates/boron-gun/src/main.rs](../crates/boron-gun/src/main.rs)
- [crates/boron-gun/src/xdp_backend.rs](../crates/boron-gun/src/xdp_backend.rs)
- [docs/unsafe-boundaries.tsv](unsafe-boundaries.tsv)

Tests and supporting documentation:

- [docs/boron-gun.md](boron-gun.md)
- [scripts/boron-gun-self-test.sh](../scripts/boron-gun-self-test.sh)
- [scripts/boron-gun-xdp-veth-smoke.sh](../scripts/boron-gun-xdp-veth-smoke.sh)
- [crates/boron-gun/tests/cli.rs](../crates/boron-gun/tests/cli.rs)

</details>

### Benchmark and tuning harnesses

Local UDP/TCP DNS client benchmarks, large catalog-zone data generation, optional
query-pipeline timing metrics, and response-cache candidate counters exist for
evidence-driven tuning.

Limits: Formal Reference Hardware/Profile conformance, always-on high-cardinality metrics, a
response-cache backend, or proof of equivalence to NSD, Knot DNS, BIND, or another
authoritative server.

<details>
<summary>Source, tests, and requirements</summary>

Source:

- [scripts/benchmark-dns-clients.sh](../scripts/benchmark-dns-clients.sh)
- [scripts/benchmark-large-catalog-zones.sh](../scripts/benchmark-large-catalog-zones.sh)
- [crates/borondns-core/src/config.rs](../crates/borondns-core/src/config.rs)
- [crates/borondns-server/src/lib.rs](../crates/borondns-server/src/lib.rs)
- [crates/borondns-server/src/health_metrics.rs](../crates/borondns-server/src/health_metrics.rs)

Tests and supporting documentation:

- [docs/dns-client-benchmark.md](dns-client-benchmark.md)
- [docs/future-optimization-tracks.md](future-optimization-tracks.md)
- [scripts/capture-benchmark-handoff.sh](../scripts/capture-benchmark-handoff.sh)
- [scripts/check-perf-regression.py](../scripts/check-perf-regression.py)

</details>

### Supplemental interop harnesses

BIND packet-torture comparison and PowerDNS/PostgreSQL catalog-TSIG interop scripts
exercise broad record mixes, live catalog updates, TSIG-gated catalog transfer, and
retained packet captures.

Limits: Mandatory execution in every local check, a replacement for the formal NSD/Knot/BIND
release matrix, or a claim that PowerDNS is part of BDS-VER-003.

<details>
<summary>Source, tests, and requirements</summary>

Source:

- [scripts/interop-bind-packet-torture-docker.sh](../scripts/interop-bind-packet-torture-docker.sh)
- [scripts/interop-powerdns-postgres-catalog-tsig-docker.sh](../scripts/interop-powerdns-postgres-catalog-tsig-docker.sh)
- [docs/manual-bind-interop.md](manual-bind-interop.md)

Tests and supporting documentation:

- [docs/manual-bind-interop.md](manual-bind-interop.md)
- retained script artifact directories under `target/evidence/` when the scripts are run

</details>
