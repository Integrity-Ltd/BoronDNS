# OxideDNS Implementation Plan

This plan tracks the implementation path from the current Rust scaffold to the SRS milestones.

## Goal

Reach the SRS-defined MVP:

- all requirements in SRS sections 3 through 6 satisfied;
- interoperability with NSD, Knot DNS, and BIND 9 primaries;
- performance targets met;
- 30-day soak test completed without anomaly;
- parser fuzzing run for at least 24 hours per parser without findings;
- dependency security audit clean;
- SRS, Architecture Document, Test Plan, and Operator Deployment Guide complete;
- at least one production-representative external operator has independently deployed and validated the server.

## First Milestone: Alpha

The SRS Alpha gate is the practical route to MVP. Alpha requires:

- all architectural invariants;
- DNS core, query processing, negative responses, unknown RR handling, anti-spoofing, AXFR, NOTIFY, EDNS, TCP, RFC 1035 RR types plus AAAA, zone store, and zone state machine;
- a TSIG HMAC-SHA256 interop subset;
- network, configuration, logging, health, and signal interfaces;
- selected reliability, maintainability, portability, observability, and resource NFRs;
- interoperability with at least one of NSD, Knot DNS, or BIND 9 as primary.

Deferred from Alpha to MVP per SRS ODS-VER-007: IXFR, full TSIG, XoT, DNSSEC serving, RRL, expanded RR catalogue, performance NFR conformance, full security/maintainability verification, second and third primary interop.

## Implementation Slices

1. DNS wire core and UDP response loop.
   - Parse DNS headers and questions.
   - Discard sub-header datagrams and QR=1 messages.
   - Return NOTIMP for unsupported opcodes.
   - Return FORMERR for invalid question count or malformed QNAME.
   - Return REFUSED for unsupported classes and out-of-zone queries.
   - Preserve query ID, OPCODE, RD bit, and question bytes in responses.

2. In-memory zone data model.
   - Represent RRsets atomically by owner, class, and type.
   - Implement most-specific-zone lookup.
   - Support RFC 1035 RR types plus AAAA for Alpha.

3. Authoritative query answers.
   - Positive RRset answers.
   - NODATA and NXDOMAIN with SOA in authority.
   - Referral and glue handling.
   - Wildcard synthesis.

4. TCP query transport.
   - DNS-over-TCP framing.
   - Pipelined query handling.
   - Graceful connection limits and shutdown.

5. AXFR client and atomic publication.
   - TCP AXFR query construction.
   - Multi-message response reassembly.
   - SOA framing and validation.
   - Atomic zone replacement.

6. Zone state machine and NOTIFY.
   - Startup loading.
   - REFRESH, RETRY, EXPIRE timers.
   - NOTIFY validation, deduplication, and expedited refresh.

7. TSIG HMAC-SHA256 subset.
   - Static key config.
   - Outbound transfer signing.
   - Inbound response verification.

8. Health, metrics, packaging, and interop harness.
   - `/healthz`, `/readyz`, and `/metrics` endpoints.
   - Structured logs and basic counters.
   - Container packaging.
   - NSD/Knot/BIND fixture environments.

## Current Status

Slice 1 has a tested UDP query/response foundation:

- malformed datagrams and response packets are discarded or rejected as specified;
- unsupported opcodes return NOTIMP;
- malformed questions return FORMERR;
- unsupported classes and out-of-zone queries return REFUSED;
- QCLASS ANY matches served IN-class data;
- QTYPE ANY defaults to a deterministic minimal real-RRset response and can be configured to return the full owner RRset set;
- LOADING zones return SERVFAIL;
- active zones can return positive, NODATA, and NXDOMAIN responses with SOA authority data;
- SOA records placed in NODATA and NXDOMAIN authority sections use `min(SOA RRset TTL, SOA MINIMUM)`, while direct SOA answers preserve the stored RRset TTL;
- CNAME queries return CNAME RRsets directly;
- non-CNAME queries follow in-zone CNAME chains, retain constructed CNAME answers for negative terminal responses, stop when chains leave the served zone, and stop on loops or the configured chain limit;
- the CNAME chain limit is configurable under `[limits]`, defaults to 8, and loop/limit termination emits warning logs;
- direct DNAME queries return DNAME RRsets directly;
- queries below a DNAME owner include the DNAME RRset, synthesize the required CNAME, and continue resolution for positive, in-zone negative, and out-of-zone terminal targets;
- wildcard owner names are stored normally and applied at query time;
- wildcard positive responses synthesize the owner name to the QNAME;
- wildcard CNAME responses synthesize the owner name and continue CNAME resolution for positive, in-zone negative, and out-of-zone terminal targets;
- wildcard names without the requested QTYPE return NODATA with SOA authority;
- empty non-terminals return NODATA and do not expand higher wildcard owner names;
- delegated child-zone queries return referrals with AA cleared, NS RRsets in authority, and in-bailiwick A/AAAA glue in additional;
- direct queries for glue or other retained occluded data below a delegation cut return a referral rather than serving the occluded RRset as parent-zone authoritative data;
- answer-section NS RRsets include in-zone target A/AAAA RRsets in the additional section;
- DS queries at the delegation owner remain authoritative in the parent zone, returning either DS answers or NODATA with SOA authority;
- DS queries below a delegation owner return the normal referral;
- MX answers include in-zone exchange A/AAAA RRsets in the additional section and omit out-of-zone exchange targets;
- SRV answers include in-zone target A/AAAA RRsets in the additional section;
- NAPTR answers include in-zone replacement A/AAAA RRsets in the additional section;
- SVCB and HTTPS answers include in-zone TargetName A/AAAA RRsets in the additional section.

Slice 2 has an in-memory zone snapshot model with atomic publication through the shared `ZoneStore`.

Slice 5 is in progress:

- AXFR query construction is implemented only for TCP framing;
- runtime AXFR query IDs are drawn from the operating system CSPRNG and sample the full 16-bit QID space;
- AXFR response parsing validates QR, QID, OPCODE, RCODE, initial and terminating SOA, rejects answer records after the terminating SOA, normalizes permitted compressed RDATA names for SOA/NS/CNAME/PTR/MX while preserving unknown-type RDATA opaquely, and validates class, bailiwick, reserved RR types, prohibited pseudo-RR and transfer meta-types, fixed-length A/AAAA RDATA, DS/DNSKEY/NSEC3PARAM/TLSA fixed-prefix RDATA, HINFO/TXT/URI character-string RDATA, uncompressed post-RFC3597 embedded names for SRV/NAPTR/DNAME/RRSIG/NSEC/SVCB/HTTPS, NSEC/NSEC3 type bit-map framing, SVCB parameter framing and ordering, exactly one apex SOA in the final zone, presence of an apex NS RRset, CNAME coexistence restrictions with DNSSEC exceptions, and DNAME/CNAME non-coexistence;
- transferred RRsets with non-uniform member TTLs are published with the lowest TTL and emit a warning log recording the inconsistency;
- unknown RR types, including private-use types and zero-length RDATA, are preserved bit-for-bit through AXFR ingestion and emitted unchanged in query responses, without interpreting pointer-looking octets inside opaque RDATA;
- successful AXFR responses are converted into active zone snapshots with the SOA serial and REFRESH, RETRY, EXPIRE, and MINIMUM fields captured from the initial SOA record;
- the runtime performs AXFR over TCP from configured primaries in order and publishes the first successful snapshot atomically;
- initial LOADING-zone transfers run in the background after runtime services are bound, so health can report `starting` while first transfers are still in progress;
- initial LOADING-zone transfers are bounded by `[limits].max_concurrent_transfers`, defaulting to 4;
- failed initial transfers leave the zone in LOADING, so authoritative queries for that zone return SERVFAIL.

Slice 6 has a preliminary AXFR-backed zone state machine:

- successful initial and refresh transfers schedule the next refresh from the transferred SOA REFRESH field, subject to a 60-second minimum interval;
- failed refresh transfers schedule retry from the transferred SOA RETRY field where available;
- failed initial transfers for LOADING zones use exponential backoff starting at `[limits].zsm_initial_retry_secs`, defaulting to 60 seconds, and capped by `[limits].zsm_initial_retry_max_secs`, defaulting to 3600 seconds;
- `[limits].zsm_min_interval_secs` configures the 60-second minimum effective SOA REFRESH/RETRY interval;
- scheduled REFRESH, RETRY, and initial-load backoff intervals receive independently sampled ±10% jitter;
- the scheduler marks zones EXPIRED when elapsed time reaches the transferred SOA EXPIRE field; queries against EXPIRED zones return SERVFAIL through the normal non-ACTIVE zone path;
- due scheduled refreshes and accepted non-duplicate NOTIFY refreshes share the same transfer worker and atomic publication path;
- refresh transfers are bounded by `[limits].max_concurrent_transfers`, and AXFR/IXFR attempts share the same transfer pool;
- refresh attempts for zones with an existing serial perform a UDP SOA poll with strict QID, opcode, echoed-question, RCODE, class, owner, and serial parsing before transfer; if the primary serial is equal to or older than the held serial, the attempt is recorded as successful without transfer;
- outbound UDP SOA polls use a connected primary socket, ignore packets from unconnected peers, and warn on malformed or unexpected primary responses with zone, primary, QID, and validation-error evidence;
- when a refresh has existing zone data and a newer primary serial, the runtime constructs a TCP IXFR query with the currently held apex SOA in the authority section, applies IXFR Mode 1 incremental diffs with strict delete/add consistency checks, accepts IXFR Mode 2 AXFR-style fallback and Mode 3 current responses, and falls back to AXFR if IXFR is unsupported or incomplete.
- IXFR fault coverage rejects non-response messages, mismatched QIDs, unexpected opcodes, error RCODEs, missing initial SOAs, incomplete newer single-SOA responses, mismatched starting old-SOA serials, final SOA chain mismatches, absent-record deletions, already-present record additions, class mismatches, out-of-zone owners, reserved record types, prohibited pseudo-RR and transfer meta-types, invalid fixed-length A/AAAA RDATA, invalid DS/DNSKEY/NSEC3PARAM/TLSA fixed-prefix RDATA, invalid HINFO/TXT/URI character-string RDATA, invalid post-RFC3597 embedded-name RDATA, invalid NSEC/NSEC3 type bit-map RDATA, and final updated zones that violate apex SOA, apex NS, CNAME coexistence, or DNAME/CNAME coexistence requirements.
- primaries that return FORMERR or NOTIMP to IXFR are placed in a per-zone IXFR-disabled cooldown, configured by `[limits].ixfr_disabled_cooldown_secs` and defaulting to 3600 seconds, during which refresh attempts use AXFR for that primary.
- `scripts/interop-ixfr-notimp-fallback.sh` covers the external process path for initial AXFR, IXFR NOTIMP fallback to AXFR, and the next refresh using AXFR while IXFR cooldown is active.

Slice 4 is in progress:

- TCP listeners bind from static configuration;
- DNS-over-TCP messages use the two-octet length prefix;
- zero-length DNS-over-TCP frames close the connection and emit a warning log;
- back-to-back framed TCP queries on one connection receive independently framed responses matched by query ID;
- TCP query handling reuses the same authoritative response core as UDP;
- idle TCP connections close after the configured `[limits].tcp_idle_timeout_secs`, defaulting to 30 seconds;
- accepted TCP read and write operations use configurable `[limits].tcp_read_timeout_secs` and `[limits].tcp_write_timeout_secs`, each defaulting to 30 seconds;
- write-timeout behavior is covered by deterministic backpressure tests against an in-memory Tokio stream.
- accepted TCP connections are limited by configurable `[limits].max_tcp_connections`, defaulting to 1024; connections accepted over the cap are immediately closed and logged at warning level.
- SIGINT and SIGTERM initiate shutdown, abort listener tasks to stop accepting new DNS/health traffic, close the refresh queue, and wait up to `[limits].graceful_shutdown_secs`, defaulting to 30 seconds, for active TCP query connections and in-flight initial or refresh transfers to drain.
- runtime shutdown tests cover the draining health state while an initial transfer is blocked, and confirm the runtime exits after the transfer releases.
- process-level CLI smoke tests cover successful `oxidedns serve` shutdown on SIGINT and SIGTERM.

Slice 6 has initial NOTIFY intake foundations:

- NOTIFY response messages are discarded when QR=1 like other inbound responses;
- NOTIFY requests require QDCOUNT=1 and QTYPE=SOA, otherwise they receive FORMERR;
- NOTIFY requests for unconfigured zones or non-IN classes receive REFUSED;
- accepted NOTIFY requests receive a NOTIFY response with AA set and the question copied verbatim;
- embedded SOA records in NOTIFY answer sections are validated against the NOTIFY QNAME and QCLASS, and malformed or mismatched embedded SOAs receive FORMERR;
- runtime NOTIFY source authorization is derived from each zone's primaries plus `notify_sources`; unauthorized NOTIFY requests are silently discarded and logged at warning level.
- accepted NOTIFY requests call a refresh-signalling hook with the optional embedded SOA serial, and the runtime deduplicates per-zone refresh signals using `[limits].notify_dedup_secs`, defaulting to 1 second, while still responding to duplicate NOTIFY messages.
- non-duplicate accepted NOTIFY signals are queued for the transfer worker; if the embedded SOA serial is newer than the active zone serial, or no comparable serial is available, the worker attempts AXFR against configured primaries and publishes the first successful snapshot.

Slice 7 has TSIG HMAC-SHA foundations:

- TSIG keys are parsed from static configuration with absolute DNS key names, supported algorithm validation, base64 secret decoding, duplicate-key rejection, and zone-to-key reference validation;
- HMAC-MD5 TSIG keys are rejected during configuration validation;
- configured TSIG secrets are redacted from debug formatting and validation error messages;
- HMAC-SHA256 signing and constant-time MAC verification are implemented against an RFC 4231 test vector.
- HMAC-SHA1 signing and constant-time MAC verification are implemented against an RFC 2202 test vector.
- HMAC-SHA384 and HMAC-SHA512 signing and constant-time MAC verification are implemented against RFC 4231 test vectors.
- RFC 8945 request signing is implemented for HMAC-SHA256, including canonical TSIG variables, 48-bit Time Signed encoding, TSIG RR wire format, ARCOUNT incrementing, and placement as the last additional record;
- zones that reference a configured TSIG key sign outbound SOA poll, IXFR, and AXFR transfer queries.
- signed SOA poll responses are verified against the stored request MAC, TSIG key name and algorithm, MAC, and time fudge before the unsigned DNS response is parsed.
- signed TCP AXFR/IXFR response streams are verified before publication, including first-message request-MAC verification, subsequent running-MAC verification, terminal TSIG enforcement, the 99-message unsigned compatibility window, and non-decreasing TSIG times.
- zones that reference a configured TSIG key require incoming NOTIFY messages to carry a valid TSIG; verified NOTIFY requests are stripped before core processing and the NOTIFY response is signed with the verified request MAC.
- NOTIFY messages with embedded SOA records accept RFC-compliant compression in SOA MNAME/RNAME RDATA, matching BIND 9 NOTIFY behavior.

EDNS/query-size work is partially started:

- inbound OPT pseudo-RRs are parsed from the additional section;
- malformed EDNS option RDATA, duplicate OPT records, and misplaced OPT records return FORMERR;
- unsupported EDNS versions return BADVERS with a response OPT record;
- responses include OPT only when the request included OPT;
- EDNS TCP keepalive requests are recognized on TCP and the response advertises the configured TCP idle timeout in 100ms units; UDP keepalive requests are silently ignored;
- EDNS padding requests are recognized, and `[limits].edns_padding_block_size` controls default-off zero-padding of response OPT RDATA when the padded response fits the applicable UDP ceiling;
- UDP response truncation applies the lesser of the client-advertised EDNS payload and configured server maximum, defaulting to 1232.
- response OPT TTL handling clears the DNSSEC DO bit until DNSSEC augmentation records are actually included, and BADVERS responses preserve only the extended RCODE bits.
- truncated UDP responses recompute the response OPT DO bit from the DNSSEC augmentation records that remain after size-driven record removal.

DNSSEC work is partially started:

- DO=1 positive responses include stored RRSIG records covering RRsets placed in the response, and set the response OPT DO bit when those augmentation records are included.
- DO=1 referral responses include existing DS RRsets for signed child delegations, existing NSEC no-DS proofs for unsigned child delegations, include stored RRSIG records covering the referral NS, DS, and NSEC RRsets, and set the response OPT DO bit when those augmentation records are included.
- DO=1 NXDOMAIN responses include existing NSEC RRsets covering the queried owner name and the closest-encloser wildcard name, plus their stored covering RRSIGs, and set the response OPT DO bit when those augmentation records are included.
- DO=1 exact-name NODATA responses include an existing NSEC RRset at the queried owner name, plus its stored covering RRSIG, and set the response OPT DO bit when those augmentation records are included.
- DO=1 wildcard-synthesized positive responses include an existing NSEC RRset covering the queried owner name, plus its stored covering RRSIG, to prove the exact queried owner did not exist.
- explicit RRSIG, NSEC, and NSEC3 queries return the requested DNSSEC RRset even when DO=0, without treating the answer as DNSSEC augmentation for the response OPT DO bit.
- QTYPE ANY responses do not return RRSIG, NSEC, or NSEC3 RRsets as ordinary data when those types were not explicitly queried, preserving the non-DO DNSSEC augmentation boundary.
- direct DNSKEY and NSEC3PARAM queries preserve and serve unknown or private algorithm numbers opaquely.
- response header construction unconditionally clears AD and CD bits.
- inbound TSIG verification accepts RFC 8945/RFC 4635 legal truncated MACs down to half the algorithm output length, rejects below-minimum or overlong MACs with BADTRUNC classification, and outbound TSIG signing continues to emit full-length MACs.
- authorized NOTIFY messages missing required TSIG, or with BADKEY, BADSIG, BADALG, or BADTRUNC verification failures, receive NOTAUTH responses carrying zero-MAC TSIG error records; BADTIME failures receive signed NOTAUTH TSIG error records with server-time other data.

Slice 8 has health endpoint foundations:

- optional `[server].health` binds a separate plain HTTP/1 listener when configured, and opens no HTTP listener when unset;
- `GET /healthz` reports `ready` with HTTP 200 once at least one zone is ACTIVE, `starting` with HTTP 503 before readiness, and `draining` with HTTP 503 during graceful shutdown;
- `GET /readyz` reports HTTP 200 only when at least one zone is ACTIVE and the runtime is not draining, otherwise HTTP 503;
- `GET /metrics` exposes minimal Prometheus text gauges for configured and ACTIVE zones, per-zone LOADING/ACTIVE/EXPIRED state, held SOA serials, last successful refresh timestamp, next scheduled refresh timestamp, refresh failures since last success, query received totals, query RCODE totals, query truncation totals, CNAME chain limit and loop totals, per-zone query counts, AXFR/IXFR transfer-session started/completed/failed counters, NOTIFY receive/unauthorized/refresh-action counters, and authorized NOTIFY TSIG verification outcome counters;
- unknown paths return HTTP 404, and methods other than GET on configured endpoint paths return HTTP 405.
- CLI startup logging is initialized from static configuration after successful config parse: `[server].log_level` defaults to `info`, accepts the existing `tracing-subscriber` filter syntax, and may be overridden by `OXIDEDNS_LOG_LEVEL` or `RUST_LOG`;
- `[server].log_format` selects `json` or `plain`, defaults to `json`, rejects unknown values before runtime startup, and has focused unit coverage for default JSON, explicit plain, and invalid values;
- JSON logs include an RFC 3339 UTC timestamp, level, target, message, and structured event key-value fields; plain logs use the standard `tracing-subscriber` text formatter.

RRL foundations are started:

- RRL is enabled by default under process-wide `[rrl]` configuration, with configurable IPv4/IPv6 source prefix lengths, per-category rates, slip value, maximum tracked accounting keys, and allowlist entries;
- UDP query responses are accounted by `(source IP prefix, response category)` for positive, NXDOMAIN, NODATA, referral, and error buckets; TCP responses and non-query responses are not subject to this UDP RRL path;
- each accounting key uses a token bucket with capacity/refill equal to the configured per-second rate, applies the configured slip policy by dropping or emitting TC=1 empty-section responses that retain the question and OPT pseudo-RR, and evicts least-recently-used keys at the configured cap;
- `/metrics` exposes RRL subject, dropped, truncated, currently tracked key, and key-eviction counters.
- `scripts/interop-rrl-udp.sh` starts OxideDNS against a fake AXFR primary, drives repeated UDP positive, NXDOMAIN, NODATA, referral, and error responses through zero-rate RRL buckets, and verifies both dropped/truncated wire behavior and RRL metrics.

XoT foundations are started:

- legacy `primaries = ["addr"]` remains the plain TCP transfer shorthand for existing deployments and test harnesses;
- explicit `[[zones.transfer_primaries]]` entries can select `transport = "tcp"` or `transport = "xot"` per primary, and cannot be mixed with the legacy shorthand inside one zone;
- XoT transfer targets require SNI-style `server_name`, at least one configured trust anchor, and paired optional client certificate/key references;
- `oxidedns check-config` and runtime startup validate XoT TLS file readability, trust-anchor parseability, client certificate/key parseability, and client private-key file mode before listeners bind;
- runtime transfer planning preserves each target's transport mode and uses Rustls/Tokio-Rustls for XoT AXFR and IXFR TCP framing;
- XoT client connections load configured PEM trust anchors, send the configured server name as SNI, require ALPN `dot`, support optional client certificate/key material, and do not fall back to cleartext TCP after TLS failure;
- focused in-process tests cover successful XoT AXFR, XoT+TSIG AXFR, XoT mutual TLS with client certificate/key material, TLS-handshake failure without cleartext retry, certificate name mismatch before DNS query emission, missing ALPN `dot` before DNS query emission, and missing required client certificate before DNS query emission. Real-primary XoT interop and the remaining TLS fault matrix are still tracked toward MVP.
- `scripts/interop-knot-xot-docker.sh` covers a real Knot DNS XoT primary path with generated local CA/server certificates, ALPN `dot`, OxideDNS XoT transfer configuration, readiness, served data, and transfer metrics. Broader real-primary XoT matrix coverage remains pending.

Interop harness foundations:

- `scripts/interop-bind-axfr.sh` starts a local BIND 9 primary with the `alpha.test.` fixture, validates BIND SOA and AXFR service with `dig`, starts OxideDNS against that primary, waits for `/readyz`, and verifies UDP, TCP, CNAME-chain, and metrics behavior from the transferred zone.
- `scripts/interop-bind-tsig-axfr.sh` starts a BIND 9 primary whose AXFR is restricted to HMAC-SHA256 TSIG, proves unsigned AXFR is rejected and signed AXFR succeeds with `dig`, starts OxideDNS with the matching TSIG key, verifies readiness and served data after the signed transfer, and checks OxideDNS logs do not contain the shared secret.
- `scripts/interop-bind-notify-refresh.sh` starts a BIND 9 primary configured to send NOTIFY, updates the primary zone serial, observes the BIND-generated NOTIFY packet through a UDP forwarding probe, verifies that OxideDNS accepts the compressed embedded SOA, and confirms that OxideDNS refreshes and republishes the newer serial and data.
- `scripts/interop-bind-ixfr-refresh.sh` starts a BIND 9 primary with IXFR journals enabled, observes OxideDNS issuing an IXFR refresh through a transfer proxy, confirms BIND returns a true incremental IXFR response, and verifies OxideDNS publishes the newer serial and data with IXFR success metrics.
- `scripts/interop-nsd-axfr-docker.sh` starts NSD inside an Alpine Docker container with the `alpha.test.` fixture, validates NSD SOA and AXFR service with `dig`, starts OxideDNS against that primary, waits for `/readyz`, and verifies UDP, TCP, CNAME-chain, and metrics behavior from the transferred zone.
- `scripts/interop-nsd-tsig-axfr-docker.sh` starts NSD inside an Alpine Docker container with AXFR restricted to HMAC-SHA256 TSIG, proves unsigned AXFR is rejected and signed AXFR succeeds with `dig`, starts OxideDNS with the matching TSIG key, verifies readiness and served data after the signed transfer, and checks OxideDNS logs do not contain the shared secret.
- `scripts/interop-nsd-notify-refresh-docker.sh` starts NSD inside Docker, observes an NSD-generated NOTIFY through a forwarding probe, verifies OxideDNS accepts the NOTIFY response path, and confirms OxideDNS refreshes and republishes the newer serial and data.
- `scripts/interop-knot-axfr-docker.sh` starts Knot DNS inside an Alpine Docker container with the `alpha.test.` fixture, validates Knot SOA and AXFR service with `dig`, starts OxideDNS against that primary, waits for `/readyz`, and verifies UDP, TCP, CNAME-chain, and metrics behavior from the transferred zone.
- `scripts/interop-knot-tsig-axfr-docker.sh` starts Knot DNS with AXFR restricted to HMAC-SHA256 TSIG, proves unsigned AXFR is rejected and signed AXFR succeeds with `dig`, starts OxideDNS with the matching TSIG key, verifies readiness and served data after the signed transfer, and checks OxideDNS logs do not contain the shared secret.
- `scripts/interop-knot-notify-refresh-docker.sh` starts Knot DNS inside Docker, observes a Knot-generated NOTIFY through a forwarding probe, verifies OxideDNS accepts the NOTIFY response path, and confirms OxideDNS refreshes and republishes the newer serial and data.
- `scripts/interop-knot-xot-docker.sh` starts Knot DNS with an XoT listener, verifies ALPN `dot`, starts OxideDNS with `transport = "xot"` and a generated trust anchor, waits for `/readyz`, and verifies served data and transfer metrics from the transferred zone.
- `scripts/interop-rrl-udp.sh` starts a fake AXFR primary and verifies runtime UDP RRL drop/slip behavior for all response categories plus Prometheus RRL counters.

Fuzzing foundations:

- `fuzz/fuzz_targets/dns_datagram.rs` covers DNS header/question parsing and ordinary datagram response construction.
- `fuzz/fuzz_targets/transfer_stream.rs` covers AXFR and IXFR response-stream parsing from TCP-style length-prefixed chunks.
- `fuzz/fuzz_targets/tsig_message.rs` covers TSIG detection, MAC extraction, request/response verification, TSIG error responses, and TCP response-stream TSIG chaining.
- `fuzz/fuzz_targets/notify_edns_datagram.rs` covers NOTIFY request handling and EDNS OPT parsing against a populated `alpha.test.` zone.

Open near-term work:

- broaden IXFR fault and interop coverage, including real-primary fallback behavior where supported;
- add real-primary XoT interop and the remaining TLS fault matrix;
- add remaining parser fuzz targets and start collecting long-run evidence for MVP verification.
