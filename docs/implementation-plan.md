# OxideDNS Implementation Plan

This plan tracks the path from the current Rust project to a working
secondary-authoritative DNS server while preserving traceability to Tibor's SRS
v0.7.

The SRS-defined "MVP" in ODS-VER-008 is not the first useful engineering
milestone. It is a full acceptance/compliance gate: all SRS requirements,
three-primary interoperability, performance evidence, a 30-day soak, 24-hour
fuzz campaigns per parser, complete documentation, and external operator
acceptance. This plan therefore uses two targets:

- **Engineering MVP**: the first deployable and reviewable secondary DNS server
  that exercises the core operational path with retained evidence.
- **SRS acceptance**: the later ODS-VER-008 compliance gate.

## Engineering MVP Target

The near-term implementation target is now aligned to the SRS v0.7 Alpha gate
plus already-started MVP protocol work:

- static TOML configuration with no runtime reload;
- secondary-only operation from configured primaries;
- memory-resident zone snapshots with atomic publication;
- UDP and TCP authoritative serving for active zones;
- AXFR initial load and refresh, with IXFR attempted where existing zone state
  permits it and AXFR fallback retained;
- authorized NOTIFY-triggered refresh;
- TSIG HMAC-SHA256 for transfer, NOTIFY, and ordinary signed-query handling;
- EDNS support including NSID request/response behavior;
- SRS v0.7 architectural invariants INV-001 through INV-009, including
  authoritative-only response composition, single-process operation, and no
  runtime code loading;
- SRS v0.7 Alpha interface surface: static configuration including validation
  and dump modes, canonical structured logging, process exit/help/version
  behavior, health/metrics, and graceful shutdown;
- health, readiness, metrics, long-LOADING zone warnings, structured logs, and
  graceful shutdown;
- safe-Rust, dependency-audit, parser-fuzz compile, and performance-smoke
  evidence commands retained in the repo;
- interoperability evidence against at least one real primary for AXFR, TSIG,
  and NOTIFY, with primary version/configuration evidence recorded for each
  real-primary run and the broader matrix tracked separately.

The Engineering MVP may include more than the Alpha subset where implementation
has already moved ahead, such as IXFR, XoT, DNSSEC serving of transferred data,
and RRL. Those features still need SRS acceptance evidence before they are
claimed complete.

## SRS Acceptance Target

The ODS-VER-008 acceptance target remains:

- all requirements in SRS sections 3 through 6 satisfied;
- interoperability with NSD, Knot DNS, and BIND 9 primaries;
- performance targets met;
- 30-day soak test completed without anomaly;
- parser fuzzing run for at least 24 hours per parser without findings;
- dependency security audit clean;
- vulnerability disclosure policy published;
- DNS Cookies, IXFR, full TSIG, XoT, DNSSEC serving, RRL, expanded RR catalogue,
  and all v0.7 interface/NFR additions fully implemented and verified;
- test coverage targets met;
- signed release artifacts produced;
- SRS, Architecture Document, Test Plan, and Operator Deployment Guide complete;
- at least one production-representative external operator has independently deployed and validated the server.

## SRS Alpha Reference

The SRS Alpha gate is the practical route to Engineering MVP. Alpha requires:

- all architectural invariants, including INV-007 through INV-009;
- DNS core, query processing, negative responses, unknown RR handling, anti-spoofing, AXFR, NOTIFY, EDNS including NSID, TCP, RFC 1035 RR types plus AAAA, zone store, and zone state machine;
- a TSIG HMAC-SHA256 interop subset;
- network, configuration, logging, health, signal, and process/CLI interfaces,
  including `--version`, `--help`, `--dump-config`, `--validate-config`, and
  the ODS-IF-PROC-001 exit-code convention;
- selected reliability, maintainability, portability, observability, and
  resource NFRs, including per-zone status metrics;
- interoperability with at least one of NSD, Knot DNS, or BIND 9 as primary,
  with the tested primary version recorded per `ODS-VER-013`.

Deferred from Alpha to SRS acceptance per SRS ODS-VER-007: IXFR, full TSIG,
XoT, DNSSEC serving, RRL, full DNS Cookies, expanded RR catalogue, `/livez` and
`/readyz` split conformance, health response-time and metrics rate-limit
requirements, performance NFR conformance, full security/maintainability
verification, reliability/resource/observability extensions, and second and
third primary interop.

`--example-config` is implemented and retained in release CLI evidence, but SRS
v0.7 makes ODS-IF-PROC-004 a MAY-level command. It is therefore useful for the
Engineering MVP workflow without being an Alpha or MVP acceptance blocker.

## Pending C.5 Decision Overlay

Appendix C.5 of SRS v0.7 still marks several defaults and policy choices as
pending confirmation. Implementation may follow the current SRS body defaults so
the server is testable, but release notes and acceptance review must not treat
those values as final project decisions until C.5 is resolved. The active overlay
includes health default port and metrics rate-limit defaults, log entry length,
configuration-warning catalogue contents, sysexits choices, external operator
acceptance, strict ANY default, transfer/session/concurrency defaults, SIGTERM
grace, clock-skew tolerances, histogram buckets, DNS Cookie default policy, NSID
default behavior, JSON-vs-logfmt default, TOML format, and multi-primary
randomized initial selection.

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
- DNS UPDATE opcode 5 returns NOTIMP without mutating the in-memory zone snapshot;
- malformed questions return FORMERR;
- unsupported classes and out-of-zone queries return REFUSED;
- QCLASS ANY matches served IN-class data;
- QTYPE ANY defaults to a deterministic minimal real-RRset response and can be configured to return the full owner RRset set;
- LOADING zones return SERVFAIL;
- active zones can return positive, NODATA, and NXDOMAIN responses with SOA authority data;
- SOA records placed in NODATA and NXDOMAIN authority sections use `min(SOA RRset TTL, SOA MINIMUM)`, while direct SOA answers preserve the stored RRset TTL;
- CNAME queries return CNAME RRsets directly;
- non-CNAME queries follow in-zone CNAME chains, retain constructed CNAME answers for negative terminal responses, stop when chains leave the served zone, and return authoritative SERVFAIL with the partial CNAME chain and empty authority section on loops or the configured chain limit;
- the CNAME chain limit is configurable under `[limits]`, defaults to 8, and loop/limit termination emits warning logs with the original QNAME, zone, and truncation reason or looping target;
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
- authoritative responses apply RFC 1035 name compression to answer, authority,
  and additional-section owner names, and to structurally valid embedded names
  for the currently encoded pre-RFC3597 name-bearing RDATA types NS, CNAME, PTR,
  SOA, and MX;
- parsed compressed QNAMEs are re-encoded in normal question-section wire form
  before response owner-name compression registers the echoed question name;
- response serialization preserves all other RDATA opaquely, including
  unknown-type RDATA with pointer-looking octets.

Slice 2 has an in-memory zone snapshot model with atomic publication through the shared `ZoneStore`.

Slice 5 is in progress:

- AXFR query construction is implemented only for TCP framing;
- runtime AXFR query IDs are drawn from the operating system CSPRNG and sample the full 16-bit QID space;
- AXFR response parsing validates QR, QID, OPCODE, RCODE, initial and terminating SOA, rejects answer records after the terminating SOA, normalizes permitted compressed RDATA names for SOA/NS/CNAME/PTR/MX while preserving unknown-type RDATA opaquely, and validates class, bailiwick, reserved RR types, prohibited pseudo-RR and transfer meta-types, fixed-length A/AAAA RDATA, DS/DNSKEY/NSEC3PARAM/TLSA fixed-prefix RDATA, HINFO/TXT/URI character-string RDATA, uncompressed post-RFC3597 embedded names for SRV/NAPTR/DNAME/RRSIG/NSEC/SVCB/HTTPS, NSEC/NSEC3 type bit-map framing including empty NSEC3 bitmaps emitted by Knot for empty non-terminals, SVCB parameter framing and ordering, exactly one apex SOA in the final zone, presence of an apex NS RRset, CNAME coexistence restrictions with DNSSEC exceptions, and DNAME/CNAME non-coexistence;
- transferred RRsets with non-uniform member TTLs are published with the lowest TTL and emit a warning log recording the inconsistency;
- unknown RR types, including private-use types and zero-length RDATA, are preserved bit-for-bit through AXFR ingestion and emitted unchanged in query responses, without interpreting pointer-looking octets inside opaque RDATA;
- successful AXFR responses are converted into active zone snapshots with the SOA serial and REFRESH, RETRY, EXPIRE, and MINIMUM fields captured from the initial SOA record;
- the runtime performs AXFR over TCP from configured primaries using a per-process randomized initial primary for each zone, then preserves a stable rotation across later attempts and publishes the first successful snapshot atomically;
- initial LOADING-zone transfers run in the background after runtime services are bound, so health can report `starting` while first transfers are still in progress;
- initial LOADING-zone transfers are bounded by `[limits].max_concurrent_transfers`, defaulting to 4;
- failed initial transfers leave the zone in LOADING, so authoritative queries for that zone return SERVFAIL.

Slice 6 has a preliminary AXFR-backed zone state machine:

- successful initial and refresh transfers schedule the next refresh from the transferred SOA REFRESH field, subject to configurable minimum and maximum effective intervals;
- failed refresh transfers schedule retry from the transferred SOA RETRY field where available;
- failed initial transfers for LOADING zones use exponential backoff starting at `[limits].zsm_initial_retry_secs`, defaulting to 60 seconds, and capped by `[limits].zsm_initial_retry_max_secs`, defaulting to 3600 seconds;
- zones remaining in LOADING emit repeated structured warning logs at `[limits].zsm_loading_warning_threshold_secs`, defaulting to 3600 seconds, with zone name, elapsed LOADING duration, latest transfer failure cause, and next retry timestamp;
- `[limits].zsm_min_interval_secs` configures the 60-second minimum effective SOA REFRESH/RETRY interval, and `[limits].zsm_max_interval_secs` configures the 86400-second maximum effective interval; original SOA timer values are preserved unchanged for serving;
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
- back-to-back framed TCP queries on one connection receive independently framed responses matched by query ID, delayed-first-response pipelining is covered by a deterministic runtime test, and accepted TCP queries are processed by per-connection in-flight tasks with serialized writes;
- TCP query handling reuses the same authoritative response core as UDP;
- idle TCP connections close after the configured `[limits].tcp_idle_timeout_secs`, defaulting to 30 seconds;
- accepted TCP read and write operations use configurable `[limits].tcp_read_timeout_secs` and `[limits].tcp_write_timeout_secs`, each defaulting to 30 seconds;
- write-timeout behavior is covered by deterministic backpressure tests against an in-memory Tokio stream;
- accepted TCP connections are limited by configurable `[limits].max_tcp_connections`, defaulting to 1024; connections accepted over the cap are immediately closed and logged at warning level;
- per-connection DNS-over-TCP in-flight queries are limited by `[limits].max_tcp_inflight_queries_per_connection`, defaulting to 64; when all per-connection permits are held, the read side stops reading new frames until a response is written or `[limits].tcp_inflight_limit_timeout_secs` elapses, defaulting to the TCP read timeout, after which the connection is closed with an info log.
- SIGINT and SIGTERM initiate shutdown, abort listener tasks to stop accepting new DNS/health traffic, close the refresh queue, and wait up to `[limits].graceful_shutdown_secs`, defaulting to 30 seconds, for active TCP query connections and in-flight initial or refresh transfers to drain.
- runtime shutdown tests cover the draining health state while an initial transfer is blocked, and confirm the runtime exits after the transfer releases.
- process-level CLI smoke tests cover successful `oxidedns serve` shutdown on SIGINT and SIGTERM.

Slice 6 has initial NOTIFY intake foundations:

- NOTIFY response messages are discarded when QR=1 like other inbound responses;
- NOTIFY requests require QDCOUNT=1 and QTYPE=SOA, otherwise they receive FORMERR;
- NOTIFY requests for unconfigured zones or non-IN classes receive REFUSED;
- accepted NOTIFY requests receive a NOTIFY response with AA set and the question copied verbatim;
- embedded SOA records in NOTIFY answer sections are validated against the NOTIFY QNAME and QCLASS, and malformed or mismatched embedded SOAs receive FORMERR;
- runtime NOTIFY source authorization is derived from each zone's primaries plus `notify_sources`; unauthorized NOTIFY requests are silently discarded, and unauthorized-source plus TSIG-failure warning logs are rate-limited per `(source /24 or /56 prefix, zone, category)` over `[limits].notify_log_rate_window_secs`, defaulting to 60 seconds.
- NOTIFY log-rate limiting emits the first warning in full, suppresses repeated warnings in the same window, and emits aggregate info summaries with suppressed unauthorized, suppressed TSIG-failure, total suppressed, and distinct source-prefix counts.
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
- ordinary UDP and TCP DNS queries bearing a configured TSIG key are verified and stripped before core answer construction, responses are signed with the verified request MAC, and valid TSIG-authenticated UDP query responses bypass RRL accounting.
- ordinary DNS queries bearing an unknown TSIG key return NOTAUTH; malformed, misplaced, or invalid TSIGs are handled before core answer construction.
- NOTIFY messages with embedded SOA records accept RFC-compliant compression in SOA MNAME/RNAME RDATA, matching BIND 9 NOTIFY behavior.

EDNS/query-size work is partially started:

- inbound OPT pseudo-RRs are parsed from the additional section;
- malformed EDNS option RDATA, duplicate OPT records, and misplaced OPT records return FORMERR;
- unsupported EDNS versions return BADVERS with a response OPT record;
- responses include OPT only when the request included OPT;
- EDNS TCP keepalive requests are recognized on TCP and the response advertises the configured TCP idle timeout in 100ms units; UDP keepalive requests are silently ignored;
- EDNS padding requests are recognized, and `[limits].edns_padding_block_size` controls default-off zero-padding of response OPT RDATA when the padded response fits the applicable UDP ceiling;
- UDP response truncation applies the lesser of the client-advertised EDNS payload and configured server maximum for EDNS clients, defaulting to 1232; non-EDNS UDP responses use the RFC 1035 512-octet ceiling and do not include response OPT.
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
- AXFR parsing accepts DS, DNSKEY, and RRSIG records with synthetic private/reserved algorithm numbers and preserves the transferred RDATA opaquely.
- NSEC3 denial proof augmentation supports transferred SHA-1 NSEC3 records for exact hash matches and covering hash ranges without generating or validating DNSSEC material.
- `scripts/audit-dnssec-passive.sh` records static evidence that the first-party runtime only parses transferred DNSSEC RDATA and selects stored DNSSEC RRsets for serving, with no DNSSEC signing, signature validation, key-management, RFC 5011 rollover, or DNSSEC record-generation surface in production code.
- response header construction unconditionally clears AD and CD bits.
- inbound TSIG verification accepts RFC 8945/RFC 4635 legal truncated MACs down to half the algorithm output length, rejects below-minimum or overlong MACs with BADTRUNC classification, and outbound TSIG signing continues to emit full-length MACs.
- authorized NOTIFY messages missing required TSIG, or with BADKEY, BADSIG, BADALG, or BADTRUNC verification failures, receive NOTAUTH responses carrying zero-MAC TSIG error records; BADTIME failures receive signed NOTAUTH TSIG error records with server-time other data.

Slice 8 has health endpoint and SRS interface foundations:

- optional `[server].health` remains a compatibility health bind override; `[health].bind_address`/`bind_port` take precedence for the SRS explicit health bind, and `[interfaces].mgmt` activates health/metrics listeners at `[health].default_port` when no explicit override is configured;
- `[interfaces].dns` overrides legacy DNS listener lists and is used for both UDP and TCP DNS sockets, `[interfaces].notify` opens additional UDP and TCP listeners that reuse the normal DNS query/NOTIFY handlers, configuration validation rejects notify listeners that overlap effective DNS UDP or TCP listener sockets and rejects obsolete `interfaces.xot`, and `[interfaces].transfer` binds same-family outbound SOA poll, AXFR, IXFR, and XoT TCP sockets while preserving ephemeral source-port selection with port `0`;
- `GET /livez` reports JSON liveness with HTTP 200 whenever the process can answer the probe, including LOADING and draining states;
- `GET /readyz` reports JSON readiness with HTTP 200 only when at least one zone is ACTIVE and the runtime is not draining, otherwise HTTP 503 with `not-ready`, `draining`, or `unhealthy` status details;
- `GET /healthz` is a backward-compatible JSON readiness alias for `/readyz`;
- `GET /metrics` exposes minimal Prometheus text gauges for configured and ACTIVE zones; SRS-named per-zone state, LOADING duration seconds during current process uptime, held SOA serial, last successful refresh timestamp, next scheduled refresh timestamp, refresh failures since last success, per-zone query counts, and per-zone query RCODE counts; query received totals; global query RCODE totals; query truncation totals; CNAME chain limit and loop totals; AXFR/IXFR transfer-session started/completed/failed counters; NOTIFY receive/unauthorized/refresh-action counters; authorized NOTIFY TSIG verification outcome counters; global plus per-source-prefix DNS Cookie case/BADCOOKIE counters; suspicious configuration-warning count; the SRS `oxidedns_secondary_build_info` gauge; and the SRS `oxidedns_secondary_query_duration_seconds` histogram with default buckets and query-category labels;
- the zone state scheduler emits `category=transfer` / `event=zone_loading_threshold_exceeded` warning logs for zones that exceed the configured LOADING threshold and repeats them at the same interval until the zone leaves LOADING;
- `GET /metrics` emits gzip-compressed output with `Content-Encoding: gzip` and `Vary: accept-encoding` when the request allows `Accept-Encoding: gzip`;
- `GET /metrics` is rate limited per source IP by `[health].metrics_rate_limit_per_minute` and `[health].metrics_rate_limit_idle_seconds`, returning HTTP 429 with `Retry-After` and the SRS JSON body while leaving `/livez`, `/readyz`, and `/healthz` unbounded by the metrics limiter;
- unknown paths return JSON HTTP 404, and methods other than GET on configured endpoint paths return HTTP 405;
- focused tests cover `/livez` and `/readyz` responses within the SRS 100 ms health-probe bound under starting and draining states.
- `scripts/capture-health-metrics-evidence.sh` records release-retainable HTTP bodies, headers, curl timings, and a repeated over-limit scrape summary for `/livez`, `/readyz`, `/healthz`, gzip `/metrics`, and per-source `/metrics` rate limiting while confirming health probes remain available after the metrics limiter is hit.
- CLI config-loading paths emit pre-config JSON bootstrap logs for process start, configuration read, and validation success/failure before applying the configured log format and level;
- CLI startup logging is initialized from static configuration after successful config parse: `[server].log_level` defaults to `info`, accepts the existing `tracing-subscriber` filter syntax, and may be overridden by `OXIDEDNS_LOG_LEVEL` or `RUST_LOG`;
- `[server].log_format` selects `json`, `logfmt`, or the compatibility `plain` local-debug format, defaults to `json`, rejects unknown values before runtime startup, and has focused unit coverage for default JSON, explicit logfmt/plain, and invalid values. The `logfmt` selector emits parseable `key=value` records with canonical `timestamp`, `level`, `target`, `message`, and event fields; `plain` remains outside the final JSON/logfmt acceptance claim;
- logging output is level-routed through bounded writers: warning/error entries go to stderr, lower levels go to stdout, and `[logging].max_entry_length_bytes` defaults to 16384, rejects values too small to preserve a parseable truncated record, can be overridden with `ODS_LOGGING_MAX_ENTRY_LENGTH_BYTES`, and bounds JSON/logfmt/plain formatted log entries by replacing oversized events with a parseable structured truncation record containing `...<truncated>` and `truncated=true`;
- `ODS_<SECTION>_<KEY>` environment overrides cover the current scalar server/health/logging/limits/TSIG subset (`server.health`, log level/format, NSID, health metrics rate-limit knobs, `logging.max_entry_length_bytes`, `limits.max_transfer_ingest_bytes`, `limits.zsm_max_interval_secs`, `limits.zsm_loading_warning_threshold_secs`, and `tsig.fudge_seconds`), take precedence before runtime validation, are reflected by `--dump-config`, and emit non-fatal `configuration_warning` stderr messages for unrecognised `ODS_*` variables;
- the current suspicious-configuration warning catalogue covers DNS Cookies disabled, RRL allowlist entries `0.0.0.0/0` and `::/0`, TSIG fudge values above 60 seconds, TSIG keys using HMAC-SHA1, TCP idle timeouts above 120 seconds, AXFR/IXFR transfer ingestion caps below 100 MiB, XoT trust anchors expiring within 30 days, and transferred SOA REFRESH/RETRY values at or above 90% of `[limits].zsm_max_interval_secs`; warnings are non-fatal and use `category=configuration_warning`; static warnings are emitted by CLI validation/dump modes and as structured startup logs during `serve`, transferred-SOA warnings are emitted when zone snapshots are accepted, and the startup warning count is exposed by `oxidedns_secondary_configuration_warnings_total`;
- `[tsig].fudge_seconds` defaults to 300 seconds, is validated as non-zero, is exposed through `ODS_TSIG_FUDGE_SECONDS`, is reflected in `--dump-config`, and is used for TSIG-signed transfer queries plus NOTIFY TSIG responses and error responses;
- `[limits].max_transfer_ingest_bytes` defaults to 4 GiB, is validated as non-zero, is exposed through `ODS_LIMITS_MAX_TRANSFER_INGEST_BYTES`, is reflected in `--dump-config`, and aborts AXFR/IXFR sessions when cumulative received DNS transfer message payload octets exceed the configured cap before a new transfer snapshot is published;
- process exit-code mapping follows the SRS v0.7 table for tested CLI/config and runtime paths: usage errors exit 64, semantically invalid configuration and XoT runtime-configuration validation errors exit 2, unreadable/unparseable configuration exits 78, UDP/TCP/health bind failures and outbound transfer bind failures exit 73 (`EX_CANTCREAT`), unreadable XoT TLS files and transfer I/O failures exit 74 (`EX_IOERR`), OS startup failures such as signal setup, randomness, and file-descriptor inspection failures map to 71 (`EX_OSERR`), and protocol/runtime failures not classified under a more specific code default to 1 (`EX_GENERAL`);
- process startup installs explicit SIGHUP and SIGPIPE `SIG_IGN` dispositions before Tokio worker threads start; binary-level signal tests cover graceful SIGTERM/SIGINT exit, continued operation after SIGHUP, survival after stdout/stderr consumers close, Linux `/proc/<pid>/status` `SigIgn` evidence for SIGHUP and SIGPIPE, and `SigCgt` evidence that SIGHUP, SIGPIPE, SIGQUIT, SIGUSR1, and SIGUSR2 have no installed handlers;
- `scripts/capture-signal-evidence.sh` records release-retainable signal artifacts for SIGTERM, SIGINT, SIGHUP ignore behavior, closed stdout/stderr consumer survival, and Linux `/proc/<pid>/status` signal-disposition masks;
- `--version` and `-V` print multi-line SRS build metadata from the same embedded build constants used by `oxidedns_secondary_build_info`, including version, build commit, RFC 3339 build timestamp, and Rust compiler version; `--help` and `-h` print usage, flag descriptions, default configuration path, Operator Deployment Guide pointer, and project pointer; `--example-config` prints the checked-in example TOML without reading a configuration file and that output validates successfully through `--validate-config`;
- JSON logs include an RFC 3339 UTC timestamp, level, target, message, and structured event key-value fields; logfmt logs include the same canonical core fields as `key=value` pairs and preserve event fields; `scripts/capture-log-evidence.sh` captures representative JSON/logfmt runtime streams, running-service long-LOADING threshold warning records, and bounded logfmt truncation records for release review; plain logs use the standard `tracing-subscriber` text formatter and remain outside the final JSON/logfmt acceptance claim.

DNS Cookie foundations are started:

- DNS Cookies default to lenient RFC 9018 version-1 server-cookie behavior, can be disabled or made strict under `[cookie]`, and use a random 128-bit server secret generated at startup without disk persistence;
- `[cookie].secret_rotation_interval_secs` defaults to `0`, preserving the SRS default of one secret per process lifetime, and non-zero values enable in-process periodic regeneration with redacted fingerprint logs; a rotation invalidates cookies issued under the previous secret like a process restart, and the server continues with the prior secret if a rotation attempt cannot obtain fresh randomness;
- UDP and TCP query paths fetch the current in-memory cookie secret for each query, so rotated secrets apply consistently across ordinary DNS and NOTIFY-capable listener sockets.

RRL foundations are started:

- RRL is enabled by default under process-wide `[rrl]` configuration, with configurable IPv4/IPv6 source prefix lengths, per-category rates, slip value, maximum tracked accounting keys, and allowlist entries;
- UDP query responses are accounted by `(source IP prefix, response category)` for positive, NXDOMAIN, NODATA, referral, and error buckets; TCP responses, non-query responses, valid DNS Cookie responses, and valid TSIG-authenticated query responses are not subject to this UDP RRL path;
- each accounting key uses a token bucket with capacity/refill equal to the configured per-second rate, applies the configured slip policy by dropping or emitting TC=1 empty-section responses that retain the question and OPT pseudo-RR, and evicts least-recently-used keys at the configured cap;
- `/metrics` exposes RRL subject, dropped, truncated, currently tracked key, and key-eviction counters.
- RRL emits the required first rate-limit warning per accounting key and periodic aggregate info summaries at `[rrl].summary_log_interval_secs` intervals, defaulting to 60 seconds, with interval drop/truncation deltas and the current rate-limited key count.
- `scripts/interop-rrl-udp.sh` starts OxideDNS against a fake AXFR primary, drives repeated UDP positive, NXDOMAIN, NODATA, referral, and error responses through zero-rate RRL buckets, and verifies both dropped/truncated wire behavior and RRL metrics.
- `scripts/rrl-evidence-campaign.sh` runs the RRL UDP interop script repeatedly by iteration count or wall-clock duration, retains wrapper config, tool versions, git state, per-run command files, logs, and a summary under `target/rrl-evidence/<timestamp>/`, and fails the campaign on the first failed interop run.

XoT foundations are started:

- legacy `primaries = ["addr"]` remains the plain TCP transfer shorthand for existing deployments and test harnesses;
- explicit `[[zones.transfer_primaries]]` entries can select `transport = "tcp"` or `transport = "xot"` per primary, and cannot be mixed with the legacy shorthand inside one zone;
- XoT transfer targets require SNI-style `server_name`, at least one configured trust anchor, and paired optional client certificate/key references;
- `oxidedns check-config` and runtime startup validate XoT TLS file readability, trust-anchor parseability, client certificate/key parseability, and client private-key file mode before listeners bind;
- runtime transfer planning preserves each target's transport mode and uses Rustls/Tokio-Rustls for XoT AXFR and IXFR TCP framing;
- XoT client connections load configured PEM trust anchors, send the configured server name as SNI, require ALPN `dot`, support optional client certificate/key material, and do not fall back to cleartext TCP after TLS failure;
- XoT client sessions emit structured logs for TLS session establishment, handshake failure, ALPN failure, and session close; establishment logs include peer IP, SNI, negotiated TLS version, and cipher suite, while close logs include duration and byte counters without certificate, private-key, or TLS key material;
- XoT revocation posture follows SRS v0.7 `ODS-FR-XOT-012`: no real-time CRL or OCSP request is performed in the transfer hot path; `scripts/audit-xot-revocation.sh` records static evidence that first-party runtime code and the locked dependency set do not include OCSP/CRL fetch or standalone HTTP/TLS client surfaces for revocation checking;
- focused in-process tests cover successful XoT AXFR, XoT+TSIG AXFR, XoT mutual TLS with client certificate/key material, TLS-handshake failure without cleartext retry, certificate name mismatch before DNS query emission, untrusted server certificate before DNS query emission, expired server certificate before DNS query emission, missing ALPN `dot` before DNS query emission, and missing required client certificate before DNS query emission.
- focused log-inspection tests cover XoT TLS session establishment and close fields plus ALPN failure logging.
- `scripts/interop-knot-xot-docker.sh` covers a real Knot DNS XoT primary path with generated local CA/server certificates, ALPN `dot`, OxideDNS XoT transfer configuration, readiness, served data, and transfer metrics.
- `scripts/interop-knot-xot-tsig-docker.sh` covers a real Knot DNS XoT primary path with AXFR restricted to HMAC-SHA256 TSIG over TLS, proves unsigned XoT AXFR is rejected and signed XoT AXFR succeeds with `dig`, starts OxideDNS with matching XoT and TSIG configuration, verifies readiness, served data, transfer metrics, and no TSIG secret leakage.
- XoT TCP connection reuse is not claimed for Engineering MVP. SRS v0.7 `ODS-FR-XOT-009` is a MAY, and the current implementation establishes a fresh XoT session per transfer.
  Broader real-primary XoT matrix coverage beyond Knot remains pending.

Interop harness foundations:

- Real-primary interop scripts source `scripts/interop-version-evidence.sh` and
  emit `primary-version.txt` in their `target/interop/...` workdir. The artifact
  records test timestamp, primary implementation/version output, primary OS or
  container package context, configuration profile, transfer transport/security
  mode, and retained configuration artifact hashes. Evidence snapshot scripts
  copy new primary-version artifacts into `interop-primary-versions/` with an
  index. Skipped scripts do not count as successful `ODS-VER-013` evidence.
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
- `scripts/interop-knot-ixfr-refresh-docker.sh` starts Knot DNS with deterministic IXFR journal settings, verifies Knot exposes a true incremental IXFR after zone reload, routes OxideDNS transfer traffic through a classifier proxy, triggers OxideDNS refresh with NOTIFY, and verifies OxideDNS publishes the updated serial/data from a mode 1 IXFR response.
- `scripts/interop-knot-xot-docker.sh` starts Knot DNS with an XoT listener, verifies ALPN `dot`, starts OxideDNS with `transport = "xot"` and a generated trust anchor, waits for `/readyz`, and verifies served data and transfer metrics from the transferred zone.
- `scripts/interop-knot-xot-tsig-docker.sh` starts Knot DNS with an XoT listener and TSIG-restricted transfer ACL, verifies unsigned XoT AXFR rejection and signed XoT AXFR success, starts OxideDNS with `transport = "xot"` plus the matching TSIG key, and verifies served data, transfer metrics, and secret redaction.
- `scripts/interop-knot-dnssec-docker.sh` starts Knot DNS inside Docker with automatic ECDSAP256SHA256 NSEC3 signing, verifies primary AXFR carries DNSKEY, RRSIG, NSEC3, and NSEC3PARAM, then starts OxideDNS and verifies DO-sensitive positive, NXDOMAIN, NODATA, direct DNSKEY/NSEC3, non-DO suppression, and metrics behavior from the signed transfer, including an SRV fixture that makes Knot emit an empty-non-terminal NSEC3 record.
- `scripts/interop-rrl-udp.sh` starts a fake AXFR primary and verifies runtime UDP RRL drop/slip behavior for all response categories plus Prometheus RRL counters.
- `scripts/rrl-evidence-campaign.sh` wraps the RRL UDP interop script for repeated retained runs, with dry-run and list-config modes for reviewable campaign setup.
- `scripts/interop-dnssec-serve.sh` starts a fake AXFR primary carrying DNSKEY, RRSIG, NSEC, and large TXT records, verifies OxideDNS serves DO-sensitive positive and NXDOMAIN DNSSEC augmentation, serves direct DNSKEY queries, clears AD/CD, handles DNSSEC UDP truncation/response-DO semantics, and proves non-EDNS UDP truncation stays within 512 octets without adding a response OPT.
- `scripts/interop-dnssec-nsec3-serve.sh` starts a fake AXFR primary carrying DNSKEY, RRSIG, NSEC3, and NSEC3PARAM records, verifies direct NSEC3/NSEC3PARAM serving, and verifies DO-sensitive NXDOMAIN NSEC3 proof material with covering RRSIGs.
- `scripts/interop-negative-responses.sh` starts a fake AXFR primary with a representative unsigned zone, verifies retained runtime evidence for NXDOMAIN, NODATA, empty non-terminal, CNAME negative terminal, DNAME out-of-zone terminal, out-of-zone REFUSED, SOA negative TTL, and zone/global RCODE metrics, and can retain client, config, metrics, and log artifacts with `OXIDEDNS_NEGATIVE_RESPONSE_ARTIFACT_DIR`.
- `scripts/interop-tcp-truncation-retry.sh` starts a fake AXFR primary with a large A RRset and a question-section-preserving AXFR response, verifies a non-EDNS UDP query receives TC=1 at the 512-octet ceiling, verifies the same query over TCP receives the complete untruncated answer, verifies an over-limit TCP connection is closed with log evidence, verifies SIGTERM puts `/readyz` into draining while an accepted TCP query completes, and can retain client, metrics, config, timing summaries, readiness, and log artifacts with `OXIDEDNS_TCP_TRUNCATION_ARTIFACT_DIR`.

Non-functional evidence foundations:

- `scripts/perf-smoke.sh` starts a synthetic 1,000-record fake AXFR primary, measures startup-to-ready time after launching OxideDNS, confirms transfer metrics and SOA serial publication, and runs a small UDP direct-hit latency sample against the transferred zone. With `OXIDEDNS_PERF_SMOKE_METRICS_OUT`, it writes retained machine-readable smoke metrics for release snapshots; with `OXIDEDNS_PERF_SMOKE_ARTIFACT_DIR`, it retains raw `/metrics`, `/readyz`, OxideDNS, primary, and client artifacts including build-info and query-latency histogram evidence. This is a repeatable smoke harness for performance evidence collection, not final ODS-NFR-PERF conformance.
- `scripts/audit-invariants.sh` records repeatable static inspection evidence for the SRS v0.7 architectural invariants: secondary-only scope, memory-resident query path, atomic zone snapshot publication, no persistent operational writes, static configuration/control surface, first-party safe-Rust discipline, authoritative-only response composition, single-process operation, and static composition with no runtime code loading.
- `scripts/audit-readonly-runtime.sh` starts a fake AXFR primary, runs OxideDNS with a non-writable `TMPDIR`, waits for `/readyz`, verifies a UDP answer from the loaded zone, confirms zero child processes while recording thread count through `/proc`, and checks file-write intent when `strace` is available. With `OXIDEDNS_READONLY_RUNTIME_ARTIFACT_DIR`, it retains config, logs, metrics, process-status, client summary, and optional syscall trace artifacts.
- `scripts/audit-spoof-evidence.py` records repeatable static evidence for SRS v0.7 `ODS-FR-SPOOF-001..007`, including CSPRNG QID selection, kernel ephemeral UDP binding, concurrent SOA poll source-port uniqueness, connected UDP response source filtering, QID and question-section validation tests for SOA/AXFR/IXFR, and SOA poll warning-log evidence.
- `scripts/audit-log-fields.py` records repeatable static evidence for SRS v0.7 `ODS-IF-LOG-005` by rejecting legacy peer/failure-cause aliases and category values outside the canonical structured-log category set.
- `scripts/audit-log-lazy-formatting.py` records repeatable static evidence for SRS v0.7 `ODS-IF-LOG-008` by checking every first-party `debug!`/`trace!` emission site for eager `format!`, `format_args!`, `String::from`, `.to_string()`, or `.to_owned()` allocation patterns inside the lazy tracing macro arguments.
- `crates/oxidedns-core/src/dns.rs` test `concurrent_snapshot_replacement_answers_from_one_zone_version` stress-checks CNAME-chain query responses while `ZoneStore` swaps complete snapshots, proving observed answers come from one published zone version.
- `crates/oxidedns-core/src/dns.rs` test `answer_datagram_does_not_panic_for_malformed_corpus` runs a focused malformed packet corpus through the public datagram answering path under `catch_unwind`, covering short/random packets, malformed names, compression loops, bad section counts, malformed EDNS, response packets, and unsupported opcodes.
- `crates/oxidedns-core/src/dns.rs` NSID tests cover configured NSID EDNS option responses, default-empty suppression, and non-empty query OPTION-DATA treated as a request per SRS v0.7 `ODS-FR-EDNS-016..017`; `scripts/interop-dnssec-serve.sh` now exercises configured NSID responses over the running UDP server for empty and non-empty NSID request data. `non_edns_udp_response_over_512_octets_is_truncated_without_opt` covers the `ODS-FR-EDNS-015` no-OPT 512-octet ceiling path.
- `scripts/engineering-mvp-evidence.sh` captures the narrow Engineering MVP gate: repository checks, parser fuzz compile, invariant audit, read-only runtime audit, anti-spoofing evidence audit, canonical log-field audit, lazy log-formatting audit, performance smoke, TCP truncation retry evidence, and BIND AXFR, TSIG AXFR, and NOTIFY refresh interop logs under `target/evidence/engineering-mvp/<timestamp>/`.
- `scripts/release-evidence-snapshot.sh` captures release-review command logs, tool versions, git state, fuzz compile checks, cargo-deny output, read-only runtime artifacts, TCP truncation retry artifacts, and optional fuzz campaign and interop script output under `target/evidence/<timestamp>/`.
- `docs/test-plan.md` records the ODS-VER-011 Continuous/Periodic/Gate cadence mapping and the ODS-VER-012 regression policy; `scripts/check-test-plan.sh` keeps that structure in the continuous check. `scripts/check-perf-regression.py` compares retained smoke metrics with a rolling history when provided. Full weekly Reference Hardware/Profile benchmark baselines remain an SRS acceptance gap beyond the current performance smoke.
- `scripts/audit-safe-rust.sh` verifies the workspace `unsafe_code = "forbid"` lint and scans first-party Rust source for unsafe construct candidates, allowing only the audited POSIX signal-disposition and file-descriptor rlimit FFI modules.
- `scripts/audit-maintainability.sh` records the first-party Rust source line count and module map, and reports the current ODS-NFR-MAINT-001 line-count target status for release review.
- `scripts/audit-dnssec-passive.sh` records repeatable static evidence for SRS v0.7 `ODS-FR-DNSSEC-013`, and is included in `scripts/check.sh` plus release evidence snapshots.
- Runtime startup validates the SRS v0.7 file-descriptor rlimit formula for `ODS-NFR-RES-004`: `2 * (max_tcp_connections + max_concurrent_transfers + 100)`, and exits with an OS-startup error if the current soft `RLIMIT_NOFILE` is too low.
- `crates/oxidedns-server/build.rs` embeds build commit, Rust compiler version, and build timestamp labels for `oxidedns_secondary_build_info`; `[metrics].latency_histogram_buckets` configures the SRS v0.7 query latency histogram bucket boundaries with validation for positive finite strictly increasing seconds; `crates/oxidedns-server/src/lib.rs` metrics tests cover build-info exposition and latency histogram bucket/count/sum output using configured buckets.

Fuzzing foundations:

- `fuzz/fuzz_targets/dns_datagram.rs` covers DNS header/question parsing and ordinary datagram response construction.
- `fuzz/fuzz_targets/transfer_stream.rs` covers AXFR and IXFR response-stream parsing from TCP-style length-prefixed chunks.
- `fuzz/fuzz_targets/tsig_message.rs` covers TSIG detection, MAC extraction, request/response verification, TSIG error responses, and TCP response-stream TSIG chaining.
- `fuzz/fuzz_targets/notify_edns_datagram.rs` covers NOTIFY request handling and EDNS OPT parsing against a populated `alpha.test.` zone.
- `scripts/fuzz-campaign.sh` runs configurable short or long cargo-fuzz campaigns and retains target logs, artifacts, command lines, tool versions, and run configuration under `target/fuzz-evidence/<timestamp>/`.

Open near-term work:

- broaden IXFR fault and interop coverage beyond BIND and Knot true-incremental evidence;
- broaden real-primary XoT interop evidence;
- expand DNSSEC passive audit output into retained release traceability and broader conformance matrix entries;
- start collecting long-run performance, fuzz, interop, and soak evidence for SRS acceptance verification.
