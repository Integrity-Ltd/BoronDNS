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
   - `/healthz` endpoint.
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
- AXFR response parsing validates QID, OPCODE, RCODE, initial and terminating SOA, rejects answer records after the terminating SOA, and validates class, bailiwick, and reserved RR types;
- successful AXFR responses are converted into active zone snapshots with the SOA serial and REFRESH, RETRY, EXPIRE, and MINIMUM fields captured from the initial SOA record;
- the runtime performs AXFR over TCP from configured primaries in order and publishes the first successful snapshot atomically;
- failed initial transfers leave the zone in LOADING, so authoritative queries for that zone return SERVFAIL.

Slice 6 has a preliminary AXFR-backed zone state machine:

- successful initial and refresh transfers schedule the next refresh from the transferred SOA REFRESH field, subject to a 60-second minimum interval;
- failed refresh transfers schedule retry from the transferred SOA RETRY field where available;
- failed initial transfers for LOADING zones use exponential backoff starting at `[limits].zsm_initial_retry_secs`, defaulting to 60 seconds, and capped by `[limits].zsm_initial_retry_max_secs`, defaulting to 3600 seconds;
- `[limits].zsm_min_interval_secs` configures the 60-second minimum effective SOA REFRESH/RETRY interval;
- scheduled REFRESH, RETRY, and initial-load backoff intervals receive independently sampled ±10% jitter;
- the scheduler marks zones EXPIRED when elapsed time reaches the transferred SOA EXPIRE field; queries against EXPIRED zones return SERVFAIL through the normal non-ACTIVE zone path;
- due scheduled refreshes and accepted non-duplicate NOTIFY refreshes share the same transfer worker and atomic publication path.

Slice 4 is in progress:

- TCP listeners bind from static configuration;
- DNS-over-TCP messages use the two-octet length prefix;
- zero-length DNS-over-TCP frames close the connection and emit a warning log;
- back-to-back framed TCP queries on one connection receive independently framed responses matched by query ID;
- TCP query handling reuses the same authoritative response core as UDP;
- idle TCP connections close after the configured `[limits].tcp_idle_timeout_secs`, defaulting to 30 seconds;
- accepted TCP read and write operations use configurable `[limits].tcp_read_timeout_secs` and `[limits].tcp_write_timeout_secs`, each defaulting to 30 seconds.
- accepted TCP connections are limited by configurable `[limits].max_tcp_connections`, defaulting to 1024; connections accepted over the cap are immediately closed and logged at warning level.

Slice 6 has initial NOTIFY intake foundations:

- NOTIFY response messages are discarded when QR=1 like other inbound responses;
- NOTIFY requests require QDCOUNT=1 and QTYPE=SOA, otherwise they receive FORMERR;
- NOTIFY requests for unconfigured zones or non-IN classes receive REFUSED;
- accepted NOTIFY requests receive a NOTIFY response with AA set and the question copied verbatim;
- embedded SOA records in NOTIFY answer sections are validated against the NOTIFY QNAME and QCLASS, and malformed or mismatched embedded SOAs receive FORMERR;
- runtime NOTIFY source authorization is derived from each zone's primaries plus `notify_sources`; unauthorized NOTIFY requests are silently discarded and logged at warning level.
- accepted NOTIFY requests call a refresh-signalling hook with the optional embedded SOA serial, and the runtime deduplicates per-zone refresh signals using `[limits].notify_dedup_secs`, defaulting to 1 second, while still responding to duplicate NOTIFY messages.
- non-duplicate accepted NOTIFY signals are queued for the transfer worker; if the embedded SOA serial is newer than the active zone serial, or no comparable serial is available, the worker attempts AXFR against configured primaries and publishes the first successful snapshot.

EDNS/query-size work is partially started:

- inbound OPT pseudo-RRs are parsed from the additional section;
- malformed EDNS option RDATA, duplicate OPT records, and misplaced OPT records return FORMERR;
- unsupported EDNS versions return BADVERS with a response OPT record;
- responses include OPT only when the request included OPT;
- EDNS TCP keepalive requests are recognized on TCP and the response advertises the configured TCP idle timeout in 100ms units; UDP keepalive requests are silently ignored;
- EDNS padding requests are recognized, and `[limits].edns_padding_block_size` controls default-off zero-padding of response OPT RDATA when the padded response fits the applicable UDP ceiling;
- UDP response truncation applies the lesser of the client-advertised EDNS payload and configured server maximum, defaulting to 1232.

Open near-term work:

- TCP pipelining, graceful shutdown, and write-timeout backpressure tests;
- replacing the current AXFR-only scheduled refresh with the full ZSM refresh-check flow, including SOA poll and IXFR preference;
- TSIG HMAC-SHA256 signing and verification;
- DNSSEC-authenticated referral augmentation;
- interop fixture against at least one real primary implementation.
