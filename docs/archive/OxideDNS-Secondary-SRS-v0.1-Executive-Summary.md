# Executive Summary

## OxideDNS-Secondary — Software Requirements Specification v0.1

**Date:** 23 May 2026
**Companion to:** *OxideDNS-Secondary Software Requirements Specification*, v0.1 (Draft 1)
**Project Documents:** PID v0.1 (May 2026); SRS v0.1 (May 2026)

---

## 1. Document Purpose

This Executive Summary accompanies the *OxideDNS-Secondary Software Requirements Specification* (SRS) v0.1. It is intended for the project sponsor, reviewers, and senior stakeholders who require a concise overview of what the SRS specifies, the scope and posture it establishes, and the principal decisions that the SRS surfaces for confirmation. It does not replace the SRS; details, normative requirement statements, and verification specifications are in the SRS body and its four appendices.

The SRS itself is approximately 308 KB of structured Markdown, comprising seven numbered sections plus four appendices, with 318 numbered requirement statements across six identifier categories.

## 2. Project Overview

OxideDNS-Secondary is a minimal, standards-compliant, secondary-only authoritative DNS server, written in Rust. Its purpose is to receive zone data from one or more configured primary DNS servers via standard zone transfer protocols (AXFR and IXFR), hold that data entirely in memory, and serve authoritative responses to DNS queries from clients over UDP and TCP — including authenticated and encrypted transfers (TSIG and DNS-over-TLS for transfers), DNSSEC record serving, and operationally mature anti-abuse mechanisms such as Response Rate Limiting.

The server is designed for production deployment in environments that operate large secondary fleets — DNS hosting providers, content delivery networks, registries, and anycast infrastructure — and is intended to be interoperable with arbitrary primary implementations (NSD, Knot DNS, BIND 9, and others) without requiring vendor-specific extensions.

## 3. Strategic Rationale

Three considerations motivate this project, expanding on the PID's strategic intent:

**Security through minimal attack surface.** A secondary-only design eliminates entire categories of functionality (zone authoring, dynamic update, recursion, key management, on-the-fly signing) and their associated code, configuration, and operational complexity. The resulting attack surface is substantially smaller than that of full-featured DNS servers, and the implementation in Rust's safe subset eliminates the classes of memory-safety defect that have historically produced critical-severity advisories in C-based DNS infrastructure.

**Operational fit with modern deployment patterns.** The server is designed for container-native deployment: no persistent state, no runtime configuration reload, no administrative interface, no filesystem writes beyond standard output. Configuration changes are applied by process restart in standard rolling-deployment patterns. The published container image is targeted at under 20 MB; integration points (Prometheus metrics, structured logs, HTTP health probes) align with the dominant operational ecosystem.

**Reduced cognitive footprint.** The project targets a total Rust codebase of 5,000 to 15,000 lines. This is aggressive scoping and is intended to be auditable in finite time by a single reviewer. The discipline is enforced by an explicit catalogue of prohibited functionality (17 negative requirements in SRS §4.18) and by foundational architectural invariants (six in SRS §3) that constrain the design space.

## 4. Architectural Posture

The SRS establishes six architectural invariants — properties the system must hold at all times during operation, distinct from the behaviours it performs. These constrain every functional and non-functional requirement and represent the design's foundational commitments:

The server is **secondary-only**: zone data is acquired exclusively through authenticated zone transfer from configured primaries (ODS-INV-001). All zone data is **memory-resident**; the query-serving path performs no disk I/O (ODS-INV-002). Zone refresh is **atomic**: every query is answered from a single internally consistent zone version (ODS-INV-003). The server holds **no persistent operational state**; every process start is a cold start (ODS-INV-004). Configuration is **static** for the process lifetime; changes are applied only by restart (ODS-INV-005). The implementation uses **Rust's safe subset** for all network-input processing, with `unsafe` blocks confined to documented and justified exceptions (ODS-INV-006).

These invariants are not behaviour to be performed but constraints on the space of possible behaviours. They are the SRS's primary commitment, and the rest of the document — 244 functional requirements, 36 non-functional requirements, 23 interface requirements — describes how the system operates within the envelope they define.

## 5. Functional Scope

The server's functional behaviour spans seventeen subsections of the SRS (§4.1 through §4.17), grouped into the following operational areas:

**DNS protocol and query handling.** Core DNS message parsing, authoritative lookup, response composition, name-compression handling, RFC-conformant CNAME and DNAME chain resolution, wildcard synthesis, and correct construction of negative responses (NXDOMAIN, NODATA) including the RFC 8020 NXDOMAIN-cut semantic and RFC 2308 negative-response TTL handling.

**Zone transfer.** Full zone transfer (AXFR, RFC 5936) and incremental zone transfer (IXFR, RFC 1995) as a client, with multi-primary failover, configurable concurrent-transfer limits, and IXFR-to-AXFR fallback. NOTIFY message receipt (RFC 1996) with source authorisation and TSIG verification, triggering expedited refresh checks through the zone state machine.

**Authentication and encryption.** TSIG authentication (RFC 8945) of zone transfers and NOTIFY messages, with mandatory HMAC-SHA256 and HMAC-SHA1 support, SHA-384/512 as SHOULD, and explicit prohibition of HMAC-MD5. Zone transfer over TLS (XoT, RFC 9103) for confidentiality of zone-transfer traffic, outbound-only, in the Strict Profile with mandatory PKIX certificate validation.

**Protocol extensions and transport.** EDNS0 (RFC 6891) including the TCP keepalive (RFC 7828) and padding (RFC 7830) options. TCP transport per RFC 7766 with connection persistence, query pipelining, and configurable idle timeouts. UDP payload size negotiation with the DNS Flag Day 2020 default of 1232 octets.

**DNSSEC.** Serving of DNSSEC records (DNSKEY, RRSIG, NSEC, NSEC3, DS, NSEC3PARAM) faithfully as received from the primary. The server does not sign and does not validate; the AD bit is set to zero unconditionally.

**Operational mechanisms.** A three-state zone lifecycle (LOADING, ACTIVE, EXPIRED), a zone state machine implementing SOA REFRESH/RETRY/EXPIRE timing with jitter and minimum-interval enforcement, and Response Rate Limiting (Vixie/Schryver design) for amplification-attack mitigation.

## 6. Non-Functional Commitments

The SRS specifies 36 non-functional requirements across seven categories. The principal commitments are:

**Performance.** Sustained throughput of at least 50,000 queries per second per CPU core under nominal workload; P99 query latency below 1 millisecond at 50% capacity and below 10 milliseconds at 90% capacity; AXFR ingestion of at least 100,000 records per second; process startup under 1 second.

**Resource bounds.** Container image at most 20 MB uncompressed; per-record memory overhead below 500 bytes; support for at least 10,000 zones totalling 10 million records on a 16 GiB host.

**Reliability.** Graceful shutdown with configurable grace period (default 30 seconds); bounded memory consumption over 30+ day continuous operation without leaks; clean restart from cold state with no persistent state to corrupt.

**Security.** Rust safe-subset discipline for all network input processing; continuous coverage-guided fuzz testing of wire-format parsers; no cryptographic key material in logs or error messages; non-root execution under operating-system capabilities or socket activation.

**Portability.** Linux (Ubuntu, Debian, RHEL, Alpine); x86_64 and aarch64 architectures; IPv4 and IPv6 supported equivalently; OCI-compatible container runtimes; agnostic to specific init system or distribution layout.

**Observability.** Structured JSON or logfmt logs to standard streams; Prometheus/OpenMetrics-compatible metrics endpoint; Kubernetes-friendly `/healthz` and `/readyz` probes; per-zone status visibility (state, serial, refresh timing, query counts).

**Maintainability.** Source line count target of 5,000–15,000 (a SHOULD with documented justified exceptions); modular organisation mappable to the SRS subsections; reproducible builds; in-code references to requirement identifiers.

## 7. Out-of-Scope Boundaries

The SRS draws explicit boundaries through 17 negative requirements (§4.18) and a comprehensive Appendix C catalogue. The boundaries are of two kinds.

**Foundational exclusions** — items whose inclusion would redefine the project's identity. These cannot be brought into scope without architectural revision. They include all primary-role functions (zone authoring, DNS UPDATE, online DNSSEC signing, NOTIFY origination, outbound AXFR/IXFR serving, master-file reading), all resolver-role functions (recursive resolution, query forwarding, DNSSEC validation for clients), and the persistence and runtime-configuration mechanisms that would violate the cold-start and static-configuration invariants.

**Current-scope exclusions** — items deliberately left out of this version for reasons of complexity or focus, but which could be added in a future version without invariant violation. Notable items include DNS Cookies (RFC 7873), EDNS Client Subnet (RFC 7871), DNS-over-TLS / DoH / DoQ for client queries, NOTIFY-over-TLS reception, DNS Catalog Zones (RFC 9432), per-zone Response Rate Limiting, view / split-horizon configurations, and operator-facing administrative tools.

The most operationally significant omission from the current scope is **DNS Cookies (RFC 7873)**, which is widely deployed in production DNS infrastructure and provides effective lightweight anti-spoofing. Its absence is conspicuous and should be considered an explicit project decision rather than an implicit endorsement.

## 8. Verification and Acceptance

The SRS specifies verification through ten methods: inspection, unit test, integration test, conformance test, interoperability test, fuzz test, performance test, soak test, operational test, and external operator acceptance. Each requirement's *Verification* field identifies the applicable method(s).

**Interoperability testing** is mandated against three production DNS implementations as primaries: NSD (NLnet Labs), Knot DNS (CZ.NIC), and BIND 9 (ISC). The test matrix covers AXFR initial load and refresh, IXFR incremental refresh including AXFR fallback, NOTIFY-triggered refresh, TSIG-authenticated transfers, and XoT-secured transfers. Test zones span small (under 1,000 records), medium (10,000–100,000), large (over 1,000,000), and DNSSEC-signed variants using both NSEC and NSEC3.

The project has two acceptance milestones, defined in terms of SRS requirement coverage:

The **Alpha milestone** is achieved when basic end-to-end secondary operation is demonstrated: all architectural invariants hold, core query handling and AXFR-based zone transfer are functional, basic TSIG authentication is operational, NOTIFY reception triggers refresh, and interoperability against at least one of {NSD, Knot, BIND} is demonstrated. IXFR, full TSIG algorithm support, XoT, DNSSEC serving, RRL, and the expanded RR catalogue are deferred from Alpha to MVP.

The **MVP milestone** is achieved when all 318 requirements of the SRS are demonstrably satisfied, interoperability against all three primaries is established, all performance targets are met, a 30-day soak test is completed without anomaly, fuzz testing has run for at least 24 hours per parser without finding, the dependency security audit is clean, all documentation is complete, and at least one production-representative external operator has independently deployed and validated the server.

## 9. Decision Points Awaiting Confirmation

The SRS surfaces 20 specific items for explicit project decision, catalogued in Appendix C.5 as a consolidated decision queue. These are items where the SRS has made a defensible choice but where the decision merits review rather than implicit acceptance. The most consequential are:

- Whether to bring **DNS Cookies (RFC 7873)** into scope (recommended).
- Whether the Verification category prefix (VER) should be formally added to §1.4.3 (cleanup item).
- Confirmation of the **Alpha milestone deferral set** — that IXFR, DNSSEC, XoT, and RRL are appropriately deferred to MVP.
- Confirmation of major **operational defaults**: 1232-octet UDP maximum, 30-second TCP idle timeout, 4 concurrent transfer sessions, RRL slip = 2, 60-second initial-load retry, JSON as default log format, TOML as configuration format.
- Whether **non-root execution** should be strengthened from SHOULD to MUST in the security section.
- Whether **PowerDNS Authoritative** should be added to the mandatory interoperability matrix.

The full table is in SRS Appendix C.5. Each decision is recorded for traceability and forms the project's design-time audit trail.

## 10. Risks and Dependencies

The principal risks to the project's success are:

**Performance target risk.** The 50,000 qps per core target is aspirational and depends on architectural choices (lookup data structure, concurrency model) that are deferred to the Architecture Document. The target should be revisited against benchmark results during implementation.

**Codebase size discipline.** The 5,000–15,000 line target is the project's enforcement mechanism for scope discipline. Pressure to add functionality during development is the primary risk to this target; the explicit Appendix C boundary and the negative requirements of §4.18 are the structural mitigations.

**Dependency security.** The implementation will depend on upstream Rust crates for cryptography, TLS, and ancillary functions. Crate selection, version pinning, and ongoing security-advisory tracking are critical and are recorded in the Architecture Document and the security NFRs.

**Interoperability discovery risk.** The interop matrix specifies three primary implementations, but real-world primary configurations vary widely. Issues are most likely to be discovered during MVP-phase external operator testing.

The principal dependencies, all the operator's or supplier's responsibility rather than the project's, include: reachable primary DNS servers for each configured zone; secure out-of-band provisioning of TSIG keys and XoT certificates; system time synchronised within TSIG's fudge window (default 300 seconds); adequate host memory for the configured zones.

## 11. Document Statistics

The SRS in its v0.1 form comprises:

| Element | Count |
|---|---|
| Major sections | 7 (Introduction, Overall Description, Architectural Invariants, Functional Requirements, Non-Functional Requirements, External Interfaces, Verification Strategy) |
| Appendices | 4 (Traceability Matrix, RR Type Catalogue, Out-of-Scope Items, Glossary) |
| Architectural invariants | 6 |
| Functional requirements (FR) | 244, in 17 area-coded subsections |
| Non-functional requirements (NFR) | 36, in 7 area-coded subsections |
| Interface requirements (IF) | 23, in 5 area-coded subsections |
| Negative requirements (NEG) | 17 |
| Verification requirements (VER) | 9 |
| RFCs catalogued in traceability index | 30+ |
| Resource record types in known catalogue | 22 plus 3 pseudo-RRs |
| Items flagged for project decision | 20 |
| Document size | ~308 KB (3,791 lines of Markdown) |

## 12. Next Steps

Following review and approval of this SRS v0.1, the project's planned next activities are:

1. **Decision-queue resolution.** The 20 items in Appendix C.5 should be reviewed and decisions recorded. Any decisions altering normative content trigger an SRS revision to v0.2.

2. **Architecture Document.** A sibling document to the SRS, specifying the implementation choices (concurrency model, zone-store data structure, dependency selection, module organisation) that satisfy the SRS requirements. This document is the implementer's primary working reference.

3. **Test Plan.** A sibling document specifying concrete test cases derived from the SRS *Verification* fields. The Test Plan's cases reference SRS requirement identifiers, completing the bidirectional traceability through Appendix A.

4. **Implementation Phase 1 — Alpha.** Implementation against the Alpha milestone criteria of SRS ODS-VER-007, leading to first interop demonstration against a single primary.

5. **Implementation Phase 2 — MVP.** Implementation of the deferred features (IXFR, XoT, DNSSEC, RRL, full TSIG, expanded RR catalogue) and execution of the comprehensive MVP acceptance per SRS ODS-VER-008.

6. **External Operator Acceptance.** Independent deployment and validation by at least one production-representative external operator, as a hard MVP gate per SRS ODS-VER-008.

---

*For requirement-level detail, normative statements, RFC traceability, and the comprehensive design boundary catalogue, refer to the SRS document directly. This Executive Summary is informative; the SRS is the normative project commitment.*
