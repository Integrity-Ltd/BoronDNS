# Software Requirements Specification

## OxideDNS-Secondary

**Document Version:** v0.1 (Draft 1)
**Date:** 23 May 2026
**Status:** Draft

---

### Document Control

| Field | Value |
|---|---|
| Project | OxideDNS-Secondary |
| Document | Software Requirements Specification (SRS) |
| Version | v0.1 |
| Date | 23 May 2026 |
| Author | DT (Architect, Lead Developer) |
| Reviewer | DTK (Sponsor, Reviewer) |
| Tester | SzI (Alpha Tester) |
| Related documents | PID v0.1 (May 2026); Architecture Document (forthcoming); Test Plan (forthcoming) |

### Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| v0.1 | 23 May 2026 | DT | Initial draft assembled from working sessions. |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Overall Description](#2-overall-description)
3. [Architectural Invariants](#3-architectural-invariants)
4. [Functional Requirements](#4-functional-requirements)
   - 4.1 DNS Protocol Core
   - 4.2 Query Processing
   - 4.3 Negative Responses
   - 4.4 Unknown RR Handling
   - 4.5 Anti-Spoofing Measures
   - 4.6 AXFR Zone Transfer Client
   - 4.7 IXFR Incremental Zone Transfer
   - 4.8 NOTIFY Handling
   - 4.9 TSIG Authentication
   - 4.10 Zone Transfer over TLS (XoT)
   - 4.11 EDNS0
   - 4.12 TCP Transport
   - 4.13 DNSSEC Record Serving
   - 4.14 RR Type Parsing and Serving
   - 4.15 In-Memory Zone Store
   - 4.16 Zone State Machine
   - 4.17 Response Rate Limiting
   - 4.18 Negative Requirements
5. [Non-Functional Requirements](#5-non-functional-requirements)
   - 5.1 Performance
   - 5.2 Reliability and Availability
   - 5.3 Security
   - 5.4 Maintainability
   - 5.5 Portability
   - 5.6 Observability
   - 5.7 Resource Limits
6. [External Interfaces](#6-external-interfaces)
   - 6.1 Network Interfaces
   - 6.2 Configuration Interface
   - 6.3 Logging Interface
   - 6.4 Health and Metrics Endpoint
   - 6.5 Process Signals
7. [Verification Strategy](#7-verification-strategy)
8. Appendix A — Requirement-to-RFC Traceability Matrix
9. Appendix B — Resource Record Type Catalogue
10. Appendix C — Out-of-Scope Items
11. Appendix D — Glossary

---

# 1. Introduction

## 1.1 Purpose

This Software Requirements Specification (SRS) defines the functional and non-functional requirements of OxideDNS-Secondary, a secondary-only authoritative DNS server written in Rust. It expands the RFC compliance target established in the Project Initiation Document (PID) into concrete, atomic, testable requirements suitable for implementation, review, and independent verification.

This document is the normative reference for what the software shall do, what it shall not do, and the criteria against which its correctness will be judged. It does not prescribe internal design or implementation choices; those are addressed by the Architecture Document, which is informed by this SRS but maintained separately.

## 1.2 Relationship to the Project Initiation Document

The PID (v0.1, May 2026) establishes the business case, scope boundaries, stakeholders, and high-level RFC compliance target. This SRS is subordinate to the PID. Where the two documents appear to conflict, the PID prevails for matters of scope and stakeholder assignment; this SRS prevails for technical and behavioural requirements. Any change to PID scope shall trigger a review of affected requirements herein.

Specifically:

- PID §3 (Scope) constrains the boundaries within which requirements may be defined.
- PID Appendix A (RFC Compliance Target) is the source from which the functional requirements in §4 are derived; Appendix A of this SRS provides clause-level traceability back to that list.
- PID §6 (Success Criteria) provides the acceptance thresholds against which the verification strategy in §7 is calibrated.

## 1.3 Intended Audience

This SRS is written for the project participants identified in PID §4 and, following open-source release, for external contributors:

- **DT** (Project Manager, Architect, Lead Developer) shall implement against these requirements.
- **DTK** (Sponsor, Reviewer) shall verify that the implementation satisfies these requirements and that the requirements themselves remain consistent with the PID and the underlying RFCs.
- **SzI** (Alpha Tester) and the DNS operations team (MVP testers) shall construct verification procedures from these requirements.
- Future external contributors shall use this document to understand the intended behaviour of the software and the boundaries of its scope.

## 1.4 Document Conventions

### 1.4.1 Normative Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in requirement statements are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals. Lowercase uses of these words carry no normative force.

Usage is further constrained as follows:

- **MUST** and **MUST NOT** are used only for requirements whose violation constitutes non-compliance with this SRS or with a referenced RFC.
- **SHOULD** and **SHOULD NOT** are used only where defensible deviations exist; each such requirement shall state, or reference, the conditions under which deviation is acceptable.
- **MAY** indicates a permitted but optional capability.

### 1.4.2 Atomicity of Requirements

Each requirement shall express a single, testable assertion. Compound requirements of the form "the server MUST do X and SHOULD do Y" shall be split into separate requirements, each with its own identifier. This rule is absolute.

### 1.4.3 Requirement Identifiers

Each requirement carries a stable identifier of the form

```
ODS-<CATEGORY>-<AREA>-<NNN>
```

where:

- **RDS** denotes OxideDNS-Secondary.
- **CATEGORY** is one of:
  - **FR** — Functional Requirement (defined in §4).
  - **NFR** — Non-Functional Requirement (defined in §5).
  - **IF** — External Interface Requirement (defined in §6).
  - **INV** — Architectural Invariant (defined in §3). The AREA component is omitted.
  - **NEG** — Negative (Prohibition) Requirement (defined in §4.18). The AREA component is omitted.
  - **VER** — Verification Requirement (defined in §7). The AREA component is omitted.
- **AREA** is a short uppercase mnemonic, 3 to 6 characters, identifying the protocol concern, non-functional concern, or interface (for example AXFR, TSIG, PERF, NET). Area codes are allocated centrally in Appendix D (Glossary) and shall not be reused for unrelated concerns.
- **NNN** is a zero-padded three-digit sequence number, unique within the (CATEGORY, AREA) namespace, starting at 001.

Examples:

- `ODS-FR-AXFR-014` — fourteenth functional requirement in the AXFR area.
- `ODS-NFR-PERF-003` — third non-functional requirement concerning performance.
- `ODS-IF-NET-001` — first network interface requirement.
- `ODS-INV-002` — second architectural invariant.
- `ODS-NEG-007` — seventh prohibition requirement.
- `ODS-VER-001` — first verification requirement.

### 1.4.4 Identifier Stability

Once allocated — including in draft revisions of this document — a requirement identifier shall never be reused, renumbered, or reassigned to a different requirement. If a requirement is removed, its identifier remains in place with status **Deprecated** and a brief rationale. If a requirement is replaced, its identifier remains in place with status **Replaced-by-X**, where X is the identifier of the replacement. This rule applies from the first numbered draft of this SRS onward.

### 1.4.5 Requirement Status

Each requirement carries a status of **Draft**, **Approved**, **Deprecated**, or **Replaced-by-X**. All requirements in this revision are **Draft** unless explicitly marked otherwise. Status transitions are recorded in the document revision history.

### 1.4.6 Cross-References

References to RFCs follow the form *RFC NNNN §S.S* where a specific clause is cited. References to requirements within this document follow the form of the identifier itself (`ODS-CAT-AREA-NNN`). References to PID sections follow the form *PID §N.N*. References to sections of this document follow the form *§N.N*.

## 1.5 Definitions, Acronyms, and Abbreviations

The following terms appear normatively throughout this document. A complete glossary, including all allocated area codes, appears in Appendix D.

| Term | Definition |
|---|---|
| Authoritative server | A DNS server holding authoritative data for one or more zones. |
| Primary | The authoritative server that holds the master copy of a zone, from which secondaries transfer. |
| Secondary | An authoritative server that receives zone data from a primary by zone transfer. The subject of this SRS. |
| AXFR | Full zone transfer (RFC 5936). |
| IXFR | Incremental zone transfer (RFC 1995). |
| NOTIFY | Zone change notification mechanism (RFC 1996). |
| TSIG | Secret Key Transaction Authentication (RFC 8945). |
| EDNS0 | Extension Mechanisms for DNS, version 0 (RFC 6891). |
| RRL | Response Rate Limiting. |
| XoT | DNS Zone Transfer over TLS (RFC 9103). |
| RR | Resource Record (RFC 1035). |
| RRset | The set of resource records sharing owner name, class, and type. |
| SOA | Start of Authority record. |
| Zone | A contiguous portion of the DNS namespace administered as a unit. |
| Zone refresh | The process by which a secondary updates its in-memory zone data from a primary. |
| PID | Project Initiation Document, v0.1, May 2026. |
| SRS | This document. |
| RDS | OxideDNS-Secondary. |

## 1.6 References

### 1.6.1 Project Documents

- **PID** — *OxideDNS-Secondary Project Initiation Document*, v0.1, May 2026.
- **Architecture Document** — *OxideDNS-Secondary Architecture Design* (to be produced in PID Phase 2; informed by this SRS).
- **Test Plan** — *OxideDNS-Secondary Test Plan* (to be produced alongside this SRS; verification procedures derive from §7).

### 1.6.2 Standards Governing This Document

- **BCP 14** — RFC 2119 (Bradner, 1997) and RFC 8174 (Leiba, 2017), "Key words for use in RFCs to Indicate Requirement Levels."

### 1.6.3 Normative RFC References

The set of RFCs constituting the compliance target for the software is listed in PID Appendix A and reproduced with clause-level traceability in Appendix A of this document. Individual RFCs are cited inline in the requirement sections from which they derive.

### 1.6.4 Informative References

Implementations, operational surveys, and guidance documents not formally required for compliance are listed in Appendix D.

---

# 2. Overall Description

## 2.1 Product Perspective

OxideDNS-Secondary is a standalone authoritative DNS server that operates exclusively in the secondary role. It is not a self-contained system: its operation depends on the existence of at least one primary DNS server holding the master copy of each zone the secondary serves. The server has no ability to author, modify, or sign zone data. It acquires zone data only through standard zone transfer protocols — AXFR or IXFR — initiated either by itself on SOA-driven refresh intervals or in response to NOTIFY messages from a primary.

Once a zone has been transferred, OxideDNS-Secondary serves authoritative answers for that zone to DNS clients over the standard DNS query protocol on UDP/53 and TCP/53. It does not perform recursive resolution, does not forward queries, and does not provide DNSSEC validation services to clients; clients receiving DNSSEC-signed records are themselves expected to perform any validation they require.

The server is designed for deployment in environments that operate large secondary fleets — DNS hosting providers, CDN operators, registries, and enterprise anycast infrastructure — and is intended to coexist with arbitrary primary implementations (NSD, Knot DNS, BIND, and others) without requiring vendor-specific extensions.

The five actor classes with which the server interacts are enumerated in §2.3.

## 2.2 Product Functions

At a behavioural level, OxideDNS-Secondary performs the following functions. Each is decomposed into atomic requirements in §4.

**Zone acquisition.** Initiates AXFR or IXFR transfers from configured primaries, authenticated by TSIG where configured. Falls back from IXFR to AXFR when the primary cannot satisfy an incremental request. Transfers over TLS (XoT) where configured.

**Zone maintenance.** Honours per-zone SOA REFRESH, RETRY, and EXPIRE timers. Receives and authenticates NOTIFY messages and triggers expedited refresh in response. Expires zones whose authoritative data is no longer fresh and ceases to serve them in accordance with RFC 1034.

**Zone storage.** Maintains each zone's authoritative data entirely in process memory. Refreshes are applied atomically: query handlers observe either the previous version of a zone in its entirety or the new version, never a mixture.

**Query answering.** Receives DNS queries over UDP and TCP, parses them, performs authoritative lookup, and returns responses including authority and additional sections per RFC 1034 and RFC 1035. Sets the AA bit appropriately. Returns NXDOMAIN, NODATA, and other error responses correctly per RFC 2308. Returns REFUSED for queries outside the served zones; never offers recursion.

**Protocol extensions.** Honours EDNS0, including advertised buffer sizes, the padding option, and the TCP keepalive option. Performs TCP fallback on truncation. Serves DNSSEC records (DNSKEY, RRSIG, NSEC, NSEC3, DS, NSEC3PARAM) verbatim as received from the primary.

**Operational integration.** Logs to standard output and standard error in a structured form. Exposes a health check interface suitable for orchestrator probes. Handles process signals for graceful shutdown, completing in-flight queries before exit.

**Abuse mitigation.** Applies Response Rate Limiting to constrain its utility as an amplification vector.

## 2.3 Actor Classes

The server interacts with five distinct classes of actor. Requirements in §4–§6 are written with reference to these classes.

**DNS Clients (resolvers and stub resolvers).** Untrusted entities — typically recursive resolvers acting on behalf of end users — that send queries expecting authoritative answers for zones the server serves. They are assumed hostile until proven otherwise: queries may be malformed, may attempt to elicit amplification, or may be part of cache-poisoning attacks. The server makes no assumption about the trustworthiness of any client.

**Primary DNS Servers.** Trusted, but only insofar as they authenticate via TSIG where configured and present zone data consistent with the SOA records they have previously delivered. The primary is the authoritative source of zone data; the secondary trusts the primary to deliver accurate zone contents but does not assume the underlying transport is secure unless XoT is configured. The set of primaries per zone is established by operator configuration.

**Operators.** Human administrators responsible for the server's configuration, deployment, and lifecycle. They supply zone definitions, primary server addresses, TSIG keys, and any tuning parameters, and are responsible for the secure handling of key material before it reaches the server. Operators interact with the running server only through process signals; there is no runtime administrative interface.

**Orchestrators and Supervisors.** Automated systems — container orchestrators, systemd, init managers, anycast routing controllers — that start, stop, and probe the server. They consume health check responses, react to process exit codes, and deliver signals. The server is designed to behave correctly under their control without requiring orchestrator-specific configuration.

**Observers (logging and metrics consumers).** Systems that consume the server's structured log output and any exposed metrics. They are not authenticated; the server emits to standard streams and is agnostic to what reads from them.

## 2.4 Operating Environment

**Operating system.** Linux, current LTS kernel versions or later. No dependency on distribution-specific facilities. The server makes use of standard POSIX networking and signal handling.

**Deployment modes.** Three deployment modes are supported:

- Native process on a Linux host.
- Container (OCI-compatible image, suitable for distroless or scratch base images, runnable on Kubernetes, Podman, Docker, containerd, and equivalent runtimes).
- Minimal virtual machine image, Alpine or equivalent base.

**Network.** The server requires bindable access to UDP/53 and TCP/53 (or operator-configured equivalents) for query service; outbound TCP access to configured primaries for zone transfers; inbound UDP and TCP access from primaries for NOTIFY; and, where XoT is configured, outbound TCP access to the primary's configured XoT port (typically TCP/853). IPv4 and IPv6 are supported equivalently; the server does not require both to be present.

**Time.** The server requires a system clock with reasonable accuracy — typically within a few minutes of real time — for TSIG signature validity. Drift exceeding TSIG's permitted fudge window will cause transfer authentication to fail.

**Storage.** No persistent storage is required. The server does not write zone data, configuration state, or operational state to disk. The configuration file, if used in preference to environment variables, is read once at startup and not subsequently re-read.

**Memory.** Memory must be sufficient to hold all served zones in fully expanded form, plus working space for in-flight queries and transfers. Capacity planning is the operator's responsibility.

## 2.5 Design and Implementation Constraints

The following constraints are inherited from the PID and are binding. They are restated here for the reader's convenience and formalised as architectural invariants with identifiers in §3.

**Implementation language.** Rust (PID §2.3). Rationale: memory safety without garbage collection, suitable for a network-facing server processing untrusted input at high query rates.

**Secondary-only.** No primary-role functionality, no dynamic update path, no recursive resolution (PID §3.1, §3.2). Enforced at the requirement level in §3 and §4.18.

**Memory residency.** Zone data resides entirely in process memory; the query path performs no disk I/O.

**No persistent state.** Operational state is not written to persistent storage. Every startup is a cold start; the primary is the source of truth for zone data, and orchestrator configuration is the source of truth for everything else.

**Static binary.** The build produces a statically linked binary with no runtime dynamic library dependencies, suitable for distroless and scratch container images.

**Container image size.** The published container image does not exceed 20 megabytes uncompressed (PID §6.1).

**Code size.** The implementation targets a total source size in the range of 5,000 to 15,000 lines of Rust (PID §2.2). This is an aspirational ceiling motivating aggressive scoping; any feature that would push the codebase beyond this range requires explicit justification recorded in the Architecture Document.

**Cryptographic dependencies.** Cryptographic primitives — HMAC, hash functions, TLS — are not implemented from scratch (PID §7.1). The server relies on well-maintained Rust cryptography crates. Specific crate choices are recorded in the Architecture Document.

**Licensing.** Source code is published under MIT OR Apache-2.0 dual license (PID §5.2). All dependencies must carry compatible licenses; copyleft dependencies are excluded.

## 2.6 Assumptions and Dependencies

**Assumptions.** The following are assumed to hold. Failure of any of these in production is the operator's responsibility, not the server's:

- At least one primary DNS server is reachable for each configured zone at startup, or within an operator-defined startup tolerance window.
- The operator has provisioned TSIG keys, where used, through a secure out-of-band channel and supplied them via configuration.
- System time is synchronised to within TSIG's permitted fudge window (default 300 seconds per RFC 8945).
- The network ports required by the server are available for binding.
- The host platform provides sufficient memory for the configured zones.

**Dependencies.** The server depends on:

- A Rust toolchain at a stable channel release for compilation. The minimum supported Rust version is recorded in the Architecture Document.
- A set of upstream Rust crates for asynchronous I/O, cryptography, and ancillary functions. The crate inventory and pinning policy is recorded in the Architecture Document; this SRS deliberately does not name specific crates, to avoid binding behavioural requirements to implementation choices.
- An operating system providing standard POSIX networking and signal handling.

No runtime dependency exists on other DNS infrastructure beyond the primary servers configured for the zones being served.

---

# 3. Architectural Invariants

This section establishes the architectural invariants of OxideDNS-Secondary. An invariant is a property the system must hold at all times during operation — not a behaviour to be performed, but a constraint on the space of possible behaviours. Every functional requirement in §4 and every non-functional requirement in §5 is written within the constraint envelope these invariants define; in case of apparent conflict, the invariants prevail.

Each invariant is presented with a normative Statement, the Rationale for its existence, the Implications it has for design, and the Verification approach by which the invariant will be confirmed.

## 3.1 Secondary-Only Operation

**ODS-INV-001 — Secondary-Only Operation**

*Statement.* The server MUST acquire zone data only through zone transfer protocols (AXFR per RFC 5936 or IXFR per RFC 1995) initiated by itself toward operator-configured primaries. The server MUST NOT accept zone data, zone modifications, or any change to its authoritative state through any other channel.

*Rationale.* The secondary-only scope is the defining design constraint of this project (PID §2.2). The security, simplicity, and auditability claims of the project derive from the absence of any write path other than authenticated zone transfer from a trusted primary.

*Implications.* There is no DNS UPDATE (RFC 2136) handler. There is no zone-file editing interface. There is no administrative interface for modifying records. There is no acceptance of out-of-band zone data injection. The complementary prohibitions are enumerated as negative requirements in §4.18.

*Verification.* Static analysis of the codebase shall confirm that the only code paths producing changes to the in-memory zone store originate in the zone transfer client. Functional tests shall confirm that UPDATE messages, however formed, are rejected with RCODE NOTIMP or REFUSED.

*Status.* Draft.

## 3.2 Memory-Resident Zone Data

**ODS-INV-002 — Memory-Resident Zone Data**

*Statement.* All zone data served by the server MUST reside in process memory. The query-serving path MUST NOT perform disk I/O.

*Rationale.* Eliminates an entire class of latency variability and a category of operational complexity. Removes the possibility of inconsistent on-disk state outliving an operational error. Permits deployment on read-only root filesystems and on scratch container images.

*Implications.* Zone data is not memory-mapped from disk. There is no on-disk zone cache. There is no swap-eligible zone storage in the design — operators are responsible for ensuring sufficient RAM and for disabling swap where production performance requires it.

*Verification.* Code review shall confirm that the query path does not invoke filesystem operations. System-call tracing (strace or equivalent) during steady-state query serving shall confirm the absence of filesystem activity outside of operator-controlled logging.

*Status.* Draft.

## 3.3 Atomic Zone Refresh

**ODS-INV-003 — Atomic Zone Refresh**

*Statement.* Every query against a zone MUST be answered from a single, internally consistent version of that zone's data. During a zone refresh, query handlers MUST observe either the pre-refresh state in its entirety or the post-refresh state in its entirety; partial observation MUST NOT occur.

*Rationale.* Partial visibility of an in-progress zone transfer produces inconsistent answers — the canonical pathology being a stale CNAME pointing at a removed target. Atomic refresh guarantees consistency from the client's perspective and is a precondition for the secondary's correctness as an authoritative source.

*Implications.* The zone store must support a publish-after-load model: a new zone version is fully constructed before it is made visible to query handlers, and the transition from old version to new version is observed atomically by all handlers. The implementation mechanism — atomic pointer swap, RCU, generational versioning, or another approach — is an architectural choice recorded in the Architecture Document, but the property must hold.

*Verification.* Concurrent test harnesses shall issue queries continuously during simulated zone refresh and shall confirm that no response contains records from two versions of the zone. Stress tests under load shall confirm the absence of torn reads.

*Status.* Draft.

## 3.4 No Persistent Operational State

**ODS-INV-004 — No Persistent Operational State**

*Statement.* The server MUST NOT write operational state — zone data, transfer history, query statistics, configuration, or any data intended to survive process restart — to persistent storage.

*Rationale.* A secondary's authoritative state is defined entirely by what the primary has most recently delivered. Persistence of any operational state introduces the possibility of restart with stale or inconsistent data, defeating the simplicity of the cold-start model. The combination of this invariant with INV-002 yields a server whose entire state is reconstructible from the orchestrator's configuration plus the primaries' current data.

*Implications.* Every startup performs full zone acquisition from the configured primaries. There is no on-disk SOA serial cache to short-circuit initial transfer. Log output emitted to stdout and stderr is not "persistent state" in the sense of this invariant — it is observable output, owned by whatever process collects it downstream. Metrics endpoints, if provided, expose live counters held in memory; they are not snapshots of disk-backed state.

*Verification.* Code review shall confirm that no write operations target the filesystem outside of standard output and standard error. The published container image shall be runnable with a read-only root filesystem.

*Status.* Draft.

## 3.5 Static Configuration

**ODS-INV-005 — Static Configuration**

*Statement.* All configuration MUST be supplied at process startup, either through environment variables or a single configuration file. The server MUST NOT re-read or otherwise alter its configuration during operation. Configuration changes are applied only by process restart.

*Rationale.* Eliminates an entire category of reload-related defects and consistency questions ("is the running state consistent with the file on disk?"). Aligns with container-native operational models, where configuration changes are expressed as new deployments rather than in-place mutation. Reduces the operational interface surface — there is no SIGHUP-driven reload, no administrative socket, no runtime configuration API.

*Implications.* No SIGHUP handler for configuration reload. No partial-reload semantics to specify or test. The orchestrator (or operator) is responsible for restarting the process to apply configuration changes, with the graceful-shutdown behaviour required by §4 supporting rolling restart deployment patterns.

*Verification.* Code review shall confirm that configuration parsing occurs once during startup and that no code path re-reads configuration sources thereafter. Behavioural tests shall confirm that signals other than SIGTERM and SIGINT (and SIGCHLD where relevant) produce no configuration effect.

*Status.* Draft.

## 3.6 Memory Safety Discipline

**ODS-INV-006 — Memory Safety Discipline**

*Statement.* The implementation MUST use Rust's safe subset for all code that processes data received from the network — including but not limited to DNS query parsing, EDNS option parsing, RR-type-specific decoders, zone transfer payload parsing, NOTIFY message handling, and TSIG verification input handling. Any use of `unsafe` blocks MUST be accompanied by a comment in the source code stating the reason the block is necessary and the invariants on which its soundness depends.

*Rationale.* The principal security argument for this project — that it is meaningfully safer than C-based alternatives — depends on actually exercising Rust's safety guarantees in the parts of the code that handle untrusted input. Unconstrained `unsafe` usage would erode this guarantee. Confining `unsafe` to justified, documented locations preserves the guarantee while permitting unavoidable interfaces to the operating system or to FFI where they arise.

*Implications.* Wire-format parsers across all protocols supported by the server are implemented in safe Rust. Any `unsafe` block in the codebase is reviewable as a finite, documented exception. The set of `unsafe` blocks is enumerable by static tooling and forms part of the security review during each release.

*Verification.* Static analysis (`cargo geiger` or equivalent) shall enumerate all `unsafe` usage in the codebase and its transitive dependencies. Each `unsafe` block in first-party code shall be reviewed during code review and approved against its documented justification. Fuzz testing (`cargo-fuzz`) against the wire-format parsers shall serve as ongoing evidence that the safe-Rust parsers handle malformed input correctly.

*Status.* Draft.

---

# 4. Functional Requirements

This section specifies the server's functional behaviour. Requirements are grouped into eighteen subsections by protocol concern; each subsection allocates an area code per the scheme of §1.4.3.


## 4.1 DNS Protocol Core

This subsection specifies the core DNS protocol behaviour required to receive a query, locate authoritative data, and emit a correct response. It derives from RFC 1034, RFC 1035, RFC 2181, and RFC 4343. Adjacent concerns are specified separately: TCP transport in §4.12, EDNS0 in §4.11, negative response detail in §4.3, anti-spoofing in §4.5, DNSSEC record serving in §4.13.

The area code **CORE** is allocated to this subsection and is registered in Appendix D. All requirements below are in status **Draft** per §1.4.5; status is annotated below only where it differs.

Requirements are grouped thematically for readability; the grouping has no normative significance.

### Message format and parsing

**ODS-FR-CORE-001.** The server MUST parse DNS messages received on its configured UDP and TCP listening sockets according to the wire format specified in RFC 1035 §4.
*Source.* RFC 1035 §4.
*Verification.* Wire-format conformance tests against a handcrafted message corpus covering combinations of flag bits, RCODEs, and section structures.

**ODS-FR-CORE-002.** The server MUST silently discard any received message shorter than the 12-octet DNS header, without generating a response.
*Source.* RFC 1035 §4.1.1. A truncated header carries no valid ID to echo and no valid context for a FORMERR response.
*Verification.* Conformance tests; sub-12-octet datagrams produce no observable response.

**ODS-FR-CORE-003.** The server MUST parse the DNS header fields (ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) in network byte order.
*Source.* RFC 1035 §4.1.1.
*Verification.* Conformance tests.

**ODS-FR-CORE-004.** The server MUST silently discard messages received on a query-serving socket with the QR bit set (i.e. responses).
*Source.* RFC 1035 §4.1.1. Responses received on a query-serving socket are either misdirected or hostile.
*Verification.* Conformance tests.

**ODS-FR-CORE-005.** The server MUST accept and process messages with OPCODE = 0 (QUERY) and OPCODE = 4 (NOTIFY). Messages with any other OPCODE value MUST receive a response with RCODE = 4 (NOTIMP) and an echoed header.
*Note.* OPCODE 5 (UPDATE) is explicitly addressed by the negative requirements in §4.18 and by ODS-INV-001; the NOTIMP response is the default for any unrecognised OPCODE. NOTIFY semantics are specified in §4.8.
*Source.* RFC 1035 §4.1.1; the IANA OPCODE registry maintained per RFC 6895.
*Verification.* Conformance tests across the OPCODE space.

### Question section

**ODS-FR-CORE-006.** The server MUST accept and process messages with QDCOUNT = 1. Messages with QDCOUNT = 0 or QDCOUNT > 1 MUST receive a response with RCODE = 1 (FORMERR).
*Source.* RFC 1035 §4.1.2; current operational practice (no multi-question query semantics are defined).
*Verification.* Conformance tests.

**ODS-FR-CORE-007.** The server MUST parse the QNAME field as a sequence of length-prefixed labels terminating in a zero-length label, rejecting with FORMERR any message in which an individual label length exceeds 63 octets or the total uncompressed QNAME length exceeds 255 octets.
*Source.* RFC 1035 §2.3.4, §3.1, §4.1.2.
*Verification.* Conformance tests including oversize labels and oversize names.

**ODS-FR-CORE-008.** The server MUST resolve DNS name compression pointers per RFC 1035 §4.1.4 when parsing QNAMEs and MUST respond with RCODE = 1 (FORMERR) when a message contains a compression loop or an out-of-bounds pointer target.
*Source.* RFC 1035 §4.1.4.
*Verification.* Conformance tests including pointer loops, self-referential pointers, and out-of-bounds pointer targets. Continuous fuzz testing.

**ODS-FR-CORE-009.** The server MUST compare domain names case-insensitively with respect to ASCII letters A–Z and a–z, treating all other octet values literally and bit-for-bit.
*Source.* RFC 1035 §2.3.3; RFC 4343 §3.
*Verification.* Lookup tests with mixed-case QNAMEs against zone data containing mixed-case owner names.

**ODS-FR-CORE-010.** The server MUST preserve the case of QNAME octets in the question section of its responses, echoing them exactly as received in the query.
*Source.* RFC 1035 §6.1; RFC 4343.
*Verification.* Wire-format inspection of responses to queries with mixed-case QNAMEs.

### Header construction in responses

**ODS-FR-CORE-011.** In every response generated by the server, the QR bit MUST be set to 1, and the OPCODE, ID, and RD bit MUST be echoed from the query.
*Source.* RFC 1035 §4.1.1; RFC 1034 §6.2.
*Verification.* Wire-format inspection across response categories.

**ODS-FR-CORE-012.** In every response generated by the server, the RA bit MUST be set to 0.
*Source.* RFC 1035 §4.1.1; ODS-INV-001 (the server never offers recursion).
*Verification.* Wire-format inspection across response categories.

**ODS-FR-CORE-013.** In every response generated by the server, the Z bits MUST be set to 0.
*Source.* RFC 1035 §4.1.1.
*Verification.* Wire-format inspection.

**ODS-FR-CORE-014.** In responses, the server MUST set the AA bit to 1 when the answer is authoritative for the queried name (a direct match, NODATA, NXDOMAIN, or wildcard synthesis within a served zone) and MUST set the AA bit to 0 for referral responses to delegated child zones.
*Source.* RFC 1034 §4.3.1; RFC 1035 §4.1.1.
*Verification.* Wire-format inspection across answer categories including referrals.

**ODS-FR-CORE-015.** In responses, the server MUST set QDCOUNT, ANCOUNT, NSCOUNT, and ARCOUNT to the exact number of records the server has placed in each respective section of the response message.
*Source.* RFC 1035 §4.1.1.
*Verification.* Wire-format inspection.

### Class handling

**ODS-FR-CORE-016.** The server MUST process queries with QCLASS = 1 (IN) by matching against IN-class zone data.
*Source.* RFC 1035 §3.2.4.
*Verification.* Lookup tests.

**ODS-FR-CORE-017.** The server MUST process queries with QCLASS = 255 (ANY) by matching against zone data of any served class. In a server serving only IN-class zones, this reduces to matching against IN.
*Source.* RFC 1035 §3.2.5.
*Verification.* Lookup tests with QCLASS = ANY.

**ODS-FR-CORE-018.** The server MUST respond with RCODE = 5 (REFUSED) to queries with QCLASS values other than IN or ANY when no zone of the requested class is served.
*Source.* RFC 1035 §3.2.4. REFUSED is selected over NOTAUTH because the server is not authoritative for any zone of the requested class.
*Verification.* Lookup tests with QCLASS = CH, HS, NONE, and reserved values.

### Authoritative lookup and response construction

**ODS-FR-CORE-019.** The server MUST identify, for each query, the most specific zone in its in-memory zone store that is an ancestor of the QNAME or equal to it. If no such zone exists, the server MUST respond with RCODE = 5 (REFUSED).
*Source.* RFC 1034 §4.3.1, §4.3.2; reasoning from the secondary-only stance — the server is not authoritative for unknown zones and offers no recursion.
*Verification.* Lookup tests with QNAMEs outside the set of served zones.

**ODS-FR-CORE-020.** Where the QNAME falls within a served zone, the server MUST search the zone for the RRset whose owner name equals QNAME (case-insensitively per ODS-FR-CORE-009) and whose type equals QTYPE; or, where QTYPE = 255 (ANY), for all RRsets at the owner name.
*Source.* RFC 1034 §4.3.2.
*Note.* RFC 8482 minimisation of ANY responses is addressed in §4.2.
*Verification.* Lookup tests across record types and ANY queries.

**ODS-FR-CORE-021.** Where the QTYPE matches an RRset at the QNAME, the server MUST place all records of that RRset in the answer section of the response.
*Source.* RFC 1034 §4.3.2; RFC 2181 §5.
*Verification.* Lookup tests.

**ODS-FR-CORE-022.** Where the QNAME exists in the served zone but no RRset of the queried QTYPE exists at that owner name, the server MUST return a NODATA response: empty answer section, AA = 1, RCODE = 0 (NOERROR), and the SOA record of the containing zone in the authority section.
*Source.* RFC 1034 §4.3.2; RFC 2181 §7; RFC 2308 §2.2.
*Verification.* Lookup tests for existing names with no matching type.

**ODS-FR-CORE-023.** Where the QNAME does not exist in the served zone and no wildcard match applies, the server MUST return an NXDOMAIN response: empty answer section, AA = 1, RCODE = 3 (NXDOMAIN), and the SOA record of the containing zone in the authority section.
*Source.* RFC 1034 §4.3.2; RFC 2308 §2.1.
*Verification.* Lookup tests for non-existent names.

**ODS-FR-CORE-024.** Where the QNAME matches a wildcard owner name in the served zone per RFC 1034 §4.3.3 as clarified by RFC 4592, the server MUST synthesise the answer from the wildcard RRset, with the owner name of the synthesised records set to the QNAME and the TTL inherited from the wildcard RRset.
*Source.* RFC 1034 §4.3.3; RFC 4592.
*Verification.* Lookup tests against zones containing wildcards, covering the edge cases enumerated in RFC 4592 (empty non-terminal occlusion, wildcards at apex, wildcards beneath delegations).

**ODS-FR-CORE-025.** Where the QNAME falls within a child zone delegated from a served zone (the QNAME is at or below an NS RRset within the served zone that is not the zone apex), the server MUST return a referral response: empty answer section, AA = 0, RCODE = 0 (NOERROR), the child zone's NS RRset in the authority section, and any associated A and AAAA glue records from the served zone in the additional section.
*Source.* RFC 1034 §4.3.2; RFC 1035 §6.2.4; RFC 4035 for DNSSEC-related referral additions (see §4.13).
*Verification.* Lookup tests against zones containing delegations, with and without glue.

### RRset semantics

**ODS-FR-CORE-026.** The server MUST treat all resource records sharing owner name, class, and type as a single RRset and MUST return all members of that RRset together when the RRset is the subject of a positive answer. The server MUST NOT return a proper subset of an RRset in the answer section of a positive response.
*Source.* RFC 2181 §5.
*Verification.* Lookup tests confirming RRset integrity in responses, including responses near the UDP message size boundary (see §4.11 for EDNS interactions).

**ODS-FR-CORE-027.** The server MUST apply a single TTL value to all members of an RRset served from its in-memory zone store. Where a zone transfer delivers an RRset whose members carry differing TTLs, the server MUST adopt the lowest TTL among them for the RRset, in accordance with RFC 2181 §5.2, and MUST emit a warning-level log entry recording the inconsistency.
*Source.* RFC 2181 §5.2.
*Note.* RFC 2181 deprecates non-uniform TTLs within an RRset; the secondary's behaviour is defensive against a non-compliant primary.
*Verification.* Zone-transfer tests delivering non-uniform TTLs; log inspection.

### Name octet handling

**ODS-FR-CORE-028.** The server MUST treat the octet values in domain name labels as opaque except for case-insensitive ASCII letter comparison per ODS-FR-CORE-009, neither rejecting nor normalising octets outside the LDH set.
*Source.* RFC 4343 §2; RFC 2181 §11.
*Note.* This permits internationalised domain names (in their wire-format A-label encoding) and other non-LDH labels to be served correctly. Validation of label syntax is a primary-side concern.
*Verification.* Lookup tests with non-LDH octet sequences in QNAMEs and owner names.

## 4.2 Query Processing

This subsection specifies query-processing semantics beyond the wire-format and lookup primitives of §4.1: recursion policy, handling of CNAME and DNAME indirection, meta-type query handling, additional section composition, and response-code selection for conditions not previously covered.

The area code **QRY** is allocated to this subsection.

### Recursion policy

**ODS-FR-QRY-001.** The server MUST process queries authoritatively regardless of the state of the RD (Recursion Desired) bit in the query header. The RD bit affects only its echo into the response header per ODS-FR-CORE-011 and MUST NOT alter the server's resolution behaviour.
*Source.* ODS-INV-001; RFC 1034 §3.7.
*Verification.* Lookup tests issuing identical queries with RD = 0 and RD = 1; responses MUST be identical apart from the echoed RD bit.

### Idempotency

**ODS-FR-QRY-002.** The processing of a query MUST NOT alter the served zone data nor any operational state observable to other queries, with the sole exceptions of statistics counters (ODS-FR-QRY-023) and rate-limit accounting state (§4.17).
*Source.* RFC 1034 §3.7; ODS-INV-003.
*Verification.* Concurrent query tests under steady-state zone conditions; zone data identity verified before and after.

### ANY-query handling

**ODS-FR-QRY-003.** The server MUST support an "any-response" configuration option taking the values "full" and "minimal", controlling the response policy for queries with QTYPE = 255 (ANY).
*Source.* RFC 8482.
*Verification.* Configuration round-trip tests; behavioural tests with each setting active.

**ODS-FR-QRY-004.** In "full" any-response mode, for QTYPE = 255 (ANY) queries against a name with at least one RRset present, the server MUST return all RRsets present at the QNAME in the answer section, applying the standard lookup semantics of §4.1.
*Source.* RFC 1034 §3.7; RFC 1035 §3.2.5.
*Verification.* Lookup tests in "full" mode against names with multiple RRsets.

**ODS-FR-QRY-005.** In "minimal" any-response mode, for QTYPE = 255 (ANY) queries against a name with at least one RRset present, the server MUST return a single RRset selected from those present at the QNAME, per RFC 8482 §4.1. The selection algorithm MUST be deterministic for a given zone state.
*Source.* RFC 8482 §4.1.
*Verification.* Repeated identical queries in "minimal" mode MUST produce identical selected RRsets given an unchanged zone.

**ODS-FR-QRY-006.** The default value of the "any-response" configuration option MUST be "minimal".
*Rationale.* RFC 8482 was published in response to operational reality: ANY queries are predominantly used for amplification, with a small minority of legitimate uses. For a new secondary intended for anycast deployment, minimisation is the safer default and consistent with the project's reduced-attack-surface stance.
*Verification.* Default-configuration tests.

**ODS-FR-QRY-007.** The server MUST NOT use the synthesised HINFO response style described in RFC 8482 §4.2.
*Rationale.* The HINFO synthesis style requires emitting a record that is not really a HINFO, which has been criticised as misleading to operators inspecting captured traffic. The subset-of-data approach (QRY-005) is more transparent.
*Verification.* Wire-format inspection of ANY responses.

### Meta-type query rejection

**ODS-FR-QRY-008.** The server MUST respond with RCODE = 4 (NOTIMP) to queries with QTYPE = 253 (MAILB) or QTYPE = 254 (MAILA).
*Source.* RFC 1035; deprecation noted in the IANA RR TYPEs registry per RFC 6895.
*Verification.* Conformance tests.

**ODS-FR-QRY-009.** The server MUST respond with RCODE = 1 (FORMERR) to queries where the QTYPE field carries a meta-type value that has no question-section semantics, specifically: OPT (41), TSIG (250), TKEY (249), and reserved values 0 and 65535.
*Source.* RFC 6891 (OPT); RFC 8945 (TSIG); RFC 6895 IANA registry.
*Note.* AXFR (252) and IXFR (251) as QTYPE values are handled per §4.6 and §4.7 respectively.
*Verification.* Conformance tests across the enumerated values.

### CNAME handling

**ODS-FR-QRY-010.** Where the QNAME has a CNAME RRset in the served zone and the QTYPE is neither CNAME (5) nor ANY (255), the server MUST include the CNAME record in the answer section, then attempt to resolve the CNAME target within the same response.
*Source.* RFC 1034 §3.6.2, §4.3.2.
*Verification.* Lookup tests against zones containing CNAME records.

**ODS-FR-QRY-011.** When chasing a CNAME chain within a single response, the server MUST follow the chain only as far as the next target falls within a zone served by this server. Where the chain leaves the set of served zones, the server MUST cease appending records and complete the response, leaving the client resolver to continue resolution.
*Source.* RFC 1034 §4.3.2.
*Verification.* Lookup tests with CNAME chains crossing the served-zone boundary.

**ODS-FR-QRY-012.** The server MUST terminate CNAME chain resolution at a configurable maximum chain length, with a default of 8 CNAME records. Exceeding this limit MUST cause the response to be delivered as constructed up to that point, and MUST be logged at warning level.
*Source.* Defence against pathological zone configurations; consistent with operational practice in NSD, Knot, and BIND.
*Verification.* Lookup tests against zones with long CNAME chains; log inspection.

**ODS-FR-QRY-013.** The server MUST detect CNAME loops (a chain in which any target name has already been included in the answer section of the current response) and MUST terminate processing of the chain at the point of detection.
*Source.* RFC 1034 §3.6.2 implicit; defence against zone misconfiguration.
*Verification.* Lookup tests against zones with cyclic CNAME chains.

### DNAME handling

**ODS-FR-QRY-014.** Where the QNAME falls strictly beneath a name carrying a DNAME RRset in the served zone (and is not the DNAME owner name itself), the server MUST include the DNAME record in the answer section and MUST synthesise a CNAME record per RFC 6672 §3.2 mapping the original QNAME to a name constructed by substituting the DNAME target for the DNAME owner in the QNAME.
*Source.* RFC 6672 §3.
*Verification.* Lookup tests against zones containing DNAME records, including the edge cases of RFC 6672 §3.3 (DNAME at apex, DNAME above a delegation, name-length overflow on synthesis).

**ODS-FR-QRY-015.** After CNAME synthesis from a DNAME, the server MUST proceed with CNAME chain resolution per ODS-FR-QRY-010 through ODS-FR-QRY-013, treating the synthesised CNAME as if it had been present in the zone authoritatively.
*Source.* RFC 6672 §3.
*Verification.* Lookup tests including DNAME-to-CNAME chains terminating both within and outside served zones.

### Empty non-terminal handling

**ODS-FR-QRY-016.** Where the QNAME exists in the served zone only as an empty non-terminal — that is, descendant names with RRsets exist beneath it but no RRset exists at the QNAME itself — the server MUST return a NODATA response per ODS-FR-CORE-022, and MUST NOT expand any wildcard owner name that would otherwise match at or above the empty non-terminal, in accordance with RFC 4592 §2.2.2.
*Source.* RFC 4592 §2.2.2; RFC 5155 §1.1.
*Verification.* Lookup tests against zones containing empty non-terminals with and without wildcards above them.

### Additional section composition

**ODS-FR-QRY-017.** Where an NS RRset is included in the authority or answer section of a response, and any NS target name falls within a zone served by this server, the server MUST include the target's A and AAAA RRsets in the additional section, subject to the message-size constraints of §4.11.
*Source.* RFC 1034 §6.2; RFC 1035 §6.2.4, §6.3.
*Verification.* Lookup tests requiring glue, including referrals to delegations within and outside served zones.

**ODS-FR-QRY-018.** Where an MX, SRV, or NAPTR record is included in the answer section of a response and the target name (EXCHANGE for MX, TARGET for SRV, REPLACEMENT for NAPTR) falls within a served zone, the server MUST include the target's A and AAAA RRsets in the additional section, subject to message-size constraints.
*Source.* RFC 1034 §3.3.9; RFC 2782; RFC 3403.
*Note.* For NAPTR, the REPLACEMENT field is only meaningful for further DNS resolution where the FLAGS indicate continuation; the additional-section inclusion is unconditional on the target being in a served zone and a valid name.
*Verification.* Lookup tests.

**ODS-FR-QRY-019.** Where SVCB or HTTPS records are included in the answer section and contain a TargetName falling within a served zone, the server MUST include the TargetName's A and AAAA RRsets in the additional section in accordance with RFC 9460 §5, subject to message-size constraints.
*Source.* RFC 9460 §5.
*Verification.* Lookup tests with SVCB and HTTPS records in both AliasMode and ServiceMode.

**ODS-FR-QRY-020.** The server MUST NOT include in any section of a response a record sourced from outside the in-memory zone store of served zones. The absence of any non-authoritative cache (ODS-INV-001, ODS-INV-002) is the structural mechanism by which this requirement holds; this requirement records the behavioural consequence.
*Source.* ODS-INV-001; RFC 1034 §6.2.
*Verification.* Record provenance audit during lookup tests.

### RCODE selection

**ODS-FR-QRY-021.** The server MUST respond with RCODE = 2 (SERVFAIL) to queries against a zone whose authoritative data has expired — that is, where the time since the most recent successful transfer of the zone exceeds the zone's SOA EXPIRE value.
*Source.* RFC 1034 §4.3.5; RFC 1035 §3.3.13.
*Verification.* Tests with simulated primary unavailability across the EXPIRE interval; response code transitions from NOERROR to SERVFAIL at the EXPIRE boundary.

**ODS-FR-QRY-022.** The server MUST respond with RCODE = 2 (SERVFAIL) when processing a query encounters an internal condition that prevents construction of a correct response.
*Note.* In a memory-resident server with statically configured zones, the set of conditions producing SERVFAIL is narrow — primarily allocation failure during response assembly. SERVFAIL MUST NOT be used to mask zone-data inconsistencies that should themselves be detected at transfer time.
*Source.* RFC 1034 §4.3.2.
*Verification.* Fault-injection tests.

### Name compression in responses

**ODS-FR-QRY-023.** The server MUST apply DNS name compression per RFC 1035 §4.1.4 in response messages where compression reduces the message size. Compression of names embedded in RDATA MUST be restricted to the RR types for which RFC 3597 §4 and the applicable type-specific RFCs permit RDATA name compression.
*Source.* RFC 1035 §4.1.4; RFC 3597 §4.
*Note.* Detailed per-RR-type compressibility is governed by RFC 3597 §4 and inherits any subsequent IETF clarifications; this requirement does not enumerate the type list.
*Verification.* Wire-format inspection of responses; round-trip parsing through a strict decoder.

### Statistics

**ODS-FR-QRY-024.** The server MUST maintain in-memory counters for: queries received, queries answered with each RCODE value emitted, queries terminated by CNAME-chain limit, queries terminated by CNAME-loop detection, and queries truncated due to message-size limits (see §4.12). The exposure of these counters to external observers is specified in §5.6 and §6.4.
*Source.* Operational requirement informed by RFC 8906.
*Verification.* Inspection of counter values under controlled query load.

## 4.3 Negative Responses

This subsection extends the negative-response composition of §4.1 (CORE-022 for NODATA, CORE-023 for NXDOMAIN) with the TTL semantics of RFC 2308 and the empty-subtree semantics of RFC 8020. It also specifies the response codes returned when a CNAME or DNAME chain terminates in a negative condition.

DNSSEC negative-proof requirements (the inclusion of NSEC or NSEC3 records authenticating non-existence) are specified in §4.13 and apply in addition to the requirements of this subsection.

The area code **NRESP** is allocated.

### Negative-response TTL semantics

**ODS-FR-NRESP-001.** The TTL of the SOA record placed in the authority section of an NXDOMAIN or NODATA response MUST be set to the lesser of (a) the TTL of the SOA RRset as stored in the zone, and (b) the value of the SOA RDATA MINIMUM field.
*Source.* RFC 2308 §3, §5.
*Note.* RFC 2308 redefined the semantics of the SOA MINIMUM field: under RFC 1035 it served as a per-RR default TTL; under RFC 2308 it is the ceiling on negative-response TTL. The min() formulation captures the redefinition without requiring zone authors to align the SOA RRset TTL and the MINIMUM field.
*Verification.* Wire-format inspection of negative responses; the SOA TTL value MUST equal `min(SOA-RRset-TTL, SOA-MINIMUM)`.

**ODS-FR-NRESP-002.** When the SOA RRset is returned in the *answer* section in response to a direct query for the SOA at the zone apex, its TTL MUST be the SOA RRset's TTL as stored in the zone, unmodified by the MINIMUM field.
*Source.* RFC 2308 §4, §5 (distinction between authority-section SOA in negative responses and answer-section SOA in positive responses).
*Verification.* Wire-format inspection of direct SOA queries vs. negative-response SOAs in the same zone, confirming distinct TTL values where MINIMUM differs from the SOA RRset TTL.

### RFC 8020 — empty subtree semantics

**ODS-FR-NRESP-003.** The server MUST NOT return NXDOMAIN for a QNAME under which named descendants with RRsets exist in the zone. Such QNAMEs are empty non-terminals; the correct response is NODATA per ODS-FR-QRY-016.
*Source.* RFC 8020 §2; RFC 4592 §2.2.2.
*Note.* RFC 8020 formalises the "NXDOMAIN cut" principle: a downstream resolver receiving NXDOMAIN may rely on the absence of any name beneath the QNAME. Emitting NXDOMAIN where descendants exist would cause the resolver to cache nonexistence of names that do in fact exist.
*Verification.* Lookup tests against zones structured to exercise the distinction — for example, a zone containing `a.b.c.example` with no records at `b.c.example` or `c.example` MUST yield NODATA for queries at those intermediate names, not NXDOMAIN.

### Negative responses at CNAME and DNAME chain endpoints

**ODS-FR-NRESP-004.** Where a CNAME or DNAME chain followed within a single response (per §4.2) terminates within a served zone at a name that does not exist in that zone, the server MUST set RCODE = 3 (NXDOMAIN), retain the chain records in the answer section, and include the SOA record of the zone containing the terminal name in the authority section per ODS-FR-NRESP-001.
*Source.* RFC 1034 §3.6.2; RFC 2308 §2.1.
*Note.* The NXDOMAIN refers to the terminal name in the chain, not the original QNAME. The response is authoritative (AA = 1, per CORE-014) for both the QNAME and the terminal name because both lie in served zones.
*Verification.* Lookup tests with CNAME and DNAME chains terminating at nonexistent names within served zones.

**ODS-FR-NRESP-005.** Where a CNAME or DNAME chain followed within a single response terminates within a served zone at a name that exists but carries no RRset of the originally queried QTYPE, the server MUST set RCODE = 0 (NOERROR), retain the chain records in the answer section, and include the SOA record of the zone containing the terminal name in the authority section per ODS-FR-NRESP-001.
*Source.* RFC 1034 §3.6.2; RFC 2308 §2.2.
*Verification.* Lookup tests with CNAME and DNAME chains ending in a NODATA condition within served zones.

**ODS-FR-NRESP-006.** Where a CNAME or DNAME chain followed within a single response leaves the set of served zones (per ODS-FR-QRY-011), the server MUST set RCODE = 0 (NOERROR), MUST set the AA bit to 1, MUST NOT include any SOA record in the authority section, and MUST retain the chain records up to the point of departure in the answer section.
*Source.* RFC 1034 §3.6.2, §6.2.5.
*Note.* AA = 1 reflects that the records included in the response are themselves drawn from authoritative zone data, even though the chain extends beyond the set of zones for which this server is authoritative. The resolver is expected to continue resolution from the terminal name. The omission of SOA distinguishes this case from the authoritative-negative cases (NRESP-004, NRESP-005) and signals to the resolver that no negative-caching information applies.
*Verification.* Lookup tests with CNAME and DNAME chains crossing the served-zone boundary.

## 4.4 Unknown RR Handling

This subsection specifies the server's handling of resource records whose RR TYPE value the server's code does not specifically recognise. The principle is forward compatibility: as new RR types are standardised, the server can transfer and serve them without code changes, treating their RDATA as opaque octet sequences. The relevant standard is RFC 3597.

The catalogue of *known* RR types — those for which the server implements type-specific parsing, validation, or response semantics — is specified in §4.14. Anything not in that catalogue falls under this subsection.

The server processes zone data exclusively in wire format (received via AXFR or IXFR); the master file presentation format defined in RFC 3597 §5 is not within scope.

The area code **URR** is allocated.

### Acceptance and storage of unknown types

**ODS-FR-URR-001.** The server MUST accept resource records of any RR TYPE value during zone transfer, regardless of whether the type is recognised, treating the RDATA of unrecognised types as opaque octet sequences of length RDLENGTH.
*Source.* RFC 3597 §3.
*Verification.* Zone transfer tests delivering records of type codes not enumerated in §4.14, including type codes assigned by IANA after the implementation's release date and type codes in the IANA Private Use range.

**ODS-FR-URR-002.** The in-memory zone store MUST preserve the RDATA of unknown RR types bit-for-bit identical to the octets received from the primary.
*Source.* RFC 3597 §3; RFC 3597 §6 (bit-for-bit comparison implies bit-for-bit storage).
*Verification.* Zone-transfer round-trip tests comparing the RDATA octets emitted in query responses to the RDATA octets received in the originating transfer.

**ODS-FR-URR-003.** The server MUST accept records of unknown RR types with RDLENGTH = 0 (zero-octet RDATA), and MUST serve such records correctly with RDLENGTH = 0 in response messages.
*Source.* RFC 3597 §3; RFC 1035 §3.2.1.
*Verification.* Zone transfer tests delivering zero-length unknown-type RDATA; wire-format inspection of responses.

### Serving unknown types

**ODS-FR-URR-004.** Where a query specifies a QTYPE matching the numeric type code of an unknown-type RRset at the QNAME within a served zone, the server MUST return the matching RRset using the standard lookup semantics of §4.1 and §4.2.
*Source.* RFC 3597 §3.
*Verification.* Lookup tests with QTYPE values matching unknown-type RRsets present in zones.

**ODS-FR-URR-005.** When emitting a record of an unknown RR type in any section of a response, the server MUST set the RDLENGTH field to the exact octet count of the stored RDATA and MUST emit the RDATA octets verbatim, without modification, reordering, or any normalisation.
*Source.* RFC 3597 §3; RFC 1035 §3.2.1.
*Verification.* Wire-format inspection of responses containing unknown-type RRs.

### Name compression — prohibition for unknown types

**ODS-FR-URR-006.** When emitting a record of an unknown RR type, the server MUST NOT apply DNS name compression (RFC 1035 §4.1.4) to any octet sequence within the RDATA, regardless of whether any sub-sequence of octets resembles a compression pointer.
*Source.* RFC 3597 §4.
*Note.* This complements ODS-FR-QRY-023, which restricts RDATA compression to RR types for which RFC 3597 §4 permits it. The principle is that compression is meaningful only when both endpoints share semantic understanding of where names appear in RDATA; for unknown types, that shared understanding is absent.
*Verification.* Wire-format inspection of responses containing unknown-type RRs; emitted RDATA MUST be bit-identical to stored RDATA.

**ODS-FR-URR-007.** When parsing the RDATA of an unknown RR type received via zone transfer, the server MUST NOT interpret any octet pattern within the RDATA as a compression pointer. The RDATA is consumed as a contiguous opaque octet sequence of exactly RDLENGTH octets.
*Source.* RFC 3597 §4.
*Verification.* Zone-transfer tests in which the RDATA of unknown-type records contains octet patterns that would be valid compression pointers in known-type contexts (in particular, leading octets with the top two bits set); storage MUST be bit-identical to the wire octets.

### Bit-for-bit comparison

**ODS-FR-URR-008.** RRset membership for unknown RR types MUST be determined by bit-for-bit comparison of RDATA. The server MUST NOT apply case folding, ordering normalisation, or any other transformation to the RDATA of unknown types when determining whether two records are members of the same RRset or whether a record is a duplicate.
*Source.* RFC 3597 §6.
*Verification.* Zone-transfer tests delivering multiple records of an unknown type at a single owner name with subtly differing RDATA; correct distinct-RR membership must be maintained.

### Reserved type values

**ODS-FR-URR-009.** The server MUST reject a zone transfer containing any record whose RR TYPE field carries one of the reserved values 0 or 65535. Type values in other ranges — including the IANA Private Use range and type codes not yet assigned at the time of the server's implementation — MUST be accepted and processed under the requirements of this subsection.
*Source.* RFC 6895 §3.1; IANA "Resource Record (RR) TYPEs" registry.
*Note.* Reserved values have no defined semantics and would expose downstream query handling to inputs with no specification. A primary delivering type 0 or 65535 is presumed misconfigured or malicious; rejecting the transfer surfaces the problem to the operator. Private Use codes are explicitly permitted by the IANA registry and are passed through opaquely.
*Verification.* Zone-transfer tests injecting reserved type values; the transfer MUST be rejected and prior zone state preserved.

## 4.5 Anti-Spoofing Measures

This subsection specifies the server's measures to resist spoofed traffic, derived from RFC 5452. The principal exposure of a secondary-only server is on its *outbound* query path — when the server issues SOA poll queries, IXFR queries, or other queries toward configured primaries. RFC 5452 measures (QID randomisation, source port randomisation, strict response matching) constitute the baseline defence on this path; TSIG (§4.9), where configured, provides a substantially stronger cryptographic defence and supersedes these baseline measures in effectiveness.

Adjacent anti-spoofing concerns are specified separately: Response Rate Limiting in §4.17, TSIG authentication in §4.9, NOTIFY source validation in §4.8, transfer-peer validation in §4.6 and §4.7, response size minimisation in §4.11. Network-layer source-address filtering (BCP 38 / RFC 2827) is the responsibility of the operator and the network in which the server is deployed; it is not within the server's scope.

The area code **SPOOF** is allocated.

### Outbound query randomisation

**ODS-FR-SPOOF-001.** When the server originates a DNS query — including SOA refresh-check queries, IXFR queries, and any other query issued outbound — it MUST select the query ID from a cryptographically secure random source, sampling the full 16-bit ID space uniformly.
*Source.* RFC 5452 §9.1.
*Verification.* Statistical analysis of query IDs generated by the server under sustained outbound query load; the distribution MUST be indistinguishable from uniform random sampling of the 16-bit space.

**ODS-FR-SPOOF-002.** When the server originates a DNS query over UDP, it MUST select the source UDP port from a cryptographically secure random source drawing from the unprivileged ephemeral port range, and SHOULD NOT reuse a source port for an outbound query to the same destination address within the window of any outstanding query to that destination.
*Source.* RFC 5452 §9.2; RFC 6056.
*Note.* On most operating systems, source port randomisation is provided automatically by the kernel when the socket is bound with port 0; the server's responsibility is to verify by testing that this behaviour holds in its deployment environment and to bind sockets in a manner that elicits it.
*Verification.* Statistical analysis of source UDP ports observed on outbound queries.

### Response validation

The following requirements apply to responses received in reply to outbound queries originated by the server. They do not apply to NOTIFY messages received from primaries (§4.8) or to inbound zone-transfer streams over established TCP connections (§4.6, §4.7).

**ODS-FR-SPOOF-003.** When the server receives a UDP or TCP response to an outbound query, the response source IP address MUST equal the destination IP address used for the original query; otherwise, the response MUST be silently discarded.
*Source.* RFC 5452 §3, §6.
*Verification.* Outbound-query tests with injected responses from IP addresses other than the query target.

**ODS-FR-SPOOF-004.** When the server receives a response to an outbound UDP query, the response source UDP port MUST equal the destination UDP port used for the original query; otherwise, the response MUST be silently discarded.
*Source.* RFC 5452 §3, §6.
*Verification.* Outbound-query tests with injected responses from source ports other than the query destination port.

**ODS-FR-SPOOF-005.** When the server receives a response to an outbound query, the QID field in the response header MUST equal the QID of the original query; otherwise, the response MUST be silently discarded.
*Source.* RFC 5452 §3.
*Verification.* Outbound-query tests with injected responses bearing mismatched QIDs.

**ODS-FR-SPOOF-006.** When the server receives a response to an outbound query, the question section of the response MUST equal the question section of the original query, with QNAME comparison performed case-insensitively per ODS-FR-CORE-009; otherwise, the response MUST be silently discarded.
*Source.* RFC 5452 §3, §6.
*Verification.* Outbound-query tests with injected responses bearing mismatched question sections.

### Response discard logging

**ODS-FR-SPOOF-007.** When a response to an outbound query is discarded under ODS-FR-SPOOF-003, ODS-FR-SPOOF-004, ODS-FR-SPOOF-005, or ODS-FR-SPOOF-006, the server MUST emit a log entry at warning level recording at minimum the source IP address of the discarded response, the validation check that failed, and a correlation identifier permitting the discard to be matched against the originating outbound query.
*Source.* RFC 5452 §3 (informative); operational requirement.
*Note.* Repeated discards from a given source may indicate a spoofing attempt and provide actionable evidence for operators. The server MAY continue to await additional responses to the same outstanding outbound query within that query's timeout window.
*Verification.* Test harness injecting forged responses; log inspection confirms structured discard records.

## 4.6 AXFR Zone Transfer Client

This subsection specifies the server's behaviour as an AXFR client — the originator of full zone transfer requests toward configured primaries. The governing standard is RFC 5936. Timing-related concerns (when an AXFR is triggered, retry intervals, exponential backoff) are specified in §4.16. TSIG authentication of AXFR sessions is specified in §4.9, with AXFR-specific signature requirements summarised here for context. IXFR and IXFR-to-AXFR fallback are specified in §4.7.

The area code **AXFR** is allocated.

### Transport and query construction

**ODS-FR-AXFR-001.** The server MUST initiate AXFR queries exclusively over TCP. AXFR queries over UDP MUST NOT be issued.
*Source.* RFC 5936 §2.1.1.
*Verification.* Connection-layer inspection during AXFR initiation.

**ODS-FR-AXFR-002.** An AXFR query message MUST be constructed with QNAME equal to the zone apex name, QTYPE = 252 (AXFR), QCLASS equal to the configured class of the zone, OPCODE = 0 (QUERY), RD = 0, and a QID selected per ODS-FR-SPOOF-001.
*Source.* RFC 5936 §2.1.2; RFC 1035 §4.1.2.
*Verification.* Wire-format inspection of outbound AXFR queries.

**ODS-FR-AXFR-003.** The server MUST establish a TCP connection to the selected primary's configured zone-transfer port (default 53) for the AXFR session. The server MAY reuse an existing TCP connection to the same primary for the AXFR query where RFC 7766 connection persistence (§4.12) is in effect.
*Source.* RFC 5936 §4.1; RFC 7766 §6.
*Verification.* Connection-management tests under both fresh-connection and persistent-connection scenarios.

### Response message handling

**ODS-FR-AXFR-004.** The server MUST process the AXFR response as a sequence of one or more DNS messages received in order on the TCP connection. Message boundaries within the response stream have no semantic significance for record content; records are processed as concatenated across messages.
*Source.* RFC 5936 §2.2, §3.1; RFC 7766 §8.
*Verification.* AXFR tests with primaries that vary the number of messages per response (single message, many small messages, near-maximum-sized messages).

**ODS-FR-AXFR-005.** Every message in the AXFR response stream MUST carry a QID equal to the QID of the originating AXFR query, and OPCODE = 0 (QUERY). Failure of either check on any message in the stream MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019.
*Source.* RFC 5936 §2.2.1.
*Verification.* Conformance tests with injected mismatched-QID or mismatched-OPCODE messages.

**ODS-FR-AXFR-006.** The server MUST ignore the values of the AA, TC, RD, RA, AD, and CD bits in AXFR response messages.
*Source.* RFC 5936 §2.2.1.
*Note.* RFC 5936 explicitly declares these bits non-significant in AXFR responses. A primary that sets them inconsistently across messages is not in violation; the secondary's tolerance is mandated.
*Verification.* AXFR tests with primaries varying these bits across messages.

**ODS-FR-AXFR-007.** The first record in the answer section of the first AXFR response message MUST be an SOA record. The server MUST verify that this SOA record's owner name equals the configured zone apex name and that its class equals the configured zone class. Failure of either check MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019.
*Source.* RFC 5936 §2.2, §2.2.1.
*Verification.* AXFR tests with primaries delivering wrong leading record, wrong apex name, or wrong class.

**ODS-FR-AXFR-008.** The server MUST recognise the AXFR response as complete when it receives a second SOA record in the response stream. All records received between (exclusive of) the initial SOA and the terminating SOA constitute the transferred zone data.
*Source.* RFC 5936 §2.2.
*Verification.* AXFR tests with various zone sizes; terminating SOA detection.

**ODS-FR-AXFR-009.** The terminating SOA record MUST be bit-for-bit identical to the initial SOA record in owner name, class, type, TTL, and RDATA. Any difference MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019.
*Source.* RFC 5936 §2.2; defensive interpretation against partial-update propagation.
*Verification.* AXFR tests with deliberately mismatched first and last SOAs.

**ODS-FR-AXFR-010.** No SOA record other than the initial SOA and the terminating SOA MUST appear in the AXFR response stream. Receipt of any additional SOA record MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019.
*Source.* RFC 5936 §2.2, §3.1.
*Verification.* AXFR tests with primaries injecting spurious mid-stream SOAs.

### Record content validation

**ODS-FR-AXFR-011.** Every record in the AXFR response stream MUST have a class equal to the configured zone class. Records of a different class MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019.
*Source.* RFC 5936 §2.2.1.
*Verification.* AXFR tests with class-inconsistent records.

**ODS-FR-AXFR-012.** Every record in the AXFR response stream MUST have an owner name at or below the zone apex name. Records with owner names outside this subtree MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019. Glue records permitted under ODS-FR-AXFR-013 are subject to this constraint as their owner names also lie below the zone apex.
*Source.* RFC 5936 §2.2.4.
*Verification.* AXFR tests with out-of-zone records injected.

**ODS-FR-AXFR-013.** The server MUST accept glue records — A and AAAA records at owner names below child-zone delegation points within the transferred zone — as part of the AXFR response stream, and MUST store them in the in-memory zone store for use in glue inclusion under ODS-FR-QRY-017.
*Source.* RFC 5936 §2.2.4; RFC 1034 §4.2.1.
*Verification.* AXFR tests delivering glue at delegation points; lookup tests confirming glue inclusion in referral responses.

**ODS-FR-AXFR-014.** Records received in the AXFR response stream whose owner names lie at or below a child-zone delegation point — that is, occluded data per RFC 5936 §2.2.4, other than the permitted glue of ODS-FR-AXFR-013 — MAY be retained in the in-memory zone store but MUST NOT be returned in query responses generated under §4.2.
*Source.* RFC 5936 §2.2.4.
*Note.* RFC 5936 permits either retention or silent discard of occluded data. Retention is acceptable provided query handling cleanly excludes such records. The implementation choice is recorded in the Architecture Document.
*Verification.* AXFR tests with occluded data; lookup tests confirming the data is never returned.

**ODS-FR-AXFR-015.** Compression pointers within an AXFR response message MUST reference positions within that same DNS message only. Pointer targets referencing positions in other messages of the response stream MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019.
*Source.* RFC 5936 §3.4; RFC 1035 §4.1.4.
*Verification.* AXFR conformance tests with cross-message compression pointers.

### Primary selection

**ODS-FR-AXFR-016.** Where a zone is configured with more than one primary server, the server MUST attempt AXFR connections in the order specified by configuration. On failure to connect, on connection abort prior to successful completion, or on receipt of an error RCODE per ODS-FR-AXFR-020, the server MUST proceed to the next primary in the configured order. After exhausting all configured primaries without successful transfer, the server MUST follow the retry semantics specified in §4.16.
*Source.* RFC 1035 §4.3; operational requirement.
*Verification.* Multi-primary tests with various failure injection patterns.

### Authentication

**ODS-FR-AXFR-017.** Where TSIG is configured for AXFR sessions with the selected primary, the server MUST sign the outbound AXFR query with the configured TSIG key per §4.9.
*Source.* RFC 8945 §5.3.1; RFC 5936 §2.2.5.
*Verification.* AXFR tests with TSIG-configured primaries; wire-format inspection of signed queries.

**ODS-FR-AXFR-018.** For TSIG-signed AXFR sessions, the server MUST verify TSIG signatures across the multi-message response in accordance with RFC 8945 §5.3.1 and §4.9 of this SRS. At minimum, the first and last messages of the response MUST carry valid TSIG signatures; intermediate messages MAY omit the TSIG record per RFC 8945 §5.3.1. Failure of any required signature verification MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019.
*Source.* RFC 8945 §5.3.1.
*Verification.* AXFR tests with valid signatures, missing required signatures, and tampered intermediate records.

### Error handling

**ODS-FR-AXFR-019.** Upon any of the following conditions, the server MUST abort the AXFR session, close the TCP connection, discard all partially received data without modifying the in-memory zone store, emit a log entry at warning level identifying the failure cause and the affected zone and primary, and follow the retry semantics specified in §4.16:
- failure of any validation requirement of this subsection;
- failure of TSIG verification under ODS-FR-AXFR-018;
- premature TCP connection close before the terminating SOA is received;
- exceeding the session timeout under ODS-FR-AXFR-021;
- receipt of a response with an error RCODE under ODS-FR-AXFR-020.

*Source.* RFC 5936 §3.1, §5.
*Note.* This requirement is the consolidated error-handling entry point referenced by other requirements in this subsection. It is enumerative rather than compositional; a single failure cause produces a single abort path.
*Verification.* Fault-injection tests covering each enumerated failure condition.

**ODS-FR-AXFR-020.** An AXFR response message with RCODE other than 0 (NOERROR) MUST cause the AXFR session to be aborted per ODS-FR-AXFR-019. The specific RCODE value MUST be recorded in the log entry to assist operator diagnosis.
*Source.* RFC 5936 §2.2.1.
*Note.* RFC 5936 identifies NOTAUTH (the queried server is not authoritative) and REFUSED (transfer policy denial) as the principal error RCODEs in AXFR responses; FORMERR may also be returned for malformed AXFR queries. The secondary's response to all such RCODEs is the same — abort and retry — but distinguishing them in logs is useful for diagnosis.
*Verification.* AXFR tests with primaries returning each error RCODE.

### Session lifecycle

**ODS-FR-AXFR-021.** The server MUST enforce a configurable timeout on AXFR sessions, measured from the moment of initial TCP connection establishment to the receipt of the terminating SOA. The default timeout MUST be 300 seconds (5 minutes). Sessions exceeding the timeout MUST be aborted per ODS-FR-AXFR-019.
*Source.* Operational requirement.
*Verification.* AXFR tests with simulated slow or stalled primary responses.

**ODS-FR-AXFR-022.** The server MUST limit the number of concurrently outstanding AXFR sessions (across all configured zones) to a configurable maximum. The default maximum MUST be 4. New AXFR initiations exceeding this limit MUST be queued and initiated as in-flight sessions complete, in FIFO order.
*Source.* Resource management; defensive configuration against startup AXFR storms.
*Verification.* Tests with simultaneous transfer triggers for many zones; verify queue ordering and limit enforcement.

### Zone publication

**ODS-FR-AXFR-023.** Upon successful completion of an AXFR session — terminating SOA received, all validation requirements of this subsection satisfied, all TSIG signatures verified where applicable — the server MUST construct the new zone state in memory and publish it atomically in accordance with ODS-INV-003. The previous zone state MUST remain in service to query handlers until publication of the new state is complete.
*Source.* ODS-INV-003.
*Verification.* Concurrent query tests during AXFR completion; verify atomic transition.

## 4.7 IXFR Incremental Zone Transfer

This subsection specifies the server's behaviour as an IXFR client. The governing standard is RFC 1995. IXFR transfers only the differences between two versions of a zone and is the preferred refresh mechanism where supported; it falls back to AXFR semantics either within a single response (Mode 2 fallback, RFC 1995 §3) or by retrying at the state-machine level (§4.16) after an IXFR session failure.

Most session-mechanics requirements of §4.6 apply to TCP-based IXFR sessions identically; rather than restate them, this subsection cross-references and specifies only the IXFR-specific additions and divergences.

The area code **IXFR** is allocated.

### Transport and query construction

**ODS-FR-IXFR-001.** The server MAY initiate IXFR queries over UDP for efficiency. Where UDP is used, the server MUST retry the IXFR query over TCP if any of the following hold on the UDP response: the TC (truncated) bit is set; the response on parsing does not constitute a complete IXFR transfer in one of the three modes specified in ODS-FR-IXFR-004.
*Source.* RFC 1995 §2.
*Note.* TCP is the dominant transport in modern deployment; UDP IXFR is permitted for compatibility but the secondary should expect to be transparently upgraded to TCP whenever the diff exceeds a single UDP message.
*Verification.* IXFR tests with UDP queries to primaries returning oversized diffs.

**ODS-FR-IXFR-002.** TCP IXFR sessions MUST be conducted under the same connection-handling requirements as AXFR sessions specified in ODS-FR-AXFR-003 and the same multi-message reassembly requirements specified in ODS-FR-AXFR-004 and ODS-FR-AXFR-005.
*Source.* RFC 1995; RFC 5936; RFC 7766.
*Verification.* TCP-layer behavioural tests parallel to those used for AXFR.

**ODS-FR-IXFR-003.** An IXFR query message MUST be constructed with QNAME equal to the zone apex name, QTYPE = 251 (IXFR), QCLASS equal to the configured class of the zone, OPCODE = 0 (QUERY), RD = 0, a QID selected per ODS-FR-SPOOF-001, and the SOA record currently held in the in-memory zone store for the zone placed in the authority section of the query message.
*Source.* RFC 1995 §3.
*Note.* The SOA placed in the authority section conveys to the primary the version from which incremental changes are requested. Its TTL and complete RDATA — particularly the SERIAL field — must match what the secondary currently holds.
*Verification.* Wire-format inspection of outbound IXFR queries.

### Response mode detection

**ODS-FR-IXFR-004.** Upon receipt of the IXFR response, the server MUST determine the response mode by inspection of the answer section per RFC 1995 §4, distinguishing three modes:
- **Mode 1 (incremental):** the answer section's first record is an SOA, the second record is also an SOA, and the response contains at least one difference sequence terminating in a copy of the first SOA;
- **Mode 2 (full-zone fallback):** the answer section's first record is an SOA, the second record is a non-SOA resource record, and the response is structured as an AXFR-style full zone delivery;
- **Mode 3 (no update available):** the answer section contains exactly one SOA record, whose serial equals the serial of the SOA sent in the IXFR query.

The server MUST process the response according to the determined mode under ODS-FR-IXFR-005 (Mode 1), ODS-FR-IXFR-011 (Mode 2), or ODS-FR-IXFR-012 (Mode 3).
*Source.* RFC 1995 §3, §4.
*Verification.* IXFR conformance tests exercising each mode.

### Mode 1: Incremental processing

**ODS-FR-IXFR-005.** For a Mode 1 IXFR response, the server MUST process the difference sequences in the order they appear in the response. Each difference sequence is structured as:
- An "old SOA" record (the version from which changes apply);
- Zero or more resource records to be deleted from the zone state at the old SOA's serial;
- A "new SOA" record (the version to which changes apply);
- Zero or more resource records to be added to reach the new SOA's serial.

The server MUST apply the deletions and additions of each difference sequence in order, transforming the working zone state from the version at the IXFR query's SOA serial to the version at the response's outer SOA serial.
*Source.* RFC 1995 §4.
*Verification.* IXFR tests with single-step and multi-step difference sequences.

**ODS-FR-IXFR-006.** The first difference sequence in a Mode 1 IXFR response MUST begin with an "old SOA" record whose serial equals the serial of the SOA sent in the IXFR query's authority section. Mismatch MUST cause the IXFR session to be aborted per ODS-FR-IXFR-013.
*Source.* RFC 1995 §4.
*Verification.* IXFR tests with deliberately mismatched starting serials.

**ODS-FR-IXFR-007.** Where a Mode 1 IXFR response contains multiple difference sequences, the "new SOA" of each sequence MUST equal the "old SOA" of the next. The "new SOA" of the final difference sequence MUST equal the response's outer terminating SOA (which in turn equals the response's first SOA). Failure of either chaining condition MUST cause the IXFR session to be aborted per ODS-FR-IXFR-013.
*Source.* RFC 1995 §4.
*Verification.* IXFR tests with broken chaining.

**ODS-FR-IXFR-008.** Within each difference sequence, the server MUST verify that every resource record listed for deletion is currently present in the working zone state at the time the deletion is applied. A deletion of an absent record MUST cause the IXFR session to be aborted per ODS-FR-IXFR-013.
*Source.* RFC 1995 §4 (consistency requirement, defensive interpretation).
*Note.* This treats diff-state inconsistency as a hard error, on the principle that a primary delivering a diff inconsistent with the secondary's current state indicates either replication drift or compromise. Conservative implementations log and continue; this SRS specifies the strict posture. See closing note 1.
*Verification.* IXFR tests with diffs deleting records the secondary doesn't hold.

**ODS-FR-IXFR-009.** Within each difference sequence, the server MUST verify that every resource record listed for addition is not currently present in the working zone state at the time the addition is applied. Addition of an already-present record MUST cause the IXFR session to be aborted per ODS-FR-IXFR-013.
*Source.* RFC 1995 §4 (consistency requirement, defensive interpretation).
*Verification.* IXFR tests with diffs adding records already present.

**ODS-FR-IXFR-010.** Upon successful application of all difference sequences with all validations passing, the server MUST publish the resulting zone state atomically per ODS-INV-003. The previous zone state MUST remain in service to query handlers until publication of the new state is complete.
*Source.* ODS-INV-003.
*Verification.* Concurrent query tests during IXFR completion.

### Mode 2: Full-zone fallback

**ODS-FR-IXFR-011.** For a Mode 2 IXFR response, the server MUST process the response under the AXFR semantics of §4.6, treating the IXFR response's first SOA as the AXFR initial SOA and applying ODS-FR-AXFR-004 through ODS-FR-AXFR-023 for content validation, error handling, and atomic publication.
*Source.* RFC 1995 §3.
*Note.* Mode 2 is the primary's signal that incremental history is not available; the secondary transparently falls back to full-zone semantics within the same session, without re-issuing a query.
*Verification.* IXFR tests against primaries that respond in Mode 2.

### Mode 3: No update available

**ODS-FR-IXFR-012.** For a Mode 3 IXFR response, the server MUST treat the session as successfully completed with no zone change. The in-memory zone state MUST NOT be modified, and the zone's refresh timing under §4.16 MUST be advanced as it would be after any successful refresh check.
*Source.* RFC 1995 §3, §4.
*Verification.* IXFR tests with primaries reporting uptodate.

### Error handling

**ODS-FR-IXFR-013.** Upon any of the following conditions, the server MUST abort the IXFR session, close any TCP connection involved, discard all partially received and partially applied data without modifying the published zone state, emit a log entry at warning level identifying the failure cause and the affected zone and primary, and follow the retry semantics specified in §4.16:
- failure of any validation requirement of this subsection;
- failure of TSIG verification under ODS-FR-IXFR-014;
- premature connection close (TCP) before the terminating SOA is received;
- exceeding the session timeout under ODS-FR-IXFR-016;
- receipt of a response with non-zero RCODE;
- inconsistency between IXFR diff content and the working zone state per ODS-FR-IXFR-008 or ODS-FR-IXFR-009.

*Source.* RFC 1995 §3, §4; RFC 5936 §3.1.
*Verification.* Fault-injection tests covering each enumerated failure condition.

**ODS-FR-IXFR-014.** After an aborted IXFR session, the zone state machine specified in §4.16 MAY direct the next refresh attempt for the zone to use AXFR rather than IXFR. This is the recommended behaviour where the failure cause indicates non-support of the IXFR protocol by the primary (in particular, RCODE = 4 (NOTIMP) or RCODE = 1 (FORMERR) in response to an otherwise well-formed IXFR query).
*Source.* RFC 1995 §3.
*Note.* The decision logic for choosing AXFR vs IXFR on retry is specified in §4.16. This requirement establishes the architectural permission for the state machine to switch protocols, not the specific algorithm.
*Verification.* Tests with primaries that don't speak IXFR; verify retry uses AXFR.

### Authentication

**ODS-FR-IXFR-015.** Where TSIG is configured for the selected primary, the server MUST sign outbound IXFR queries with the configured TSIG key per §4.9, and MUST verify TSIG signatures on inbound IXFR response messages per §4.9. Failure of TSIG verification MUST cause the IXFR session to be aborted per ODS-FR-IXFR-013.
*Source.* RFC 8945 §5.3.1; RFC 1995.
*Note.* For Mode 2 (AXFR-style) IXFR responses, TSIG signature placement follows the multi-message rules of RFC 8945 §5.3.1 as specified for AXFR in ODS-FR-AXFR-018.
*Verification.* IXFR tests with valid signatures, missing required signatures, and tampered messages.

### Session lifecycle

**ODS-FR-IXFR-016.** The server MUST enforce a configurable timeout on IXFR sessions, with a default of 60 seconds. Sessions exceeding the timeout MUST be aborted per ODS-FR-IXFR-013.
*Source.* Operational requirement.
*Note.* IXFR is typically much faster than AXFR because the diff is small; 60 seconds is generous for the common case and short enough that a stuck IXFR session does not block the state machine for long. Operators with unusually large diffs or slow primaries can tune.
*Verification.* IXFR tests with simulated slow primary responses.

**ODS-FR-IXFR-017.** IXFR sessions MUST count against the same concurrent transfer session pool as AXFR sessions under ODS-FR-AXFR-022.
*Source.* Resource management.
*Verification.* Tests with mixed concurrent AXFR and IXFR initiations.

### Inherited requirements from §4.6

**ODS-FR-IXFR-018.** Except as specified or modified in this subsection, IXFR sessions are subject to the following requirements of §4.6, applied with "IXFR session" substituted for "AXFR session":
- header bit non-significance: ODS-FR-AXFR-006;
- class consistency in records: ODS-FR-AXFR-011;
- owner name within zone: ODS-FR-AXFR-012;
- glue records: ODS-FR-AXFR-013;
- occluded data handling: ODS-FR-AXFR-014;
- compression scope within messages: ODS-FR-AXFR-015;
- multi-primary failover: ODS-FR-AXFR-016.

*Source.* RFC 1995; this SRS §4.6.
*Note.* The traceability matrix in Appendix A records the duplication so that future edits to §4.6 surface IXFR impact for review.
*Verification.* Per the verification of each referenced AXFR requirement.

## 4.8 NOTIFY Handling

This subsection specifies the server's behaviour as a receiver of NOTIFY messages. The governing standard is RFC 1996. The server does not originate NOTIFY messages (a primary-side function); NOTIFY handling here is exclusively reception, validation, and the consequent triggering of refresh actions in the zone state machine (§4.16).

NOTIFY messages received from authorised sources cause expedited zone-refresh checks. The mechanism that decides whether and how to refresh in response is the zone state machine; this subsection specifies the message-level reception and the conditions under which the state machine is signalled.

The area code **NOTIFY** is allocated.

### Transport and reception

**ODS-FR-NOTIFY-001.** The server MUST accept NOTIFY messages on its configured UDP and TCP listening sockets (typically port 53), identifying NOTIFY by OPCODE = 4 in the message header per ODS-FR-CORE-005. Messages with QR = 1 (NOTIFY responses) MUST be silently discarded per ODS-FR-CORE-004.
*Source.* RFC 1996 §3.1.
*Note.* Because this server is secondary-only and does not originate NOTIFY, it has no legitimate need to receive NOTIFY responses; they are treated as stray traffic.
*Verification.* Reception tests on both UDP and TCP listening sockets; injected NOTIFY responses confirmed to be discarded.

### Message format validation

**ODS-FR-NOTIFY-002.** The server MUST verify that a received NOTIFY message has QDCOUNT = 1 and that the question section's QTYPE = 6 (SOA). Messages failing either check MUST be responded to with RCODE = 1 (FORMERR), echoing the QID and the OPCODE per the response construction of ODS-FR-NOTIFY-006.
*Source.* RFC 1996 §3.7.
*Verification.* Conformance tests with malformed NOTIFY messages.

**ODS-FR-NOTIFY-003.** If the QNAME and QCLASS in a received NOTIFY message do not match any zone configured to be served by this server, the server MUST respond with RCODE = 5 (REFUSED) and MUST take no further action on the message.
*Source.* RFC 1996 §3.10.
*Verification.* Tests with NOTIFY messages naming zones not served.

### Source authentication

**ODS-FR-NOTIFY-004.** The server MUST accept NOTIFY messages only from IP addresses configured as the primary (or other authorised notifier) for the named zone. NOTIFY messages from unauthorised source addresses MUST be silently discarded; the server MUST NOT emit a response of any kind. The discard MUST be logged at warning level, including the source IP address and the NOTIFY's QNAME.
*Source.* RFC 1996 §3.10, §3.11; defensive operational posture.
*Note.* Silent discard (rather than REFUSED) is selected to avoid revealing to unauthorised parties which zones the server serves. The log entry is the operator's signal for investigation. The authorised source list is established by configuration alongside the primaries list for the zone (§6.2).
*Verification.* Tests with NOTIFY messages from unauthorised source addresses; verify no response emitted and discard logged.

### TSIG authentication

**ODS-FR-NOTIFY-005.** Where TSIG is configured for an authorised notifier of a zone, NOTIFY messages from that notifier MUST be signed with the configured TSIG key. The server MUST verify TSIG signatures on such inbound NOTIFY messages per §4.9 before any further processing. TSIG verification failure MUST cause the NOTIFY to be rejected with the TSIG-specific response defined in §4.9, and MUST be logged at warning level.
*Source.* RFC 8945; RFC 1996.
*Note.* TSIG verification follows source-IP authorisation: an IP-unauthorised source's message is silently discarded under ODS-FR-NOTIFY-004 and never reaches TSIG validation. An IP-authorised source with a TSIG failure does receive a TSIG-protocol response, because the failure mode is meaningful to a legitimately configured sender.
*Verification.* Tests with valid TSIG-signed NOTIFYs, tampered TSIG-signed NOTIFYs, and NOTIFYs missing required TSIG.

### Response

**ODS-FR-NOTIFY-006.** Upon successful validation of a NOTIFY message — OPCODE, message format (ODS-FR-NOTIFY-002), zone served (ODS-FR-NOTIFY-003), source authorisation (ODS-FR-NOTIFY-004), and TSIG verification where applicable (ODS-FR-NOTIFY-005) — the server MUST emit a NOTIFY response message on the same transport (UDP or TCP) as the received NOTIFY, containing:
- the QID of the received NOTIFY, echoed unchanged;
- QR = 1;
- OPCODE = 4 (NOTIFY);
- AA = 1;
- RCODE = 0 (NOERROR);
- the question section copied verbatim from the received NOTIFY;
- a freshly computed TSIG record per §4.9 where the received NOTIFY was TSIG-signed.

*Source.* RFC 1996 §4.7, §4.8; RFC 8945.
*Verification.* Wire-format inspection of NOTIFY responses across valid input scenarios.

### Refresh triggering

**ODS-FR-NOTIFY-007.** Upon successful acceptance of a NOTIFY message for a zone, and subject to the rate-limit deduplication of ODS-FR-NOTIFY-009, the server MUST signal the zone state machine (§4.16) to perform an expedited refresh check for the named zone.
*Source.* RFC 1996 §4.4.
*Note.* The state machine determines whether the refresh check is satisfied by the SOA embedded in the NOTIFY (per ODS-FR-NOTIFY-008), an out-of-band SOA poll, or proceeding directly to IXFR; this requirement establishes only the signalling.
*Verification.* Tests confirming refresh check is initiated within an operationally meaningful time of NOTIFY acceptance.

**ODS-FR-NOTIFY-008.** Where a received NOTIFY message contains an SOA record in the answer section per RFC 1996 §3.7, the server MUST verify that the SOA's owner name matches the NOTIFY's QNAME and that its class matches QCLASS. The serial field of this SOA MAY be used by the state machine (§4.16) to skip the SOA poll and proceed directly to refresh if the serial exceeds the currently held serial. Fields of the embedded SOA other than the serial — REFRESH, RETRY, EXPIRE, MINIMUM — MUST NOT be applied to the zone's timer state; those fields are governed only by the SOA delivered via completed zone transfer.
*Source.* RFC 1996 §3.7, §4.5.
*Verification.* Tests with NOTIFY messages carrying SOAs in answer section, including mismatched owner names, mismatched classes, and serials greater, equal, and lesser than the currently held serial.

### Rate-limit deduplication

**ODS-FR-NOTIFY-009.** The server MUST respond to every well-formed NOTIFY message per ODS-FR-NOTIFY-006 (subject to the source-authorisation requirement of ODS-FR-NOTIFY-004), but MUST NOT signal the state machine to initiate a new refresh cycle for a zone if a refresh for that zone is already in progress or has completed within a configurable deduplication interval. The default deduplication interval MUST be 1 second.
*Source.* RFC 1996 §3.6, §4.4.
*Note.* RFC 1996 §3.6 anticipates NOTIFY retransmission by the primary. The receiver should always respond (to suppress retransmission), but should not multiply refresh efforts on duplicate signals. Duplicate-suppression is per-zone, not per-(source, zone) — multiple authorised notifiers for the same zone do not multiply refresh actions.
*Verification.* Tests with bursts of NOTIFY messages for the same zone; verify all are responded to but only one refresh is initiated.

### Logging

**ODS-FR-NOTIFY-010.** The server MUST emit a log entry at info level for each accepted NOTIFY message, recording at minimum the source IP address, the QNAME, the embedded SOA serial (where present per ODS-FR-NOTIFY-008), and the action taken (refresh signalled, or deduplicated). Discards and rejections MUST be logged at warning level per ODS-FR-NOTIFY-004 and ODS-FR-NOTIFY-005.
*Source.* Operational requirement; RFC 8906 (operational visibility).
*Verification.* Log inspection across acceptance, deduplication, and rejection scenarios.

## 4.9 TSIG Authentication

This subsection specifies the server's implementation of Transaction SIGnature (TSIG) authentication for DNS protocol exchanges. The governing standards are RFC 8945 (TSIG, which obsoletes RFC 2845) and RFC 4635 (HMAC SHA algorithm identifiers). TSIG provides per-message authentication and integrity using shared symmetric keys; it is applied to:

- outbound queries from the server to configured primaries (SOA polls, AXFR queries, IXFR queries) and the inbound responses to them;
- inbound NOTIFY messages and the outbound responses to them.

TSIG is not used between the server and ordinary DNS clients in standard operation; a TSIG record on a client query received from a non-primary source is processed only as far as required to identify the absence of a matching configured key and to return the appropriate TSIG-error response.

The area code **TSIG** is allocated.

### Supported algorithms

**ODS-FR-TSIG-001.** The server MUST implement and accept the HMAC-SHA256 algorithm for TSIG signing and verification (algorithm name `hmac-sha256`).
*Source.* RFC 8945 §6; RFC 4635 §3.
*Verification.* Cryptographic test vectors per RFC 4231.

**ODS-FR-TSIG-002.** The server MUST implement and accept the HMAC-SHA1 algorithm for TSIG signing and verification (algorithm name `hmac-sha1`).
*Source.* RFC 4635 §3.
*Rationale.* SHA-1-based TSIG remains widely deployed in primary implementations and operator configurations; support is required for interoperability.
*Verification.* Cryptographic test vectors per RFC 2202.

**ODS-FR-TSIG-003.** The server SHOULD implement and accept the HMAC-SHA384 and HMAC-SHA512 algorithms (algorithm names `hmac-sha384` and `hmac-sha512`).
*Source.* RFC 4635 §3.
*Rationale.* These algorithms are part of the HMAC-SHA family and add negligible implementation complexity once SHA-256 is supported; their inclusion future-proofs the server against operators choosing stronger algorithms.
*Verification.* Cryptographic test vectors per RFC 4231.

**ODS-FR-TSIG-004.** The server MUST NOT implement the HMAC-MD5 algorithm (algorithm name `hmac-md5.sig-alg.reg.int`). Where a received message bears a TSIG record carrying this algorithm name, the server MUST respond per ODS-FR-TSIG-015 with a BADALG TSIG error (error code 21).
*Source.* RFC 8945 §6 ("hmac-md5 MUST NOT be used by new implementations").
*Verification.* Reception tests with HMAC-MD5-signed messages; verify BADALG response.

### Key configuration and storage

**ODS-FR-TSIG-005.** TSIG keys MUST be configured at process startup per §6.2 and MUST be immutable for the lifetime of the process, in accordance with ODS-INV-005. Each key entry comprises a key name (a DNS name), an algorithm identifier, and a shared secret.
*Source.* ODS-INV-005; RFC 8945 §3.
*Verification.* Configuration round-trip tests; runtime configuration mutation attempts (none should be possible).

**ODS-FR-TSIG-006.** Shared secret material MUST NOT appear in log output at any verbosity level, MUST NOT appear in error messages or diagnostic output of any kind, and MUST be zeroed in process memory at process termination.
*Source.* Standard cryptographic key handling; defensive operational posture.
*Verification.* Static analysis of log statements; review of error-formatting code paths; memory inspection at shutdown.

### Inbound message verification

**ODS-FR-TSIG-007.** In a received DNS message bearing a TSIG record, the TSIG record MUST appear as the last record in the additional section. Messages with TSIG in any other position, or with more than one TSIG record, MUST be rejected with RCODE = 1 (FORMERR).
*Source.* RFC 8945 §5.2.
*Verification.* Conformance tests with TSIG records in non-final positions and with duplicate TSIG records.

**ODS-FR-TSIG-008.** Upon detection of a TSIG record in a received message, the server MUST perform verification in the following order. The first check to fail terminates verification and produces the corresponding error response per ODS-FR-TSIG-015:
- (a) Locate the matching key by the TSIG record's owner name; absence of a matching key produces BADKEY (error code 17).
- (b) Verify that the algorithm name in the TSIG RDATA matches the algorithm configured for the key; mismatch produces BADKEY (per RFC 8945 §5.2.2).
- (c) Verify that the absolute difference between the server's current time and the time-signed field of the TSIG RDATA does not exceed the fudge value; exceedance produces BADTIME (error code 18).
- (d) Compute the expected MAC over the message — with the TSIG record removed and the header ID field temporarily restored to the original-ID field of the TSIG RDATA — using the configured secret and algorithm.
- (e) Compare the computed MAC with the received MAC; mismatch produces BADSIG (error code 16).

A message is considered authenticated only when all five checks pass.
*Source.* RFC 8945 §5.4.
*Verification.* Tests injecting failures at each check stage.

**ODS-FR-TSIG-009.** MAC comparison during TSIG verification MUST be performed using a constant-time comparison function that does not leak timing information about the position of any byte mismatch.
*Source.* Standard cryptographic practice; defence against timing-attack side channels.
*Verification.* Code review confirming use of a constant-time comparison primitive; the implementation choice (e.g., `subtle` crate) is recorded in the Architecture Document.

### Multi-message TSIG for AXFR and IXFR

**ODS-FR-TSIG-010.** For a multi-message TSIG-signed response (an AXFR or IXFR Mode 2 response in reply to a signed query), the server MUST verify that at least one TSIG-signed message appears within every window of 100 consecutive envelopes of the response stream. A gap exceeding 100 envelopes between consecutive signed messages MUST cause the session to be aborted with a TSIG verification failure logged at warning level.
*Source.* RFC 8945 §5.3.1.
*Verification.* Test response streams with various TSIG placement patterns including gaps at and beyond 100 envelopes.

**ODS-FR-TSIG-011.** For multi-message TSIG-signed responses, the server MUST maintain the cumulative MAC envelope context required by RFC 8945 §5.3.1: the MAC of the originating signed query is the prior-MAC input to the first response message's MAC computation; each subsequently verified TSIG MAC becomes the prior-MAC input to the next signed message's MAC computation. The server MUST advance and verify this state correctly across the response stream.
*Source.* RFC 8945 §5.3.1.
*Verification.* Conformance tests with primaries known to implement multi-message TSIG correctly; cross-implementation interop tests against BIND, NSD, and Knot.

### Outbound signing

**ODS-FR-TSIG-012.** When the server originates a DNS message destined for a peer with which a TSIG key is configured (AXFR query, IXFR query, SOA poll query, NOTIFY response), the server MUST sign the message by appending a TSIG record to the additional section. The TSIG RDATA MUST be constructed per RFC 8945 §5.3 with:
- algorithm name and shared secret taken from the configured key;
- time signed set to the server's current time at signing;
- fudge set to a configurable value with a default of 300 seconds;
- original ID set to the message's QID;
- MAC computed over the message (and the prior-MAC envelope context where applicable per ODS-FR-TSIG-011);
- error and other-len fields set to zero.

*Source.* RFC 8945 §5.3.
*Verification.* Wire-format inspection of outbound signed messages; cryptographic verification against the configured key.

### Error responses

**ODS-FR-TSIG-013.** When the server detects a TSIG verification failure on an inbound message and the source is one to which a response is appropriate (i.e., an authorised primary or notifier per §4.6, §4.7, or §4.8 — not an unauthorised source under ODS-FR-NOTIFY-004, which is silently discarded), the server MUST respond per RFC 8945 §5.2.2 with:
- RCODE = 9 (NOTAUTH);
- a TSIG record in the response's additional section carrying the appropriate error code in its error field;
- for BADTIME errors, the server's current time included in the "other data" field of the TSIG record (to allow the remote side to detect and resolve the clock skew);
- for BADKEY, BADSIG, BADALG, and BADTRUNC errors, the TSIG record's MAC field MAY be zero-length, since the key in question cannot be relied upon as a basis for a verifiable response.

*Source.* RFC 8945 §5.2.2, §5.4.
*Verification.* Conformance tests across all TSIG error conditions.

### MAC truncation

**ODS-FR-TSIG-014.** The server MUST accept TSIG records on inbound messages with MAC sizes within the per-algorithm range specified by RFC 8945 §5.2.2.1 and RFC 4635 §3.1. MACs smaller than the minimum permitted truncation length for the algorithm MUST cause a BADTRUNC TSIG error (error code 22) per ODS-FR-TSIG-013.
*Source.* RFC 8945 §5.2.2.1; RFC 4635 §3.1.
*Verification.* Conformance tests with truncated MACs at the minimum permitted size and below.

**ODS-FR-TSIG-015.** When the server signs an outbound message, the TSIG record MUST carry the MAC at the full output length of the algorithm, without truncation.
*Source.* RFC 8945 §10.5 (truncation provides no significant benefit and is discouraged).
*Verification.* Wire-format inspection of outbound signed messages.

### Oversized UDP responses

**ODS-FR-TSIG-016.** Where a TSIG-signed response message would exceed the available UDP message size (the smaller of the inbound EDNS0-advertised buffer size and the server's own configured maximum), the server MUST set the TC bit in the response, omit the TSIG record, and respond with the truncated header — signalling to the remote side to retry the operation over TCP.
*Source.* RFC 8945 §5.2.1.
*Note.* In practice this case is rare for the message types the server signs (NOTIFY responses are small); the requirement is for correctness under boundary conditions.
*Verification.* Tests with artificially low EDNS0 buffer sizes forcing truncation of signed responses.

### Logging

**ODS-FR-TSIG-017.** The server MUST log TSIG events as follows:
- successful inbound verification: debug level, with at minimum key name and source IP;
- successful outbound signing: debug level, with at minimum key name and destination IP;
- any TSIG error (BADKEY, BADSIG, BADTIME, BADALG, BADTRUNC), inbound or outbound: warning level, with at minimum key name, error type, peer IP, message direction, and timestamp.

MAC values, shared secret material, and any other key-derived material MUST NOT appear in any log entry at any level.
*Source.* Operational requirement informed by RFC 8906; security requirement for key material confidentiality.
*Verification.* Log inspection across success and failure scenarios; static analysis of log-statement contents.

## 4.10 Zone Transfer over TLS (XoT)

This subsection specifies the server's behaviour as an XoT (Zone Transfer over TLS) client. The governing standard is RFC 9103. XoT provides confidentiality and channel integrity for zone-transfer traffic by tunnelling AXFR and IXFR exchanges inside TLS, complementing the per-message authentication provided by TSIG (§4.9).

The scope of XoT within this server is limited to **outbound** zone-transfer connections to configured primaries. The server does not implement an XoT listener; inbound NOTIFY messages from primaries continue to be received over standard UDP and TCP transports per §4.8. The decision to enable XoT is per (zone, primary) tuple in configuration; when enabled, all transfers from the affected primary use XoT exclusively, and the protocol mechanics of §4.6 (AXFR) and §4.7 (IXFR) operate inside the TLS tunnel without further modification.

The area code **XOT** is allocated.

### TLS configuration

**ODS-FR-XOT-001.** The server MUST implement TLS 1.2 (RFC 5246) for XoT connections, and SHOULD implement TLS 1.3 (RFC 8446). Where both endpoints support TLS 1.3, it MUST be selected in preference to TLS 1.2 during TLS version negotiation.
*Source.* RFC 9103 §7.1.
*Note.* TLS 1.3 is the preferred version for new deployments. The TLS 1.2 requirement provides interoperability with primary implementations that have not yet deployed TLS 1.3 but have deployed XoT.
*Verification.* Handshake tests against test peers offering TLS 1.2 only, TLS 1.3 only, and both.

**ODS-FR-XOT-002.** TLS cipher-suite selection MUST conform to the current recommendations of BCP 195 (RFC 9325): authenticated encryption with associated data (AEAD) cipher suites only; NULL, anonymous, RC4, 3DES, and export-grade cipher suites MUST NOT be offered or accepted. The specific suite list is determined by the underlying TLS implementation but MUST fall within these constraints.
*Source.* BCP 195 (RFC 9325).
*Verification.* TLS handshake-capture tests; the offered ClientHello cipher list MUST be entirely AEAD with no prohibited suites.

### Transport

**ODS-FR-XOT-003.** The server MUST initiate XoT connections to the configured primary on TCP port 853 by default. The destination port MUST be overridable per (zone, primary) tuple in configuration.
*Source.* RFC 9103 §6.
*Verification.* Connection-layer inspection during XoT initiation; configurable-port tests.

**ODS-FR-XOT-004.** XoT connections MUST present the ALPN protocol identifier `dot` (RFC 7858) during TLS negotiation. Failure of the primary to confirm ALPN `dot` MUST cause the XoT session to be aborted per ODS-FR-XOT-010.
*Source.* RFC 9103 §7.4.
*Verification.* TLS handshake inspection; tests against peers not confirming `dot` ALPN.

### Authentication

**ODS-FR-XOT-005.** The server MUST authenticate the primary's TLS certificate using X.509 PKIX path validation against the configured trust anchors, in accordance with RFC 5280. The configured primary hostname MUST be presented as the TLS SNI (RFC 6066) during the handshake, and the primary's certificate MUST present a matching SubjectAltName entry. Validation failure for any reason — expired certificate, untrusted issuer, hostname mismatch, malformed certificate — MUST cause the XoT session to be aborted per ODS-FR-XOT-010.
*Source.* RFC 9103 §9.1; RFC 5280; RFC 6066.
*Verification.* Tests with expired, untrusted, mismatched-name, and otherwise-invalid certificates.

### Profile and fallback prohibition

**ODS-FR-XOT-006.** Where XoT is configured for a (zone, primary) tuple, the server MUST apply the Strict Profile of RFC 9103 §9.1: TLS is mandatory, certificate authentication per ODS-FR-XOT-005 is mandatory, and the server MUST NOT establish an XoT session without successful TLS handshake and certificate authentication. The Opportunistic Privacy Profile of RFC 9103 §9.2 MUST NOT be used. The server MUST NOT fall back to unencrypted TCP transport when an XoT connection or authentication fails.
*Source.* RFC 9103 §9.1, §9.2.
*Verification.* Tests confirming that TLS failures result in transfer abort, not cleartext retry. Code review confirming no Opportunistic-Profile code path exists.

### Mutual TLS (optional)

**ODS-FR-XOT-007.** The server MAY present a client certificate during the TLS handshake for mutual authentication (mTLS), where configured per (zone, primary) tuple, in accordance with RFC 9103 §9.4. The client certificate and the corresponding private key MUST be supplied via configuration per §6.2 and MUST be subject to the key-material handling requirements analogous to TSIG key material under ODS-FR-TSIG-006.
*Source.* RFC 9103 §9.4.
*Verification.* Configuration round-trip tests; handshake tests against primaries requiring client certificates.

### Combination with TSIG

**ODS-FR-XOT-008.** XoT and TSIG MAY be configured concurrently for the same (zone, primary) tuple. Where both are configured, TSIG signing and verification per §4.9 MUST be performed in addition to the TLS protection of XoT; neither mechanism supersedes the other. TLS provides channel confidentiality and certificate-based identity; TSIG provides per-message integrity that survives connection boundaries.
*Source.* RFC 9103 §9.3.
*Verification.* Conformance tests with peers configured for XoT-only, TSIG-only, XoT+TSIG, and neither.

### Connection management

**ODS-FR-XOT-009.** The server MAY reuse an established XoT TCP connection for successive zone transfers from the same primary, applying the connection-persistence semantics of RFC 7766 (§4.12) within the TLS tunnel.
*Source.* RFC 9103 §6.5; RFC 7766.
*Verification.* Connection-management tests with multiple sequential transfers to the same primary.

### Error handling and logging

**ODS-FR-XOT-010.** TLS handshake failures, certificate validation failures, ALPN negotiation failures, and TLS-protocol errors during an XoT session MUST cause the affected transfer session to be aborted in the manner prescribed by ODS-FR-AXFR-019 (for AXFR) or ODS-FR-IXFR-013 (for IXFR). The state-machine retry semantics of §4.16 apply unchanged.
*Source.* RFC 9103 §7; this SRS §4.6, §4.7.
*Verification.* Fault-injection tests across TLS error categories.

**ODS-FR-XOT-011.** XoT events MUST be logged as follows:
- successful handshake and session establishment: info level, with at minimum peer IP address, SNI presented, negotiated TLS version, and negotiated cipher suite;
- handshake failure, certificate validation failure, ALPN failure: warning level, with at minimum peer IP address, SNI presented, and the failure cause;
- session termination: info level, with at minimum peer IP, session duration, and bytes transferred.

Certificate material and private key material MUST NOT appear in any log entry. Negotiated session keys, master secrets, and any TLS key-derivation material MUST NOT appear in any log entry.
*Source.* Operational requirement; security requirement for cryptographic material confidentiality.
*Verification.* Log inspection across success and failure scenarios; static analysis of log-statement contents.

## 4.11 EDNS0

This subsection specifies the server's implementation of Extension Mechanisms for DNS (EDNS0). The governing standards are RFC 6891 (base EDNS0), RFC 7828 (edns-tcp-keepalive option), and RFC 7830 (EDNS(0) Padding option). EDNS0 extends DNS messages to carry larger UDP payloads, signal protocol-version capabilities, and convey extensible options between requestor and responder.

The interaction between EDNS0 UDP payload negotiation and TCP fallback is governed jointly by this subsection and §4.12; the response truncation behaviour (TC bit setting and message construction under size constraints) is specified in §4.12, while the determination of the applicable UDP size ceiling is specified here.

EDNS options not enumerated in this subsection are recognised as unknown and handled per ODS-FR-EDNS-014. EDNS Client Subnet (RFC 7871), DNS Cookies (RFC 7873), and EDNS Expire (RFC 7314) are not in scope per PID Appendix A.

The area code **EDNS** is allocated.

### OPT RR parsing

**ODS-FR-EDNS-001.** The server MUST parse the OPT pseudo-RR (RFC 6891 §6.1) when it appears in inbound DNS messages, decoding the fixed fields (owner name, TYPE, class, TTL containing extended-RCODE / VERSION / DO / Z, RDLENGTH) and the RDATA option pairs (option-code, option-length, option-data). RDATA whose options are not bit-exact consumable up to RDLENGTH (option-length exceeding remaining RDATA, trailing octets, or other framing defects) MUST cause the message to be rejected with RCODE = 1 (FORMERR).
*Source.* RFC 6891 §6.1.2.
*Verification.* Wire-format conformance tests with valid, oversized-option-length, and trailing-octet OPT RDATA.

**ODS-FR-EDNS-002.** Inbound DNS messages MUST contain at most one OPT RR. Messages containing two or more OPT RRs MUST be rejected with RCODE = 1 (FORMERR).
*Source.* RFC 6891 §6.1.1.
*Verification.* Conformance tests with multiple OPT RRs.

**ODS-FR-EDNS-003.** An OPT RR in an inbound message MUST appear in the additional section with the root name (".") as its owner name and TYPE = 41. OPT RRs appearing in the answer, authority, or question sections, or carrying any owner name other than the root, MUST cause the message to be rejected with RCODE = 1 (FORMERR).
*Source.* RFC 6891 §6.1.1, §6.1.2.
*Verification.* Conformance tests.

### Version handling

**ODS-FR-EDNS-004.** The server MUST accept inbound OPT RRs with the VERSION field equal to 0. Inbound OPT RRs with VERSION > 0 MUST cause the server to respond with extended RCODE = 16 (BADVERS), with the response carrying an OPT RR whose VERSION field is 0 — indicating the highest EDNS version supported by the server.
*Source.* RFC 6891 §6.1.3.
*Verification.* Conformance tests across VERSION values 0, 1, 2, 255.

### UDP payload size negotiation

**ODS-FR-EDNS-005.** The class field of an inbound OPT RR advertises the requestor's maximum UDP payload size. The server MUST treat class-field values below 512 as equal to 512 in subsequent processing; values at 512 and above MUST be used as advertised, subject to the upper bound established by ODS-FR-EDNS-006.
*Source.* RFC 6891 §6.2.3.
*Verification.* Wire-format conformance tests with advertised payload sizes of 0, 256, 512, 1232, 4096, and 65535.

**ODS-FR-EDNS-006.** The server MUST enforce a configurable maximum UDP response size, with a default of 1232 octets. The applied UDP payload size ceiling for any given response MUST be the lesser of the requestor's advertised payload size (after ODS-FR-EDNS-005 normalisation) and the server's configured maximum. Responses that would exceed this ceiling MUST trigger truncation as specified in §4.12.
*Source.* RFC 6891 §6.2.5; DNS Flag Day 2020 consensus (1232 octets is the widely-adopted ceiling avoiding IP fragmentation on the public Internet).
*Verification.* Tests at the boundary of the ceiling; tests confirming TC bit is set per §4.12.

### Response OPT RR

**ODS-FR-EDNS-007.** Where an inbound query contained an OPT RR, the response MUST include an OPT RR in its additional section. Where an inbound query did not contain an OPT RR, the response MUST NOT include an OPT RR.
*Source.* RFC 6891 §6.1.1; RFC 6891 §7.
*Verification.* Wire-format inspection of responses across queries with and without OPT.

**ODS-FR-EDNS-008.** The OPT RR included in a response MUST have owner name ".", TYPE = 41, the class field set to the server's configured maximum UDP payload size (default 1232), the VERSION field set to 0, and the Z bits (other than DO) set to 0.
*Source.* RFC 6891 §6.1.
*Verification.* Wire-format inspection of response OPT RRs.

**ODS-FR-EDNS-009.** The DO bit in the response OPT RR's TTL field MUST be set in accordance with the DNSSEC response semantics specified in §4.13. The setting of DO in the response does not echo the query's DO setting verbatim; the §4.13 requirements govern.
*Source.* RFC 6891 §6.1.4; RFC 4035 §3.2.1.
*Verification.* Per §4.13.

### Extended RCODE

**ODS-FR-EDNS-010.** Where the server's response uses an RCODE in the extended range (16 or greater), the high 8 bits of the response OPT RR's TTL field MUST encode the upper 8 bits of the 12-bit extended RCODE, with the low 4 bits of the RCODE encoded in the response header's RCODE field. For RCODEs in the range 0–15, the extended-RCODE field (high 8 bits of the OPT TTL) MUST be 0.
*Source.* RFC 6891 §6.1.3.
*Verification.* Conformance tests with extended RCODEs including BADVERS (16) and BADTRUNC (22 — see also §4.9 TSIG).

### TCP Keepalive option (RFC 7828)

**ODS-FR-EDNS-011.** The server MUST recognise the edns-tcp-keepalive option (option code 11) per RFC 7828 in inbound queries received over TCP. The option MUST be silently ignored when received in queries over UDP, in accordance with RFC 7828 §3.4.
*Source.* RFC 7828 §3.4.
*Verification.* Conformance tests with the option on both transports.

**ODS-FR-EDNS-012.** In responses to TCP queries that included the edns-tcp-keepalive option, the server MUST include an edns-tcp-keepalive option in the response OPT RR's RDATA, advertising the server's idle-timeout policy expressed in 100-millisecond units per RFC 7828 §3.1. The advertised timeout value MUST be configurable, with a default of 300 (= 30 seconds).
*Source.* RFC 7828 §3.
*Note.* TCP connection persistence and idle timeout management are specified in §4.12; the edns-tcp-keepalive option is the wire-level advertisement of the policy.
*Verification.* Wire-format inspection of responses to TCP queries that requested keepalive.

### Padding option (RFC 7830)

**ODS-FR-EDNS-013.** The server MUST recognise the Padding option (option code 12) per RFC 7830 in inbound queries. The server MAY include a Padding option in its response when configured to do so; the padding policy is operator-configurable with a default of no padding applied.
*Source.* RFC 7830; RFC 8467 (informative).
*Note.* RFC 7830 specifies padding as discretionary on the responder side. For an authoritative server operating over standard UDP and TCP (without DoT or DoH), padding offers limited privacy benefit beyond what the standard transports provide; padding is more relevant in DoT/DoH paths. Default-off accordingly. If the team subsequently brings DoT or DoH into scope, the default may warrant revisiting.
*Verification.* Conformance tests with padding configured on and off.

### Unknown options

**ODS-FR-EDNS-014.** The server MUST silently ignore OPT options whose option codes it does not recognise in inbound messages. Unknown options MUST NOT cause the message to be rejected.
*Source.* RFC 6891 §6.1.2.
*Verification.* Conformance tests with synthetic option codes outside the recognised set.

## 4.12 TCP Transport

This subsection specifies the server's implementation of DNS over TCP. The governing standard is RFC 7766, which raised TCP from an optional fallback transport to a first-class requirement. TCP serves three roles for this server: as the carrier for responses too large to fit within UDP payload limits (where the server signals TC and the client retries over TCP), as the mandatory transport for AXFR and IXFR queries to primaries (§4.6, §4.7), and as an optional transport for NOTIFY messages (§4.8).

The interaction with EDNS0 — the UDP payload size negotiation that drives truncation, and the edns-tcp-keepalive option that influences idle timeout — is specified in §4.11. The interaction with XoT, where TCP is encapsulated in TLS, is specified in §4.10.

The area code **TCP** is allocated.

### Message framing

**ODS-FR-TCP-001.** DNS messages exchanged over TCP MUST be framed with a 2-octet length prefix in network byte order, followed by the DNS message of exactly the indicated length. Multiple DNS messages MAY be exchanged on the same TCP connection, each independently framed. A length prefix value of 0 MUST cause the connection to be closed, with a log entry at warning level recording the malformed framing.
*Source.* RFC 7766 §8; RFC 1035 §4.2.2.
*Verification.* TCP framing tests with valid frames, zero-length frames, frames where declared length exceeds remaining stream data, and back-to-back frames.

### Inbound connection lifecycle

**ODS-FR-TCP-002.** The server MUST keep accepted TCP connections open for receipt of subsequent queries from the same client until any of the following: idle timeout under ODS-FR-TCP-003, read or write timeout under ODS-FR-TCP-004, client-initiated TCP close, the global concurrent connection limit under ODS-FR-TCP-005 requires reclamation, or server shutdown.
*Source.* RFC 7766 §6.2.1.
*Verification.* Connection-management tests confirming connections persist across multiple queries.

**ODS-FR-TCP-003.** The server MUST enforce a configurable TCP idle timeout on accepted connections, with a default of 30 seconds. The applied timeout MAY be reduced below the configured default for individual connections where the client advertises a shorter timeout via the edns-tcp-keepalive option (ODS-FR-EDNS-012). Idle is measured from the completion of the last message exchange (response sent or query received). Connections idle beyond the applied timeout MUST be closed by the server with a TCP FIN.
*Source.* RFC 7766 §6.2.3; RFC 7828 §3.
*Verification.* Connection-lifecycle tests with varied client edns-tcp-keepalive values; verify timeout is enforced and connection is closed with FIN.

**ODS-FR-TCP-004.** The server MUST enforce configurable read and write timeouts on accepted TCP connections, with defaults of 30 seconds each. Read operations that fail to receive any data within the read timeout, or write operations that fail to make progress within the write timeout, MUST cause the connection to be closed with a TCP RST.
*Source.* Operational requirement; defensive against slow-loris-style resource exhaustion.
*Verification.* Tests with simulated slow clients.

### Concurrency limits

**ODS-FR-TCP-005.** The server MUST limit the number of concurrently accepted TCP connections to a configurable maximum, with a default of 1024. New connection attempts when the limit is reached MUST be either refused at the TCP layer or accepted and immediately closed; the choice is implementation-defined and recorded in the Architecture Document. Connection refusal due to the limit MUST be logged at warning level.
*Source.* RFC 7766 §10; resource management.
*Verification.* Tests at and beyond the concurrent connection limit.

**ODS-FR-TCP-006.** The server MAY enforce a configurable per-source-IP TCP connection limit. The default policy is no per-source-IP limit beyond the global limit of ODS-FR-TCP-005. Where configured, connection attempts from an IP address at its per-IP cap MUST be refused or immediately closed, with the refusal logged at info level.
*Source.* Operational requirement; defence against single-client connection exhaustion.
*Verification.* Tests with configured per-IP limits.

### Pipelining and out-of-order responses

**ODS-FR-TCP-007.** The server MUST accept multiple in-flight queries on a single TCP connection (query pipelining). The server MAY emit responses to pipelined queries in any order, with responses matched to queries by the QID field of the response header. The server MUST process queries as resources permit, without imposing implicit ordering between independent queries on the same connection.
*Source.* RFC 7766 §6.2.
*Verification.* Pipelined-query tests verifying responses are emitted and correctly matched.

### Truncation and TCP fallback

**ODS-FR-TCP-008.** Where a UDP response would exceed the applicable UDP payload size ceiling determined per ODS-FR-EDNS-006, the server MUST construct a truncated response per RFC 1035 §4.2.1: the TC bit in the response header MUST be set to 1, and resource records MUST be removed from the response in the following order until the response fits within the ceiling:
- (a) additional section records, with the exception of the OPT RR (which is retained for EDNS response context);
- (b) authority section records other than any SOA record required to be present under §4.3 (NRESP) for NXDOMAIN or NODATA semantics;
- (c) answer section records.

The truncated response MUST be emitted with the TC bit set, and the client is expected to retry the original query over TCP.
*Source.* RFC 1035 §4.2.1; RFC 2181 §9.
*Verification.* Tests near and beyond the UDP payload ceiling, verifying truncation order and TC bit setting; inspection of retained OPT RR and SOA where applicable.

### Outbound TCP connections

**ODS-FR-TCP-009.** TCP connections initiated by the server toward primaries (for AXFR per §4.6, IXFR per §4.7, SOA poll where TCP is used, or NOTIFY response where TCP was the incoming transport) MUST use the same 2-octet length-prefix framing specified in ODS-FR-TCP-001. The server MAY reuse a single TCP connection to a primary for multiple outbound queries, subject to the primary's connection-management policy and the connection persistence requirements of RFC 7766 §6.
*Source.* RFC 7766 §8; RFC 5936 §4.1.
*Verification.* Outbound TCP framing tests; connection-reuse tests for multiple sequential queries.

**ODS-FR-TCP-010.** The server MUST enforce a configurable timeout on outbound TCP connection establishment, with a default of 10 seconds. Connection attempts that fail to establish within the timeout MUST be abandoned; the failure MUST be treated as a transfer or query failure under the relevant requirements of §4.6, §4.7, or §4.16 (zone state machine).
*Source.* Operational requirement.
*Verification.* Tests with simulated unreachable primaries.

## 4.13 DNSSEC Record Serving

This subsection specifies the server's behaviour with respect to DNSSEC, restricted to the serve-only role. The server transfers DNSSEC records from the primary and serves them faithfully; it does not sign, does not generate denial-of-existence proofs, does not validate signatures, and does not manage key material. The primary is the sole source of all signed data.

The governing standards within this scope are RFC 4033 (introduction), RFC 4034 (DNSSEC resource records), RFC 4035 (protocol modifications), RFC 5155 (NSEC3), RFC 6840 (clarifications), and RFC 6944 (algorithm requirements). The corresponding primary-side standards — DNSKEY generation, signing, NSEC/NSEC3 chain construction, RFC 5011 key rollover — are explicitly excluded per PID §3.2 and ODS-INV-001.

CDS (type 59) and CDNSKEY (type 60) records, where present in a transferred zone, are handled under the unknown-RR semantics of §4.4 — their wire format is preserved and they are served on direct query, but no type-aware processing is required. They are not enumerated as known DNSSEC types below.

The area code **DNSSEC** is allocated.

### DNSSEC record types

**ODS-FR-DNSSEC-001.** The server MUST implement type-aware parsing, storage, and serving of the following DNSSEC resource record types, in accordance with the wire formats specified in RFC 4034 and RFC 5155:
- DNSKEY (type 48), RFC 4034 §2;
- RRSIG (type 46), RFC 4034 §3;
- NSEC (type 47), RFC 4034 §4;
- DS (type 43), RFC 4034 §5;
- NSEC3 (type 50), RFC 5155 §3;
- NSEC3PARAM (type 51), RFC 5155 §4.

Type-aware handling MUST include the ability to identify, for each RRSIG record, the type covered by that signature via the RRSIG RDATA's "type covered" field, to permit matching of RRSIGs to the RRsets they cover during response construction.
*Source.* RFC 4034 §2–§5; RFC 5155 §3, §4; PID Appendix A.
*Verification.* Wire-format conformance tests for each record type; round-trip tests confirming opaque-equivalent preservation of RDATA.

### DO bit inspection

**ODS-FR-DNSSEC-002.** The server MUST inspect the DO (DNSSEC OK) bit in the OPT RR of each inbound query per RFC 4035 §3.2.1. Where DO = 1, the server MUST construct responses with DNSSEC augmentation per ODS-FR-DNSSEC-003 through ODS-FR-DNSSEC-007. Where DO = 0 (or no OPT RR is present), the server MUST construct responses without DNSSEC augmentation per ODS-FR-DNSSEC-008.
*Source.* RFC 4035 §3.2.1.
*Verification.* Tests confirming response composition varies by DO bit setting.

### Response augmentation (DO = 1)

**ODS-FR-DNSSEC-003.** Where DO = 1 in the query and the response references a DNSSEC-signed zone, the server MUST include the RRSIG records covering each RRset placed in any section of the response (answer, authority, additional), provided those RRSIGs exist in the zone store and the message size permits inclusion. RRSIGs are matched to RRsets by the "type covered" field of the RRSIG RDATA.
*Source.* RFC 4035 §3.1; RFC 4035 §3.1.1.
*Verification.* Lookup tests against signed zones; wire-format inspection of RRSIG presence.

**ODS-FR-DNSSEC-004.** In an NXDOMAIN response (per ODS-FR-CORE-023) where DO = 1 and the queried zone is signed, the server MUST include in the authority section the NSEC or NSEC3 records (and their corresponding RRSIGs) that authenticate the non-existence of the QNAME, in accordance with RFC 4035 §3.1.3 for NSEC or RFC 5155 §7.2.2 for NSEC3.
*Source.* RFC 4035 §3.1.3; RFC 5155 §7.2.2.
*Verification.* Lookup tests against signed zones with NSEC and NSEC3 chains; verify denial-of-existence proofs.

**ODS-FR-DNSSEC-005.** In a NODATA response (per ODS-FR-CORE-022) where DO = 1 and the queried zone is signed, the server MUST include in the authority section the NSEC or NSEC3 records (and their corresponding RRSIGs) that authenticate the existence of the QNAME together with the absence of the queried type, in accordance with RFC 4035 §3.1.3.1 for NSEC or RFC 5155 §7.2.3, §7.2.4 for NSEC3.
*Source.* RFC 4035 §3.1.3.1; RFC 5155 §7.2.3, §7.2.4.
*Verification.* Lookup tests producing NODATA against signed zones.

**ODS-FR-DNSSEC-006.** Where a positive response is synthesised from a wildcard owner name (per ODS-FR-CORE-024) and DO = 1 and the zone is signed, the server MUST include in the authority section the NSEC or NSEC3 records (and their RRSIGs) that authenticate the non-existence of the QNAME as a non-wildcard match, in accordance with RFC 4035 §3.1.3.4 or RFC 5155 §7.2.5.
*Source.* RFC 4035 §3.1.3.4; RFC 5155 §7.2.5.
*Verification.* Lookup tests against signed zones with wildcards.

**ODS-FR-DNSSEC-007.** In a referral response (per ODS-FR-CORE-025) where DO = 1 and the parent zone is signed, the server MUST include in the authority section either the DS RRset for the child zone (and its RRSIGs) where DS records exist, or the NSEC or NSEC3 records (and their RRSIGs) that authenticate the absence of DS records where the child zone is unsigned, in accordance with RFC 4035 §3.1.4 or RFC 5155 §7.2.7.
*Source.* RFC 4035 §3.1.4; RFC 5155 §7.2.7.
*Verification.* Lookup tests against signed parent zones with both signed-child and unsigned-child delegations.

### Response composition (DO = 0)

**ODS-FR-DNSSEC-008.** Where DO = 0 in the query (or no OPT RR is present), the server MUST NOT include RRSIG, NSEC, or NSEC3 records in any section of the response, with the single exception that records of these types MAY be returned where they are themselves the explicitly queried QTYPE.
*Source.* RFC 4035 §3.2.1.
*Note.* The exception covers a client explicitly requesting (for example) QTYPE = RRSIG at a name: the response then contains the RRSIG RRset by virtue of being the queried type, not by virtue of DNSSEC augmentation.
*Verification.* Tests with DO = 0 queries against signed zones; verify absence of DNSSEC augmentation except in the explicit-type case.

### Header bits in responses

**ODS-FR-DNSSEC-009.** The DO bit in the response OPT RR's TTL field MUST be set to 1 when the response contains DNSSEC records included as augmentation under ODS-FR-DNSSEC-003 through ODS-FR-DNSSEC-007. In all other responses (including DO = 0 responses and responses to unsigned zones), the DO bit MUST be set to 0.
*Source.* RFC 4035 §3.2.2; RFC 6840 §5.6.
*Verification.* Wire-format inspection of response OPT RRs across signed and unsigned zone responses, DO = 0 and DO = 1 queries.

**ODS-FR-DNSSEC-010.** The server MUST set the AD (Authentic Data) bit to 0 in every response message regardless of query state.
*Source.* RFC 6840 §5.8 (the AD bit's meaning in authoritative responses is unspecified; this server's posture is to never assert AD).
*Note.* Resolvers ignore the AD bit on responses from authoritative servers per the same RFC clause. Setting AD = 0 unambiguously avoids any implicit claim of validation by the server (which does not validate).
*Verification.* Wire-format inspection of all response messages.

**ODS-FR-DNSSEC-011.** The server MUST set the CD (Checking Disabled) bit to 0 in every response message regardless of query state.
*Source.* RFC 6840 §5.9; RFC 4035 §3.2.2.
*Note.* The CD bit is meaningful in responses from recursive servers; in authoritative responses it has no defined semantics. Setting CD = 0 is the unambiguous choice.
*Verification.* Wire-format inspection.

### Algorithm opacity

**ODS-FR-DNSSEC-012.** The server MUST accept DNSSEC records bearing any algorithm number in the relevant algorithm field, including algorithm numbers reserved or unassigned at the time of implementation. The server MUST NOT perform algorithm-validity checks during zone transfer, storage, or serving; algorithm interpretation is exclusively the responsibility of client validators.
*Source.* RFC 6944; RFC 4034 Appendix A.
*Note.* This requirement allows the secondary to faithfully serve zones using algorithms not anticipated at implementation time — for example, future post-quantum algorithms that may be standardised after this server is built.
*Verification.* Zone-transfer tests delivering DNSKEY, RRSIG, and DS records with synthetic algorithm numbers.

### Prohibited operations

**ODS-FR-DNSSEC-013.** The server MUST NOT generate RRSIG records, MUST NOT generate NSEC or NSEC3 records, MUST NOT generate or maintain DNSKEY records or DNSSEC key material of any kind, MUST NOT perform DNSSEC signature verification or validation, and MUST NOT participate in any DNSSEC key rollover protocol (including RFC 5011). All DNSSEC records served by this server are received via zone transfer from primaries.
*Source.* ODS-INV-001; PID §3.2.
*Note.* This requirement is the DNSSEC-specific restatement of the architectural invariant. It is cross-referenced from §4.18 (Negative Requirements) for the explicit catalogue of prohibitions.
*Verification.* Static analysis of the codebase; no code path producing DNSSEC records exists outside the zone-transfer ingestion layer.

## 4.14 RR Type Parsing and Serving

This subsection establishes the catalogue of resource record types for which the server implements type-aware parsing, validation, storage, and serving. Records of types not enumerated here are handled under the unknown-type semantics of §4.4 — accepted opaquely, preserved bit-for-bit, and served on direct query without type-specific interpretation.

DNSSEC record types (DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, DS) appear in the catalogue below for completeness, but their response-augmentation behaviour and serving semantics are specified in §4.13; this subsection establishes only their wire-format parsing membership. The pseudo-RR types OPT (41), TSIG (250), and TKEY (249) are not zone-content RRs and do not appear here; their handling is specified in §4.11, §4.9, and §4.18 respectively.

The area code **RR** is allocated.

### Catalogue

**ODS-FR-RR-001.** The server MUST implement type-aware parsing, storage, and serving for the resource record types enumerated in the catalogue table below, in accordance with the wire-format specification of each type's referenced RFC. RR types not in this catalogue MUST be handled under the unknown-type semantics of §4.4.

| RR Type | Code | Specifying RFC | RDATA Compression Policy |
|---|---|---|---|
| A | 1 | RFC 1035 §3.4.1 | N/A (no names in RDATA) |
| NS | 2 | RFC 1035 §3.3.11 | Permitted (NSDNAME) |
| CNAME | 5 | RFC 1035 §3.3.1 | Permitted (CNAME field) |
| SOA | 6 | RFC 1035 §3.3.13 | Permitted (MNAME, RNAME) |
| PTR | 12 | RFC 1035 §3.3.12 | Permitted (PTRDNAME) |
| HINFO | 13 | RFC 1035 §3.3.2 | N/A (no names in RDATA) |
| MX | 15 | RFC 1035 §3.3.9 | Permitted (EXCHANGE) |
| TXT | 16 | RFC 1035 §3.3.14 | N/A (no names in RDATA) |
| AAAA | 28 | RFC 3596 §2.1 | N/A (no names in RDATA) |
| SRV | 33 | RFC 2782 | Prohibited (TARGET) |
| NAPTR | 35 | RFC 3403 §4 | Prohibited (REPLACEMENT) |
| DNAME | 39 | RFC 6672 §2 | Prohibited (TARGET) |
| DS | 43 | RFC 4034 §5 | N/A |
| RRSIG | 46 | RFC 4034 §3 | Prohibited (Signer's Name) |
| NSEC | 47 | RFC 4034 §4 | Prohibited (Next Domain Name) |
| DNSKEY | 48 | RFC 4034 §2 | N/A |
| NSEC3 | 50 | RFC 5155 §3 | N/A |
| NSEC3PARAM | 51 | RFC 5155 §4 | N/A |
| TLSA | 52 | RFC 6698 §2.1 | N/A |
| SVCB | 64 | RFC 9460 §2.2 | Prohibited (TargetName) |
| HTTPS | 65 | RFC 9460 §2.2 | Prohibited (TargetName) |
| URI | 256 | RFC 7553 §4.5 | N/A |

*Source.* PID Appendix A; the specifying RFCs above; RFC 3597 §4 for the compression-policy distinction between pre-RFC-3597 types (permitted) and later types (prohibited); RFC 6604 (clarifying SRV non-compressibility).
*Note.* The "Prohibited" entries derive from RFC 3597 §4's restriction that DNS name compression applies only to RR types whose RDATA structure was defined prior to RFC 3597, plus type-specific clarifications.
*Verification.* Wire-format conformance tests per type; compression-handling tests for the permitted/prohibited boundary.

### Structural constraints from RR semantics

The following requirements specify zone-level constraints that derive from RR-type semantics and are enforced at zone-transfer completion (per §4.6, §4.7). Violations cause transfer abort under ODS-FR-AXFR-019 or ODS-FR-IXFR-013, with the offending record(s) logged.

**ODS-FR-RR-002.** Each served zone MUST contain exactly one SOA record, and that SOA record MUST be at the zone apex. The presence of zero, multiple, or non-apex SOA records in a transferred zone MUST cause the transfer to be aborted.
*Source.* RFC 1034 §4.3.5; RFC 1035 §3.3.13; RFC 2181 §6.1.
*Verification.* Zone-transfer tests delivering zones with anomalous SOA placements.

**ODS-FR-RR-003.** Each served zone MUST contain at least one NS record at the zone apex. Absence of an apex NS RRset in a transferred zone MUST cause the transfer to be aborted.
*Source.* RFC 1034 §4.2.1.
*Verification.* Zone-transfer tests with apex-NS-less zones.

**ODS-FR-RR-004.** SOA serial number arithmetic MUST be performed in accordance with RFC 1982 §3.2: serial A is considered greater than serial B when (A − B) mod 2³² lies in the range [1, 2³¹−1]. This applies to all SOA serial comparisons performed by the server, including IXFR query-target evaluation (§4.7) and zone-state-machine freshness evaluation (§4.16).
*Source.* RFC 1982 §3.2; RFC 1035 §3.3.13.
*Verification.* Unit tests across the serial-arithmetic boundary cases (wrap-around, equal, near-2³¹ differences).

**ODS-FR-RR-005.** At any owner name carrying a CNAME RRset, no other RRset of any other type MUST be present, with the exception of RRSIG, NSEC, and NSEC3 records as required for DNSSEC support of that name. Transferred zones violating this constraint MUST cause the transfer to be aborted.
*Source.* RFC 1034 §3.6.2; RFC 2181 §10.1; RFC 4035 (DNSSEC exception).
*Verification.* Zone-transfer tests with CNAME-and-other-data coexistence at non-DNSSEC names.

**ODS-FR-RR-006.** At any owner name carrying a DNAME RRset, no CNAME RRset MUST be present at that same owner name, with the exception of RRSIG, NSEC, and NSEC3 records as required for DNSSEC. Transferred zones violating this constraint MUST cause the transfer to be aborted.
*Source.* RFC 6672 §2.4.
*Verification.* Zone-transfer tests with DNAME and CNAME at the same name.

### RDATA wire-format validation

**ODS-FR-RR-007.** During zone transfer, the server MUST validate each known-type record's RDATA for conformance to the wire-format requirements of its specifying RFC, including at minimum:
- RDLENGTH equal to the expected fixed size for types with fixed RDATA size (A: 4 octets; AAAA: 16 octets);
- domain name fields within RDATA parse as valid wire-format names without exceeding RDATA bounds;
- character-string fields have length octets consistent with RDATA bounds and do not exceed 255 octets per string;
- multi-field RDATA's total decoded size equals RDLENGTH exactly (no trailing bytes, no truncation).

Records failing validation MUST cause the zone transfer to be aborted per ODS-FR-AXFR-019 or ODS-FR-IXFR-013. The transfer abort log entry MUST identify the offending record's owner name, type, and the specific validation failure.
*Source.* Each RR type's specifying RFC; defensive parsing posture.
*Verification.* Zone-transfer tests with deliberately malformed records of each type; fuzz testing of the parsers.

### Type-specific parsing notes (informative)

The following observations are not separate requirements but identify points of subtlety in the catalogue:

- **TXT (16).** RDATA is one or more character-string components; the server preserves component boundaries on transfer and serving.
- **NAPTR (35).** The REPLACEMENT field is a domain name; the REGEXP field is a character string permitted to contain otherwise restricted characters; the server preserves byte content faithfully.
- **TLSA (52).** Owner names typically have the `_port._proto.name` structure; this is owner-name content, not a parsing constraint on the RR type.
- **SVCB (64) and HTTPS (65).** SvcParams parsing — the ordered list of `SvcParamKey` / `SvcParamValue` pairs in RDATA — follows RFC 9460 §2.2. The server is required to parse the structure for additional-section inclusion of TargetName under ODS-FR-QRY-019, and to detect AliasMode (SvcPriority = 0) versus ServiceMode (SvcPriority > 0).
- **RRSIG (46).** The Signer's Name field is in canonical form per RFC 4034 §6.2 (uncompressed, lowercased on the wire for canonical comparison). The "Type Covered" field at RDATA offset 0–1 is the discriminator used in DNSSEC response composition per §4.13.
- **NSEC (47).** The "Next Domain Name" field is uncompressed (RFC 4034 §6.2). The Type Bit Maps encoding is per RFC 4034 §4.1.2.

## 4.15 In-Memory Zone Store

This subsection specifies the externally observable semantics of the server's in-memory zone store: how zones are identified and indexed, the consistency guarantees of lookups during refresh, and the observable lifecycle states of a zone. The implementation strategy — the specific data structures, indexing mechanism, and concurrency primitive used to satisfy these requirements — is an architectural decision recorded in the Architecture Document.

The architectural invariants from §3 establish the foundational properties of the zone store: memory-resident (ODS-INV-002), atomic refresh (ODS-INV-003), no persistent operational state (ODS-INV-004). This subsection specifies the behavioural consequences of those invariants in concrete, testable form.

The area code **ZONE** is allocated.

### Zone identity and lookup

**ODS-FR-ZONE-001.** Each zone designated for service is identified uniquely by the tuple (zone apex name, zone class), where zone names are compared case-insensitively per ODS-FR-CORE-009 and RFC 4343. The set of designated zones is established by configuration at process startup per ODS-INV-005 and is immutable for the process lifetime.
*Source.* RFC 1034 §4.2; ODS-INV-005.
*Verification.* Configuration round-trip tests; runtime-modification attempts confirmed impossible.

**ODS-FR-ZONE-002.** Within each zone, the in-memory zone store MUST support lookup by (owner name, RR type) → RRset, with owner-name comparison case-insensitive per ODS-FR-CORE-009. Lookups MUST also support the queries required by §4.1 and §4.2: longest-suffix-match for zone-cut determination, wildcard-owner-name matching per RFC 4592, and direct equality for RRset retrieval.
*Source.* RFC 1034 §3.1; RFC 2181 §5; RFC 4592.
*Verification.* Lookup tests covering each access pattern across zones with varying structure and depth.

### Consistency

**ODS-FR-ZONE-003.** For each query, the zone store MUST present a single internally consistent version of the zone throughout the query's processing. The atomic publication of a refreshed zone version per ODS-INV-003 ensures that the transition from one version to its successor does not produce mixed observations within any query. Concurrent queries against the same zone MAY observe different versions across the refresh boundary, but no single query MUST observe a mixture.
*Source.* ODS-INV-003.
*Verification.* Concurrent query tests sustained across simulated zone refreshes; per-query record-set provenance verified to derive from a single zone version.

### Wildcard and glue storage

**ODS-FR-ZONE-004.** Wildcard owner names (labels containing the asterisk character `*` per RFC 4592) MUST be stored in the zone store as regular records. The wildcard semantics — synthesis of responses with the QNAME substituted for the wildcard owner — are applied at query time per ODS-FR-CORE-024 and ODS-FR-QRY-016, not at storage time.
*Source.* RFC 4592 §2; RFC 1034 §4.3.3.
*Verification.* Zone-transfer tests delivering wildcard records; lookup tests covering wildcard expansion and the related empty-non-terminal occlusion cases.

**ODS-FR-ZONE-005.** Glue records (A and AAAA records at owner names below child-zone NS delegation points within the served zone, accepted per ODS-FR-AXFR-013) MUST be stored in the zone store and made available to query handlers for additional-section composition per ODS-FR-QRY-017. Glue records MUST be distinguishable in the store from authoritative-data records of the parent zone for the purposes of the occluded-data exclusion of ODS-FR-AXFR-014 and the AA-bit determination of ODS-FR-CORE-014.
*Source.* RFC 1034 §6.2; RFC 1035 §6.2.4.
*Note.* "Distinguishable" does not prescribe a representation; the implementation may use a flag, separate sub-structure, or other mechanism. The behavioural requirement is that glue is included in additional sections but does not influence AA or appear in answer/authority sections of queries that strictly target authoritative data.
*Verification.* Lookup tests requiring glue; lookup tests at and below delegation points confirming occluded data is not served.

### Zone lifecycle states

**ODS-FR-ZONE-006.** Each designated zone is in one of three query-observable states at any time:

- **LOADING.** No zone transfer has yet completed successfully for this zone since process startup. The zone store holds no authoritative data for the zone. Queries against a LOADING zone MUST receive RCODE = 2 (SERVFAIL).
- **ACTIVE.** At least one zone transfer has completed successfully, and the time elapsed since the most recent successful transfer does not exceed the value of the zone's SOA EXPIRE field. Queries against an ACTIVE zone are processed and answered per the requirements of §4.1 through §4.13 as applicable.
- **EXPIRED.** The time elapsed since the most recent successful transfer exceeds the zone's SOA EXPIRE field. Queries against an EXPIRED zone MUST receive RCODE = 2 (SERVFAIL) per ODS-FR-QRY-021.

State transitions are governed by the zone state machine specified in §4.16. The internal status REFRESHING — denoting that a refresh attempt is in progress for a zone otherwise in ACTIVE state — is not a query-observable state; queries during an in-progress refresh are processed against the previously published zone version per ODS-FR-ZONE-003.

*Source.* RFC 1034 §4.3.5; this SRS §4.16.
*Note.* LOADING and EXPIRED are observationally identical to clients (both yield SERVFAIL); internally they have different causes and trigger different state-machine behaviour. The state distinction is necessary for the state machine, not for the wire protocol.
*Verification.* Zone-state tests covering each state with the corresponding query response; transitions exercised through transfer success, transfer failure, and EXPIRE-window elapse.

## 4.16 Zone State Machine

This subsection specifies the timing and decision logic that governs zone refresh: when refresh attempts are initiated, what protocol (AXFR or IXFR) is chosen for each attempt, how failures are retried, and when zones transition between the lifecycle states established in §4.15.

The state machine is the consumer of the timing fields in the SOA record (REFRESH, RETRY, EXPIRE) and the orchestrator of the transfer sessions specified in §4.6 and §4.7. It is triggered by scheduled timer expiry, by accepted NOTIFY messages (§4.8), and by transfer-session completion (success or failure). It is the sole component that initiates transfer attempts; query handlers do not.

The area code **ZSM** is allocated.

### Initial load

**ODS-FR-ZSM-001.** At process startup, all designated zones enter the LOADING state per ODS-FR-ZONE-006. The state machine MUST initiate an AXFR transfer (not IXFR, as no prior zone data exists) for each LOADING zone, subject to the concurrent transfer session limit of ODS-FR-AXFR-022.
*Source.* This SRS §4.15, §4.6, §4.7.
*Verification.* Startup tests with many configured zones; verify all are scheduled for initial AXFR.

**ODS-FR-ZSM-002.** Where an initial AXFR transfer for a LOADING zone fails, the state machine MUST schedule a retry after a delay. The first retry delay MUST be configurable, with a default of 60 seconds. Each subsequent failed retry MUST double the delay (exponential backoff), up to a configurable maximum (default 3600 seconds = 1 hour). The zone remains in LOADING state across initial-load retries; the state machine MUST NOT abandon initial-load retries while the process is running.
*Source.* RFC 1034 §4.3.5 (general retry principle); operational requirement.
*Verification.* Tests with unreachable primaries; verify retry intervals and continuity.

### Refresh triggering

**ODS-FR-ZSM-003.** The state machine MUST initiate a refresh attempt for an ACTIVE or EXPIRED zone under any of the following conditions:
- Wall-clock time has reached the next scheduled refresh time for the zone (set per ODS-FR-ZSM-004 or ODS-FR-ZSM-008);
- A NOTIFY message has been accepted for the zone per §4.8 and the NOTIFY's signal to the state machine (per ODS-FR-NOTIFY-007) has cleared the dedup interval of ODS-FR-NOTIFY-009.

*Source.* RFC 1034 §4.3.5; RFC 1996 §4.4.
*Verification.* Tests confirming both trigger pathways.

**ODS-FR-ZSM-004.** Upon successful completion of a refresh attempt (successful transfer, or SOA poll showing serial equality), the state machine MUST:
- Transition the zone to ACTIVE state (from LOADING, EXPIRED, or unchanged ACTIVE);
- Record the wall-clock timestamp of completion as the zone's "last successful refresh" time;
- Schedule the next refresh attempt at (last successful refresh + REFRESH interval), where REFRESH is read from the SOA RDATA of the just-confirmed-current zone, subject to the minimum of ODS-FR-ZSM-011 and the jitter of ODS-FR-ZSM-010.

*Source.* RFC 1034 §4.3.5; RFC 1035 §3.3.13.
*Verification.* Refresh-cycle tests measuring time between successful refreshes.

### Protocol selection

**ODS-FR-ZSM-005.** For each refresh attempt against a zone that already holds data (ACTIVE or EXPIRED with prior data), the state machine MUST attempt IXFR by default. Where the primary has, within the preceding "IXFR-disabled cooldown" interval (configurable, default 3600 seconds = 1 hour), returned RCODE = 4 (NOTIMP) or RCODE = 1 (FORMERR) in response to an IXFR query for this zone, the state machine MUST use AXFR instead for the current attempt.
*Source.* RFC 1995 §3.
*Note.* Mode 2 IXFR response (full-zone fallback per ODS-FR-IXFR-011) is considered a successful IXFR, not evidence of IXFR non-support; the primary supports the protocol but had no incremental history to deliver.
*Verification.* Tests with primaries returning IXFR support, NOTIMP, and FORMERR; verify next-attempt protocol selection.

### SOA poll optimisation

**ODS-FR-ZSM-006.** Prior to initiating an IXFR or AXFR for a refresh, the state machine MAY perform an SOA query against the selected primary to compare the primary's current serial against the secondary's held serial. Serial comparison MUST use the arithmetic of ODS-FR-RR-004 (RFC 1982). If the primary's serial is equal to or less than the secondary's held serial, no transfer is needed and the refresh attempt is recorded as successful per ODS-FR-ZSM-004. If the primary's serial is greater, the configured transfer protocol is initiated per ODS-FR-ZSM-005.
*Source.* RFC 1034 §4.3.5.
*Note.* The SOA poll is optional because IXFR's Mode 3 response (RFC 1995 §4, per ODS-FR-IXFR-004) provides equivalent "no update available" signalling at the cost of one IXFR query rather than one SOA query plus one IXFR query. Implementations may choose either pattern; both are operationally correct.
*Verification.* Refresh tests with primaries at equal serial confirming refresh is recorded as successful without transfer.

**ODS-FR-ZSM-007.** Where a refresh attempt has been triggered by a NOTIFY message that carried an SOA record in its answer section (per ODS-FR-NOTIFY-008), the state machine MAY use that embedded SOA's serial as the primary-side input to the comparison of ODS-FR-ZSM-006, skipping a separate SOA poll. If the embedded serial is equal to or less than the secondary's held serial, the refresh is recorded as successful per ODS-FR-ZSM-004 without any further query. If greater, the configured transfer protocol is initiated.
*Source.* RFC 1996 §3.7.
*Verification.* Tests with NOTIFY messages carrying embedded SOAs at various serial relationships.

### Refresh failure

**ODS-FR-ZSM-008.** Where a refresh attempt fails — transfer abort per §4.6 or §4.7, SOA poll failure, all configured primaries exhausted without success — the state machine MUST:
- Leave the zone in its prior state (ACTIVE if previously ACTIVE, LOADING if previously LOADING) with its prior data intact, subject to the EXPIRE evaluation of ODS-FR-ZSM-009;
- Schedule the next refresh attempt at (current time + RETRY interval), where RETRY is read from the zone's currently held SOA RDATA for an ACTIVE zone, or from the initial-load backoff (ODS-FR-ZSM-002) for a LOADING zone, subject to ODS-FR-ZSM-010 (jitter) and ODS-FR-ZSM-011 (minimum).

*Source.* RFC 1034 §4.3.5; RFC 1035 §3.3.13.
*Verification.* Failure-injection tests across transfer abort causes.

### Expiration

**ODS-FR-ZSM-009.** For each ACTIVE zone, the state machine MUST monitor the elapsed wall-clock time since the most recent successful refresh. When this elapsed time exceeds the zone's SOA EXPIRE value, the state machine MUST transition the zone to EXPIRED state per ODS-FR-ZONE-006. The state machine MUST continue to schedule and attempt refreshes for EXPIRED zones at intervals not exceeding the SOA RETRY value (with jitter and minimum applied per ODS-FR-ZSM-010 and ODS-FR-ZSM-011); on the first successful refresh of an EXPIRED zone, the state machine MUST transition the zone back to ACTIVE per ODS-FR-ZSM-004.
*Source.* RFC 1034 §4.3.5; RFC 1035 §3.3.13.
*Verification.* Long-running tests with simulated primary unreachability spanning the EXPIRE interval; verify state transitions to EXPIRED and recovery to ACTIVE.

### Jitter and minimum intervals

**ODS-FR-ZSM-010.** The state machine MUST apply uniform random jitter in the range ±10% to every scheduled interval (REFRESH, RETRY, initial-load backoff) before scheduling. The jitter MUST be drawn independently per zone per scheduling decision.
*Source.* Defensive operational practice against synchronised refresh storms.
*Verification.* Statistical analysis of scheduled refresh times across many zones and many cycles; the empirical distribution MUST be consistent with the specified jitter.

**ODS-FR-ZSM-011.** The state machine MUST enforce a configurable minimum effective interval for REFRESH and RETRY values read from SOA records, with a default minimum of 60 seconds. SOA REFRESH or RETRY values below the minimum MUST be treated as equal to the minimum for scheduling purposes. The original SOA values are preserved unchanged for serving.
*Source.* Defensive operational practice; protection against refresh storms from pathological primary configurations.
*Note.* The configured minimum constrains only the state machine's scheduling; it does not modify the SOA record served to clients.
*Verification.* Tests with SOA records containing REFRESH or RETRY below the minimum.

### Shutdown

**ODS-FR-ZSM-012.** On process shutdown initiated by SIGTERM, the state machine MUST cease initiating new refresh attempts. Refresh timers MUST NOT trigger new transfers after the SIGTERM signal is received. In-progress transfer sessions complete or are aborted per the graceful shutdown timing specified in §5.5.
*Source.* This SRS §5.5; §6.5.
*Verification.* Shutdown tests confirming no new transfers initiated after SIGTERM.

## 4.17 Response Rate Limiting

This subsection specifies Response Rate Limiting (RRL), the mechanism by which the server constrains its utility as an amplification vector for reflection attacks. RRL accounts the rate of responses produced for each accounting key (typically a source-IP prefix and a response category), and applies a configurable action — silent drop or truncation-marker response — when the rate exceeds a configured threshold.

RRL is not the subject of an IETF standard track RFC. The design specified below follows the Vixie / Schryver model implemented in BIND 9 and adopted with variations by NSD and Knot DNS; it is established operational practice rather than formal standardisation. PID Appendix A lists RRL as a required feature without RFC citation, on the basis of its operational maturity.

RRL is one of three complementary anti-amplification mechanisms in this server: the ANY-query minimisation policy of §4.2 (ODS-FR-QRY-005, ODS-FR-QRY-006) reduces the per-response amplification factor for ANY queries specifically; TCP fallback via TC=1 (§4.12) requires reflected clients to establish a TCP handshake to receive substantial data; and RRL itself bounds the rate at which the server contributes to any reflection campaign.

The area code **RRL** is allocated.

### Mechanism

**ODS-FR-RRL-001.** The server MUST implement Response Rate Limiting as specified in this subsection, applied to all responses produced for clients (responses to ordinary DNS queries). RRL MUST be enabled by default. The operator MAY disable RRL by configuration, but doing so removes the server's primary structural defence against amplification reflection.
*Source.* Operational requirement; defence against DNS amplification reflection attacks.
*Verification.* Configuration tests with RRL enabled and disabled; functional tests confirming RRL takes effect.

### Accounting

**ODS-FR-RRL-002.** RRL MUST account responses per a tuple of (source IP prefix, response category). The source IP prefix length MUST be configurable, with defaults of /24 for IPv4 and /56 for IPv6. The response categories MUST be:
- (a) positive responses (RCODE = NOERROR with non-empty answer section);
- (b) NXDOMAIN responses (RCODE = NXDOMAIN);
- (c) NODATA responses (RCODE = NOERROR with empty answer section and SOA in authority);
- (d) referral responses (RCODE = NOERROR with non-empty NS authority and empty answer section);
- (e) error responses (RCODE other than NOERROR or NXDOMAIN — SERVFAIL, REFUSED, FORMERR, NOTIMP, etc.).

*Source.* Vixie / Schryver RRL design; BIND 9 RRL implementation.
*Verification.* Tests confirming responses of each category are counted under the corresponding accounting key.

### Thresholds and bucket model

**ODS-FR-RRL-003.** For each response category, the server MUST enforce a configurable per-second rate limit, applied per accounting key. The default rate limits MUST be:
- positive responses: 20 responses per second;
- NXDOMAIN responses: 5 responses per second;
- NODATA responses: 10 responses per second;
- referral responses: 10 responses per second;
- error responses: 5 responses per second.

*Source.* BIND 9 default RRL configuration.
*Note.* These defaults are conservative for typical-traffic deployments. Operators serving high-traffic zones or anycast networks may need to tune upward; operators of low-traffic zones may benefit from tuning downward to detect anomalies faster.
*Verification.* Tests at and beyond the limit thresholds.

**ODS-FR-RRL-004.** The rate-limit MUST be implemented as a token-bucket per accounting key: bucket capacity equal to the configured per-second rate, refilled at the configured per-second rate (one token per (1 / rate) seconds). Each response produced for the accounting key consumes one token. When the bucket is empty, the response is subject to the action of ODS-FR-RRL-005.
*Source.* Standard rate-limiting design.
*Verification.* Burst-tolerance tests confirming the bucket model.

### Limit-exceeded action

**ODS-FR-RRL-005.** When a response would be produced for an accounting key whose token bucket is exhausted, the server MUST apply the configured "slip" policy, parameterised by an integer N with default value 2:
- If N = 0: every rate-limited response MUST be silently dropped (no message sent on the wire).
- If N ≥ 1: of every N consecutive rate-limited responses for that accounting key, exactly one MUST be emitted as a truncated response (TC bit set, empty answer/authority/additional sections, retaining the question section and OPT RR if applicable), and the remaining N−1 MUST be silently dropped.

The truncated response provides an escape path for legitimate clients (which can switch to TCP per §4.12 to receive the full response) while substantially reducing the amplification utility of the server to a spoofed-source attacker.
*Source.* Vixie / Schryver RRL design; BIND 9 RRL implementation.
*Verification.* Tests measuring drop/truncate ratio under sustained rate-limit pressure.

### Exemptions

**ODS-FR-RRL-006.** The server MUST support a configurable allowlist of source IP addresses and prefixes that are exempt from RRL accounting and limit enforcement. Responses to allowlisted clients MUST NOT consume tokens and MUST NOT be subject to ODS-FR-RRL-005's action.
*Source.* Operational requirement; trusted recursive resolvers and internal monitoring should not be impeded.
*Verification.* Configuration round-trip tests; functional tests with allowlisted source addresses under high query load.

**ODS-FR-RRL-007.** Responses to TCP queries MUST NOT be subject to RRL. RRL accounting and action MUST apply only to responses sent over UDP.
*Source.* Operational practice; TCP's three-way handshake provides intrinsic anti-spoofing that obviates the need for RRL on the TCP path.
*Verification.* Tests with sustained TCP query load; verify no RRL action taken on TCP responses.

**ODS-FR-RRL-008.** Responses to queries authenticated via TSIG (per §4.9) MUST NOT be subject to RRL.
*Source.* Operational practice; TSIG-authenticated queries are presumed legitimate, and the cryptographic cost of TSIG processing itself serves as a rate limit on attacker capabilities.
*Verification.* Tests with TSIG-authenticated queries under high rate.

### Configuration scope and state

**ODS-FR-RRL-009.** RRL configuration in this version of the server is process-wide; the rate limits and slip value apply uniformly across all zones served. Per-zone or per-view RRL configuration is not supported.
*Source.* Implementation simplicity per PID §2.2 (minimal codebase target).
*Note.* Per-zone RRL is a frequently requested capability and may be added in a future version. The decision to defer it here reflects the project's minimal-codebase target, not a position on its desirability. Operators requiring per-zone RRL today should use a server with that capability.
*Verification.* Configuration tests confirming global application.

**ODS-FR-RRL-010.** The server MUST enforce a configurable maximum number of concurrently tracked RRL accounting keys, with a default of 100000. When the limit is reached, the least-recently-used (LRU) accounting key MUST be evicted to make room for a new key. Eviction MUST NOT affect serving — an evicted key's accounting starts fresh on its next observed response.
*Source.* Resource management; defence against state-exhaustion attacks from many distinct source prefixes.
*Verification.* Stress tests with many distinct source prefixes; verify LRU eviction and bounded memory consumption.

### Observability

**ODS-FR-RRL-011.** The server MUST log RRL events:
- First entry into rate-limited state for an accounting key: warning level, with the key (source prefix and response category) and the threshold value;
- Periodic aggregate summary: info level, every configurable interval (default 60 seconds), reporting the number of responses dropped, the number emitted as truncated, and the number of currently-rate-limited accounting keys.

Per-event logging of individual drops or truncations MUST NOT be performed at info level or above, to avoid log amplification during attack conditions.
*Source.* Operational requirement; observability without log flooding.
*Verification.* Log inspection across normal and attack conditions.

**ODS-FR-RRL-012.** The server MUST maintain in-memory counters for RRL:
- total responses subject to RRL (across all keys);
- total responses dropped due to RRL;
- total responses emitted as truncated due to RRL;
- currently tracked accounting key count;
- accounting key evictions due to the cap of ODS-FR-RRL-010.

Exposure of these counters is per §5.6 and §6.4.
*Source.* Operational requirement informed by RFC 8906.
*Verification.* Counter inspection under controlled load.

## 4.18 Negative Requirements

This subsection consolidates the prohibition requirements — those phrased as "MUST NOT" — that enforce the architectural invariants of §3 (chiefly ODS-INV-001) and the scope boundaries of §2. The prohibitions catalogued here are largely the negative restatement of constraints already established positively elsewhere in the SRS; their consolidation into a single audit-reviewable section is the purpose of this subsection.

Each prohibition cross-references the positive requirement, architectural invariant, or PID scope clause that it enforces. New normative content is not introduced; the prohibitions are presented compactly with statement, enforcement reference, and verification approach. Detailed rationale is in the enforced clause cited.

The category identifier is **NEG**; per §1.4.3, the AREA component is omitted from these identifiers.

### Secondary-only role enforcement

**ODS-NEG-001.** The server MUST NOT process DNS UPDATE messages (OPCODE = 5, RFC 2136). Inbound messages with OPCODE = 5 are rejected with RCODE = 4 (NOTIMP) per ODS-FR-CORE-005.
*Enforces.* ODS-INV-001.
*Verification.* Conformance tests with UPDATE messages of various forms; verify NOTIMP response and zero modification to the in-memory zone store.

**ODS-NEG-002.** The server MUST NOT generate, modify, or maintain any DNSSEC record — RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, or any other type whose generation is properly a primary-role activity. All DNSSEC records served originate from the primary via zone transfer.
*Enforces.* ODS-INV-001; ODS-FR-DNSSEC-013.
*Verification.* Static analysis of the codebase confirming no code path generates DNSSEC records.

**ODS-NEG-003.** The server MUST NOT accept zone data, zone modifications, or any change to its authoritative state through any channel other than authenticated zone transfer (AXFR per §4.6 or IXFR per §4.7) from configured primaries.
*Enforces.* ODS-INV-001.
*Verification.* Static analysis confirming the only code paths that write to the in-memory zone store originate in the zone-transfer client; no administrative interface exists.

**ODS-NEG-004.** The server MUST NOT originate NOTIFY messages. NOTIFY origination is a primary-role function; the server's role per §4.8 is exclusively NOTIFY reception.
*Enforces.* ODS-INV-001; PID §3.2 (out-of-scope).
*Verification.* Static analysis confirming no NOTIFY-emission code path exists.

**ODS-NEG-005.** The server MUST NOT serve outbound AXFR or IXFR responses to inbound zone-transfer queries. Queries received with QTYPE = 252 (AXFR) or QTYPE = 251 (IXFR) MUST be rejected with RCODE = 5 (REFUSED).
*Enforces.* ODS-INV-001; PID §3.2 (the server does not act as a transfer source for downstream secondaries).
*Verification.* Conformance tests with AXFR and IXFR queries received as a server; verify REFUSED response with no transfer attempted.

**ODS-NEG-006.** The server MUST NOT read zone data from presentation-format (master) files per RFC 1035 §5. All zone data is received in wire format via zone transfer.
*Enforces.* ODS-INV-001; PID §3.2.
*Verification.* Static analysis confirming no presentation-format parser exists.

### Resolver-role prohibitions

**ODS-NEG-007.** The server MUST NOT perform recursive resolution. The RA bit in responses MUST be 0 unconditionally per ODS-FR-CORE-012. Queries for names outside any served zone MUST be rejected with RCODE = 5 (REFUSED) per ODS-FR-CORE-019.
*Enforces.* ODS-INV-001; PID §3.2.
*Verification.* Conformance tests with queries for names outside served zones; verify REFUSED and RA = 0.

**ODS-NEG-008.** The server MUST NOT forward DNS queries to any other server. Every response is determined exclusively from the server's in-memory zone store.
*Enforces.* ODS-INV-001; PID §3.2.
*Verification.* Static analysis confirming no query-forwarding code path exists; network-layer tests confirming no outbound queries are generated in response to inbound queries.

**ODS-NEG-009.** The server MUST NOT perform DNSSEC signature validation on inbound or outbound messages. The AD (Authentic Data) bit in responses MUST be 0 unconditionally per ODS-FR-DNSSEC-010, regardless of whether the queried zone is signed.
*Enforces.* ODS-INV-001 (the server does not act as a validator); PID §3.2.
*Verification.* Static analysis confirming no signature-validation code path exists outside any explicitly-required TSIG verification under §4.9.

### Lifecycle and operational prohibitions

**ODS-NEG-010.** The server MUST NOT write operational state — zone data, transfer history, query statistics, configuration data, or any data intended to survive process restart — to persistent storage. Log output to standard streams is not "operational state" within the scope of this prohibition.
*Enforces.* ODS-INV-004.
*Verification.* System-call tracing during steady-state operation confirming absence of filesystem write operations outside standard streams; runnable on read-only root filesystems.

**ODS-NEG-011.** The server MUST NOT re-read configuration sources after process startup. The server MUST NOT install a SIGHUP handler (or equivalent mechanism) that re-reads configuration. Configuration changes are applied only via process restart.
*Enforces.* ODS-INV-005.
*Verification.* Code review confirming configuration is parsed once at startup; SIGHUP signal tests confirming no configuration reload behaviour.

**ODS-NEG-012.** The server MUST NOT serve authoritative zone data for a zone whose authoritative data has expired — that is, where the elapsed time since the most recent successful refresh exceeds the zone's SOA EXPIRE value. Queries against expired zones receive RCODE = 2 (SERVFAIL) per ODS-FR-QRY-021 and ODS-FR-ZONE-006.
*Enforces.* ODS-INV-001 (authoritative data must remain consistent with the primary); RFC 1034 §4.3.5.
*Verification.* Tests with zones whose primaries are unreachable past the EXPIRE interval; verify SERVFAIL response.

### Cryptographic and protocol-option prohibitions

**ODS-NEG-013.** The server MUST NOT implement the HMAC-MD5 TSIG algorithm (algorithm name `hmac-md5.sig-alg.reg.int`). Messages bearing TSIG records with this algorithm name MUST receive a BADALG TSIG error response per ODS-FR-TSIG-004.
*Enforces.* ODS-FR-TSIG-004; RFC 8945 §6 ("hmac-md5 MUST NOT be used by new implementations").
*Verification.* Conformance tests with HMAC-MD5-signed messages; verify BADALG response.

**ODS-NEG-014.** The server MUST NOT implement the TKEY mechanism (RFC 2930) for dynamic key establishment. Queries with QTYPE = 249 (TKEY) MUST be rejected with RCODE = 1 (FORMERR) per ODS-FR-QRY-009.
*Enforces.* PID §3.2; static-configuration invariant for TSIG keys per ODS-FR-TSIG-005.
*Verification.* Conformance tests with TKEY queries.

**ODS-NEG-015.** The server MUST NOT use the synthesised HINFO response style described in RFC 8482 §4.2 for QTYPE = ANY queries.
*Enforces.* ODS-FR-QRY-007.
*Verification.* Wire-format inspection of ANY-query responses; verify no synthesised HINFO records.

**ODS-NEG-016.** Where XoT is configured for a (zone, primary) tuple, the server MUST NOT fall back to unencrypted TCP zone transfer on TLS connection-establishment or certificate-authentication failure. The Opportunistic Privacy Profile of RFC 9103 §9.2 MUST NOT be used.
*Enforces.* ODS-FR-XOT-006.
*Verification.* Tests with TLS-failing primaries under XoT configuration; verify no cleartext retry.

**ODS-NEG-017.** The server MUST NOT accept inbound TLS connections for XoT (server-side XoT, including NOTIFY-over-TLS receipt). XoT in this server is scoped to outbound zone-transfer connections only, per the scope statement of §4.10.
*Enforces.* §4.10 scope; PID §3.2.
*Verification.* Network-layer tests confirming no TLS listener is bound; inbound TLS connection attempts are refused at the TCP layer.

# 5. Non-Functional Requirements

This section specifies properties of the system beyond its functional behaviour: how fast it must be, how reliable, how secure, how maintainable, how portable, how observable, and what resource bounds it must respect. The functional requirements of §4 specify *what* the server does; the non-functional requirements of this section specify *under what constraints*.

Each subsection allocates an area code per the scheme of §1.4.3 (ODS-NFR-<AREA>-NNN). The standard requirement template applies, presented more compactly than the functional sections; the per-subsection identifier range follows.

Many of the targets below are derived from PID §6.1 (success criteria) and operational benchmarking against existing secondary-only authoritative servers (NSD, Knot DNS). Where the PID did not specify a target explicitly, I have proposed values consistent with established practice; these are flagged in the closing notes for review.

## 5.1 Performance

The area code **PERF** is allocated.

**ODS-NFR-PERF-001.** The server MUST sustain a query-handling throughput of at least 50,000 queries per second per CPU core under nominal workload — defined as a median DNS query mix against fully in-memory zones, UDP transport, no TSIG verification on queries.
*Source.* Operational requirement; comparable to NSD and Knot on equivalent hardware.
*Verification.* Sustained-load benchmarking using `dnsperf` or `kxdpgun` against a synthetic zone of 100,000 records on a single-core configuration.

**ODS-NFR-PERF-002.** Under nominal workload at no more than 50% of the throughput of ODS-NFR-PERF-001, the server MUST achieve a 99th-percentile query response latency below 1 millisecond for direct-hit lookups (queries answered without CNAME chain expansion).
*Source.* Operational requirement.
*Verification.* Latency-distribution inspection under controlled load.

**ODS-NFR-PERF-003.** Under workload at up to 90% of the throughput of ODS-NFR-PERF-001, the server MUST achieve a 99th-percentile query response latency below 10 milliseconds.
*Source.* Operational requirement.
*Verification.* Latency-distribution inspection at near-capacity load.

**ODS-NFR-PERF-004.** AXFR transfer ingestion MUST sustain at least 100,000 records per second on a contemporary Linux host with adequate network bandwidth to deliver the transfer.
*Source.* Operational requirement; bounds transfer time for large zones to operationally acceptable values.
*Verification.* AXFR ingestion timing with synthetic zones of varying sizes.

**ODS-NFR-PERF-005.** Process initialization (binding sockets, parsing configuration, initiating first transfer attempts) MUST complete within 1 second of process start on a contemporary Linux host with adequate resources. Zone-transfer completion time (loading data into ACTIVE state per §4.15) is separate and constrained by primary responsiveness and zone size.
*Source.* Operational requirement; orchestrator-friendly startup.
*Verification.* Startup-timing tests with configurations of varying zone counts.

## 5.2 Reliability and Availability

The area code **REL** is allocated.

**ODS-NFR-REL-001.** On receipt of SIGTERM, the server MUST cease accepting new queries and new TCP connections, allow in-flight query processing and transfer sessions to complete within a configurable grace period (default 30 seconds), then exit with status code 0. Sessions still active at the end of the grace period MUST be aborted and the server MUST exit regardless.
*Source.* Operational requirement; orchestrator-friendly graceful shutdown.
*Verification.* Shutdown-behaviour tests under sustained query load and active transfer sessions.

**ODS-NFR-REL-002.** A process crash MUST NOT corrupt any persistent state on the host (per ODS-INV-004, no persistent state exists to corrupt). A subsequent process start MUST initialize cleanly from configuration, performing full zone acquisition per §4.16.
*Source.* ODS-INV-004.
*Verification.* Forced-kill tests followed by restart verification.

**ODS-NFR-REL-003.** Steady-state memory consumption MUST be bounded across extended operation (≥ 30 days continuous runtime). The server MUST NOT exhibit unbounded memory growth under sustained query load with zones of stable size and stable client population.
*Source.* Operational requirement for long-running infrastructure services.
*Verification.* Long-duration soak testing with memory profiling at intervals.

**ODS-NFR-REL-004.** Network errors on inbound or outbound connections — malformed packets, mid-transfer connection drops, exhausted file descriptors, kernel buffer exhaustion — MUST NOT cause process termination. Errors MUST be handled per the requirements of §4.6, §4.7, §4.8, §4.10, and §4.12; the process continues serving subsequent traffic.
*Source.* Operational requirement.
*Verification.* Fault-injection tests across the enumerated failure modes.

**ODS-NFR-REL-005.** The server MUST be deployable under rolling-restart patterns: replacement processes can be started while existing processes drain. SIGTERM-initiated drain completes within the grace period of ODS-NFR-REL-001 with no observable service interruption from clients exhibiting reasonable retry behaviour.
*Source.* Operational requirement; container-native deployment.
*Verification.* Rolling-restart tests in a representative orchestrator environment.

## 5.3 Security

The area code **SEC** is allocated.

**ODS-NFR-SEC-001.** The implementation MUST satisfy ODS-INV-006: Rust's safe subset is used for all code processing data received from the network; `unsafe` blocks are confined to documented, justified exceptions.
*Source.* ODS-INV-006.
*Verification.* `cargo geiger` enumeration plus per-block review of all `unsafe` code at release time.

**ODS-NFR-SEC-002.** Wire-format parsers — DNS message, EDNS option, RR-type-specific decoders, TSIG verification input, AXFR/IXFR stream parser — MUST be subject to continuous fuzz testing using `cargo-fuzz` or equivalent. Each release MUST be preceded by a minimum of 24 hours of fuzz testing per parser with no resulting crash, panic, or memory-safety finding.
*Source.* Defensive engineering; aligned with the project's security thesis.
*Verification.* CI pipeline integration of fuzz tests; release-process documentation.

**ODS-NFR-SEC-003.** Cryptographic key material — TSIG shared secrets per ODS-FR-TSIG-006, XoT client TLS private keys per ODS-FR-XOT-007 — MUST NOT appear in any log entry at any verbosity level, MUST NOT appear in error messages, and MUST be zeroed in process memory at process termination.
*Source.* ODS-FR-TSIG-006; ODS-FR-XOT-007; standard cryptographic key handling.
*Verification.* Static analysis of log-statement contents; static analysis of error-formatting code paths; memory inspection at controlled shutdown.

**ODS-NFR-SEC-004.** The server SHOULD be designed to run as an unprivileged operating-system user. Where binding to privileged ports (53, 853) is required, this SHOULD be achieved via OS-level capabilities (Linux `CAP_NET_BIND_SERVICE`) or socket activation from a supervisor, not by running the server process as root.
*Source.* Standard security practice; least-privilege principle.
*Verification.* Deployment tests confirming non-root execution viability.

**ODS-NFR-SEC-005.** The server MUST NOT listen on any network port beyond those required for configured DNS query service (UDP/53, TCP/53), optional XoT outbound (which does not require listening), and the optional health and metrics endpoint per §6.4. The server MUST NOT open any administrative or debugging port at any time, in accordance with ODS-INV-005 and ODS-NEG-011.
*Source.* Defensive engineering; ODS-INV-005.
*Verification.* Runtime network-layer inspection confirming bound ports match configuration.

**ODS-NFR-SEC-006.** Third-party Rust crates depended on by the server MUST be from well-maintained sources, subjected to security review at adoption time, and tracked against ongoing security advisories. The dependency set MUST be minimised consistent with functional requirements. Specific crate choices, with security justification, are recorded in the Architecture Document.
*Source.* PID §7.1; standard supply-chain security practice.
*Verification.* Periodic `cargo audit` execution; review of advisories at each release.

## 5.4 Maintainability

The area code **MAINT** is allocated.

**ODS-NFR-MAINT-001.** The total source-line count of first-party Rust code SHOULD remain within the range 5,000 to 15,000 lines, excluding tests, dependencies, and generated code. Feature additions or implementation choices that push the codebase beyond 15,000 lines require explicit justification recorded in the Architecture Document or release notes.
*Source.* PID §2.2.
*Verification.* Source-line measurement at release time using `tokei` or equivalent.

**ODS-NFR-MAINT-002.** The codebase MUST be organised into a small number of clearly-named, single-purpose modules, with each major functional area of §4 mappable to identifiable modules. The mapping is recorded in the Architecture Document.
*Source.* Maintainability and auditability per PID design principle.
*Verification.* Code review against the documented module mapping at release time.

**ODS-NFR-MAINT-003.** Every `unsafe` block in first-party Rust code MUST carry a comment stating the reason `unsafe` is necessary and the invariants on which its soundness depends, per ODS-INV-006.
*Source.* ODS-INV-006.
*Verification.* Static analysis confirming each `unsafe` block has an accompanying comment satisfying the form.

**ODS-NFR-MAINT-004.** Implementation of functional requirements of §4 SHOULD include code-level comments referencing the requirement identifier and relevant RFC clause. The Appendix A traceability matrix is the canonical mapping; in-code references aid review.
*Source.* Maintainability; review efficiency.
*Verification.* Code review confirming representative references in implementation comments.

**ODS-NFR-MAINT-005.** The build process MUST produce deterministic, reproducible binaries given a fixed source tree and pinned dependency set. The reproducibility approach (e.g., `cargo build --locked`, container build with pinned base image and tooling) is recorded in the Architecture Document.
*Source.* Supply-chain security; auditable releases.
*Verification.* Two independent builds from the same source produce bit-identical binaries.

## 5.5 Portability

The area code **PORT** is allocated.

**ODS-NFR-PORT-001.** The server MUST build and run on current LTS releases of major Linux distributions: Ubuntu LTS, Debian stable, Red Hat Enterprise Linux / Rocky Linux / AlmaLinux current major version, and Alpine current release. No distribution-specific configuration MUST be required.
*Source.* PID §2.4; operational requirement.
*Verification.* Per-distribution smoke tests in CI.

**ODS-NFR-PORT-002.** The server MUST build and run on the x86_64 (amd64) and aarch64 (arm64) processor architectures. Additional architectures MAY be supported on a best-effort basis without commitment.
*Source.* Operational requirement; modern Linux server architecture diversity.
*Verification.* Per-architecture build and smoke-test CI pipelines.

**ODS-NFR-PORT-003.** The server MUST be runnable in OCI-compatible container runtimes (Docker, Podman, containerd, CRI-O). The published container image MUST be runnable in Kubernetes without privileged mode, without host networking, and without escalated capabilities beyond `CAP_NET_BIND_SERVICE` (where required per ODS-NFR-SEC-004).
*Source.* PID §2.4.
*Verification.* Container deployment tests in representative runtimes.

**ODS-NFR-PORT-004.** The server MUST support both IPv4 and IPv6 for all network operations: client query service, zone-transfer initiation toward primaries, NOTIFY reception, XoT.
*Source.* Operational requirement; modern dual-stack expectation.
*Verification.* Per-address-family functional tests across all network operations.

**ODS-NFR-PORT-005.** The server MUST NOT depend on systemd, sysvinit, OpenRC, or any specific init system; on distribution-specific package management; or on distribution-specific filesystem layouts beyond those mandated by POSIX. The server's operation MUST be agnostic to the supervising process.
*Source.* Portability; container-native design.
*Verification.* Code review for init-system-specific or distribution-specific dependencies.

## 5.6 Observability

The area code **OBS** is allocated.

**ODS-NFR-OBS-001.** The server MUST emit log entries to stdout and stderr in a structured format (JSON or logfmt; the choice is configurable, default JSON). Each entry MUST include at minimum: a timestamp in RFC 3339 format, a level (debug / info / warning / error), a message, and contextual key-value pairs identifying the affected zone, peer IP, request identifier, or other relevant entity.
*Source.* Operational requirement; log-ingestion ecosystem compatibility.
*Verification.* Log output inspection; parser-conformance tests against the chosen format.

**ODS-NFR-OBS-002.** The server MUST support configurable log verbosity at the process level, with verbosity levels following the hierarchy error < warning < info < debug. The default verbosity MUST be info.
*Source.* Operational requirement.
*Verification.* Configuration tests across all levels.

**ODS-NFR-OBS-003.** The server MUST expose its in-memory counters — the query-handling counters of ODS-FR-QRY-024, the RRL counters of ODS-FR-RRL-012, the NOTIFY counters of §4.8, the TSIG counters per §4.9, the transfer-session counters per §4.6 and §4.7 — via a metrics endpoint per §6.4. The exposition format MUST be compatible with the Prometheus / OpenMetrics text format.
*Source.* Operational requirement; ecosystem compatibility.
*Verification.* Endpoint inspection; format-parsing tests against Prometheus scrapers.

**ODS-NFR-OBS-004.** The server MUST expose a health endpoint per §6.4 reporting the server's operational status in one of four states: **starting** (initial transfers in progress, no zones yet ACTIVE), **ready** (at least one zone in ACTIVE state), **draining** (SIGTERM received, graceful shutdown in progress), **unhealthy** (internal error preventing service). State transitions MUST be observable on the endpoint within 1 second of the actual state change.
*Source.* Operational requirement; orchestrator-friendly health probing.
*Verification.* Endpoint inspection across state transitions.

**ODS-NFR-OBS-005.** The metrics endpoint MUST expose per-zone status: zone state (LOADING / ACTIVE / EXPIRED per ODS-FR-ZONE-006), currently held SOA serial, timestamp of most recent successful refresh, timestamp of next scheduled refresh, count of refresh failures since the most recent success, and count of queries served for the zone since process start.
*Source.* Operational requirement.
*Verification.* Per-zone metric inspection.

## 5.7 Resource Limits

The area code **RES** is allocated.

**ODS-NFR-RES-001.** The published container image MUST NOT exceed 20 megabytes uncompressed.
*Source.* PID §6.1.
*Verification.* Image size measurement at release time.

**ODS-NFR-RES-002.** Memory consumption per zone SHOULD scale approximately linearly with the number of records in the zone, with a target per-record overhead (including indices and metadata) of less than 500 bytes.
*Source.* Operational requirement; informed by typical secondary deployment sizing.
*Verification.* Memory profiling with zones of varying record counts.

**ODS-NFR-RES-003.** The server MUST support concurrent service of at least 10,000 zones with a combined record count up to 10 million records on a host with 16 GiB of available memory.
*Source.* Operational requirement; large-secondary deployment sizing.
*Verification.* Capacity benchmarking with synthetic zone sets at the specified scale.

**ODS-NFR-RES-004.** The server's steady-state file-descriptor consumption MUST be bounded by approximately 2 × (the configured concurrent client TCP connection limit per ODS-FR-TCP-005 + the configured concurrent outbound TCP connection limit + 100 reserve for listening sockets and process overhead). The server MUST verify at startup that the OS-provided file-descriptor `rlimit` is sufficient for the configured limits, and MUST fail to start with a clear error message if not.
*Source.* Operational requirement.
*Verification.* Startup checks under varied `rlimit` settings; runtime file-descriptor count inspection.

**ODS-NFR-RES-005.** The total number of concurrent zone-transfer sessions (AXFR plus IXFR) MUST be bounded by the limit established in ODS-FR-AXFR-022, with the default of 4.
*Source.* ODS-FR-AXFR-022.
*Verification.* Per ODS-FR-AXFR-022.

# 6. External Interfaces

This section specifies the concrete external interfaces the server presents to its environment: the network ports it listens on and connects from, the configuration mechanism through which operators control it, the logging interface through which observers collect its output, the health and metrics endpoint through which orchestrators probe it, and the process signals to which it responds.

Many requirements in this section are concrete realisations of behaviours already specified elsewhere — the configuration interface (§6.2) materialises what §4.6, §4.9, §4.10, and others demand operators be able to configure; the logging interface (§6.3) materialises the structured-logging requirements of §5.6. Where this section restates rather than introduces, cross-references are explicit.

The category identifier is **IF**; each subsection allocates its own area code per §1.4.3.

## 6.1 Network Interfaces

The area code **NET** is allocated.

**ODS-IF-NET-001.** The server MUST bind UDP and TCP listening sockets at startup for DNS query service. Bind addresses MUST be configurable per §6.2. The default bind addresses MUST be 0.0.0.0 (IPv4 wildcard) and `::` (IPv6 wildcard), and the default port MUST be 53.
*Source.* PID §2.4; RFC 1035 §4.2.
*Verification.* Network-layer inspection after startup confirming bound sockets match configuration.

**ODS-IF-NET-002.** The server MUST support binding to multiple specific addresses simultaneously, including arbitrary combinations of IPv4 and IPv6 addresses. Independent UDP and TCP listening sockets MUST be created per (address, transport) tuple as required by the operating system.
*Source.* Operational requirement; anycast and multi-interface deployment.
*Verification.* Configuration tests with multi-address bind specifications.

**ODS-IF-NET-003.** The server MUST initiate outbound TCP connections for zone-transfer queries (§4.6, §4.7), SOA poll queries (§4.16), and XoT connections (§4.10) from a source address selected by the operating system, unless an outbound source address is explicitly configured per zone or per primary.
*Source.* Operational requirement.
*Verification.* Network-layer inspection of outbound connections.

**ODS-IF-NET-004.** At startup, if any required listening socket fails to bind — for reasons including port already in use, permission denied, or address unavailable — the server MUST log the failure at error level identifying the affected (address, port, transport) tuple, and MUST exit with non-zero status code. The server MUST NOT continue operating with a partial set of listening sockets.
*Source.* Fail-fast configuration discipline.
*Verification.* Tests with conflicting bind addresses confirming exit behaviour.

## 6.2 Configuration Interface

The area code **CONF** is allocated.

**ODS-IF-CONF-001.** All operational configuration MUST be supplied via a single TOML-formatted configuration file, the path of which is specified to the process at startup via a command-line argument (default path: `/etc/oxidedns-secondary/config.toml`).
*Source.* ODS-INV-005; operational simplicity.
*Note.* TOML is selected for ecosystem alignment with the Rust toolchain (Cargo). YAML and JSON are alternative formats; TOML's restricted, unambiguous syntax avoids the YAML edge cases (Norway-problem booleans, indentation-sensitive structure, multiple parser implementations producing different results) that have produced production incidents in other DNS server projects.
*Verification.* Configuration parsing tests; round-trip tests confirming idempotent serialisation where applicable.

**ODS-IF-CONF-002.** The configuration schema MUST be documented in a versioned schema specification maintained alongside the project. Schema changes between server versions MUST follow a backward-compatibility policy: addition of new optional fields is permitted at any release; removal or semantic change of existing fields requires a major-version increment per semantic versioning.
*Source.* Operational stability for in-place upgrades.
*Verification.* Schema documentation maintained per project release; version-compatibility tests in CI.

**ODS-IF-CONF-003.** The configuration MUST be capable of expressing, at minimum:
- the set of zones designated for service, each with zone name, class, and ordered list of primary servers (IP addresses with optional port);
- per-zone TSIG configuration: key reference and applicability (queries, transfers, NOTIFY);
- per-(zone, primary) XoT configuration: trust anchors, expected SNI, optional client certificate;
- TSIG key definitions: key name, algorithm, secret value (inline or by file reference per ODS-IF-CONF-004);
- network bind configuration per ODS-IF-NET-001 and ODS-IF-NET-002;
- logging configuration per §6.3;
- health and metrics endpoint configuration per §6.4;
- tunable parameters (timeouts, limits, RRL thresholds, jitter, keepalive intervals) with override of defaults.

*Source.* The configuration prerequisites stated by §4 requirements; operational completeness.
*Verification.* Schema completeness review against the enumerated categories.

**ODS-IF-CONF-004.** TSIG shared secrets and XoT client TLS private keys MAY be specified inline within the configuration file or by reference to a separate file path. Where referenced by file path, the server MUST verify at startup that the referenced file is readable by the server process and is not world-readable (file mode permitting access by the "other" class). Either failure MUST prevent startup with a clear error message.
*Source.* ODS-FR-TSIG-006; ODS-FR-XOT-007; operational security for key material.
*Verification.* Startup tests with various secret-file permission modes.

**ODS-IF-CONF-005.** The server MUST validate the entire configuration at startup before binding any listening sockets. Validation MUST include schema conformance, TSIG algorithm support per §4.9, XoT trust-anchor parseability per §4.10, network-address parseability, and value-range checks for numeric parameters (port numbers, timeout values, rate limits). Any validation failure MUST cause the server to log a clear error message identifying the specific configuration defect and exit with non-zero status; the server MUST NOT begin partial operation with partially valid configuration.
*Source.* Fail-fast configuration discipline; ODS-INV-005.
*Verification.* Tests with deliberately invalid configurations across each validation category.

**ODS-IF-CONF-006.** The server SHOULD also accept a documented subset of configuration parameters via environment variables. Where supported, environment variables MUST take precedence over the corresponding configuration file value. Not every configuration parameter requires an environment-variable equivalent; the supported subset is documented per ODS-IF-CONF-002.
*Source.* Container-native operational convenience.
*Verification.* Tests confirming environment-variable precedence for supported parameters.

**ODS-IF-CONF-007.** The server MUST NOT install a SIGHUP handler that re-reads configuration, in accordance with ODS-INV-005 and ODS-NEG-011. Configuration changes are applied only by process restart.
*Source.* ODS-INV-005; ODS-NEG-011.
*Verification.* SIGHUP signal tests confirming no configuration change behaviour.

## 6.3 Logging Interface

The area code **LOG** is allocated.

**ODS-IF-LOG-001.** The server MUST write log entries to standard output and standard error: entries at the info and debug levels to stdout, entries at the warning and error levels to stderr. The server MUST NOT open, create, or write to any log file directly. Persistent log storage is the responsibility of the supervising process or log-collection infrastructure.
*Source.* Container-native logging convention; ODS-INV-004 (no persistent state, no filesystem writes beyond standard streams).
*Verification.* Log-output stream verification across log levels.

**ODS-IF-LOG-002.** Log entry format MUST be either JSON or logfmt, as selected by configuration per §6.2. The default format MUST be JSON. Format selection is global to the process and applies uniformly to stdout and stderr output. The chosen format MUST conform to the structured-logging requirements of ODS-NFR-OBS-001.
*Source.* ODS-NFR-OBS-001.
*Verification.* Per ODS-NFR-OBS-001.

**ODS-IF-LOG-003.** Log level MUST be configurable via the configuration file per §6.2 and via environment variable (`ODS_LOG_LEVEL` or equivalent) per ODS-IF-CONF-006. The default log level MUST be info per ODS-NFR-OBS-002.
*Source.* ODS-NFR-OBS-002.
*Verification.* Per ODS-NFR-OBS-002.

**ODS-IF-LOG-004.** The server MUST NOT integrate directly with syslog, systemd-journald, Windows Event Log, or any other host-specific logging mechanism. Operators requiring such integration are expected to use standard tools (e.g., `systemd-cat`, log shipping agents) to redirect or transform the server's standard-stream output.
*Source.* Container-native logging convention; portability per §5.5.
*Verification.* Code review confirming no syslog/journald linkage; dependency review confirming no such libraries.

## 6.4 Health and Metrics Endpoint

The area code **HEALTH** is allocated.

**ODS-IF-HEALTH-001.** The server MUST expose a combined health and metrics endpoint over plain HTTP/1.1 (no TLS, no authentication). The endpoint is activated by configuration per §6.2 with a configurable bind address and port; when not configured, the endpoint MUST NOT be activated and no HTTP listening socket MUST be opened.
*Source.* Operational requirement; orchestrator-friendly probing.
*Note.* HTTP/1.1 without TLS is the dominant pattern for in-cluster service probes. Operators requiring secure exposure are expected to bind the endpoint to a private interface or deploy it behind a reverse proxy.
*Verification.* Endpoint reachability tests across enabled and disabled configurations.

**ODS-IF-HEALTH-002.** When activated, the endpoint MUST serve the following HTTP paths in response to GET requests:

- `/healthz` — returns the server's overall health state per ODS-NFR-OBS-004 as a plain-text body. HTTP status 200 when in the *ready* state; HTTP status 503 when in *starting*, *draining*, or *unhealthy* states.
- `/readyz` — returns the server's readiness to serve queries, distinct from `/healthz` in that it returns 200 only when at least one zone has reached ACTIVE state per ODS-FR-ZONE-006 (not merely when the process has started). HTTP status 200 when ready; 503 otherwise.
- `/metrics` — returns server metrics in the Prometheus / OpenMetrics text exposition format per ODS-NFR-OBS-003. HTTP status 200 with the metrics text body.
- All other paths — return HTTP status 404.

Methods other than GET MUST receive HTTP status 405.
*Source.* Operational requirement; Kubernetes probe conventions; Prometheus scraping convention.
*Verification.* HTTP request tests against each path and method combination.

**ODS-IF-HEALTH-003.** The endpoint MUST be accessible without authentication. Network-layer access control — firewall rules, network policy, or binding to a private interface — is the operator's responsibility.
*Source.* Operational simplicity.
*Note.* This is an opinionated stance: authentication on a probe endpoint is operationally fraught (key distribution to probes, token rotation, etc.) and adds complexity disproportionate to the security benefit. The standard mitigation — bind to a private interface — is the appropriate boundary.
*Verification.* Endpoint access tests without credentials confirming response.

**ODS-IF-HEALTH-004.** The endpoint MUST be served from a separate thread or asynchronous task isolated from the main DNS query-handling path, such that endpoint scraping load — including high-frequency metric scraping by aggressive Prometheus configurations — MUST NOT measurably impact DNS query latency as measured against ODS-NFR-PERF-002 and ODS-NFR-PERF-003.
*Source.* Operational isolation.
*Verification.* Load tests with high-frequency metrics scraping concurrent with sustained DNS query load.

## 6.5 Process Signals

The area code **SIG** is allocated.

**ODS-IF-SIG-001.** The server MUST handle SIGTERM by initiating graceful shutdown in accordance with ODS-NFR-REL-001.
*Source.* ODS-NFR-REL-001; container orchestrator convention.
*Verification.* SIGTERM tests confirming graceful shutdown behaviour.

**ODS-IF-SIG-002.** The server MUST handle SIGINT identically to SIGTERM, initiating graceful shutdown.
*Source.* Interactive operator convenience (Ctrl+C during foreground execution).
*Verification.* SIGINT tests.

**ODS-IF-SIG-003.** The server MUST NOT install a handler for SIGHUP. Receipt of SIGHUP MUST be ignored in accordance with ODS-INV-005 and ODS-NEG-011.
*Source.* ODS-INV-005; ODS-NEG-011.
*Verification.* SIGHUP signal tests; observe no behavioural change.

**ODS-IF-SIG-004.** The server MUST NOT install handlers for SIGUSR1, SIGUSR2, SIGQUIT, or any other signal not enumerated in this subsection. Such signals MUST follow operating-system default behaviour (typically process termination with core dump for SIGQUIT, termination for SIGUSR1 and SIGUSR2).
*Source.* Minimal signal-handling surface; principle of least operational interface.
*Verification.* Code review confirming the signal-handler registrations exactly match the enumeration of ODS-IF-SIG-001 through ODS-IF-SIG-003.

# 7. Verification Strategy

This section specifies how the requirements of §3 through §6 are verified. It does *not* enumerate concrete test cases — that is the function of the Test Plan, a sibling document per §1.6.1. Rather, this section specifies the methods by which verification is performed, the scope of interoperability testing, the structure of RFC-compliance assessment, the acceptance criteria mapping requirements to PID milestones, and the boundary between the SRS and the Test Plan.

A new requirement category is introduced in this section: **ODS-VER-NNN** for verification requirements. The AREA component is omitted from these identifiers, following the pattern of ODS-INV-NNN and ODS-NEG-NNN. The category is added to the §1.4.3 enumeration in a future SRS revision; flagged in closing notes.

## 7.1 Verification Methods

The following methods are used, individually or in combination, to verify the requirements of this SRS:

**Inspection.** Static code review, static analysis (`cargo clippy`, `cargo geiger`, `cargo audit`), and documentation review. Used for requirements verifiable by examination of source code or static artifacts: architectural invariants, requirements concerning code structure or memory safety discipline, prohibitions verifiable by code search.

**Unit test.** Automated, code-level tests of individual functions or modules in isolation. Used for parser correctness, RR-type decoding, algorithmic logic (SOA serial arithmetic, RRL token bucket), and any requirement whose verification can be made deterministic without external dependencies.

**Integration test.** Automated, in-process tests exercising multiple modules together — for example, a query handler running against an in-memory zone store loaded from a synthetic AXFR response. Used for end-to-end behaviour within a single server process.

**Conformance test.** Tests deriving inputs from RFC-specified wire-format test vectors and verifying outputs against RFC-specified expected behaviour. Used for protocol-correctness requirements throughout §4.

**Interoperability test.** Tests of the server running against real implementations of peer roles — primary servers (NSD, Knot DNS, BIND 9), TSIG-capable peers, DNS clients (dig, kdig, drill). Used for any requirement whose verification depends on real-world peer behaviour and not just specification reading.

**Fuzz test.** Coverage-guided fuzzing using `cargo-fuzz` or equivalent, applied to wire-format parsers and any code path consuming untrusted input. Used for ODS-NFR-SEC-002 and as supporting evidence for parser-related functional requirements.

**Performance test.** Sustained-load benchmarking, latency-distribution measurement, capacity-scaling tests. Used for §5.1 (PERF) and the capacity-related requirements of §5.7 (RES).

**Soak test.** Long-duration runtime tests (days to weeks) under realistic workload, measuring memory consumption, file-descriptor stability, and detection of slow leaks or accumulating state. Used for ODS-NFR-REL-003 and supporting verification for §5.2 (REL).

**Operational test.** Deployment in representative environments (containers, virtual machines), exercising startup, signal handling, configuration parsing, and orchestrator integration. Used for §5.5 (PORT), §6.1, §6.2, §6.4, §6.5.

**External operator acceptance.** Independent deployment and verification by operators outside the project team. Used during PID Phase 4 (MVP testing) and as ongoing post-release validation; constitutes the highest-confidence form of operational verification.

**ODS-VER-001.** Verification of each requirement in §3 through §6 MUST be performed using the method or combination of methods specified in that requirement's *Verification* field. Each *Verification* field MUST map to one or more methods enumerated in this subsection.
*Source.* SRS internal consistency.
*Verification.* Self-referential; covered by the SRS review process.

**ODS-VER-002.** Verification evidence — test outputs, benchmark results, code-review records, fuzz-test summaries, interop test logs — MUST be captured by the project's continuous integration system and retained for each release.
*Source.* Audit and reproducibility; PID §7.
*Verification.* CI pipeline review at release time.

## 7.2 Interoperability Matrix

**ODS-VER-003.** The server MUST be tested for interoperability as a secondary against the following primary implementations, each at its current stable major release at the time of test execution:
- **NSD** (NLnet Labs);
- **Knot DNS** (CZ.NIC);
- **BIND 9** (ISC).

For each (server, primary) pair, the test matrix MUST cover:
- AXFR initial load and refresh per §4.6;
- IXFR incremental refresh including IXFR-to-AXFR fallback per §4.7;
- NOTIFY receipt and refresh triggering per §4.8;
- TSIG-authenticated transfers per §4.9 with at least the HMAC-SHA256 algorithm;
- XoT-secured transfers per §4.10, against any primary in the list that supports XoT at the time of testing (Knot DNS at minimum as of 2026).

*Source.* PID §6; operational requirement for production interoperability.
*Verification.* Interop test pipeline execution per the matrix.

**ODS-VER-004.** The interoperability matrix MUST exercise zones of operationally representative complexity:
- at least one small zone (< 1,000 records) for baseline correctness;
- at least one medium zone (10,000–100,000 records) for typical-load behaviour;
- at least one large zone (> 1,000,000 records) for scaling validation;
- at least one DNSSEC-signed zone using NSEC; and one DNSSEC-signed zone using NSEC3.

*Source.* Coverage of the operational range for which the server is intended.
*Verification.* Test corpus inventory at release time.

## 7.3 RFC Compliance Assessment

**ODS-VER-005.** For each RFC listed in PID Appendix A, the project MUST maintain a clause-level traceability mapping (recorded in Appendix A of this SRS) from each requirement-bearing RFC clause to one or more requirements in §3 through §6. Compliance with an RFC is asserted only when all in-scope requirement-bearing clauses of that RFC are mapped to verifying SRS requirements, and all those SRS requirements have been verified per ODS-VER-001.
*Source.* PID §2.3 (RFC compliance target).
*Verification.* Traceability matrix review at release time.

**ODS-VER-006.** Where an RFC referenced by PID Appendix A contains normative clauses that fall outside this server's scope — for example, primary-side requirements within an RFC that also covers secondary-side behaviour, or resolver-side requirements within an RFC primarily about authoritative service — the traceability matrix MUST mark those clauses as out-of-scope with a brief rationale referencing ODS-INV-001 (secondary-only) or PID §3.2. The RFC is then assessed for compliance limited to the in-scope clauses, and the compliance claim is documented accordingly (for example, "Compliant with RFC X, secondary-side clauses only; primary-side clauses out of scope per ODS-INV-001").
*Source.* Accurate scoping of compliance claims.
*Verification.* Traceability matrix review.

## 7.4 Acceptance Criteria for PID Milestones

The PID establishes Alpha and MVP milestones. The acceptance criteria for each are stated below in terms of SRS requirement coverage.

**ODS-VER-007 — Alpha Milestone.** The Alpha milestone is achieved when the following are demonstrably satisfied:

- All ODS-INV requirements (§3);
- Functional requirements: §4.1 (CORE) in full; §4.2 (QRY) excluding RFC 8482 minimal-ANY (ODS-FR-QRY-003 through -007 deferred); §4.3 (NRESP) in full; §4.4 (URR) in full; §4.5 (SPOOF) in full; §4.6 (AXFR) in full; §4.8 (NOTIFY) in full; §4.11 (EDNS) in full; §4.12 (TCP) in full; §4.14 (RR) restricted to RFC 1035 types plus AAAA; §4.15 (ZONE) in full; §4.16 (ZSM) in full;
- TSIG (§4.9): minimum subset sufficient for HMAC-SHA256 interop with at least one TSIG-configured primary (ODS-FR-TSIG-001, -005 through -012, -017);
- Interface requirements: §6.1, §6.2 (CONF) in full, §6.3, §6.4 (HEALTH) excluding `/readyz` distinction, §6.5;
- Non-functional requirements: §5.2 (REL) in full, §5.4 (MAINT) -001 and -003, §5.5 (PORT) -001 to -004, §5.6 (OBS) -001, -002, -004, §5.7 (RES) -001 (container image size);
- Interoperability per §7.2 with **at least one** of {NSD, Knot DNS, BIND 9} as primary.

Deferred from Alpha to MVP: §4.7 (IXFR), §4.9 (full TSIG), §4.10 (XOT), §4.13 (DNSSEC serving), §4.17 (RRL), §4.14 expanded RR catalogue, performance NFR conformance, full security/maintainability verification, second and third primary interop.
*Source.* PID §6.
*Verification.* Acceptance review at the Alpha milestone gate.

**ODS-VER-008 — MVP Milestone.** The MVP milestone is achieved when the following are demonstrably satisfied:

- All requirements of §3 through §6 to their full normative content;
- Interoperability per §7.2 with all three primaries (NSD, Knot DNS, BIND 9);
- All ODS-NFR-PERF performance targets met under benchmarking;
- A 30-day soak test per ODS-NFR-REL-003 completed without anomaly;
- Fuzz testing per ODS-NFR-SEC-002 executed for ≥ 24 hours per parser without finding;
- Dependency security audit per ODS-NFR-SEC-006 clean;
- Documentation complete: this SRS, the Architecture Document, the Test Plan, and the Operator Deployment Guide;
- External operator acceptance per §7.1 by at least one production-representative operator.

*Source.* PID §6.
*Verification.* Acceptance review at the MVP milestone gate.

## 7.5 Verification Evidence and Traceability

**ODS-VER-009.** The traceability matrix in Appendix A MUST record, for each requirement in §3 through §6, the verification status: **Not Verified**, **Verified** (with date and reference to the evidence), or **Deferred** (with target milestone). The matrix is the canonical record of verification progress.
*Source.* Audit and project tracking.
*Verification.* Matrix review at each release.

## 7.6 Test Plan Boundary

The Test Plan is a sibling document per §1.6.1, maintained independently of this SRS. Its scope and relationship to this SRS is as follows:

- The SRS specifies *what* is to be verified, *by what method*, and *for what acceptance criterion*.
- The Test Plan specifies *the concrete test cases* — fixtures, inputs, expected outputs, harness configuration, tooling.
- Each test case in the Test Plan MUST reference one or more SRS requirement identifiers, establishing bidirectional traceability via Appendix A.
- Changes to the SRS that affect verification approach (modifications to *Verification* fields, additions or modifications of requirements) trigger review of the corresponding Test Plan content; the project's change-management process governs the coordination.

The separation prevents the SRS from accumulating test-case detail that does not serve the SRS's normative purpose, while ensuring that the SRS's verification statements are realised in executable artifacts.

# Appendix A — Requirement-to-RFC Traceability Matrix

## A.1 Purpose

Appendix A is the canonical bidirectional mapping between RFCs (and other normative references) and the requirements of this SRS. Its purposes are:

- to demonstrate, for each RFC in the project's compliance target (PID Appendix A), that all in-scope normative clauses are realised by one or more SRS requirements;
- to identify, for each RFC, those clauses that fall outside this server's scope, with reference to the architectural invariant or PID scope clause that excludes them;
- to provide, for each SRS requirement, the source RFC(s) and clause(s) from which it derives;
- to track verification status per requirement, supporting the milestone acceptance criteria of ODS-VER-007 and ODS-VER-008.

Appendix A is intended to be maintained as a living document throughout the project's lifetime. The current version, drafted alongside the SRS body, provides the structural foundation and a coarse-grained RFC-to-requirement mapping. Clause-level refinement is iterative work conducted during the implementation and review phases.

## A.2 Conventions

### A.2.1 Identifier stability

Requirement identifiers in this Appendix are immutable per ODS-§1.4.4. A requirement marked **Deprecated** in §3 through §6 remains in the Appendix tables with a pointer to its replacement; rows are never removed.

### A.2.2 Scope categorisation

Each RFC entry in A.3 is categorised by scope:

- **Full.** All normative clauses of the RFC are in scope and mapped to implementing requirements.
- **Partial (secondary-side).** The RFC's secondary-server-side clauses are in scope and mapped; primary-side, resolver-side, or validator-side clauses are out of scope per ODS-INV-001 or PID §3.2, and are catalogued in A.5.
- **Partial (selected clauses).** Specific clauses are in scope (for example, only the wire-format definition of a particular RR type); the remainder are out of scope, catalogued in A.5.
- **Informative.** The RFC is cited for guidance or background rather than for normative requirements. No traceability mapping is required.

### A.2.3 Verification status

Each requirement carries a verification status per ODS-VER-009:

- **Not Verified** — verification has not yet been performed.
- **Verified** — verification has been performed; the date and evidence reference are recorded.
- **Deferred** — verification is deferred to a specific milestone (typically MVP per ODS-VER-008).
- **Not Applicable** — the requirement has been Deprecated or replaced; the row is retained for identifier stability.

Status tracking is maintained per A.6.

### A.2.4 Mapping granularity

Two granularities of mapping are supported:

- **Coarse-grained.** RFC → SRS subsection (for example, RFC 5936 → §4.6). Sufficient for project-level compliance assertion when the SRS subsection covers the RFC fully.
- **Fine-grained.** RFC clause → SRS requirement identifier (for example, RFC 5936 §2.2.1 → ODS-FR-AXFR-005, ODS-FR-AXFR-007). Required for partial-scope RFCs and for clause-level audit.

The coarse-grained mapping is provided comprehensively in A.3 below. Fine-grained mapping is illustrated for representative RFCs in A.4 and is to be completed iteratively during implementation review.

## A.3 RFC Compliance Index

### A.3.1 Core DNS protocol

**RFC 1034 — Domain Names: Concepts and Facilities** (Mockapetris, 1987).
*Scope.* Partial (secondary/server-side).
*Implementing sections.* §3 (architectural invariants), §4.1 (CORE), §4.2 (QRY), §4.3 (NRESP), §4.6 (AXFR), §4.15 (ZONE), §4.16 (ZSM).
*Key clauses.* §3.1 (name hierarchy) → CORE-007, CORE-009; §3.6.2 (CNAME) → QRY-010..013, NRESP-004..006; §3.7 (recursion) → QRY-001, NEG-007; §4.2 (zone concepts) → AXFR-012, AXFR-013, ZONE-001; §4.3.2 (response construction) → CORE-019..025; §4.3.5 (zone refresh timing) → ZSM-001..012; §6.2 (response semantics) → CORE-011..014.
*Out-of-scope clauses.* §5 (resolver-side) — ODS-INV-001; §6.1 (master files) — ODS-NEG-006; primary-role aspects of §4.3.5 — ODS-INV-001.

**RFC 1035 — Domain Names: Implementation and Specification** (Mockapetris, 1987).
*Scope.* Partial (secondary/server-side).
*Implementing sections.* §4.1 (CORE), §4.2 (QRY), §4.3 (NRESP), §4.4 (URR), §4.11 (EDNS), §4.12 (TCP), §4.14 (RR).
*Key clauses.* §2.3 (name encoding) → CORE-007, CORE-008, CORE-009; §3.2 (RR class) → CORE-016..018; §3.3 (RR type wire formats) → RR-001 + catalogue; §3.3.13 (SOA) → RR-002, RR-004, NRESP-001; §4.1 (message format) → CORE-001..015; §4.1.4 (compression) → CORE-008, QRY-023, URR-006; §4.2.1 (TC bit, UDP) → TCP-008, EDNS-006; §4.2.2 (TCP framing) → TCP-001; §6.2.4–6.2.5 (referrals, glue) → CORE-025, QRY-017.
*Out-of-scope clauses.* §5 (master file format) — ODS-NEG-006; §7 (resolver implementation) — ODS-INV-001; §4.3 (zone transfer original specification) — superseded by RFC 5936 for AXFR and RFC 1995 for IXFR; primary-role aspects throughout — ODS-INV-001.

**RFC 2181 — Clarifications to the DNS Specification** (Elz & Bush, 1997).
*Scope.* Partial (secondary/server-side).
*Implementing sections.* §4.1 (CORE), §4.3 (NRESP), §4.12 (TCP), §4.14 (RR).
*Key clauses.* §5 (RRset semantics) → CORE-026, CORE-027; §5.2 (TTL uniformity) → CORE-027; §6.1 (SOA at apex) → RR-002; §7 (NODATA) → CORE-022; §9 (response size, truncation) → TCP-008; §10.1 (CNAME exclusivity) → RR-005; §11 (name format) → CORE-028.
*Out-of-scope clauses.* §6.2 (zone publication, primary-side) — ODS-INV-001.

**RFC 4343 — Domain Name System (DNS) Case Insensitivity Clarification** (Eastlake, 2006).
*Scope.* Full.
*Implementing sections.* §4.1 (CORE), §4.4 (URR), §4.14 (RR).
*Key clauses.* §2 (octet-level handling) → CORE-028, URR-008; §3 (case-insensitive comparison) → CORE-009, CORE-010.

**RFC 4592 — The Role of Wildcards in the Domain Name System** (Lewis, 2006).
*Scope.* Full (secondary-server-side aspects).
*Implementing sections.* §4.1 (CORE), §4.2 (QRY), §4.3 (NRESP), §4.13 (DNSSEC), §4.15 (ZONE).
*Key clauses.* §2.2.2 (empty non-terminal handling) → QRY-016, NRESP-003; §2.2.3 (occlusion) → QRY-016, AXFR-014; §3 (synthesis rules) → CORE-024; §3.4 (DNSSEC interaction) → DNSSEC-006.

### A.3.2 Zone transfer and notification

**RFC 5936 — DNS Zone Transfer Protocol (AXFR)** (Lewis & Hoenes, 2010).
*Scope.* Full (client-side; this server is exclusively an AXFR client).
*Implementing sections.* §4.6 (AXFR), §4.10 (XOT for transfer encryption).
*Key clauses.* §2.1.1 (TCP transport) → AXFR-001; §2.1.2 (query construction) → AXFR-002; §2.2 (response structure, message reassembly) → AXFR-004..008; §2.2.1 (header bit non-significance) → AXFR-006; §2.2.4 (out-of-zone, glue, occluded data) → AXFR-012..014; §3.1 (error handling) → AXFR-019, AXFR-020; §4.1 (TCP persistence) → AXFR-003; §2.2.5 (TSIG signing) → AXFR-017, AXFR-018, TSIG-010, TSIG-011.
*Out-of-scope clauses.* AXFR server-side requirements throughout — ODS-NEG-005.

**RFC 1995 — Incremental Zone Transfer in DNS** (Ohta, 1996).
*Scope.* Full (client-side).
*Implementing sections.* §4.7 (IXFR).
*Key clauses.* §2 (UDP/TCP transport) → IXFR-001, IXFR-002; §3 (response modes, AXFR fallback) → IXFR-004, IXFR-011, IXFR-014; §4 (incremental encoding) → IXFR-005..010, IXFR-013.
*Out-of-scope clauses.* IXFR server-side requirements — ODS-NEG-005.

**RFC 1996 — A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)** (Vixie, 1996).
*Scope.* Partial (receiver-side; this server is exclusively a NOTIFY receiver).
*Implementing sections.* §4.8 (NOTIFY), §4.16 (ZSM for refresh triggering).
*Key clauses.* §3.1 (transport) → NOTIFY-001; §3.6 (retransmission semantics) → NOTIFY-009; §3.7 (embedded SOA) → NOTIFY-008, ZSM-007; §3.10 (zone authorisation) → NOTIFY-003, NOTIFY-004; §4.4 (refresh triggering) → NOTIFY-007, ZSM-003; §4.7, §4.8 (response construction) → NOTIFY-006.
*Out-of-scope clauses.* NOTIFY origination (§3.x originator semantics) — ODS-NEG-004.

**RFC 8945 — Secret Key Transaction Authentication for DNS (TSIG)** (Dupont, Morris, Vixie, Eastlake, Gudmundsson, Wellington, 2020).
*Scope.* Full.
*Implementing sections.* §4.9 (TSIG), §4.6 (AXFR signing), §4.7 (IXFR signing), §4.8 (NOTIFY signing).
*Key clauses.* §4 (TSIG RR format) → TSIG-007, TSIG-008; §5.2 (TSIG on requests/responses) → TSIG-013; §5.2.1 (UDP size limits) → TSIG-016; §5.2.2.1 (truncation) → TSIG-014; §5.3 (signing process) → TSIG-012; §5.3.1 (multi-message TSIG) → TSIG-010, TSIG-011, AXFR-018, IXFR-015; §5.4 (verification process) → TSIG-008..011; §6 (algorithms, HMAC-MD5 deprecation) → TSIG-001, TSIG-004, NEG-013.

**RFC 4635 — HMAC SHA TSIG Algorithm Identifiers** (Eastlake, 2006).
*Scope.* Full.
*Implementing sections.* §4.9 (TSIG).
*Key clauses.* §3 (algorithm identifiers) → TSIG-001..003; §3.1 (truncation lengths) → TSIG-014.

**RFC 9103 — DNS Zone Transfer over TLS** (Toorop, Dickinson, Sahib, Aras, Mankin, 2022).
*Scope.* Partial (client-side; this server is XoT client only per §4.10 scope statement).
*Implementing sections.* §4.10 (XOT).
*Key clauses.* §6 (port, ALPN) → XOT-003, XOT-004; §6.5 (connection persistence) → XOT-009; §7.1 (TLS versions) → XOT-001; §7.4 (ALPN) → XOT-004; §9.1 (Strict Profile, authentication) → XOT-005, XOT-006; §9.2 (Opportunistic Profile) → ODS-NEG-016 (prohibited); §9.3 (combined with TSIG) → XOT-008; §9.4 (mTLS) → XOT-007.
*Out-of-scope clauses.* §6.4 (NOTIFY over TLS, receiver side) — ODS-NEG-017; XoT server-side requirements throughout — ODS-NEG-005 implicitly via secondary-only role.

### A.3.3 Negative response and resilience

**RFC 2308 — Negative Caching of DNS Queries (DNS NCACHE)** (Andrews, 1998).
*Scope.* Partial (authoritative server-side aspects).
*Implementing sections.* §4.3 (NRESP), §4.1 (CORE-022, CORE-023).
*Key clauses.* §2.1 (NXDOMAIN response composition) → CORE-023, NRESP-001; §2.2 (NODATA response composition) → CORE-022, NRESP-001; §3 (negative response TTL) → NRESP-001, NRESP-002; §4–§5 (SOA TTL semantics) → NRESP-001; §6 (authoritative-side semantics) → NRESP-001..006.
*Out-of-scope clauses.* §7 (resolver caching) — ODS-INV-001.

**RFC 5452 — Measures for Making DNS More Resilient against Forged Answers** (Hubert & van Mook, 2009).
*Scope.* Full (insofar as the server originates queries; primarily resolver-oriented).
*Implementing sections.* §4.5 (SPOOF).
*Key clauses.* §3 (response matching) → SPOOF-003..006; §6 (validation rules) → SPOOF-003..006; §9.1 (QID entropy) → SPOOF-001; §9.2 (source port entropy) → SPOOF-002.

**RFC 8020 — NXDOMAIN: There Really Is Nothing Underneath** (Bortzmeyer & Huque, 2016).
*Scope.* Full.
*Implementing sections.* §4.3 (NRESP).
*Key clauses.* §2 (NXDOMAIN cut semantics) → NRESP-003.

**RFC 8482 — Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY** (Abley, Gudmundsson, Majkowski, Hunt, 2018).
*Scope.* Full.
*Implementing sections.* §4.2 (QRY).
*Key clauses.* §4.1 (subset response) → QRY-005; §4.2 (HINFO synthesis, prohibited) → QRY-007, NEG-015.

### A.3.4 Transport

**RFC 6891 — Extension Mechanisms for DNS (EDNS(0))** (Damas, Graff, Vixie, 2013).
*Scope.* Full (insofar as authoritative-server-side; obsoletes RFC 2671).
*Implementing sections.* §4.11 (EDNS), §4.12 (TCP for truncation interaction), §4.13 (DNSSEC for DO bit).
*Key clauses.* §6.1.1 (OPT RR placement and multiplicity) → EDNS-002, EDNS-003; §6.1.2 (RDATA option encoding) → EDNS-001; §6.1.3 (extended RCODE, VERSION, DO bit) → EDNS-004, EDNS-010, DNSSEC-009; §6.1.4 (Z bits) → EDNS-008; §6.2.3 (UDP payload size handling) → EDNS-005; §6.2.5 (response size) → EDNS-006; §7 (response OPT semantics) → EDNS-007, EDNS-008.

**RFC 7766 — DNS Transport over TCP — Implementation Requirements** (Dickinson, Dickinson, Bellis, Mankin, Wessels, 2016).
*Scope.* Full.
*Implementing sections.* §4.12 (TCP), §4.6 (AXFR transport), §4.7 (IXFR transport).
*Key clauses.* §6.2 (pipelining, out-of-order responses) → TCP-007; §6.2.1 (connection persistence) → TCP-002; §6.2.3 (idle timeout) → TCP-003; §8 (message framing) → TCP-001, TCP-009, AXFR-003; §10 (resource limits) → TCP-005.

**RFC 7828 — The edns-tcp-keepalive EDNS0 Option** (Wouters, Abley, Dickinson, Bellis, 2016).
*Scope.* Full.
*Implementing sections.* §4.11 (EDNS), §4.12 (TCP).
*Key clauses.* §3 (option encoding, server response) → EDNS-011, EDNS-012; §3.4 (UDP behaviour) → EDNS-011.

**RFC 7830 — The EDNS(0) Padding Option** (Mayrhofer, 2016).
*Scope.* Full (recognition required; emission optional).
*Implementing sections.* §4.11 (EDNS).
*Key clauses.* §3 (option encoding and use) → EDNS-013.

### A.3.5 Resource Record types

**RFC 1982 — Serial Number Arithmetic** (Elz & Bush, 1996).
*Scope.* Full.
*Implementing sections.* §4.7 (IXFR), §4.14 (RR), §4.16 (ZSM).
*Key clauses.* §3.2 (comparison arithmetic) → RR-004, IXFR-006, ZSM-006.

**RFC 2782 — A DNS RR for specifying the location of services (DNS SRV)** (Gulbrandsen, Vixie, Esibov, 2000).
*Scope.* Full (RR format and compression policy).
*Implementing sections.* §4.14 (RR), §4.2 (QRY for additional section).
*Key clauses.* RR wire format → RR-001 + catalogue; §2.7 (non-compressibility, with RFC 6604 clarification) → QRY-023, RR catalogue.

**RFC 3403 — Dynamic Delegation Discovery System (DDDS) Part Three: The DNS Database (NAPTR)** (Mealling, 2002).
*Scope.* Partial (RR format only).
*Implementing sections.* §4.14 (RR), §4.2 (QRY).
*Key clauses.* §4 (NAPTR RR format) → RR-001 + catalogue.
*Out-of-scope clauses.* DDDS algorithm — beyond DNS-server scope.

**RFC 3596 — DNS Extensions to Support IP Version 6 (AAAA)** (Thomson, Huitema, Ksinant, Souissi, 2003).
*Scope.* Full.
*Implementing sections.* §4.14 (RR).
*Key clauses.* §2 (AAAA wire format) → RR-001 + catalogue, RR-007.

**RFC 3597 — Handling of Unknown DNS Resource Record (RR) Types** (Gustafsson, 2003).
*Scope.* Full.
*Implementing sections.* §4.4 (URR), §4.14 (RR for compression policy).
*Key clauses.* §3 (parsing, storage, serving) → URR-001..005; §4 (compression prohibition) → URR-006, URR-007, QRY-023; §6 (comparison) → URR-008.
*Out-of-scope clauses.* §5 (master file representation) — ODS-NEG-006.

**RFC 6604 — xNAME RCODE and Status Bits Clarification** (Eastlake, 2012). Note: cited specifically for clarifications on SRV non-compressibility.
*Scope.* Informative for SRV compression interpretation.
*Implementing sections.* §4.14 (RR catalogue compression policy).

**RFC 6672 — DNAME Redirection in the DNS** (Rose & Wijngaards, 2012).
*Scope.* Full (secondary-side aspects).
*Implementing sections.* §4.2 (QRY), §4.14 (RR).
*Key clauses.* §2 (DNAME RR format) → RR-001 + catalogue; §2.4 (CNAME coexistence prohibition) → RR-006; §3 (DNAME-to-CNAME synthesis) → QRY-014, QRY-015; §3.2, §3.3 (synthesis semantics, edge cases) → QRY-014.

**RFC 6698 — The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA** (Hoffman & Schlyter, 2012).
*Scope.* Partial (TLSA RR format only).
*Implementing sections.* §4.14 (RR).
*Key clauses.* §2.1 (TLSA wire format) → RR-001 + catalogue.
*Out-of-scope clauses.* DANE validation semantics — ODS-INV-001 (server is not a validator).

**RFC 7553 — The Uniform Resource Identifier (URI) DNS Resource Record** (Faltstrom & Kolkman, 2015).
*Scope.* Full.
*Implementing sections.* §4.14 (RR).
*Key clauses.* §4.5 (URI wire format) → RR-001 + catalogue.

**RFC 9460 — Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)** (Schwartz, Bishop, Nygren, 2023).
*Scope.* Full (RR format and additional-section composition).
*Implementing sections.* §4.14 (RR), §4.2 (QRY).
*Key clauses.* §2.2 (RR format) → RR-001 + catalogue; §5 (additional section processing) → QRY-019.

### A.3.6 DNSSEC

**RFC 4033 — DNS Security Introduction and Requirements** (Arends, Austein, Larson, Massey, Rose, 2005).
*Scope.* Informative (architecture and overview).
*Implementing sections.* §4.13 (DNSSEC), as context.

**RFC 4034 — Resource Records for the DNS Security Extensions** (Arends et al., 2005).
*Scope.* Full (serve-only).
*Implementing sections.* §4.13 (DNSSEC), §4.14 (RR).
*Key clauses.* §2 (DNSKEY) → DNSSEC-001, RR catalogue; §3 (RRSIG) → DNSSEC-001, DNSSEC-003; §4 (NSEC) → DNSSEC-001, DNSSEC-004, DNSSEC-005; §5 (DS) → DNSSEC-001, DNSSEC-007; §6.2 (canonical form) → RR catalogue (RRSIG, NSEC).
*Out-of-scope clauses.* Signing aspects (primary-side) — ODS-NEG-002.

**RFC 4035 — Protocol Modifications for the DNS Security Extensions** (Arends et al., 2005).
*Scope.* Partial (serve-only, no validation).
*Implementing sections.* §4.13 (DNSSEC).
*Key clauses.* §3.1 (response composition with DNSSEC RRs) → DNSSEC-003..007; §3.1.3 (negative response proofs) → DNSSEC-004, DNSSEC-005; §3.1.3.4 (wildcard proofs) → DNSSEC-006; §3.1.4 (referral proofs) → DNSSEC-007; §3.2.1 (DO bit handling) → DNSSEC-002, DNSSEC-008; §3.2.2 (DO bit in responses) → DNSSEC-009; §3.2.3 (CD, AD bits for authoritative) → DNSSEC-010, DNSSEC-011.
*Out-of-scope clauses.* §4 (resolver-side validation) — ODS-INV-001.

**RFC 5155 — DNS Security (DNSSEC) Hashed Authenticated Denial of Existence (NSEC3)** (Laurie, Sisson, Arends, Blacka, 2008).
*Scope.* Partial (serve-only, no generation).
*Implementing sections.* §4.13 (DNSSEC), §4.14 (RR).
*Key clauses.* §3 (NSEC3 RR format) → DNSSEC-001, RR catalogue; §4 (NSEC3PARAM RR format) → DNSSEC-001, RR catalogue; §7.2.2 (NXDOMAIN proofs) → DNSSEC-004; §7.2.3, §7.2.4 (NODATA proofs) → DNSSEC-005; §7.2.5 (wildcard proofs) → DNSSEC-006; §7.2.7 (referral proofs) → DNSSEC-007.
*Out-of-scope clauses.* §7.1 (chain generation, primary-side) — ODS-NEG-002.

**RFC 6840 — Clarifications and Implementation Notes for DNS Security (DNSSEC)** (Weiler & Blacka, 2013).
*Scope.* Partial (serve-only clarifications).
*Implementing sections.* §4.13 (DNSSEC).
*Key clauses.* §5.6 (DO bit handling) → DNSSEC-009; §5.8 (AD bit) → DNSSEC-010; §5.9 (CD bit) → DNSSEC-011.
*Out-of-scope clauses.* Validator-side clarifications — ODS-INV-001.

**RFC 6944 — Applicability Statement: DNS Security (DNSSEC) DNSKEY Algorithm Implementation Status** (Rose, 2013).
*Scope.* Informative (algorithm guidance; superseded by RFC 8624 for current recommendations, but cited per PID).
*Implementing sections.* §4.13 (DNSSEC).
*Key clauses.* Algorithm opacity for serve-only → DNSSEC-012.

### A.3.7 IANA and operational

**RFC 6895 — Domain Name System (DNS) IANA Considerations** (Eastlake, 2013).
*Scope.* Informative (registry maintenance).
*Implementing sections.* Cited in §4.1, §4.2, §4.4 for OPCODE, RCODE, RR TYPE, EDNS option registry references.

**RFC 8906 — A Common Operational Problem in DNS Servers: Failure To Communicate** (Andrews & Huque, 2020).
*Scope.* Informative (operational guidance for testing).
*Implementing sections.* Cited in §4.2 (QRY-024 statistics), §4.8 (NOTIFY-010 logging); used as test-design input per §7.3.

### A.3.8 TLS standards underlying XoT

**RFC 5246 — The Transport Layer Security (TLS) Protocol Version 1.2** (Dierks & Rescorla, 2008).
*Scope.* Required-to-implement per XOT-001.
*Implementing sections.* §4.10 (XOT).

**RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3** (Rescorla, 2018).
*Scope.* Recommended per XOT-001.
*Implementing sections.* §4.10 (XOT).

**RFC 9325 — Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)** (Sheffer, Saint-Andre, Fossati, 2022) — BCP 195.
*Scope.* Full (cipher suite and TLS-usage profile).
*Implementing sections.* §4.10 (XOT).
*Key clauses.* AEAD cipher requirements → XOT-002; prohibited cipher categories → XOT-002.

**RFC 6066 — Transport Layer Security (TLS) Extensions: Extension Definitions** (Eastlake, 2011).
*Scope.* Partial (SNI extension required for XoT).
*Implementing sections.* §4.10 (XOT).
*Key clauses.* SNI extension → XOT-005.

**RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile** (Cooper et al., 2008).
*Scope.* Full (PKIX validation for XoT).
*Implementing sections.* §4.10 (XOT).
*Key clauses.* Path validation algorithm → XOT-005.

**RFC 7858 — Specification for DNS over Transport Layer Security (TLS)** (Hu, Zhu, Heidemann, Mankin, Wessels, Hoffman, 2016).
*Scope.* Partial (ALPN identifier "dot" only; this server does not implement DoT for queries).
*Implementing sections.* §4.10 (XOT).
*Key clauses.* ALPN identifier → XOT-004.

## A.4 Sample Fine-Grained Clause Mapping

This section illustrates fine-grained mapping for two representative RFCs. The full clause-level mapping for all RFCs is iterative work conducted during implementation review; these samples establish the format.

### A.4.1 RFC 5936 — fine-grained mapping (AXFR client)

| RFC Clause | Topic | Implementing Requirement(s) | Status |
|---|---|---|---|
| §2.1.1 | TCP transport mandate | ODS-FR-AXFR-001 | Draft |
| §2.1.2 | Query construction | ODS-FR-AXFR-002 | Draft |
| §2.2 | Multi-message response reassembly | ODS-FR-AXFR-004 | Draft |
| §2.2 | Terminal SOA detection | ODS-FR-AXFR-008, ODS-FR-AXFR-009 | Draft |
| §2.2.1 | QID and OPCODE validation | ODS-FR-AXFR-005 | Draft |
| §2.2.1 | Header flag bit non-significance | ODS-FR-AXFR-006 | Draft |
| §2.2.1 | First record SOA validation | ODS-FR-AXFR-007 | Draft |
| §2.2.1 | Class consistency | ODS-FR-AXFR-011 | Draft |
| §2.2.4 | Glue records | ODS-FR-AXFR-013 | Draft |
| §2.2.4 | Occluded data handling | ODS-FR-AXFR-014 | Draft |
| §2.2.5 | TSIG signing of multi-message | ODS-FR-AXFR-017, ODS-FR-AXFR-018 | Draft |
| §3.1 | Error handling | ODS-FR-AXFR-019, ODS-FR-AXFR-020 | Draft |
| §3.1 | No middle SOA | ODS-FR-AXFR-010 | Draft |
| §3.4 | Compression scope within message | ODS-FR-AXFR-015 | Draft |
| §4.1 | TCP connection management | ODS-FR-AXFR-003 | Draft |
| §5 | Error RCODE handling | ODS-FR-AXFR-020 | Draft |

### A.4.2 RFC 8945 — fine-grained mapping (TSIG)

| RFC Clause | Topic | Implementing Requirement(s) | Status |
|---|---|---|---|
| §3 | Key configuration | ODS-FR-TSIG-005 | Draft |
| §4 | TSIG RR wire format | ODS-FR-TSIG-007, ODS-FR-TSIG-008 | Draft |
| §4.2 | Original ID handling | ODS-FR-TSIG-008(d) | Draft |
| §4.3 | Error codes | ODS-FR-TSIG-013 | Draft |
| §5.2 | TSIG on requests/responses | ODS-FR-TSIG-008, ODS-FR-TSIG-012 | Draft |
| §5.2.1 | UDP truncation of signed responses | ODS-FR-TSIG-016 | Draft |
| §5.2.2 | TSIG error response semantics | ODS-FR-TSIG-013 | Draft |
| §5.2.2.1 | MAC truncation rules | ODS-FR-TSIG-014 | Draft |
| §5.3 | Signing algorithm | ODS-FR-TSIG-012 | Draft |
| §5.3.1 | Multi-message TSIG envelope | ODS-FR-TSIG-010, ODS-FR-TSIG-011 | Draft |
| §5.4 | Verification algorithm | ODS-FR-TSIG-008 | Draft |
| §5.4.1 | BADTIME / fudge handling | ODS-FR-TSIG-008(c) | Draft |
| §6 | Algorithm requirements | ODS-FR-TSIG-001, ODS-FR-TSIG-002, ODS-FR-TSIG-003 | Draft |
| §6 | HMAC-MD5 prohibition | ODS-FR-TSIG-004, ODS-NEG-013 | Draft |
| §10.5 | Truncation discouragement | ODS-FR-TSIG-015 | Draft |

## A.5 Out-of-Scope Clauses Register

This section catalogues, by RFC, those clauses that fall outside this server's scope, with reference to the architectural invariant or PID scope clause that excludes them. The register supports accurate partial-compliance assertions per ODS-VER-006.

**RFC 1034.** Resolver-side aspects (§5 in part) — ODS-INV-001. Master file format (§6.1) — ODS-NEG-006. Primary-role aspects of zone management (§4.3.5, various) — ODS-INV-001.

**RFC 1035.** Master file format (§5) — ODS-NEG-006. Resolver implementation (§7) — ODS-INV-001. Original zone transfer specification (§4.3) — superseded by RFC 5936 / RFC 1995.

**RFC 2181.** Primary-side zone publication concerns (§6.2 in part) — ODS-INV-001.

**RFC 2308.** Resolver caching semantics (§7) — ODS-INV-001.

**RFC 4035.** Resolver-side validation (§4) — ODS-INV-001. Signing semantics (cross-cutting with RFC 4034) — ODS-NEG-002.

**RFC 5155.** Chain generation (§7.1) — ODS-NEG-002.

**RFC 5936.** AXFR server-side requirements — ODS-NEG-005 (no outbound AXFR serving).

**RFC 1995.** IXFR server-side requirements — ODS-NEG-005.

**RFC 1996.** NOTIFY origination (originator semantics) — ODS-NEG-004.

**RFC 6698 (TLSA).** DANE validation semantics — ODS-INV-001 (server is not a validator).

**RFC 9103.** NOTIFY-over-TLS reception (§6.4) — ODS-NEG-017. Opportunistic Privacy Profile (§9.2) — ODS-NEG-016.

**RFC 7858.** DNS-over-TLS for client queries (full RFC scope except ALPN identifier) — out of project scope per PID §3.2.

## A.6 Verification Status Tracking

Verification status is tracked per requirement per ODS-VER-009. The expected mechanism for production maintenance of status is a structured table (spreadsheet, database, or version-controlled CSV) alongside the SRS source, rather than inline in the SRS document. The following columns are required:

- **Requirement ID** — the immutable identifier from §3 through §6 (or A.4 fine-grained sub-mappings).
- **Verification Method** — one or more methods from §7.1, mirroring the requirement's *Verification* field.
- **Status** — Not Verified / Verified / Deferred / Not Applicable per A.2.3.
- **Verification Date** — date of most recent verification activity yielding the current status.
- **Evidence Reference** — pointer to the CI build, test report, code review record, or external operator report substantiating the status.
- **Deferred Target** — for status Deferred, the milestone (Alpha, MVP, post-MVP) at which verification is required.
- **Notes** — free-text annotations.

A representative initial state of the tracking table:

| Requirement | Method | Status | Date | Evidence | Deferred Target | Notes |
|---|---|---|---|---|---|---|
| ODS-INV-001 | Inspection | Not Verified | — | — | Alpha | Foundational; verify at first build |
| ODS-FR-CORE-001 | Conformance | Not Verified | — | — | Alpha | — |
| ODS-FR-AXFR-001 | Inspection | Not Verified | — | — | Alpha | — |
| ODS-FR-IXFR-001 | Conformance | Not Verified | — | — | MVP | Per VER-007 deferred |
| ODS-FR-DNSSEC-001 | Conformance | Not Verified | — | — | MVP | Per VER-007 deferred |
| ODS-FR-XOT-001 | Interop | Not Verified | — | — | MVP | Per VER-007 deferred |
| ... | ... | ... | ... | ... | ... | ... |

Population of this table is the responsibility of the test and review team; the SRS records the conventions and column definitions but does not include the live tracking content.

## A.7 Cross-Reference Index

For project navigation convenience, the following inverse index is provided. Each entry maps from an SRS subsection to the principal RFC sources for its requirements.

| Subsection | Area | Principal RFCs |
|---|---|---|
| 4.1 DNS Core | CORE | 1034, 1035, 2181, 4343 |
| 4.2 Query Processing | QRY | 1034, 1035, 2181, 4592, 6672, 8482 |
| 4.3 Negative Responses | NRESP | 1034, 2308, 8020, 4592 |
| 4.4 Unknown RR | URR | 3597, 6895 |
| 4.5 Anti-Spoofing | SPOOF | 5452 |
| 4.6 AXFR | AXFR | 5936, 1995, 8945, 7766 |
| 4.7 IXFR | IXFR | 1995, 5936, 8945 |
| 4.8 NOTIFY | NOTIFY | 1996, 8945 |
| 4.9 TSIG | TSIG | 8945, 4635 |
| 4.10 XoT | XOT | 9103, 5246, 8446, 9325, 6066, 5280, 7858 |
| 4.11 EDNS0 | EDNS | 6891, 7828, 7830 |
| 4.12 TCP Transport | TCP | 7766, 1035, 2181 |
| 4.13 DNSSEC Serving | DNSSEC | 4033, 4034, 4035, 5155, 6840, 6944 |
| 4.14 RR Type Catalogue | RR | 1035, 1982, 2782, 3403, 3596, 3597, 6604, 6672, 6698, 7553, 9460 |
| 4.15 Zone Store | ZONE | 1034, 4592 |
| 4.16 Zone State Machine | ZSM | 1034, 1996, 1982 |
| 4.17 RRL | RRL | (no IETF RFC; Vixie/Schryver operational design) |
| 4.18 Negative Requirements | NEG | (cross-references to enforcing requirements) |

# Appendix B — Resource Record Type Catalogue

## B.1 Purpose

This appendix is the implementer's reference for the resource record types listed in the catalogue of §4.14 (ODS-FR-RR-001). For each known type it provides the RDATA structure summary, the compression policy, owner-name conventions where they exist, and notes on parsing subtleties or cross-references to dependent SRS subsections. The catalogue table reproduced in B.2 below is identical in content to the table in §4.14; per-type expansion follows.

The §4.14 table is the *normative* source — it is part of the normative requirement ODS-FR-RR-001. This appendix is implementation-supporting documentation. Where the two are silently in conflict, §4.14 prevails; the Appendix should be updated to match.

When a new known type is added to the server's type-aware repertoire, both the §4.14 catalogue table and the corresponding entry in this appendix must be updated in the same SRS revision.

### Notation

RDATA structures are described as a sequence of fields separated by `|`. Field types follow this convention:

- **uint8, uint16, uint32** — unsigned integers of the indicated width, network byte order;
- **int32** — signed integer, network byte order (used for SOA REFRESH/RETRY/EXPIRE which can in principle be negative, though such use is operationally pathological);
- **domain name** — wire-format DNS name as defined by RFC 1035 §3.1, with compression status per the per-type compression policy;
- **character-string** — length-octet-prefixed octet sequence, up to 255 octets, per RFC 1035 §3.3;
- **variable octets** — opaque octet sequence whose length is implied by RDLENGTH minus the size of fixed-position fields.

## B.2 Known RR Types (Catalogue)

The complete normative catalogue, reproduced from §4.14:

| RR Type | Code | Specifying RFC | RDATA Compression Policy |
|---|---|---|---|
| A | 1 | RFC 1035 §3.4.1 | N/A |
| NS | 2 | RFC 1035 §3.3.11 | Permitted (NSDNAME) |
| CNAME | 5 | RFC 1035 §3.3.1 | Permitted (CNAME field) |
| SOA | 6 | RFC 1035 §3.3.13 | Permitted (MNAME, RNAME) |
| PTR | 12 | RFC 1035 §3.3.12 | Permitted (PTRDNAME) |
| HINFO | 13 | RFC 1035 §3.3.2 | N/A |
| MX | 15 | RFC 1035 §3.3.9 | Permitted (EXCHANGE) |
| TXT | 16 | RFC 1035 §3.3.14 | N/A |
| AAAA | 28 | RFC 3596 §2.1 | N/A |
| SRV | 33 | RFC 2782 | Prohibited (TARGET) |
| NAPTR | 35 | RFC 3403 §4 | Prohibited (REPLACEMENT) |
| DNAME | 39 | RFC 6672 §2 | Prohibited (TARGET) |
| DS | 43 | RFC 4034 §5 | N/A |
| RRSIG | 46 | RFC 4034 §3 | Prohibited (Signer's Name) |
| NSEC | 47 | RFC 4034 §4 | Prohibited (Next Domain Name) |
| DNSKEY | 48 | RFC 4034 §2 | N/A |
| NSEC3 | 50 | RFC 5155 §3 | N/A |
| NSEC3PARAM | 51 | RFC 5155 §4 | N/A |
| TLSA | 52 | RFC 6698 §2.1 | N/A |
| SVCB | 64 | RFC 9460 §2.2 | Prohibited (TargetName) |
| HTTPS | 65 | RFC 9460 §2.2 | Prohibited (TargetName) |
| URI | 256 | RFC 7553 §4.5 | N/A |

### B.2.1 A — IPv4 Address (code 1)

*RFC.* RFC 1035 §3.4.1.
*RDATA.* Four-octet IPv4 address (network byte order).
*Compression.* Not applicable.
*Validation.* RDLENGTH MUST be exactly 4 octets per ODS-FR-RR-007.

### B.2.2 NS — Name Server (code 2)

*RFC.* RFC 1035 §3.3.11.
*RDATA.* `NSDNAME` (domain name) — a name server authoritative for the zone whose apex (or whose delegation point) is the owner name.
*Compression.* Permitted in NSDNAME.
*Owner-name convention.* Either the zone apex (server's own authoritative servers) or a sub-domain owner name (marking a delegation cut to that child zone).
*Cross-references.* ODS-FR-RR-003 requires at least one NS at zone apex. NS RRsets in the authority or answer sections trigger glue inclusion per ODS-FR-QRY-017.

### B.2.3 CNAME — Canonical Name (code 5)

*RFC.* RFC 1035 §3.3.1.
*RDATA.* `CNAME` (domain name) — the canonical name to which the owner name aliases.
*Compression.* Permitted.
*Cross-references.* CNAME exclusivity per ODS-FR-RR-005 (no coexistence with other RRsets at the same owner name except DNSSEC RRs). CNAME chain handling per ODS-FR-QRY-010 through ODS-FR-QRY-013.

### B.2.4 SOA — Start of Authority (code 6)

*RFC.* RFC 1035 §3.3.13.
*RDATA.* `MNAME` (domain name, master server) `|` `RNAME` (domain name, responsible party mailbox, with `@` encoded as the first label boundary) `|` `SERIAL` (uint32) `|` `REFRESH` (int32, seconds) `|` `RETRY` (int32, seconds) `|` `EXPIRE` (int32, seconds) `|` `MINIMUM` (uint32, seconds).
*Compression.* Permitted in MNAME and RNAME.
*Owner-name convention.* MUST be the zone apex per ODS-FR-RR-002. Exactly one SOA per zone.
*Notes.*
- SERIAL is compared using RFC 1982 arithmetic per ODS-FR-RR-004.
- MINIMUM was redefined by RFC 2308 §3 as the maximum TTL for negative-response caching, not the per-RR default TTL it originally was in RFC 1035.
- REFRESH, RETRY, EXPIRE drive the zone state machine of §4.16.

### B.2.5 PTR — Pointer (code 12)

*RFC.* RFC 1035 §3.3.12.
*RDATA.* `PTRDNAME` (domain name) — the name the pointer record resolves to (typically a hostname for reverse DNS).
*Compression.* Permitted.
*Owner-name convention.* For IPv4 reverse DNS: reversed octets under `in-addr.arpa` (e.g., `1.2.0.192.in-addr.arpa` for the address 192.0.2.1). For IPv6 reverse: reversed nibbles under `ip6.arpa`.

### B.2.6 HINFO — Host Information (code 13)

*RFC.* RFC 1035 §3.3.2.
*RDATA.* `CPU` (character-string) `|` `OS` (character-string).
*Compression.* Not applicable.
*Notes.* HINFO is largely deprecated for operational use due to information-disclosure concerns. The HINFO synthesis pattern of RFC 8482 §4.2 for ANY-query minimisation is explicitly prohibited by ODS-NEG-015; this server's minimal-ANY policy returns a real RRset per ODS-FR-QRY-005.

### B.2.7 MX — Mail Exchange (code 15)

*RFC.* RFC 1035 §3.3.9.
*RDATA.* `PREFERENCE` (uint16) `|` `EXCHANGE` (domain name) — preference value (lower = preferred) and the mail exchange host name.
*Compression.* Permitted in EXCHANGE.
*Cross-references.* Triggers additional-section inclusion of A/AAAA for EXCHANGE per ODS-FR-QRY-018.

### B.2.8 TXT — Text (code 16)

*RFC.* RFC 1035 §3.3.14.
*RDATA.* One or more length-prefixed character-strings, each up to 255 octets; total RDATA up to 65535 octets.
*Compression.* Not applicable.
*Notes.* TXT is the carrier for a wide variety of unstructured key=value content (SPF — though SPF type 99 is obsolete and TXT is now used; DKIM; DMARC; CAA-equivalent text records pre-CAA; ACME challenges; etc.). The server preserves the character-string structure (including individual string boundaries) exactly as received.

### B.2.9 AAAA — IPv6 Address (code 28)

*RFC.* RFC 3596 §2.1.
*RDATA.* Sixteen-octet IPv6 address (network byte order).
*Compression.* Not applicable.
*Validation.* RDLENGTH MUST be exactly 16 octets per ODS-FR-RR-007.

### B.2.10 SRV — Service Location (code 33)

*RFC.* RFC 2782; non-compressibility clarified by RFC 6604.
*RDATA.* `PRIORITY` (uint16) `|` `WEIGHT` (uint16) `|` `PORT` (uint16) `|` `TARGET` (domain name).
*Compression.* Prohibited in TARGET.
*Owner-name convention.* `_service._proto.name` (e.g., `_sip._tcp.example.com`, `_xmpp-client._tcp.example.com`).
*Cross-references.* Triggers additional-section inclusion of A/AAAA for TARGET per ODS-FR-QRY-018.

### B.2.11 NAPTR — Naming Authority Pointer (code 35)

*RFC.* RFC 3403 §4.
*RDATA.* `ORDER` (uint16) `|` `PREFERENCE` (uint16) `|` `FLAGS` (character-string) `|` `SERVICES` (character-string) `|` `REGEXP` (character-string) `|` `REPLACEMENT` (domain name).
*Compression.* Prohibited in REPLACEMENT.
*Notes.*
- The REGEXP field may contain octets that would be otherwise restricted in DNS data; the server preserves byte content exactly.
- REPLACEMENT is meaningful for further DNS resolution only when FLAGS indicate continuation (per RFC 3404); the server includes A/AAAA glue for REPLACEMENT per ODS-FR-QRY-018 where REPLACEMENT names a record in a served zone.

### B.2.12 DNAME — Delegation Name (code 39)

*RFC.* RFC 6672 §2.
*RDATA.* `TARGET` (domain name) — the redirection target for the DNAME subtree.
*Compression.* Prohibited in TARGET (per RFC 3597 §4, as a post-RFC-3597 type).
*Notes.*
- Triggers CNAME synthesis per ODS-FR-QRY-014, ODS-FR-QRY-015.
- DNAME cannot coexist with CNAME at the same owner name per ODS-FR-RR-006.
- Edge cases (DNAME at apex, DNAME above a delegation, synthesised-name length overflow) per RFC 6672 §3.3.

### B.2.13 DS — Delegation Signer (code 43)

*RFC.* RFC 4034 §5.
*RDATA.* `KEY TAG` (uint16) `|` `ALGORITHM` (uint8) `|` `DIGEST TYPE` (uint8) `|` `DIGEST` (variable octets).
*Compression.* Not applicable.
*Owner-name convention.* The owner name is the child zone apex; the DS RRset itself resides in the parent zone (the secondary serves DS as part of the parent zone's data).
*Cross-references.* Used in DNSSEC referral response composition per ODS-FR-DNSSEC-007.

### B.2.14 RRSIG — Resource Record Signature (code 46)

*RFC.* RFC 4034 §3.
*RDATA.* `TYPE COVERED` (uint16) `|` `ALGORITHM` (uint8) `|` `LABELS` (uint8) `|` `ORIGINAL TTL` (uint32) `|` `SIGNATURE EXPIRATION` (uint32, seconds since epoch) `|` `SIGNATURE INCEPTION` (uint32, seconds since epoch) `|` `KEY TAG` (uint16) `|` `SIGNER'S NAME` (domain name, canonical/uncompressed) `|` `SIGNATURE` (variable octets, algorithm-specific encoding).
*Compression.* Prohibited in SIGNER'S NAME (per RFC 4034 §6.2; canonical form).
*Cross-references.*
- The TYPE COVERED field identifies which RRset this RRSIG signs; required by §4.13 response composition (per ODS-FR-DNSSEC-001).
- The server does not generate RRSIG records (ODS-NEG-002).

### B.2.15 NSEC — Next Secure (code 47)

*RFC.* RFC 4034 §4.
*RDATA.* `NEXT DOMAIN NAME` (domain name, uncompressed per RFC 4034 §6.2) `|` `TYPE BIT MAPS` (variable encoding per RFC 4034 §4.1.2).
*Compression.* Prohibited in NEXT DOMAIN NAME.
*Owner-name convention.* The owner name is the existent name in the canonical order; NEXT DOMAIN NAME points to the next existent name. NSEC records collectively form a chain through all existent owner names in the zone.
*Cross-references.* Used in authenticated negative responses per ODS-FR-DNSSEC-004, ODS-FR-DNSSEC-005, ODS-FR-DNSSEC-006.

### B.2.16 DNSKEY — DNS Public Key (code 48)

*RFC.* RFC 4034 §2.
*RDATA.* `FLAGS` (uint16; bit 7 = ZONE flag, bit 15 = SEP flag) `|` `PROTOCOL` (uint8, MUST be 3) `|` `ALGORITHM` (uint8) `|` `PUBLIC KEY` (variable octets, algorithm-specific encoding).
*Compression.* Not applicable.
*Cross-references.* Per ODS-NEG-002, this server does not generate DNSKEY records or maintain DNSSEC key material.

### B.2.17 NSEC3 — Hashed Authenticated Denial (code 50)

*RFC.* RFC 5155 §3.
*RDATA.* `HASH ALGORITHM` (uint8) `|` `FLAGS` (uint8) `|` `ITERATIONS` (uint16) `|` `SALT LENGTH` (uint8) `|` `SALT` (variable, length per SALT LENGTH) `|` `HASH LENGTH` (uint8) `|` `NEXT HASHED OWNER NAME` (variable, length per HASH LENGTH) `|` `TYPE BIT MAPS` (per RFC 4034 §4.1.2).
*Compression.* Not applicable.
*Owner-name convention.* The owner name is the Base32hex-encoded hash of an existent name, with the zone apex appended (per RFC 5155 §1.3, §7).
*Cross-references.* Used in authenticated negative responses per ODS-FR-DNSSEC-004, ODS-FR-DNSSEC-005, ODS-FR-DNSSEC-006. Per ODS-NEG-002, this server does not generate NSEC3 records.

### B.2.18 NSEC3PARAM — NSEC3 Parameters (code 51)

*RFC.* RFC 5155 §4.
*RDATA.* `HASH ALGORITHM` (uint8) `|` `FLAGS` (uint8) `|` `ITERATIONS` (uint16) `|` `SALT LENGTH` (uint8) `|` `SALT` (variable).
*Compression.* Not applicable.
*Owner-name convention.* MUST be the zone apex (per RFC 5155).
*Notes.* Conveys the parameters of the NSEC3 chain used in the zone (resolvers need these to compute matching NSEC3 owner names for negative-response validation).

### B.2.19 TLSA — DANE TLS Authentication (code 52)

*RFC.* RFC 6698 §2.1.
*RDATA.* `CERT USAGE` (uint8) `|` `SELECTOR` (uint8) `|` `MATCHING TYPE` (uint8) `|` `CERTIFICATE ASSOCIATION DATA` (variable octets).
*Compression.* Not applicable.
*Owner-name convention.* `_port._proto.name` (e.g., `_443._tcp.www.example.com`).
*Notes.* This server serves TLSA records as data; DANE validation semantics are out of scope per ODS-INV-001 (the server is not a validator).

### B.2.20 SVCB — Service Binding (code 64)

*RFC.* RFC 9460 §2.2.
*RDATA.* `SVCPRIORITY` (uint16) `|` `TARGETNAME` (domain name, uncompressed) `|` `SVCPARAMS` (variable: an ordered list of `SvcParamKey` (uint16) `|` `SvcParamLength` (uint16) `|` `SvcParamValue` (variable, per-key encoding) triples).
*Compression.* Prohibited in TARGETNAME and in any names appearing within SVCPARAMS.
*Notes.*
- `SVCPRIORITY = 0` indicates AliasMode (TARGETNAME is the alias target; SVCPARAMS MUST be empty).
- `SVCPRIORITY > 0` indicates ServiceMode (TARGETNAME and SVCPARAMS describe a concrete service endpoint).
- Common SvcParamKeys include `alpn` (1), `no-default-alpn` (2), `port` (3), `ipv4hint` (4), `ech` (5), `ipv6hint` (6).
*Cross-references.* Triggers additional-section inclusion of A/AAAA for TARGETNAME per ODS-FR-QRY-019.

### B.2.21 HTTPS — HTTPS Service Binding (code 65)

*RFC.* RFC 9460 §2.2.
*RDATA.* Structurally identical to SVCB.
*Compression.* As for SVCB.
*Notes.* HTTPS is the HTTPS-specific instantiation of SVCB. The wire format is identical; behavioural and parsing requirements are identical. Used by clients to discover HTTPS service parameters (ALPN profile, port, IP hints) for a name without requiring an explicit HTTPS connection first.

### B.2.22 URI — Uniform Resource Identifier (code 256)

*RFC.* RFC 7553 §4.5.
*RDATA.* `PRIORITY` (uint16) `|` `WEIGHT` (uint16) `|` `TARGET` (one or more raw URI octets; the URI itself, not a DNS domain name and not DNS `character-string` wire format).
*Compression.* Not applicable.
*Owner-name convention.* `_service._proto.name` (similar to SRV).
*Notes.* RFC 7553 §4.5 defines the TARGET as all remaining RDATA octets after the two uint16 fields, without the presentation-format quotes and with length greater than zero. The server validates that the target is present and treats the URI octets opaquely — no URI parsing or normalisation.

## B.3 Pseudo-Resource Records

Pseudo-RRs are protocol mechanisms encoded in RR form but never appearing as authoritative zone content. They are not eligible for inclusion in zone transfers; their handling is specified in dedicated subsections.

### B.3.1 OPT — EDNS0 Pseudo-RR (code 41)

*RFC.* RFC 6891.
*Handling.* Per §4.11 (EDNS).
*Appearance.* Additional section only, at most one per message, owner name MUST be root, TYPE = 41.
*RDATA.* Variable; ordered list of EDNS option pairs.
*Notes.* The TTL field of an OPT RR carries the EDNS extended-RCODE (high 8 bits), VERSION (next 8 bits), DO flag (bit 16), and reserved Z bits. The class field carries the requestor's UDP payload size. See §4.11 for full requirements.

### B.3.2 TSIG — Transaction Signature (code 250)

*RFC.* RFC 8945.
*Handling.* Per §4.9 (TSIG).
*Appearance.* Last record of the additional section in TSIG-signed messages.
*Notes.* The class field is always 255 (ANY); the TTL is always 0. The RDATA carries algorithm name, time signed, fudge, MAC, original ID, error code, and other-data. See §4.9 for full requirements.

### B.3.3 TKEY — Transaction Key (code 249) — prohibited

*RFC.* RFC 2930.
*Handling.* Prohibited per ODS-NEG-014.
*Disposition.* Queries with QTYPE = 249 receive RCODE = 1 (FORMERR) per ODS-FR-QRY-009. No TKEY processing code path exists in this server.

## B.4 Out-of-Catalogue Types

The following RR types are not in the type-aware catalogue of §4.14 and are handled under the unknown-type semantics of §4.4 (ODS-FR-URR-001 through ODS-FR-URR-009). They are accepted from primaries, stored bit-for-bit, served on direct query, and propagated faithfully without type-aware interpretation.

| RR Type | Code | RFC | Notes |
|---|---|---|---|
| LOC | 29 | RFC 1876 | Geographic location |
| SSHFP | 44 | RFC 4255 | SSH key fingerprint |
| IPSECKEY | 45 | RFC 4025 | IPsec key |
| SPF | 99 | RFC 7208 | Obsolete; superseded by TXT |
| OPENPGPKEY | 61 | RFC 7929 | OpenPGP public key |
| CSYNC | 62 | RFC 7477 | Child-to-parent synchronisation signal |
| ZONEMD | 63 | RFC 8976 | Zone message digest |
| SMIMEA | 53 | RFC 8162 | S/MIME certificate association |
| CDS | 59 | RFC 7344 | Child DS (signalled to parent) |
| CDNSKEY | 60 | RFC 7344 | Child DNSKEY (signalled to parent) |
| CAA | 257 | RFC 8659 | Certification Authority Authorization |
| HIP | 55 | RFC 8005 | Host Identity Protocol |

This list is illustrative, not exhaustive. Any RR type code not in §4.14's catalogue and not enumerated as pseudo-RR or reserved is handled under §4.4.

## B.5 Reserved Type Values

Reserved type values 0 and 65535 are rejected per ODS-FR-URR-009 (zone transfers containing such records are aborted) and per ODS-FR-QRY-009 (queries using such values as QTYPE receive FORMERR). The IANA Private Use range (65280–65534 as of the current registry) is accepted and handled under §4.4.

## B.6 Notes on Compression Policy

The per-type compression policy in B.2 derives from two sources:

- **Pre-RFC 3597 type definitions.** RR types whose RDATA structure was defined prior to RFC 3597 (1996-era types: NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT) may use DNS name compression in their RDATA name fields when emitted.
- **Post-RFC 3597 type definitions.** RR types defined after RFC 3597 — including SRV, DNAME, RRSIG, NSEC, SVCB, HTTPS, NAPTR (per RFC 3597 §4 and RFC 6604 specifically for SRV) — MUST NOT use DNS name compression in their RDATA name fields.

The rationale, articulated in RFC 3597 §4, is that compression is meaningful only when both sender and receiver share semantic understanding of where names appear in the RDATA. For types unknown to one party, compressed names would be uninterpretable. The simplest stable rule — that types defined after RFC 3597 do not use compression — preserves forward compatibility.

The catalogue table of B.2 records the policy per type. When emitting responses, the server follows the policy per ODS-FR-QRY-023 (general compression policy) and ODS-FR-URR-006 (no compression for unknown types).

# Appendix C — Out-of-Scope Items

## C.1 Purpose

Appendix C catalogues items outside this server's scope, with rationale for each exclusion and reference to the SRS clause that records or enforces it. The intent is that a reader of the SRS alone can understand where the project's boundaries lie without needing to consult the PID for context.

Two kinds of exclusion are distinguished:

- **Foundational exclusions.** Items whose inclusion would violate an architectural invariant of §3 (typically ODS-INV-001, the secondary-only invariant). These cannot be brought into scope without redefining the project's identity.
- **Scope-decision exclusions.** Items deliberately left out of the current version's scope for reasons of complexity, codebase size, or focus, but which could be added in a future version without architectural-invariant violation.

The SRS's normative content — architectural invariants (§3), negative requirements (§4.18), and specific functional and non-functional requirements — enforces each exclusion. Appendix C is descriptive and cross-references rather than introducing new normative content.

Section C.5 also catalogues items specifically flagged during SRS drafting for project decision — exclusions where the choice merits explicit confirmation rather than implicit endorsement.

## C.2 Foundational Exclusions

These items conflict with the secondary-only architectural stance of ODS-INV-001, with the no-persistent-state stance of ODS-INV-004, or with the static-configuration stance of ODS-INV-005. They are excluded permanently from this project; bringing any of them into scope would redefine the project as something other than a secondary-only authoritative DNS server.

### C.2.1 Primary-role functions

*Description.* Acting as a primary (master) DNS server: authoring zone content, signing records, generating denial-of-existence chains, managing DNSSEC key material, originating NOTIFY messages to downstream secondaries.

*Rationale.* The project's identity is secondary-only per PID §2.2. The entire architectural argument — minimal codebase, reduced attack surface, no write path — derives from this scoping.

*Enforcement.* ODS-INV-001; ODS-NEG-002 (no DNSSEC signing); ODS-NEG-003 (no non-transfer modification); ODS-NEG-004 (no NOTIFY origination); ODS-NEG-006 (no master file reading).

### C.2.2 DNS UPDATE handling (RFC 2136)

*Description.* Accepting and processing DNS UPDATE messages (OPCODE = 5) for dynamic zone modification.

*Rationale.* Dynamic update is a primary-role function: the receiver of UPDATE modifies the authoritative zone content. A secondary that accepted UPDATE would by definition no longer be a secondary.

*Enforcement.* ODS-INV-001; ODS-NEG-001.

### C.2.3 Online DNSSEC signing

*Description.* Generating RRSIG records dynamically in response to queries (the pattern sometimes called "on-the-fly signing" or "live signing").

*Rationale.* Online signing requires possession and use of DNSKEY private material — categorically a primary-role responsibility. The server's DNSSEC role is exclusively to serve records received from the primary.

*Enforcement.* ODS-INV-001; ODS-NEG-002.

### C.2.4 Recursive resolution

*Description.* Resolving queries for names outside the served zones by issuing queries to other servers and returning the result.

*Rationale.* Recursive resolution is the resolver-role function; this server is exclusively authoritative. Queries for names outside served zones receive REFUSED per ODS-FR-CORE-019.

*Enforcement.* ODS-INV-001; ODS-NEG-007.

### C.2.5 Query forwarding

*Description.* Forwarding inbound queries to a designated forwarder server (the hybrid forwarder configuration some authoritative servers offer).

*Rationale.* As recursive resolution; the server determines every response from its in-memory zone store, with no consultation of any external DNS service.

*Enforcement.* ODS-INV-001; ODS-NEG-008.

### C.2.6 DNSSEC signature validation for clients

*Description.* Verifying DNSSEC signatures on served records, setting AD=1 in responses to indicate validated authenticity.

*Rationale.* DNSSEC validation is the validator-role function (typically performed by recursive resolvers, not by authoritative servers). This server's DNSSEC posture is faithful service of signed records, not validation.

*Enforcement.* ODS-INV-001; ODS-NEG-009; ODS-FR-DNSSEC-010 (AD bit always 0).

### C.2.7 Master file (zone-file) reading

*Description.* Reading zone data from RFC 1035 §5 presentation-format files (the BIND-style "zone files" still in widespread operational use).

*Rationale.* All zone data acquired by this server is received in wire format via zone transfer (AXFR or IXFR) from configured primaries. The presentation-format parser is a substantial component (BIND's covers thousands of lines) and adding it would significantly increase codebase size and parser-attack-surface. Operators wanting to "serve a zone file" are expected to configure a primary that loads the zone file and have this server transfer from it.

*Enforcement.* ODS-INV-001; ODS-NEG-006.

### C.2.8 Outbound AXFR/IXFR serving

*Description.* Acting as a transfer source for downstream secondaries — for example, in hierarchical secondary fleets where a tier-one secondary serves zones to tier-two secondaries.

*Rationale.* The server is a transfer client exclusively. Operators wanting hierarchical fan-out should use either a primary at each tier, or a different secondary implementation that supports outbound transfer.

*Enforcement.* ODS-INV-001; ODS-NEG-005.

### C.2.9 Persistent operational state

*Description.* Writing zone data, refresh history, query statistics, or any other operational state to disk for recovery across restarts.

*Rationale.* ODS-INV-004 establishes that the server holds no persistent operational state. Every restart performs full zone acquisition from primaries; orchestrator configuration is the source of truth for all non-zone state.

*Enforcement.* ODS-INV-004; ODS-NEG-010.

### C.2.10 Runtime configuration reload

*Description.* Re-reading configuration during process operation, in response to a signal (typically SIGHUP) or an administrative command.

*Rationale.* ODS-INV-005 establishes static configuration. Configuration changes are applied only by process restart. This eliminates an entire category of reload-consistency bugs and aligns with container-native deployment patterns.

*Enforcement.* ODS-INV-005; ODS-NEG-011; ODS-IF-CONF-007.

### C.2.11 Administrative network interface

*Description.* A network-accessible interface for runtime server control (BIND's `rndc` over TCP, Knot's `knotc` over Unix socket or TCP, similar mechanisms in other servers).

*Rationale.* Per ODS-INV-005 and ODS-IF-SIG (the minimal signal-handling surface), the server's runtime control interface is limited to SIGTERM and SIGINT for graceful shutdown. There is no administrative command interface; reconfiguration requires restart.

*Enforcement.* ODS-INV-005; ODS-NFR-SEC-005.

## C.3 Current-Scope Exclusions

These items could be added in a future version without violating any architectural invariant. They are excluded from the current version's scope for reasons of minimal-codebase focus, PID-defined feature set, or operational simplicity. Future versions of the SRS may revisit any of these.

### C.3.1 DNS Cookies (RFC 7873)

*Description.* The EDNS Cookie option providing lightweight transaction authentication, defending against off-path UDP-response spoofing.

*Rationale for exclusion.* Not specified in PID Appendix A's RFC list.

*Enforcement.* No specific NEG; the server simply does not implement RFC 7873.

*Note.* This is the most operationally significant omission identified during SRS drafting. DNS Cookies is widely deployed in BIND, NSD, Knot, and PowerDNS, and provides anti-spoofing benefit comparable to TSIG with substantially less operational overhead. Adding it is a contained change: one new EDNS option subsection and integration with the §4.5 SPOOF requirements. Flagged at §4.5 and §4.11 closing notes; tracked in C.5.

### C.3.2 EDNS Client Subnet (RFC 7871)

*Description.* The EDNS option by which a recursive resolver advertises the client's network prefix, enabling location-tailored responses from the authoritative server.

*Rationale for exclusion.* Out of PID scope. ECS is primarily relevant to operators serving geographically distributed content (CDN-style deployments); for a baseline secondary, it is an optional enhancement.

*Enforcement.* Not implemented.

### C.3.3 DNS-over-TLS for client queries (RFC 7858)

*Description.* Serving ordinary DNS query traffic over TLS on TCP port 853.

*Rationale for exclusion.* DoT is primarily a resolver-client privacy mechanism; authoritative-to-resolver use of DoT is uncommon. Out of PID scope.

*Note.* The §4.10 XoT support covers TLS for zone transfer, which is a different operational context (server-to-server, not server-to-client).

*Enforcement.* No specific NEG; not implemented.

### C.3.4 DNS-over-HTTPS (RFC 8484)

*Description.* Serving DNS queries over HTTPS.

*Rationale for exclusion.* As DoT, primarily a resolver-client concern. Out of PID scope. Would require an HTTPS server stack, materially expanding codebase.

*Enforcement.* Not implemented.

### C.3.5 DNS-over-QUIC (RFC 9250)

*Description.* DNS over QUIC transport.

*Rationale for exclusion.* Emerging transport; not in PID scope. Adoption is uneven and the operational benefit for authoritative service is unclear.

*Enforcement.* Not implemented.

### C.3.6 NOTIFY-over-TLS reception (RFC 9103 §6.4)

*Description.* Receiving NOTIFY messages from primaries over TLS connections.

*Rationale for exclusion.* The §4.10 XoT scope is outbound (transfer-client) only; the server does not implement a TLS listener. NOTIFY reception remains over plain UDP/TCP per §4.8, with TSIG providing authentication.

*Enforcement.* ODS-NEG-017.

*Note.* Flagged at §4.10 closing notes; tracked in C.5.

### C.3.7 Per-zone Response Rate Limiting

*Description.* Configuring different RRL thresholds, slip values, or accounting strategies per zone or per view.

*Rationale for exclusion.* Implementation simplicity. The current version applies RRL globally per ODS-FR-RRL-009.

*Enforcement.* ODS-FR-RRL-009.

*Note.* Flagged at §4.17 closing notes; tracked in C.5.

### C.3.8 View / split-horizon DNS

*Description.* Returning different answers for the same QNAME based on client characteristics (source IP, EDNS option content, transport).

*Rationale for exclusion.* Substantial complexity. Most commonly useful in primary-role deployments where authoritative content varies by audience; for a secondary, the primary makes the views and the secondary serves what it's given.

*Enforcement.* Not implemented; per ODS-INV-001 the secondary serves what the primary delivers.

### C.3.9 DNS Catalog Zones (RFC 9432)

*Description.* The mechanism by which a primary publishes a "catalog zone" listing the zones that secondaries should serve, allowing dynamic zone provisioning by adding entries to the catalog.

*Rationale for exclusion.* Per ODS-INV-005, configuration is static; catalog zones imply dynamic zone-set changes outside the operator's static configuration.

*Enforcement.* ODS-INV-005 prevents implementation under current invariants.

*Note.* A future version relaxing ODS-INV-005 to permit catalog-driven zone configuration would constitute a significant architectural change requiring SRS revision.

### C.3.10 EDNS Expire (RFC 7314)

*Description.* An EDNS option allowing a primary to convey the SOA EXPIRE value to a secondary directly during zone transfer, avoiding subsequent SOA polls in some scenarios.

*Rationale for exclusion.* Minor operational optimisation; out of PID scope.

*Enforcement.* Not implemented.

### C.3.11 HMAC-MD5 TSIG (RFC 2845 algorithm)

*Description.* The HMAC-MD5 TSIG algorithm originally specified by RFC 2845.

*Rationale for exclusion.* Explicitly deprecated by RFC 8945 §6 ("hmac-md5 MUST NOT be used by new implementations").

*Enforcement.* ODS-FR-TSIG-004; ODS-NEG-013.

### C.3.12 TKEY mechanism (RFC 2930)

*Description.* The DNS protocol mechanism for establishing TSIG keys dynamically via in-band DNS exchanges.

*Rationale for exclusion.* Per ODS-INV-005, TSIG keys are configured statically. Dynamic key establishment is structurally incompatible with the static-configuration invariant.

*Enforcement.* ODS-INV-005; ODS-NEG-014.

### C.3.13 Operator-facing tools

*Description.* Web-based administrative interfaces; configuration GUIs; configuration migration tools (e.g., a converter from BIND `named.conf` to this server's TOML schema); zone-content inspection or diff tools.

*Rationale for exclusion.* Out of project scope. The project's deliverable is the server binary plus configuration documentation; ancillary tooling is a separate concern.

*Enforcement.* Not implemented; outside SRS-specified server behaviour.

### C.3.14 Built-in monitoring and alerting

*Description.* Integrated alerting on metrics thresholds; dashboards; notification systems for operational events.

*Rationale for exclusion.* The server exposes structured logs (§5.6, §6.3) and metrics (§5.6, §6.4) in standard formats; alerting and dashboarding are the appropriate concern of Prometheus, Grafana, log-aggregation tooling, and equivalent platforms that integrate with the metrics endpoint.

*Enforcement.* Not implemented.

## C.4 Standards Referenced but Not Implemented

The following IETF standards are cited in the SRS or its inputs for context but are not implemented by this server. Each is cross-referenced to its catalogue entry in C.2 or C.3.

| RFC | Title (abbreviated) | Disposition | Cross-ref |
|---|---|---|---|
| 1035 §5 | Master file format | Foundational exclusion | C.2.7 |
| 2136 | DNS UPDATE | Foundational exclusion | C.2.2 |
| 2845 | TSIG (original; HMAC-MD5) | Superseded by RFC 8945; HMAC-MD5 prohibited | C.3.11 |
| 2930 | TKEY | Current-scope exclusion | C.3.12 |
| 5011 | Trust anchor rollover | Foundational exclusion (primary-role) | C.2.1 |
| 7314 | EDNS Expire | Current-scope exclusion | C.3.10 |
| 7858 | DNS-over-TLS (client queries) | Current-scope exclusion | C.3.3 |
| 7871 | EDNS Client Subnet | Current-scope exclusion | C.3.2 |
| 7873 | DNS Cookies | Current-scope exclusion (flagged) | C.3.1 |
| 8484 | DNS-over-HTTPS | Current-scope exclusion | C.3.4 |
| 9250 | DNS-over-QUIC | Current-scope exclusion | C.3.5 |
| 9432 | DNS Catalog Zones | Current-scope exclusion (incompatible with ODS-INV-005) | C.3.9 |

## C.5 Items Flagged for Project Decision

The following items, all currently out of scope, were specifically flagged during SRS drafting for explicit team decision rather than implicit endorsement. Each was raised at a particular subsection's closing notes; the decisions are collected here for traceability and to support review.

| Item | Flagged at | Recommendation | Decision |
|---|---|---|---|
| DNS Cookies (RFC 7873) | §4.5, §4.11 | Bring into scope (most consequential omission) | Pending |
| NOTIFY-over-TLS reception | §4.10 | Remain out of scope (current) | Pending |
| Per-zone RRL configuration | §4.17 | Remain out of scope (current) | Pending |
| mTLS for XoT as MUST | §4.10 | Remain MAY | Pending |
| CAA / ZONEMD / CDS / CDNSKEY as known types | §4.14, B.4 | Remain handled as unknown via §4.4 | Pending |
| DANE TLSA validation for XoT certs | §4.10 | Out of scope (PKIX only) | Pending |
| Non-root execution as MUST | §5.3 | Strengthen to MUST | Pending |
| PowerDNS Authoritative in interop matrix | §7.2 | Consider adding | Pending |
| External operator acceptance as MVP criterion | §7.4 | Confirm as MVP criterion | Pending |
| Strict default for ANY-query mode ("minimal") | §4.2 | Confirm | Pending |
| 4 concurrent transfer sessions (default) | §4.6 | Confirm | Pending |
| 60-second initial-load retry default | §4.16 | Confirm | Pending |
| 1232-octet max UDP response default | §4.11 | Confirm | Pending |
| 1024 concurrent TCP connections (default) | §4.12 | Confirm | Pending |
| Slip = 2 (RRL default) | §4.17 | Confirm | Pending |
| Three-state zone lifecycle model (LOADING/ACTIVE/EXPIRED) | §4.15 | Confirm | Pending |
| Logging format default JSON vs logfmt | §5.6, §6.3 | Confirm JSON | Pending |
| TOML configuration format | §6.2 | Confirm | Pending |
| Combined health/metrics endpoint vs separate | §6.4 | Confirm | Pending |
| Verification category VER prefix (extends §1.4.3) | §7 | Confirm | Pending |

The Decision column is to be populated as the project's review process reaches each item.

# Appendix D — Glossary

## D.1 Purpose

Appendix D consolidates the definitions and abbreviations used throughout this SRS. Its components are:

- A single alphabetical list of terms used in the SRS, with brief definitions covering both acronym expansions and substantive technical terms (D.3);
- The actor classes from §2.3, reproduced here for reference convenience (D.4);
- The identifier categories of §1.4.3 plus VER added in §7, and the area code registry consolidating all area codes allocated through §4, §5, and §6 (D.5).

The glossary entries in D.3 and D.4 are informative; they aid reader comprehension but do not override the normative content of the SRS. The area code registry in D.5 is normative — it is the canonical list of area codes for the requirement identifier scheme of §1.4.3, and changes to the registry are governed by the identifier-stability rules of §1.4.4.

Where a term's primary definition is provided in a specific RFC, the entry below summarises the meaning as used in this SRS and references the RFC for the authoritative definition.

## D.2 Conventions

- Entries are listed alphabetically by term.
- Acronyms are listed by their abbreviated form (e.g., **AXFR**) with the expansion in the definition body.
- Terms with formal definitions in a specific RFC carry the RFC reference; the definition shown is a summary for SRS use.
- Cross-references between entries are noted with "*See also.*"

## D.3 Glossary of Terms

**A.** Address record type (code 1; RFC 1035 §3.4.1). Encodes an IPv4 address in 4 octets of RDATA.

**AAAA.** IPv6 address record type (code 28; RFC 3596). Encodes an IPv6 address in 16 octets of RDATA.

**AA bit.** Authoritative Answer bit, in the DNS message header (RFC 1035 §4.1.1). Set in responses where the server is authoritative for the queried name.

**AD bit.** Authentic Data bit (RFC 4035 §3). Used by validating resolvers to indicate that response data has been verified by DNSSEC. This server sets AD = 0 unconditionally (ODS-FR-DNSSEC-010), as it does not perform validation.

**ALPN.** Application-Layer Protocol Negotiation (RFC 7301). Used in TLS to negotiate the application protocol carried over the TLS connection; this server uses the ALPN identifier `dot` for XoT connections (ODS-FR-XOT-004).

**AXFR.** Full zone transfer protocol (RFC 5936). The mechanism by which the server acquires the complete state of a zone from a primary. *See also.* IXFR.

**Architectural invariant.** A property the system must hold at all times during operation, specified in §3. Invariants constrain the space of possible behaviours and are distinct from behaviours themselves. *See also.* ODS-INV-NNN in D.5.

**Authoritative server.** A DNS server holding authoritative data for one or more zones. This server is authoritative-only (never a resolver, never a forwarder).

**BADALG.** TSIG error code 21 (RFC 8945 §4.3). Returned when the TSIG algorithm name is unsupported.

**BADKEY.** TSIG error code 17. Returned when no matching key is configured for the TSIG's owner name.

**BADSIG.** TSIG error code 16. Returned when the TSIG MAC verification fails.

**BADTIME.** TSIG error code 18. Returned when the time-signed field deviates from current time by more than the fudge value.

**BADTRUNC.** TSIG error code 22 (RFC 8945; RFC 4635). Returned when the MAC truncation is below the algorithm's minimum.

**BADVERS.** EDNS extended error code 16 (RFC 6891 §6.1.3). Returned when an inbound OPT RR carries an EDNS VERSION the server does not support.

**Bailiwick.** A name is "in bailiwick" of another name when the former is at or below the latter in the DNS hierarchy. Used to qualify glue records (in-bailiwick glue is included by the secondary; out-of-bailiwick glue is not relevant to this server).

**BCP.** Best Current Practice — an IETF document category. Cited examples in this SRS: BCP 14 (RFC 2119, RFC 8174), BCP 195 (RFC 9325).

**CAA.** Certification Authority Authorization record (type 257, RFC 8659). Handled as an unknown type per §4.4.

**CD bit.** Checking Disabled bit (RFC 4035). Used in queries from validating resolvers. This server sets CD = 0 unconditionally in responses (ODS-FR-DNSSEC-011).

**Class.** DNS resource class (RFC 1035 §3.2.4). This server primarily handles class IN (Internet, class 1). *See also.* QCLASS.

**CNAME.** Canonical Name record (type 5, RFC 1035 §3.3.1). Specifies a canonical name to which the owner name aliases.

**Cold start.** A process start in which no prior state is recovered. Per ODS-INV-004, every start of this server is a cold start.

**Compression.** DNS name compression (RFC 1035 §4.1.4). The encoding of repeated domain names within a DNS message as 14-bit pointers into earlier in the message. The compression policy per RR type is specified in §4.14 and Appendix B.

**DANE.** DNS-based Authentication of Named Entities (RFC 6698 et al.). The TLSA record is the principal DANE mechanism. This server serves TLSA records as data but does not perform DANE validation.

**Delegation.** The mechanism by which authority for a sub-domain is conferred on another zone, represented by NS records at the delegation cut and (typically) glue records.

**DNAME.** Delegation Name record (type 39, RFC 6672). Redirects a subtree of the namespace to another subtree; the server synthesises CNAMEs in response (ODS-FR-QRY-014).

**DNS.** Domain Name System (RFC 1034, RFC 1035).

**DNSKEY.** DNSSEC Key record (type 48, RFC 4034 §2). Carries the public key for a DNSSEC zone-signing or key-signing operation.

**DNSSEC.** DNS Security Extensions (RFC 4033, RFC 4034, RFC 4035, RFC 5155, others). The cryptographic authentication mechanism for DNS data. This server serves DNSSEC records as data; it does not sign or validate.

**DO bit.** DNSSEC OK bit (RFC 3225, RFC 6891). Set by clients to indicate willingness to receive DNSSEC records. Carried in the OPT RR's TTL field.

**DoH.** DNS-over-HTTPS (RFC 8484). Not implemented; see Appendix C.3.4.

**DoQ.** DNS-over-QUIC (RFC 9250). Not implemented; see Appendix C.3.5.

**DoT.** DNS-over-TLS (RFC 7858). DoT for ordinary client queries is not implemented; the related XoT mechanism for zone transfer is implemented in §4.10.

**DS.** Delegation Signer record (type 43, RFC 4034 §5). Identifies a DNSKEY of a child zone, allowing the parent to authenticate the child's signing key.

**ECS.** EDNS Client Subnet (RFC 7871). Not implemented; see Appendix C.3.2.

**EDNS, EDNS0.** Extension Mechanisms for DNS, version 0 (RFC 6891). Implemented in §4.11.

**EXPIRE.** SOA RDATA field (RFC 1035 §3.3.13). The interval after which a secondary that has not successfully refreshed the zone must cease serving it. *See also.* ODS-FR-ZONE-006 (EXPIRED state), ODS-FR-QRY-021.

**Fudge.** TSIG RDATA field (RFC 8945 §4). The permitted absolute difference (in seconds) between the time-signed field and the receiver's current time.

**Glue.** A and AAAA records served by a parent zone for the name-server names of a child zone, where the name-server names fall within the child zone (in-bailiwick glue). Necessary to bootstrap resolution of the delegation.

**Graceful shutdown.** Process termination that completes in-flight work before exit, per ODS-NFR-REL-001.

**Header.** DNS message header (RFC 1035 §4.1.1). Fixed 12-octet structure containing ID, flags, OPCODE, RCODE, and section counts.

**HINFO.** Host Information record (type 13, RFC 1035 §3.3.2). Largely deprecated.

**HMAC.** Keyed-Hash Message Authentication Code (RFC 2104). The cryptographic primitive underlying TSIG algorithms.

**HTTPS.** HTTPS record type (code 65, RFC 9460). HTTPS-specific SVCB variant; the same wire format as SVCB. *See also.* SVCB.

**IANA.** Internet Assigned Numbers Authority. Maintains the registries for DNS RR types, OPCODEs, RCODEs, and other protocol numbers (RFC 6895).

**IETF.** Internet Engineering Task Force. The standards body whose RFCs constitute this server's compliance target.

**IN.** Class Internet (value 1). The default and dominant DNS resource class.

**Interoperability test.** A test of the server against real-world peer implementations (primaries, resolvers); see §7.1 and §7.2.

**Invariant.** *See* Architectural invariant.

**IXFR.** Incremental Zone Transfer protocol (RFC 1995). The mechanism by which the server acquires only the differences between two versions of a zone. *See also.* AXFR.

**Jitter.** Random variation added to scheduled intervals to avoid synchronised events across many actors; specified for the zone state machine in ODS-FR-ZSM-010.

**Label.** A single component of a DNS name (RFC 1035 §3.1). Maximum 63 octets per label; maximum 255 octets per name.

**LOADING.** Zone state (ODS-FR-ZONE-006). No successful zone transfer has yet completed for the zone since process startup; queries against a LOADING zone receive SERVFAIL.

**Logfmt.** Structured log line format (key=value pairs). One of the two supported log formats per ODS-NFR-OBS-001, with JSON as the other.

**MAC.** Message Authentication Code. The cryptographic output of TSIG and HMAC operations.

**Master file.** Presentation-format zone file (RFC 1035 §5). Not read by this server; see Appendix C.2.7.

**MD5.** Message Digest 5 hash function (RFC 1321). Prohibited for TSIG use per ODS-NEG-013.

**MINIMUM.** SOA RDATA field (RFC 1035 §3.3.13; redefined by RFC 2308 §3). The maximum TTL for negative-response caching by downstream resolvers.

**mTLS.** Mutual TLS. TLS with client-certificate authentication of the connection initiator. Supported optionally for XoT per ODS-FR-XOT-007.

**MX.** Mail Exchange record (type 15, RFC 1035 §3.3.9). Identifies a mail server for the domain.

**NAPTR.** Naming Authority Pointer record (type 35, RFC 3403). Used in DDDS resolution.

**NODATA.** A response where the queried name exists in the zone but no RRset of the queried QTYPE exists at that name. RCODE = NOERROR with empty answer section and SOA in authority. *See also.* ODS-FR-CORE-022.

**NOTIFY.** DNS NOTIFY message (RFC 1996, OPCODE = 4). A primary's signal to its secondaries that zone data has changed. Implemented in §4.8 (receiver side only; this server does not originate NOTIFY).

**NSEC.** Next Secure record (type 47, RFC 4034 §4). DNSSEC authenticated denial of existence.

**NSEC3.** Hashed NSEC (type 50, RFC 5155). Hashed-name variant of NSEC, defeating zone enumeration.

**NSEC3PARAM.** NSEC3 Parameters record (type 51, RFC 5155 §4).

**NXDOMAIN.** Non-existent domain. RCODE = 3, returned when the queried name does not exist in the zone (ODS-FR-CORE-023). *See also.* RFC 8020 for the "no descendants either" cut semantic.

**OpenMetrics.** Standardised metrics exposition format compatible with Prometheus; used for the metrics endpoint per ODS-NFR-OBS-003.

**OPCODE.** DNS operation code (RFC 1035 §4.1.1). This server handles OPCODE 0 (QUERY) and OPCODE 4 (NOTIFY).

**OPT.** EDNS pseudo-RR (type 41, RFC 6891). Carries EDNS options in the additional section of DNS messages.

**Orchestrator.** Automated process supervisor; in this SRS, typically Kubernetes, systemd, or equivalent. *See also.* Actor classes in D.4.

**Original ID.** TSIG RDATA field (RFC 8945 §4.2). Used to reconstruct the original message ID for MAC verification when the message has transited a NAT or similar intermediary.

**PID.** Project Initiation Document (this project, v0.1, May 2026).

**PKIX.** Public Key Infrastructure using X.509 (RFC 5280). The certificate-authentication framework used for XoT trust validation.

**Primary.** A DNS server that holds the authoritative master copy of a zone. The source from which this server (a secondary) transfers zone data.

**Pseudo-RR.** A resource record carrying protocol metadata rather than zone content. OPT, TSIG, and TKEY are pseudo-RRs; they are never part of a zone transfer. *See also.* Appendix B.3.

**QID.** Query Identifier — the 16-bit ID field in the DNS message header. Used to match responses to queries.

**QNAME.** Query Name — the name field of the question section.

**QCLASS.** Query Class — the class field of the question section.

**QR bit.** Query/Response bit (RFC 1035 §4.1.1). 0 in queries, 1 in responses.

**QTYPE.** Query Type — the type field of the question section.

**RA bit.** Recursion Available bit (RFC 1035 §4.1.1). Set in responses by recursive servers. This server sets RA = 0 unconditionally (ODS-FR-CORE-012) as it does not perform recursion.

**RCODE.** Response Code (RFC 1035 §4.1.1). 4-bit field in the response header indicating the response category (NOERROR, FORMERR, NXDOMAIN, etc.). Extended to 12 bits in EDNS responses (RFC 6891).

**RD bit.** Recursion Desired bit (RFC 1035 §4.1.1). Echoed from query to response per ODS-FR-CORE-011 but otherwise ignored by this server.

**RDATA.** Resource Record Data — the variable-length record content.

**RDLENGTH.** Resource Record Data Length — 16-bit field giving the length of RDATA.

**Recursion.** Resolution of a query by issuing further queries on the client's behalf. Not performed by this server (ODS-NEG-007).

**Referral.** A response that delegates resolution to another zone. RCODE = NOERROR, empty answer section, NS records of the child zone in authority section, optional glue in additional section. *See also.* ODS-FR-CORE-025.

**REFRESH.** SOA RDATA field. The interval between scheduled refresh attempts by a secondary.

**RESOLVER.** A DNS client that resolves names on behalf of end users. *See also.* DNS Client in D.4.

**RETRY.** SOA RDATA field. The interval between retry attempts after a failed refresh.

**RR.** Resource Record (RFC 1035).

**RRL.** Response Rate Limiting. The mitigation against DNS amplification attacks specified in §4.17.

**RRset.** Resource Record Set (RFC 2181 §5). The set of RRs sharing owner name, class, and type.

**RRSIG.** Resource Record Signature record (type 46, RFC 4034 §3). DNSSEC signature over an RRset.

**RSA.** Rivest-Shamir-Adleman public-key cryptosystem. One of the DNSSEC and TLS algorithm families.

**SERIAL.** SOA RDATA field. 32-bit version number of the zone, compared per RFC 1982 arithmetic.

**SEP flag.** Secure Entry Point flag in DNSKEY FLAGS (RFC 3757). Marks a key intended as the trust anchor for the zone.

**SERVFAIL.** Server Failure response (RCODE = 2). Returned for internal errors or expired zones (ODS-FR-QRY-021, ODS-FR-ZONE-006).

**SHA-1, SHA-256, SHA-384, SHA-512.** Secure Hash Algorithm variants. Used as TSIG algorithm primitives (RFC 4635).

**SIGHUP, SIGINT, SIGTERM, SIGUSR1, SIGUSR2.** POSIX signals; handled per §6.5.

**Slip.** RRL configuration parameter (ODS-FR-RRL-005). Controls the ratio of rate-limited responses emitted as truncated (TC=1) versus dropped.

**SNI.** Server Name Indication (RFC 6066). TLS extension by which the client indicates the intended server name; used in XoT to identify the configured primary.

**SOA.** Start of Authority record (type 6, RFC 1035 §3.3.13). Required at each zone apex; carries the zone's serial number and timing parameters.

**Soak test.** Long-duration runtime test (days to weeks) under realistic workload; method specified in §7.1.

**SPKI.** Subject Public Key Information. An identifier-pinning approach for TLS authentication (RFC 7469); not implemented but cited in §4.10.

**SRS.** Software Requirements Specification (this document).

**SRV.** Service location record (type 33, RFC 2782).

**Stub resolver.** A simple DNS client that queries a recursive resolver rather than performing resolution itself.

**SVCB.** Service Binding record (type 64, RFC 9460).

**TC bit.** Truncated bit (RFC 1035 §4.1.1). Set in a response that has been truncated, signalling the client to retry over TCP.

**TKEY.** Transaction Key record (type 249, RFC 2930). Not implemented (ODS-NEG-014).

**TLS.** Transport Layer Security (RFC 5246 for TLS 1.2; RFC 8446 for TLS 1.3).

**TLSA.** DANE TLS Authentication record (type 52, RFC 6698).

**TOML.** Tom's Obvious Minimal Language. The configuration file format selected per ODS-IF-CONF-001.

**TSIG.** Transaction SIGnature (RFC 8945; obsoletes RFC 2845). Symmetric-key authentication of DNS messages.

**TTL.** Time To Live (RFC 1035). The validity duration of a cached record, in seconds.

**UDP.** User Datagram Protocol (RFC 768).

**Unknown RR type.** An RR type not enumerated in the catalogue of §4.14. Handled per §4.4 (URR semantics).

**URI.** Uniform Resource Identifier record (type 256, RFC 7553).

**Verification.** The process of demonstrating that a requirement is satisfied. Methods are specified in §7.1.

**Wildcard.** An owner name beginning with the `*` label (RFC 4592). The server synthesises responses for non-existent names matching the wildcard per ODS-FR-CORE-024.

**Wire format.** The over-the-wire encoding of DNS messages and zone data (RFC 1035 §4 et seq.).

**XoT.** DNS Zone Transfer over TLS (RFC 9103). Implemented as outbound only (transfer client) per §4.10.

**Zone.** A contiguous portion of the DNS namespace administered as a unit (RFC 1034 §4.2).

**Zone apex.** The top of a zone — the name at which the SOA and apex NS records reside.

**Zone refresh.** The process by which a secondary updates its in-memory zone data from the primary; governed by §4.16.

**ZSK.** Zone Signing Key. A DNSKEY used to sign zone records (as opposed to a Key Signing Key used to sign DNSKEY records). Distinction is primary-side; the server serves both opaquely.

## D.4 Actor Classes

Five classes of actor interact with the server. The full descriptions are in §2.3; reproduced compactly here for reference.

**DNS Client (Resolver, Stub Resolver).** Untrusted entity sending DNS queries expecting authoritative answers. Includes recursive resolvers acting on behalf of end users and direct stub resolvers. The server assumes hostility until proven otherwise.

**Primary DNS Server.** Trusted (via TSIG, where configured) source of zone data. The server transfers zones from configured primaries and accepts NOTIFY from them.

**Operator.** Human administrator responsible for the server's configuration and deployment. Interacts only at process startup (via configuration) and during operation (via signals).

**Orchestrator (Supervisor).** Automated process supervisor: container orchestrator (Kubernetes, Docker), init system (systemd), or anycast routing controller. Starts, stops, and probes the server.

**Observer (Logging and Metrics Consumer).** Downstream system consuming the server's structured log output and metrics endpoint. Unauthenticated; the server emits and is agnostic to what consumes.

## D.5 Identifier Categories and Area Code Registry

### D.5.1 Categories

Per §1.4.3, requirement identifiers follow the form `ODS-<CATEGORY>-<AREA>-<NNN>` (with AREA omitted for some categories). The current categories are:

| Category | Name | AREA component | Defined in |
|---|---|---|---|
| FR | Functional Requirement | Required | §4 |
| NFR | Non-Functional Requirement | Required | §5 |
| IF | External Interface Requirement | Required | §6 |
| INV | Architectural Invariant | Omitted | §3 |
| NEG | Negative (Prohibition) Requirement | Omitted | §4.18 |
| VER | Verification Requirement | Omitted | §7 (added in current SRS revision) |

VER is the only category added beyond the §1.4.3 original enumeration; the next SRS revision should incorporate VER into the §1.4.3 list explicitly.

### D.5.2 Area code registry (normative)

Area codes are short uppercase mnemonics (3–6 characters) registered in the table below. Each area code is unique across the SRS and is associated with one subsection. New area codes are allocated only by SRS revision; per the identifier-stability rule of §1.4.4, area codes are never reused for different concerns.

#### Functional area codes (ODS-FR-`AREA`-NNN)

| Area | Subsection | Topic |
|---|---|---|
| CORE | §4.1 | DNS protocol core (message format, headers, basic lookup) |
| QRY | §4.2 | Query processing (CNAME, DNAME, additional section, RCODE selection) |
| NRESP | §4.3 | Negative responses (NXDOMAIN, NODATA, TTL semantics) |
| URR | §4.4 | Unknown RR type handling |
| SPOOF | §4.5 | Anti-spoofing measures |
| AXFR | §4.6 | Full zone transfer (AXFR client) |
| IXFR | §4.7 | Incremental zone transfer |
| NOTIFY | §4.8 | NOTIFY message reception |
| TSIG | §4.9 | TSIG authentication |
| XOT | §4.10 | Zone transfer over TLS |
| EDNS | §4.11 | EDNS0 |
| TCP | §4.12 | TCP transport |
| DNSSEC | §4.13 | DNSSEC record serving |
| RR | §4.14 | RR type catalogue and structural constraints |
| ZONE | §4.15 | In-memory zone store |
| ZSM | §4.16 | Zone state machine |
| RRL | §4.17 | Response Rate Limiting |

#### Non-functional area codes (ODS-NFR-`AREA`-NNN)

| Area | Subsection | Topic |
|---|---|---|
| PERF | §5.1 | Performance |
| REL | §5.2 | Reliability and availability |
| SEC | §5.3 | Security |
| MAINT | §5.4 | Maintainability |
| PORT | §5.5 | Portability |
| OBS | §5.6 | Observability |
| RES | §5.7 | Resource limits |

#### Interface area codes (ODS-IF-`AREA`-NNN)

| Area | Subsection | Topic |
|---|---|---|
| NET | §6.1 | Network interfaces |
| CONF | §6.2 | Configuration interface |
| LOG | §6.3 | Logging interface |
| HEALTH | §6.4 | Health and metrics endpoint |
| SIG | §6.5 | Process signals |

### D.5.3 Reserved category prefixes

The following prefixes are reserved for future use and MUST NOT be allocated as area codes in any category:

- **TODO**, **TBD**, **REQ**, **REQ-** — reserved against accidental collision with informal notation.
- **TEST**, **VER**, **VRF** — reserved; VER is used as a category (D.5.1).

### D.5.4 Maintenance discipline

Adding a new area code requires editing this registry in the same SRS revision as the area code's first allocation. Area codes follow the identifier-stability rule of §1.4.4: once allocated, they MUST NOT be reused for a different concern, and MUST NOT be removed even if the subsection they describe is removed (the registry row is preserved with a "Deprecated" annotation).

---

*End of document.*
