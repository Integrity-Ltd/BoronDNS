# Software Requirements Specification

## OxideDNS-Secondary

**Document Version:** v0.9.1 (Draft 9, point release 1)
**Date:** 26 May 2026
**Status:** Draft — CHAOS class self-identification addition, OxideDNS namespace alignment

---

### Document Control

| Field | Value |
|---|---|
| Project | OxideDNS-Secondary |
| Document | Software Requirements Specification (SRS) |
| Version | v0.9.1 |
| Date | 26 May 2026 |
| Author | DT (Architect, Lead Developer) |
| Reviewer | DTK (Sponsor, Reviewer) |
| Tester | SzI (Alpha Tester) |
| Related documents | PID v0.1 (May 2026); Architecture Document; Test Plan; Operator Deployment Guide (per ODS-NFR-MAINT-009) |

### Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| v0.1 | 23 May 2026 | DT | Initial draft assembled from working sessions. |
| v0.2 | 24 May 2026 | DT | Added three-interface segregation as MVP requirement (ODS-IF-NET-005, -006, -007; ODS-IF-CONF-003 extended). Added post-MVP / v2 scope section (Appendix C.6) covering XDP/eBPF kernel bypass, optimised packed-binary zone store, and pre-baked response cache. |
| v0.3 | 24 May 2026 | DT | Functional audit closure. Cross-reference fix in ODS-FR-QRY-002. Specification gaps: non-EDNS UDP ceiling, AA bit completeness, CNAME chain limit/loop semantics, TCP per-connection in-flight cap, AXFR/IXFR zone-size cap, pseudo-RR rejection. Design decisions: UDP IXFR removed; minimal-ANY deterministic selection; XoT revocation posture explicit; NOTIFY discard log rate-limiting; max effective REFRESH; long-LOADING warning; multi-primary randomized initial selection. New MVP scope: DNS Cookies (§4.19), NSID (ODS-FR-EDNS-016), per-zone counters. |
| v0.4 | 24 May 2026 | DT | Non-functional audit closure. Reference Hardware Profile (Dual Xeon Gold 6230R) and Reference Query Mix introduced (Appendix E); all PERF/RES targets now reference it. New NFRs: PERF-006/-007/-008, REL-006/-007, SEC-007, MAINT-006/-007/-008/-009, OBS-006/-007, RES-006. SEC-004 elevated SHOULD→MUST. MAINT-004 elevated SHOULD→MUST with CI enforcement. OBS-004 split into `/livez` and `/readyz`. |
| v0.5 | 24 May 2026 | DT | Interface audit closure. **Network interfaces**: renamed `interface.xot` -> `interface.transfer` (covers AXFR/IXFR/SOA-poll/XoT outbound traffic); ODS-IF-NET-008 records the MVP decision to reject a fourth active NOTIFY interface role and receive authorized NOTIFY on DNS listeners; NET-005 clarifies health-endpoint binding relationship with `interface.mgmt`. **Configuration interface**: new CONF-008 (warning-level configuration issues, non-aborting), CONF-009 (`--dump-config` CLI mode), CONF-010 (`--validate-config` CLI mode), CONF-011 (parameter naming convention), CONF-012 (environment variable naming convention); CONF-001 extended to explicitly exclude include directives; CONF-004 note added for external secret stores; CONF-003 explicit constraint against interface-name bindings. **Logging interface**: new LOG-005 (canonical structured field names), LOG-006 (bootstrap logging before config parsed), LOG-007 (log entry maximum size), LOG-008 (lazy formatting in hot paths). **Health/metrics endpoint**: HEALTH-001 and HEALTH-002 clarified for relationship with `interface.mgmt`; HEALTH-002 extended with explicit response body content; new HEALTH-005 (response time bounds, gzip support), HEALTH-006 (per-source rate limit on `/metrics`). **Process signals**: SIG-001 extended to reference REL-005 100-ms signal-to-action latency; SIG-004 amended to permit SIGPIPE ignore disposition. **New §6.6 Process Lifecycle and Command-Line Interface**: PROC area code allocated. New requirements PROC-001 (exit code convention per `sysexits.h` style), PROC-002 (`--version` / `-V`), PROC-003 (`--help` / `-h`), PROC-004 (`--example-config`, optional). Appendix C.5 updated. Glossary D.5.2 updated with PROC area code. |
| v0.6 | 24 May 2026 | DT | Architectural invariants audit closure. **Precision refinements to existing invariants**: ODS-INV-001 (Secondary-Only Operation) tightened terminology ("authoritative state" → "in-memory zone store of any authoritatively-served zone"), explicit handling of NOTIFY-borne SOA, verification corrected to NOTIMP-only; ODS-INV-002 (Memory-Resident Zone Data) "query-serving path" scope explicit (startup-time configuration reading excluded, /proc introspection permitted); ODS-INV-003 (Atomic Zone Refresh) multi-delta IXFR atomicity clarified; ODS-INV-004 (No Persistent Operational State) /tmp coverage added (server runnable with /tmp absent or read-only); ODS-INV-005 (Static Configuration) environment-variable and file sources clarified as additive with env precedence, runtime-derived state explicitly excluded from "configuration"; ODS-INV-006 (Memory Safety Discipline) first-party vs third-party dependency boundary clarified, panic-freedom discipline added. **Three new foundational invariants**: ODS-INV-007 (Authoritative-Only Response Composition) elevating the established NEG-007/-008 + QRY-020 constraints to invariant level; ODS-INV-008 (Single-Process Architecture) prohibiting fork/exec/subprocess invocation; ODS-INV-009 (Static Composition; No Runtime Code Loading) prohibiting plugin loading and embedded interpreters. **Section structure**: new §3.7, §3.8, §3.9 added; §3 introductory text amended with conflict-resolution policy between invariants. **Status fields** updated from "Draft" to "Reviewed v0.6 (architectural invariants audit closure)" or "Introduced v0.6" as appropriate. Cross-references to ODS-INV-007 added to ODS-NEG-007 and ODS-NEG-008. Appendix C.5 updated with audit-resolution entries. |
| v0.7 | 24 May 2026 | DT | **Verification strategy audit closure — final audit cycle revision.** §7 intro updated (removed obsolete "future revision" note regarding VER category, which was registered in earlier revisions). **Method catalog (§7.1) expanded** with four new methods: Property-based test, Differential test, Static analysis (elevated as distinct method from Inspection), Security audit. **ODS-VER-001 reformulated** from self-referential tautology to a coherence requirement (Verification fields must reference methods enumerated in §7.1). **Six new VER requirements**: ODS-VER-010 (pre-release verification gate with release-notes capture); ODS-VER-011 (Continuous / Periodic / Gate verification classification); ODS-VER-012 (regression detection and triage policy, with configurable performance-regression threshold); ODS-VER-013 (interoperability primary version recording for reproducibility); ODS-VER-014 (RFC compliance assertion publication in release notes and primary documentation); ODS-VER-015 (verification responsibility allocation). **ODS-VER-007 (Alpha milestone) corrected**: §6.6 PROC requirements added to Alpha scope (PROC-001/-002/-003); §6.1 NET-008 marked optional; §6.2 CONF-008–-012 included in Alpha; §5.6 OBS-005 added to Alpha. **ODS-VER-009 (traceability matrix) extended** with explicit update cadence (synchronous with each release). **Appendix C.5 updated** with v0.7 resolutions. **Closing audit-cycle note** added at end of §7. With this revision the audit cycle initiated at v0.2 is complete: functional (§4) in v0.3, non-functional (§5) in v0.4, interface (§6) in v0.5, architectural invariants (§3) in v0.6, verification (§7) in v0.7. |
| v0.8 | 25 May 2026 | DT | **Zone Provisioning feature addition; CIA-driven security expansion.** **New §4.20 Zone Provisioning** allows the set of zones served by a server instance to be derived from explicit `[[zones]]` configuration and/or DNS Catalog Zones per RFC 9432 via `[[catalog_zones]]`. New area code **PROV** allocated. New requirements ODS-FR-PROV-001 through ODS-FR-PROV-014 covering explicit zones, catalog parsing, member-zone lifecycle (provisioning, de-provisioning), security constraints, and resource limits. **ODS-INV-005 (Static Configuration) clarified**: catalog-derived member-zone set added to the enumerated examples of runtime-derived state explicitly excluded from the "configuration" scope of the invariant. The invariant's *Implications* paragraph extended to note that the configured explicit and catalog-zone sources are static, while the derived catalog member set is runtime-derived state akin to zone contents and the zone state machine state. **Appendix C.3.9 (DNS Catalog Zones) removed** from the exclusions list and promoted to in-scope; the rationale-for-exclusion has been resolved by the §4.20 design which preserves ODS-INV-005 by isolating statically configured catalog-zone coordinates from the runtime-derived member set. **New security requirements from CIA threat-model analysis (§5.3)**: ODS-NFR-SEC-008 (TSIG key material loadable from environment variables with zeroization at load), ODS-NFR-SEC-009 (transfer authentication advisory and `require_tsig` flag), ODS-NFR-SEC-010 (mandatory catalog-zone TSIG authentication; refusal to start with a catalog zone without TSIG key), ODS-NFR-SEC-011 (catalog must not redirect member-zone primary coordinates), ODS-NFR-SEC-012 (multi-primary catalog support for SPOF mitigation), ODS-NFR-SEC-013 (`max_member_zones` resource exhaustion cap), ODS-NFR-SEC-014 (per-transfer-session timeout for tarpit defence), ODS-NFR-SEC-015 (catalog member-zone name syntactic validation). **New observability requirement ODS-NFR-OBS-008**: catalog-specific Prometheus metrics catalogue. **§6.2 extended**: ODS-IF-CONF-013 specifies `[[zones]]` and `[[catalog_zones]]` zone-provisioning configuration. **§6.4 extended**: ODS-NFR-OBS-004 `/readyz` semantics updated to include catalog-zone state. **Appendix D.5.2 area code registry updated** with PROV. |
| v0.9 | 25 May 2026 | DT | **Implementation-alignment requirements update.** Incorporates functional clarifications from the Alpha review without making implementation audit claims part of the normative SRS. **Functional additions:** ODS-FR-DNSSEC-014 (NSEC3 iteration count cap per RFC 9276 / BCP 236); ODS-FR-QRY-025 (DNAME synthesis name-length overflow handling per RFC 6672 §5.3.1); ODS-FR-AXFR-025 (optional, off-by-default out-of-zone A/AAAA glue tolerance); and ODS-FR-AXFR-026 (DNAME multiplicity validation per RFC 6672 §2.4). **Configuration interface additions:** ODS-IF-CONF-014 (environment-variable override re-validation), ODS-IF-CONF-015 (NSEC3 max iterations parameter), and ODS-IF-CONF-016 (out-of-zone glue tolerance parameter). **Interoperability matrix extension:** ODS-VER-003 extended to require XoT interop coverage against BIND 9 in addition to the already-required Knot DNS XoT coverage. Implementation evidence remains tracked in verification and release-evidence documents, not in normative SRS requirements. **No invariant changes**: §3 (ODS-INV-001 through ODS-INV-009) is unchanged. **No NEG changes**: §4.18 is unchanged. |
| v0.9.1 | 26 May 2026 | DT | **CHAOS class self-identification addition.** Incorporates the 26 May 2026 v0.9.1 SRS attachment after normalising legacy non-OxideDNS naming to the project-canonical `OxideDNS`/`ODS-` namespace and preserving the already-adopted OxideDNS v0.9 corrections for catalog-zone configuration (`[[zones]]` and `[[catalog_zones]]`), DNS-interface NOTIFY handling, and the bounded EDE profile. Introduces §4.21 (CHAOS Class Query Handling) and allocates functional area code **CHAS**. New requirements ODS-FR-CHAS-001 through ODS-FR-CHAS-006 specify opt-in `version.bind.` / `version.server.` and `hostname.bind.` / `id.server.` CH/TXT responses, REFUSED defaults, REFUSED handling for unsupported CHAOS names and non-TXT CHAOS queries, IN-class orthogonality, and low-noise counters/logging. Adds ODS-IF-CONF-018 for the `[chaos]` configuration subtree; ODS-IF-CONF-017 remains allocated to the bounded Extended DNS Errors profile from v0.9 implementation alignment, so the incoming v0.9.1 `CONF-017` allocation is renumbered to avoid identifier collision. No invariant changes. No NEG changes. |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Overall Description](#2-overall-description)
3. [Architectural Invariants](#3-architectural-invariants)
   - 3.1 Secondary-Only Operation
   - 3.2 Memory-Resident Zone Data
   - 3.3 Atomic Zone Refresh
   - 3.4 No Persistent Operational State
   - 3.5 Static Configuration
   - 3.6 Memory Safety Discipline
   - 3.7 Authoritative-Only Response Composition *(new in v0.6)*
   - 3.8 Single-Process Architecture *(new in v0.6)*
   - 3.9 Static Composition; No Runtime Code Loading *(new in v0.6)*
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
   - 4.19 DNS Cookies
   - 4.20 Zone Provisioning *(new in v0.8)*
   - 4.21 CHAOS Class Query Handling *(new in v0.9.1)*
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
   - 6.6 Process Lifecycle and Command-Line Interface
7. [Verification Strategy](#7-verification-strategy)
   - 7.1 Verification Methods
   - 7.2 Interoperability Matrix
   - 7.3 RFC Compliance Assessment
   - 7.4 Acceptance Criteria for PID Milestones
   - 7.5 Verification Evidence and Traceability
   - 7.6 Test Plan Boundary
   - 7.7 Audit Cycle Closure *(new in v0.7)*
8. Appendix A — Requirement-to-RFC Traceability Matrix
9. Appendix B — Resource Record Type Catalogue
10. Appendix C — Out-of-Scope Items and Post-MVP Scope
11. Appendix D — Glossary
12. Appendix E — Reference Hardware Profile and Reference Query Mix

---

# 1. Introduction

## 1.1 Purpose

This Software Requirements Specification (SRS) defines the functional and non-functional requirements of OxideDNS-Secondary, a secondary-only authoritative DNS server written in Rust. It expands the RFC compliance target established in the Project Initiation Document (PID) into concrete, traceable, testable requirements suitable for implementation, review, and independent verification.

This document is the normative reference for externally observable behaviour, explicit scope exclusions, and the criteria against which correctness will be judged. Internal design choices, data structures, concurrency models, and implementation evidence belong in the Architecture Document, Test Plan, verification ledger, or release notes unless they are necessary to define externally observable behaviour.

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

Each requirement should express a single, testable assertion. Compound requirements of the form "the server MUST do X and SHOULD do Y" should be split into separate requirements, each with its own identifier. Where a requirement intentionally groups tightly coupled protocol behavior, configuration, logging, or metrics into one operational case, its verification text must identify the observable sub-cases to be tested. This keeps requirements maintainable without forcing identifier churn for coherent wire-protocol or operator-facing behaviors.

### 1.4.3 Requirement Identifiers

Each requirement carries a stable identifier of the form

```
ODS-<CATEGORY>-<AREA>-<NNN>
```

where:

- **ODS** denotes the OxideDNS-Secondary requirement namespace.
- **CATEGORY** is one of:
  - **FR** — Functional Requirement (defined in §4).
  - **NFR** — Non-Functional Requirement (defined in §5).
  - **IF** — External Interface Requirement (defined in §6).
  - **INV** — Architectural Invariant (defined in §3). The AREA component is omitted.
  - **NEG** — Negative (Prohibition) Requirement (defined in §4.18). The AREA component is omitted.
  - **VER** — Verification Requirement (defined in §7). The AREA component is omitted.
- **AREA** is a short uppercase mnemonic, 3 to 6 characters, identifying the protocol concern, non-functional concern, or interface (for example AXFR, TSIG, PERF, NET). Area codes are allocated centrally in Appendix D (Glossary) and shall not be reused for unrelated concerns.
- **NNN** is a zero-padded three-digit sequence number, unique within the (CATEGORY, AREA) namespace, starting at 001.

Earlier draft snapshots used two suffixed functional identifiers while the v0.9.1 text was being normalised. The current SRS allocates numeric replacements instead: `ODS-FR-CORE-029` for error-response question echoing and `ODS-FR-ZSM-014` for SOA poll wire construction. No suffixed requirement identifiers shall be allocated.

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
| ODS | OxideDNS-Secondary requirement namespace. |

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

At a behavioural level, OxideDNS-Secondary performs the following functions. Section 4 decomposes these functions into numbered requirements; where a requirement intentionally groups a coherent operational case, its verification text identifies the observable sub-cases to test.

**Zone acquisition.** Initiates AXFR or IXFR transfers from configured primaries, authenticated by TSIG where configured. Falls back from IXFR to AXFR when the primary cannot satisfy an incremental request. Transfers over TLS (XoT) where configured.

**Zone maintenance.** Honours per-zone SOA REFRESH, RETRY, and EXPIRE timers. Receives and authenticates NOTIFY messages and triggers expedited refresh in response. Expires zones whose authoritative data is no longer fresh and ceases to serve them in accordance with RFC 1034.

**Zone storage.** Maintains each zone's authoritative data entirely in process memory. Refreshes are applied atomically: query handlers observe either the previous version of a zone in its entirety or the new version, never a mixture.

**Query answering.** Receives DNS queries over UDP and TCP, parses them, performs authoritative lookup, and returns responses including authority and additional sections per RFC 1034 and RFC 1035. Sets the AA bit appropriately. Returns NXDOMAIN, NODATA, and other error responses correctly per RFC 2308. Returns REFUSED for queries outside the served zones; never offers recursion.

**Protocol extensions.** Honours EDNS0, including advertised buffer sizes, the padding option, and the TCP keepalive option. Performs TCP fallback on truncation. Provides passive DNSSEC serving by serving DNSSEC records (DNSKEY, RRSIG, NSEC, NSEC3, DS, NSEC3PARAM) verbatim as received from the primary.

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

**Static release artifact.** The published Linux release artifact targets `x86_64-unknown-linux-musl` and is verified as a statically linked binary with no runtime shared-library dependencies. Non-release developer builds may use the host toolchain's normal dynamic-linking conventions and are not the portability baseline.

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

This section establishes the architectural invariants of OxideDNS-Secondary. An invariant is a property the system must hold at all times during operation — not a behaviour to be performed, but a constraint on the space of possible behaviours. Every functional requirement in §4 and every non-functional requirement in §5 is written within the constraint envelope these invariants define; in case of apparent conflict between an invariant and any other requirement of this SRS, the invariant prevails.

The invariants of this section are intended to be mutually consistent; in the unlikely event of apparent conflict between two invariants, the conflict represents an SRS defect requiring revision to resolve explicitly. No implementation-level decision MAY be made to silently resolve such a conflict.

Each invariant is presented with a normative Statement, the Rationale for its existence, the Implications it has for design, and the Verification approach by which the invariant will be confirmed. A Status field records the audit-review status of each invariant.

In v0.1 the section was assembled at draft maturity. In v0.6, following the §3 audit cycle, the existing invariants ODS-INV-001 through ODS-INV-006 received precision refinements (terminology clarification, scope boundaries made explicit, edge cases addressed), and three new foundational invariants were added: ODS-INV-007 (Authoritative-Only Response Composition), ODS-INV-008 (Single-Process Architecture), and ODS-INV-009 (Static Composition; No Runtime Code Loading). The new invariants elevate to foundational status constraints previously expressed only at negative-requirement or implementation-decision level.

## 3.1 Secondary-Only Operation

**ODS-INV-001 — Secondary-Only Operation**

*Statement.* The server MUST acquire zone data only through zone transfer protocols (AXFR per RFC 5936 or IXFR per RFC 1995) initiated by itself toward operator-configured primaries. The server MUST NOT accept zone data, zone modifications, or any change to the in-memory zone store of any authoritatively-served zone (per §3.2 and §4.15) through any other channel.

*Rationale.* The secondary-only scope is the defining design constraint of this project (PID §2.2). The security, simplicity, and auditability claims of the project derive from the absence of any write path other than authenticated zone transfer from a trusted primary.

*Implications.* There is no DNS UPDATE (RFC 2136) handler: UPDATE messages are received on the DNS query interface (per ODS-FR-NOTIFY/QRY listening) but are rejected with RCODE NOTIMP per ODS-FR-CORE-005 and ODS-NEG-001; no UPDATE-message processing logic exists in the server. There is no zone-file editing interface, no administrative interface for modifying records, and no acceptance of out-of-band zone data injection. The complementary prohibitions are enumerated as negative requirements in §4.18.

Zone-state data carried as optional content in NOTIFY messages — most notably the optional SOA RR in the NOTIFY answer section per RFC 1996 §3.7 — is not trusted as authoritative; the server validates current zone state via an independent SOA poll to the configured primary per ODS-FR-NOTIFY-005 and §4.16. The NOTIFY's hint is a trigger, not a data delivery.

*Verification.* Static analysis of the codebase shall confirm that the only code paths producing changes to the in-memory zone store originate in the zone transfer client (AXFR/IXFR completion path, atomic publication per ODS-INV-003). Functional tests shall confirm that UPDATE messages, however formed, are rejected with RCODE NOTIMP per ODS-FR-CORE-005 and ODS-NEG-001. Functional tests shall confirm that an SOA in the answer section of a NOTIFY does not alter the server's held SOA serial without an independent successful SOA poll.

*Status.* Reviewed v0.6 (architectural invariants audit closure).

## 3.2 Memory-Resident Zone Data

**ODS-INV-002 — Memory-Resident Zone Data**

*Statement.* All zone data served by the server MUST reside in process memory. From process start completion (after socket binding per ODS-IF-NET-004) through process termination, the query-serving path — defined as the code paths from network socket receive to network socket send for any DNS query — MUST NOT perform filesystem I/O against any path outside `/proc/self/*` and similar process-introspection pseudo-files used for metrics collection per §5.6.

Configuration file reading and secret-file reading per ODS-IF-CONF-004 occur only during the startup phase, before query handling begins; these are not within scope of the prohibition. Log emission to stdout and stderr (per ODS-IF-LOG-001) is file-descriptor I/O directed at standard streams, not filesystem path I/O against zone storage; this is permitted.

*Rationale.* Eliminates an entire class of latency variability and a category of operational complexity. Removes the possibility of inconsistent on-disk state outliving an operational error. Permits deployment on read-only root filesystems and on scratch container images.

*Implications.* Zone data is not memory-mapped from disk. There is no on-disk zone cache. There is no swap-eligible zone storage in the design — operators are responsible for ensuring sufficient RAM (per ODS-NFR-RES-003) and for disabling swap where production performance requires it. Configuration parsing is a startup-only filesystem operation; once startup completes, the query path is filesystem-free.

*Verification.* Code review shall confirm that the query path does not invoke filesystem operations against zone-storage paths. System-call tracing (`strace` with `--syscall=openat,read,write,pread,pwrite` or equivalent) during steady-state query serving shall confirm the absence of filesystem activity outside of operator-controlled logging and `/proc/self/*` introspection.

*Status.* Reviewed v0.6 (architectural invariants audit closure).

## 3.3 Atomic Zone Refresh

**ODS-INV-003 — Atomic Zone Refresh**

*Statement.* Every query against a zone MUST be answered from a single, internally consistent version of that zone's data — a single SOA generation with all RRsets reflecting that generation's content. Refresh transitions between zone versions MUST be atomic from the perspective of any concurrent query handler. A multi-delta IXFR transfer MAY result in multiple distinct atomic transitions (one per applied difference sequence per ODS-FR-IXFR-008 and ODS-FR-IXFR-010), each transitioning the zone to a self-consistent SOA generation; but no query MAY observe a torn read within any single transition (i.e., no query MAY see records from two SOA generations co-existing in a response).

*Rationale.* Partial visibility of an in-progress zone transfer produces inconsistent answers — the canonical pathology being a stale CNAME pointing at a removed target. Atomic refresh guarantees consistency from the client's perspective and is a precondition for the secondary's correctness as an authoritative source. The multi-transition allowance for multi-delta IXFR aligns with RFC 1995 semantics, where each difference sequence represents one SOA generation in the primary's history.

*Implications.* The zone store must support a publish-after-load model: a new zone version is fully constructed before it is made visible to query handlers, and the transition from old version to new version is observed atomically by all handlers. The implementation mechanism is an architectural choice recorded in the Architecture Document, but the property must hold. For multi-delta IXFR, the implementation MAY perform N sequential atomic transitions for N difference sequences, OR MAY accumulate the deltas and perform a single atomic transition to the final state; both are conformant.

*Verification.* Concurrent test harnesses shall issue queries continuously during simulated zone refresh (AXFR and IXFR, single-delta and multi-delta) and shall confirm that no response contains records from two SOA generations of the zone. Stress tests under load shall confirm the absence of torn reads. The multi-delta IXFR semantics — observable as monotonically increasing SOA serials in successive query responses during the transfer — shall be confirmed in dedicated tests.

*Status.* Reviewed v0.6 (architectural invariants audit closure).

## 3.4 No Persistent Operational State

**ODS-INV-004 — No Persistent Operational State**

*Statement.* The server MUST NOT write operational state — zone data, transfer history, query statistics, configuration, or any data intended to survive process restart — to persistent storage. The server MUST NOT write to any filesystem path other than standard output and standard error (per ODS-IF-LOG-001).

*Rationale.* A secondary's authoritative state is defined entirely by what the primary has most recently delivered. Persistence of any operational state introduces the possibility of restart with stale or inconsistent data, defeating the simplicity of the cold-start model. The combination of this invariant with INV-002 yields a server whose entire state is reconstructible from the orchestrator's configuration plus the primaries' current data.

*Implications.* Every startup performs full zone acquisition from the configured primaries. There is no on-disk SOA serial cache to short-circuit initial transfer. Log output emitted to stdout and stderr is not "persistent state" in the sense of this invariant — it is observable output, owned by whatever process collects it downstream. Metrics endpoints, if provided, expose live counters held in memory; they are not snapshots of disk-backed state.

The server MUST be runnable with both the root filesystem and `/tmp` (and any other writable filesystem mount within the container) absent or mounted read-only. Where third-party Rust crates depended on by the server (per ODS-NFR-SEC-006) attempt to use `/tmp` or `TMPDIR` for transient files, the server's invocation environment MUST be capable of operating without such a writable filesystem — either the dependency MUST fall back to in-memory equivalents, or the dependency MUST NOT be used on the runtime hot path. Crash dumps and core files generated by the kernel as a consequence of process termination are an operating-system mechanism outside the server's volitional control; they are not a violation of this invariant.

*Verification.* Code review shall confirm that no write operations target the filesystem outside of standard output and standard error. The published container image shall be runnable with a read-only root filesystem AND with no `/tmp` mount (or with `/tmp` mounted read-only), confirming that no dependency forces writable filesystem requirements on the runtime hot path. Strace-based filesystem-write tracing during steady-state operation shall confirm the same.

*Status.* Reviewed v0.6 (architectural invariants audit closure).

## 3.5 Static Configuration

**ODS-INV-005 — Static Configuration**

*Statement.* All configuration MUST be supplied at process startup via the configuration file (per ODS-IF-CONF-001), via environment variables (per ODS-IF-CONF-006 and ODS-IF-CONF-012), or both; where both are supplied for the same parameter, environment variables take precedence. The server MUST NOT re-read or otherwise alter its configuration during operation. Configuration changes are applied only by process restart.

*Rationale.* Eliminates an entire category of reload-related defects and consistency questions ("is the running state consistent with the file on disk?"). Aligns with container-native operational models, where configuration changes are expressed as new deployments rather than in-place mutation. Reduces the operational interface surface — there is no SIGHUP-driven reload, no administrative socket, no runtime configuration API.

*Implications.* No SIGHUP handler for configuration reload (per ODS-IF-CONF-007 and ODS-IF-SIG-003). No partial-reload semantics to specify or test. The orchestrator (or operator) is responsible for restarting the process to apply configuration changes, with the graceful-shutdown behaviour required by ODS-NFR-REL-001 supporting rolling restart deployment patterns.

The §4.20 Zone Provisioning subsystem operates within this invariant by isolating the statically configured sources from the derived zone set: explicit `[[zones]]`, catalog-zone coordinates (apex name, primary IPs, TSIG key reference), and inherited member transfer policy are statically configured per ODS-IF-CONF-013 and are not altered during process lifetime. For `[[catalog_zones]]`, the resulting member-zone set itself is runtime-derived state (enumerated below), updated whenever the catalog zone is successfully transferred or incrementally updated.

"Configuration" in this invariant refers exclusively to the parameters supplied at startup per the cited sources, governing the server's policies, bindings, and operating thresholds. **Runtime-derived state** — operational data generated by the server during its lifetime — is not "configuration" in the sense of this invariant; such state evolves during operation and is intentionally not persisted (per ODS-INV-004). Examples of runtime-derived state explicitly outside the scope of this invariant include:

- the DNS Cookie secret of ODS-FR-COOKIE-004 (generated fresh at each process start, held in memory for the process lifetime, zeroed at termination per ODS-NFR-SEC-003);
- RRL accounting tables (per §4.17, dynamic);
- TSIG counters, query counters, transfer-session counters (per §5.6);
- in-flight TCP connections and their per-connection state;
- the zone state machine's current state for each zone (per §4.16);
- the in-memory zone store contents (per §3.2; updated by zone transfer per §3.1);
- for `[[catalog_zones]]` (per §4.20.2 and ODS-FR-PROV-002), the set of member zones derived from the catalog zone's contents, including additions and removals occurring during process lifetime as the catalog zone is updated by the primary.

Such state may legitimately change during process lifetime without violating this invariant.

*Verification.* Code review shall confirm that configuration parsing occurs once during startup and that no code path re-reads configuration sources thereafter (no file watchers on the configuration file, no periodic re-evaluation of environment variables). Behavioural tests shall confirm that signals other than SIGTERM and SIGINT produce no configuration effect. For `[[catalog_zones]]` (§4.20.2), code review shall confirm that the catalog transfer pathway alters only the runtime member-zone set and never re-reads or alters the static configuration sources.

*Status.* Reviewed v0.9 (catalog-zone runtime-state clarification).

## 3.6 Memory Safety Discipline

**ODS-INV-006 — Memory Safety Discipline**

*Statement.* **First-party** Rust code authored by this project MUST use Rust's safe subset for all code that processes data received from the network — including but not limited to DNS query parsing, EDNS option parsing, RR-type-specific decoders, zone transfer payload parsing, NOTIFY message handling, and TSIG verification input handling. Any use of `unsafe` blocks in first-party code MUST be accompanied by a comment in the source code stating the reason the block is necessary and the invariants on which its soundness depends (per ODS-NFR-MAINT-003).

Third-party dependencies (Rust crates depended on by the server per ODS-NFR-SEC-006) MAY contain `unsafe` blocks where they are required for performance, FFI to system libraries, or interfacing with cryptographic primitives in lower-level C; such dependencies are selected and reviewed under ODS-NFR-SEC-006. The intent of this invariant is the discipline applied to code authored by this project, not a wholesale prohibition of well-reviewed third-party libraries that contain `unsafe` internally.

*Rationale.* The principal security argument for this project — that it is meaningfully safer than C-based alternatives — depends on actually exercising Rust's safety guarantees in the parts of the code that handle untrusted input. Unconstrained `unsafe` usage in first-party code would erode this guarantee. Confining `unsafe` to justified, documented locations preserves the guarantee while permitting unavoidable interfaces to the operating system or to FFI where they arise.

*Implications.* Wire-format parsers across all protocols supported by the server are implemented in safe Rust at the first-party level. Any `unsafe` block in first-party code is reviewable as a finite, documented exception. The set of `unsafe` blocks in first-party code is enumerable by static tooling and forms part of the security review during each release. Dependency-level `unsafe` is reviewed separately as part of crate adoption decisions.

**Panic discipline.** Safe Rust prevents memory-safety bugs but does not prevent runtime panics. The query-serving path (network input → response output) MUST be designed and tested to be panic-free on any input: malformed queries MUST be handled with explicit error responses per §4.1 (FORMERR, NOTIMP, REFUSED as appropriate), never with `unwrap()`, `expect()`, panicking integer-overflow constructs, or other panic-inducing constructs reachable from untrusted input. Panics in non-query background tasks (e.g., a Tokio task processing a transfer session) MUST be isolated to the affected task via `catch_unwind` at task spawn boundaries, MUST NOT propagate to whole-process termination. The fuzz testing of ODS-NFR-SEC-002 is the principal verification mechanism for panic-freedom on untrusted input.

*Verification.* Static analysis (`cargo geiger` or equivalent) shall enumerate all `unsafe` usage in the first-party codebase and in its transitive dependencies. Each `unsafe` block in first-party code shall be reviewed during code review and approved against its documented justification per ODS-NFR-MAINT-003. Fuzz testing (`cargo-fuzz` per ODS-NFR-SEC-002) against the wire-format parsers shall serve as ongoing evidence that the safe-Rust parsers handle malformed input correctly without panic. Code-review checks confirm `catch_unwind` is in place at Tokio task spawn boundaries for non-query tasks.

*Status.* Reviewed v0.6 (architectural invariants audit closure).

## 3.7 Authoritative-Only Response Composition

**ODS-INV-007 — Authoritative-Only Response Composition**

*Statement.* Every record present in any section (answer, authority, additional) of a DNS response emitted by this server MUST originate from one of the following sources:

(a) the in-memory zone store of an authoritatively-served zone, populated per ODS-INV-001 via zone transfer from a configured primary;

(b) server-generated synthetic records constructed in the response-composition path, namely: the OPT pseudo-RR per §4.11 (including all EDNS options carried in its RDATA — NSID, COOKIE, padding, and any other EDNS option supported in MVP scope); the TSIG RR per §4.9 for outbound message signing per ODS-FR-TSIG-014; the empty owner-name SOA appended in negative responses per §4.3.

The server MUST NOT perform any external DNS lookup (no recursion, no upstream forwarding, no resolver functionality), MUST NOT maintain any cache of records sourced from outside its zones (no response cache, no negative cache of upstream answers, no glue cache external to zone data), and MUST NOT compose response content from any source other than (a) and (b) above.

*Rationale.* The server is positioned as an authoritative source for a fixed, configured set of zones; it serves only what its primaries deliver via zone transfer. Any other response composition would violate the secondary-only architectural posture and would introduce a category of correctness and security concerns the project explicitly excludes (cache-poisoning attack surface, upstream-failure cascade, name-resolution attack vectors). This invariant elevates to foundational status what was previously stated piecewise across ODS-NEG-007 (no recursion), ODS-NEG-008 (no upstream forwarding), and ODS-FR-QRY-020 (no out-of-zone-store records in responses).

*Implications.* No DNS resolver functionality at any layer. No `/etc/resolv.conf` consultation. No glue-record fetching beyond what is delivered in-bailiwick via zone transfer (glue records in responses are sourced exclusively from authoritative zone data per §4.2). No response cache. No "stub resolver" component for name resolution. No forwarder mode of any kind. The implication for the §4.18 negative requirements is that ODS-NEG-007 and ODS-NEG-008 are not standalone constraints but are direct consequences of this invariant; they are retained in §4.18 for traceability of negative requirements, but their normative weight derives from ODS-INV-007.

*Verification.* Static analysis confirming that the response-composition code paths read only from the zone store and the server's own synthetic generators. Static analysis confirming the absence of `resolv.conf` parsing, DNS-client libraries (other than for zone-transfer purposes per §4.6 and §4.7), and any recursive resolver crate (e.g., `trust-dns-resolver` is NOT permitted; `trust-dns-client` in client-only mode for AXFR/IXFR IS permitted). Functional tests confirming that out-of-zone names trigger REFUSED per §4.1 without any external lookup attempt observable via packet capture.

*Status.* Introduced v0.6 (architectural invariants audit closure; foundational status elevated from ODS-NEG-007, ODS-NEG-008, ODS-FR-QRY-020).

## 3.8 Single-Process Architecture

**ODS-INV-008 — Single-Process Architecture**

*Statement.* The server MUST run as a single OS process. The server MUST NOT invoke `fork(2)`, `vfork(2)`, `clone(2)` with new-process semantics (`CLONE_VM` not set, etc.), or any function of the `exec*(3)` family (`execve`, `execvp`, `execle`, etc.). The server MUST NOT invoke `posix_spawn(3)`, `system(3)`, `popen(3)`, or any equivalent subprocess-creation facility. 

Thread creation within the process — POSIX threads via `pthread_create`, Tokio runtime worker threads, blocking-IO threadpool threads — is permitted and expected; this invariant prohibits process-level creation, not thread-level concurrency.

*Rationale.* A single-process model has a smaller security surface: no shell to inject into via `exec`, no inter-process privilege boundary to enforce, no IPC channel to authenticate or authorise, no helper-binary path to spoof. The principal worker scaling model in this project is async I/O on a Tokio runtime with a bounded worker threadpool, not multi-process scaling. Single-process operation also simplifies observability (single PID, single metrics endpoint, single signal target per §6.5) and orchestrator interaction (one container, one process per container, idiomatic Kubernetes pod model).

*Implications.* No subprocess invocation for any purpose: no `std::process::Command::spawn` or equivalent calls in first-party code (excluding test code, which MAY spawn helpers for integration tests). No shelling out to external DNS tools (`dig`, `drill`, `kdig`) at runtime; no calling external utilities for cryptographic operations (all cryptography via in-process Rust crates per ODS-NFR-SEC-006). Privileged port binding (53, 853) is achieved via Linux capabilities (`CAP_NET_BIND_SERVICE` per ODS-NFR-SEC-004) or socket activation from a supervisor (also single-process from the server's perspective), not via setuid binaries or privilege-separated worker processes. The server does not implement any "supervisor and worker" pattern; failures are handled by orchestrator-level restart, not by in-process subprocess respawn.

*Verification.* Static analysis confirming no `std::process::Command`, `nix::unistd::fork`, or equivalent calls in first-party code outside the test tree. Runtime inspection of process tree (`pstree`, `ps --forest`, or `/proc/<pid>/task/`) during sustained operation confirming single PID with thread-only concurrency. CI-integrated grep for prohibited APIs.

*Status.* Introduced v0.6 (architectural invariants audit closure).

## 3.9 Static Composition; No Runtime Code Loading

**ODS-INV-009 — Static Composition; No Runtime Code Loading**

*Statement.* The server binary MUST be a statically composed Rust binary, produced by the deterministic build process of ODS-NFR-MAINT-005. The server MUST NOT load executable code at runtime from any source: no plugin mechanism via `dlopen(3)` or platform equivalents, no embedded scripting interpreter (Lua, JavaScript, Python, Wasm interpreter, etc.), no LLVM JIT or other just-in-time compilation, no eBPF-program loading driven by configuration or runtime input, no other code-from-data execution.

*Rationale.* Runtime code loading is a substantial security surface: a compromised plugin or scripted policy escapes the static review process, defeats the reproducible-build guarantees of ODS-NFR-MAINT-005 and the signed-release verification of ODS-NFR-MAINT-008, complicates supply-chain audit, and produces a runtime behaviour that the operator cannot fully verify from the binary alone. The project's minimal-codebase target (ODS-NFR-MAINT-001), defensive engineering posture (ODS-NFR-SEC-001 through ODS-NFR-SEC-007), and reproducibility commitments (ODS-NFR-MAINT-005, ODS-NFR-MAINT-008) presume that the entire executable surface is the binary that comes out of `cargo build` — nothing additional is composed at runtime.

*Implications.* No "policy as code" mechanism for RRL, ACLs, configuration validation, or any other operational decision; all such policies are expressed in the static TOML configuration schema per §6.2. The configuration file is data, parsed by the server; it does not contain executable expressions, embedded scripts, or any code-bearing construct. Any future post-MVP XDP/eBPF integration (Appendix C.6.1) MUST compile the kernel-side eBPF program at server build time and embed it in the server binary as compiled bytecode; runtime loading from external configuration of an eBPF program is forbidden. No "scriptable response transformation" feature is or will be added in this server's design. The configuration validation of ODS-IF-CONF-005 is implemented via Rust code paths, not via a runtime-evaluated rule language.

The published Linux binary target is `x86_64-unknown-linux-musl` and MUST be verified as static (`ldd` reports "not a dynamic executable" or equivalent). Developer and distribution builds that use another target MAY dynamically link to the host platform's standard C runtime libraries, but those builds are not the release portability artifact and MUST NOT be described as scratch-compatible unless binary inspection proves the claim.

*Verification.* Static analysis confirming no `dlopen` family calls, no `Mmap::map_executable` patterns, and no embedded interpreter crates (`mlua`, `boa_engine`, `rusty_v8`, `wasmtime`, `wasmer`, etc.) in the dependency tree. Release binary inspection (`ldd`, `objdump -p`, or equivalent) confirming the published musl artifact has no runtime shared-library dependencies. CI-integrated dependency-tree audit at each release confirming no new code-loading capability is introduced.

*Status.* Introduced v0.6 (architectural invariants audit closure).

---

# 4. Functional Requirements

This section specifies the server's functional behaviour. Requirements are grouped by protocol concern. Functional requirement subsections allocate an area code per the scheme of §1.4.3; §4.18 is the negative-requirement subsection and uses the `ODS-NEG-NNN` category without an AREA component.


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

**ODS-FR-CORE-029.** In any error response (FORMERR, NOTIMP, REFUSED, SERVFAIL), the server SHOULD echo the question section as received if it was successfully parsed, with QDCOUNT = 1 in the response header. Where the question section could not be parsed (parse failure before the question section was successfully extracted — for example, oversized labels per ODS-FR-CORE-007, compression-loop in QNAME per ODS-FR-CORE-008, or QDCOUNT > 1), the server MUST emit the response with QDCOUNT = 0 and no records in the question section.
*Source.* RFC 1035 §4.1.1; defensive composition for malformed inputs where the question content cannot be safely reproduced.
*Note.* This is the explicit specification of the case left implicit by RFC 1035 §4.1.1 (which presupposes a parseable question). Setting QDCOUNT = 0 in this case is the dominant operational practice among existing implementations and avoids the risk of returning a malformed echoed question to the client. Earlier draft snapshots used a suffixed CORE label for this requirement; that label is historical only and must not be used for new traceability.
*Verification.* Conformance tests including queries that fail parsing at the question-section stage; the resulting FORMERR responses MUST exhibit QDCOUNT = 0 with an empty question section.

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

**ODS-FR-CORE-014.** In responses, the server MUST set the AA bit to 1 when the answer is authoritative for the queried name (a direct match, NODATA, NXDOMAIN, or wildcard synthesis within a served zone) or when returning an opt-in NOERROR response for a recognised CHAOS-class self-identification query per ODS-FR-CHAS-001 and ODS-FR-CHAS-002. The server MUST set the AA bit to 0 for referral responses to delegated child zones. For all other response categories — REFUSED (per ODS-FR-CORE-018, ODS-FR-CORE-019, ODS-FR-CHAS-001, ODS-FR-CHAS-002, ODS-FR-CHAS-003, and ODS-FR-CHAS-004), FORMERR (per ODS-FR-CORE-006, ODS-FR-CORE-007, ODS-FR-CORE-008), NOTIMP (per ODS-FR-CORE-005, ODS-FR-QRY-008), SERVFAIL (per ODS-FR-QRY-021, ODS-FR-QRY-022), NOTAUTH (per ODS-FR-TSIG-013), and any other response not falling into the authoritative-positive, authoritative-negative, or recognised CHAOS self-identification categories above — the AA bit MUST be set to 0.
*Source.* RFC 1034 §4.3.1; RFC 1035 §4.1.1; defensive interpretation for error categories not explicitly addressed by RFC 1035.
*Verification.* Wire-format inspection across answer categories including referrals, REFUSED, FORMERR, NOTIMP, SERVFAIL, and NOTAUTH responses.

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

**ODS-FR-CORE-018.** Except for the CHAOS-class self-identification surface specified in §4.21, the server MUST respond with RCODE = 5 (REFUSED) to queries with QCLASS values other than IN or ANY when no zone of the requested class is served.
*Source.* RFC 1035 §3.2.4. REFUSED is selected over NOTAUTH because the server is not authoritative for any zone of the requested class.
*Note.* CHAOS-class `TXT` queries for the explicitly enumerated names in ODS-FR-CHAS-001 and ODS-FR-CHAS-002 are handled by the §4.21 meta-query path. All other non-IN/non-ANY class queries, including unsupported CHAOS names and non-TXT CHAOS queries per ODS-FR-CHAS-003 and ODS-FR-CHAS-004, remain refused.
*Verification.* Lookup tests with QCLASS = CH, HS, NONE, and reserved values, including the traditional CH-class informational queries.

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
*Note.* If the wildcard owner name (e.g., `*.example.com`) exists in the zone but carries no RRset of the queried QTYPE, the wildcard match still applies and the result is a NODATA response per ODS-FR-CORE-022 with the SOA of the containing zone in the authority section. If the wildcard owner name carries no RRsets at all (an empty wildcard non-terminal), it is treated as any other empty non-terminal per ODS-FR-QRY-016 — the wildcard does not synthesise, and the response is NODATA at the QNAME.
*Verification.* Lookup tests against zones containing wildcards, covering the edge cases enumerated in RFC 4592 (empty non-terminal occlusion, wildcards at apex, wildcards beneath delegations), and the empty-wildcard-owner-name case.

**ODS-FR-CORE-025.** Where the QNAME falls within a child zone delegated from a served zone (the QNAME is at or below an NS RRset within the served zone that is not the zone apex), the server MUST return a referral response: empty answer section, AA = 0, RCODE = 0 (NOERROR), the child zone's NS RRset in the authority section, and any associated A and AAAA glue records from the served zone in the additional section.
*Source.* RFC 1034 §4.3.2; RFC 1035 §6.2.4; RFC 4035 for DNSSEC-related referral additions (see §4.13).
*Verification.* Lookup tests against zones containing delegations, with and without glue.

### RRset semantics

**ODS-FR-CORE-026.** Except for RRSIG records, the server MUST treat all resource records sharing owner name, class, and type as a single RRset and MUST return all members of that RRset together when the RRset is the subject of a positive answer. The server MUST NOT return a proper subset of an RRset in the answer section of a positive response.
*Source.* RFC 2181 §5; RFC 4035 §2.2; RFC 4034 §3.
*Note.* RRSIG records are handled by DNSSEC-specific rules: each RRSIG covers an RRset identified by its Type Covered field, and multiple RRSIG records at the same owner name may cover different RRsets. They are therefore matched to the covered RRsets per ODS-FR-DNSSEC-003 rather than treated as one ordinary owner/class/type RRset.
*Verification.* Lookup tests confirming RRset integrity in responses, including responses near the UDP message size boundary (see §4.11 for EDNS interactions), plus DNSSEC tests confirming RRSIG selection by Type Covered.

**ODS-FR-CORE-027.** Except for RRSIG records, the server MUST apply a single TTL value to all members of an RRset served from its in-memory zone store. Where a zone transfer delivers an RRset whose members carry differing TTLs, the server MUST adopt the lowest TTL among them for the RRset, in accordance with RFC 2181 §5.2, and MUST emit a warning-level log entry recording the inconsistency.
*Source.* RFC 2181 §5.2; RFC 4035 §2.2; RFC 4034 §3.
*Note.* RFC 2181 deprecates non-uniform TTLs within an RRset; the secondary's behaviour is defensive against a non-compliant primary. RRSIG TTL handling follows the RFC 4035 §2.2 exception: RRSIG records do not form ordinary RRsets, and their TTL values at a common owner name do not follow normal RRset TTL rules. RFC 4034 §3.1.4 supplies the covered-RRset Original TTL field used by validators.
*Verification.* Zone-transfer tests delivering non-uniform TTLs; log inspection; DNSSEC transfer/serving tests with RRSIG records covering RRsets with different TTLs at the same owner name.

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

**ODS-FR-QRY-002.** The processing of a query MUST NOT alter the served zone data nor any operational state observable to other queries, with the sole exceptions of statistics counters (ODS-FR-QRY-024) and rate-limit accounting state (§4.17).
*Source.* RFC 1034 §3.7; ODS-INV-003.
*Verification.* Concurrent query tests under steady-state zone conditions; zone data identity verified before and after.

### ANY-query handling

**ODS-FR-QRY-003.** The server MUST support an "any-response" configuration option taking the values "full" and "minimal", controlling the response policy for queries with QTYPE = 255 (ANY).
*Source.* RFC 8482.
*Verification.* Configuration round-trip tests; behavioural tests with each setting active.

**ODS-FR-QRY-004.** In "full" any-response mode, for QTYPE = 255 (ANY) queries against a name with at least one RRset present, the server MUST return all RRsets present at the QNAME in the answer section, applying the standard lookup semantics of §4.1.
*Source.* RFC 1034 §3.7; RFC 1035 §3.2.5.
*Verification.* Lookup tests in "full" mode against names with multiple RRsets.

**ODS-FR-QRY-005.** In "minimal" any-response mode, for QTYPE = 255 (ANY) queries against a name with at least one RRset present, the server MUST return a single RRset selected from those present at the QNAME, per RFC 8482 §4.1. The selection algorithm MUST be the following deterministic procedure:

- If an RRset with type CNAME is present at the QNAME, return that RRset (CNAME owner names by definition have no other types of co-located data per ODS-FR-RR-005, so this case is exclusive).
- Otherwise, return the RRset whose type code is the numerically smallest among those present at the QNAME, with the exception that RRSIG, NSEC, and NSEC3 records — being DNSSEC supporting data, not first-class application data — are excluded from consideration unless they are the only types present at the QNAME.

This procedure produces a stable, predictable selection for a given zone state, is independent of insertion order or in-memory representation, and aligns with the operational preference of returning the most fundamental data type at a name (A < AAAA < MX < ... by IANA numeric assignment) when present.
*Source.* RFC 8482 §4.1.
*Verification.* Repeated identical queries in "minimal" mode MUST produce identical selected RRsets given an unchanged zone; the selection MUST follow the algorithm above against a test corpus covering names with various type combinations including CNAME-only, A+AAAA+MX+TXT, and DNSSEC-only names.

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

**ODS-FR-QRY-012.** The server MUST terminate CNAME chain resolution at a configurable maximum chain length, with a default of 8 CNAME records. Where this limit is reached before the chain terminates at a non-CNAME RRset within the served zones, the server MUST emit the response with RCODE = 2 (SERVFAIL), AA = 1 (the partial chain consists of authoritative records), an empty authority section (no SOA, as the failure is not an authoritative negative response), and the partial CNAME chain retained in the answer section up to the limit. The event MUST be logged at warning level recording at minimum the original QNAME, the zone, and the truncation reason.
*Source.* Defence against pathological zone configurations; consistent with operational practice in NSD, Knot, and BIND.
*Note.* SERVFAIL is selected over partial NOERROR to make the failure unambiguous to the client resolver: a NOERROR response with an apparently complete chain might be cached as a partial result, whereas SERVFAIL signals that the response is unusable and triggers normal resolver retry/failover behaviour.
*Verification.* Lookup tests against zones with CNAME chains longer than the configured limit; wire-format inspection confirming SERVFAIL, AA=1, and partial chain in answer; log inspection.

**ODS-FR-QRY-013.** The server MUST detect CNAME loops (a chain in which any target name has already been included in the answer section of the current response) and MUST terminate processing of the chain at the point of detection. The emitted response MUST follow the same composition rules as ODS-FR-QRY-012: RCODE = 2 (SERVFAIL), AA = 1, empty authority section, partial chain in the answer section up to (but not including) the looping repetition. The event MUST be logged at warning level recording the original QNAME, the zone, and the looping target name.
*Source.* RFC 1034 §3.6.2 implicit; defence against zone misconfiguration.
*Verification.* Lookup tests against zones with cyclic CNAME chains; wire-format inspection confirming SERVFAIL with partial chain.

### DNAME handling

**ODS-FR-QRY-014.** Where the QNAME falls strictly beneath a name carrying a DNAME RRset in the served zone (and is not the DNAME owner name itself), the server MUST include the DNAME record in the answer section and MUST synthesise a CNAME record per RFC 6672 §3.2 mapping the original QNAME to a name constructed by substituting the DNAME target for the DNAME owner in the QNAME. If the resulting synthesised name exceeds the 255-octet domain-name length limit, the server MUST follow ODS-FR-QRY-025 below.
*Source.* RFC 6672 §3.
*Verification.* Lookup tests against zones containing DNAME records, including the edge cases of RFC 6672 §3.3 (DNAME at apex, DNAME above a delegation, name-length overflow on synthesis).

**ODS-FR-QRY-015.** After CNAME synthesis from a DNAME, the server MUST proceed with CNAME chain resolution per ODS-FR-QRY-010 through ODS-FR-QRY-013, treating the synthesised CNAME as if it had been present in the zone authoritatively.
*Source.* RFC 6672 §3.
*Verification.* Lookup tests including DNAME-to-CNAME chains terminating both within and outside served zones.

**ODS-FR-QRY-025.** Where DNAME synthesis under ODS-FR-QRY-014 would produce a target name whose wire-format encoding exceeds 255 octets (the domain-name length limit of RFC 1035 §2.3.4), the server MUST respond with RCODE = 6 (YXDOMAIN) per RFC 6672 §5.3.1. The response MUST include the DNAME record itself in the answer section (since the DNAME RRset's existence has been determined and is correctly returned) but MUST NOT include any synthesised CNAME for the overflowing QNAME. The synthesised name is not constructed and is not used.
*Source.* RFC 6672 §5.3.1; RFC 1035 §2.3.4.
*Note.* RCODE = 6 was assigned by RFC 2136 for the dynamic-update setting where a name "exists when it should not"; RFC 6672 §5.3.1 reuses the same RCODE value for the present semantic of "QNAME would exceed 255 octets after DNAME substitution". The reuse is normative.
*Verification.* Lookup tests with DNAME owner names whose targets, when substituted into the QNAME, exceed 255 octets; verify YXDOMAIN response, DNAME RR included in answer, no CNAME synthesised. *Added in v0.9.*

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

**ODS-FR-QRY-024.** The server MUST maintain in-memory counters for: queries received, queries answered with each RCODE value emitted, queries terminated by CNAME-chain limit, queries terminated by CNAME-loop detection, and queries truncated due to message-size limits (see §4.12). These counters MUST be maintained both globally (across all zones) and per-zone for zone-scoped metrics (query count, RCODE distribution). The exposure of these counters to external observers is specified in §5.6 and §6.4.
*Source.* Operational requirement; informed by RFC 8906 response-behavior testing guidance.
*Note.* Per-zone disaggregation is essential for production monitoring; an operator serving many zones must be able to distinguish per-zone traffic patterns to detect anomalies, capacity-plan, and diagnose incidents. The implementation MUST expose per-zone counters as labels on the corresponding metric series (e.g., Prometheus `zone="example.com"` label) rather than as separate top-level metric names.
*Verification.* Inspection of counter values under controlled query load distributed across multiple zones; verify both global aggregates and per-zone disaggregation.

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

**ODS-FR-URR-009.** The server MUST reject a zone transfer containing any record whose RR TYPE field carries one of the following values: the reserved values 0 and 65535; the pseudo-RR type codes OPT (41), TKEY (249), TSIG (250); or the query meta-type codes AXFR (252), IXFR (251), MAILB (253), MAILA (254), ANY (255). Type values in other ranges — including the IANA Private Use range and type codes not yet assigned at the time of the server's implementation — MUST be accepted and processed under the requirements of this subsection.
*Source.* RFC 6895 §3.1; IANA "Resource Record (RR) TYPEs" registry; RFC 6891 (OPT is per-message context, not zone content); RFC 8945 (TSIG is per-message authentication); RFC 2930 (TKEY is per-message key establishment).
*Note.* The pseudo-RR and meta-type codes have no defined semantics as stored zone data; their presence in a zone transfer indicates either a misconfigured primary, a corrupted transfer, or a malicious peer attempting to inject records that would be misinterpreted by query-handling code. Rejecting the transfer surfaces the problem to the operator. The reserved values 0 and 65535 are likewise prohibited by IANA. Private Use codes are explicitly permitted by the IANA registry and are passed through opaquely.
*Verification.* Zone-transfer tests injecting each prohibited type value; the transfer MUST be rejected and prior zone state preserved.

## 4.5 Anti-Spoofing Measures

This subsection specifies the server's measures to resist spoofed traffic, derived from RFC 5452. The principal exposure of a secondary-only server is on its *outbound* query path — when the server issues SOA poll queries, IXFR queries, or other queries toward configured primaries. RFC 5452 measures (QID randomisation, source port randomisation, strict response matching) constitute the baseline defence on this path; TSIG (§4.9), where configured, provides a substantially stronger cryptographic defence and supersedes these baseline measures in effectiveness.

Adjacent anti-spoofing concerns are specified separately: Response Rate Limiting in §4.17, TSIG authentication in §4.9, NOTIFY source validation in §4.8, transfer-peer validation in §4.6 and §4.7, response size minimisation in §4.11, **DNS Cookies in §4.19** (which provides lightweight source-address confirmation for the inbound query path against off-path spoofers). Network-layer source-address filtering (BCP 38 / RFC 2827) is the responsibility of the operator and the network in which the server is deployed; it is not within the server's scope.

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

**ODS-FR-AXFR-016.** Where a zone is configured with more than one primary server, the server MUST select an initial primary by uniform-random choice across the configured list, performed once per process per zone at startup, and MUST attempt subsequent primaries in a stable rotation derived from the initial selection (i.e., process N starts with primary K, then proceeds K+1, K+2, ... modulo list length on failure). On failure to connect, on connection abort prior to successful completion, or on receipt of an error RCODE per ODS-FR-AXFR-020, the server MUST proceed to the next primary in the rotation. After exhausting all configured primaries without successful transfer, the server MUST follow the retry semantics specified in §4.16.
*Source.* RFC 1035 §4.3; operational requirement.
*Note.* Per-process randomised initial selection spreads transfer load across primaries when many secondaries share the same configured primary list (avoiding thundering-herd against the first-listed primary), while the stable rotation within a single process keeps logs and metrics interpretable. The randomised seed MUST persist for the process lifetime per ODS-INV-005 and MUST NOT change between transfer attempts within the same process.
*Verification.* Multi-primary tests with various failure injection patterns; statistical analysis confirming that across many process instances the initial-primary distribution is uniform over the configured list.

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

**ODS-FR-AXFR-024.** The server MUST enforce a configurable maximum cumulative ingestion size per AXFR session, measured as the total number of octets of zone data received (excluding TCP framing and TSIG overhead). The default maximum MUST be 4 gibibytes (4 × 2³⁰ octets). When the ingestion size exceeds the configured maximum, the AXFR session MUST be aborted per ODS-FR-AXFR-019, with the abort log entry recording the size at which the limit was exceeded. Any partially ingested data MUST be discarded without modifying the in-memory zone store.
*Source.* Defence against memory-exhaustion attacks from a compromised, misconfigured, or hostile primary delivering an unbounded transfer stream.
*Note.* The default limit is generous (a 4 GiB zone in wire format is larger than any operational zone known to the project at this writing), and the limit is per-session rather than across sessions. The configurable nature allows operators of unusually large zones to raise the limit; the existence of the limit prevents an unbounded-allocation DoS even with that flexibility.
*Verification.* AXFR tests with primaries delivering oversized transfer streams; verify abort behaviour, log entry, and memory release after abort.

**ODS-FR-AXFR-025.** The server MAY support an optional, off-by-default, configuration parameter (per ODS-IF-CONF-016) that relaxes the strict out-of-zone owner-name rejection of ODS-FR-AXFR-012 for compatibility with primary configurations that emit traditional out-of-zone glue (typically NS targets and their A/AAAA records that lie outside the transferred zone's apex subtree). Where this option is enabled:
- A and AAAA records whose owner names lie outside the zone apex subtree MUST be retained in the in-memory zone store as glue candidates and MAY be used in the additional section of referral responses per ODS-FR-QRY-017;
- Records of any other type with owner names outside the zone apex subtree MUST continue to cause the AXFR session to be aborted per ODS-FR-AXFR-019;
- Each tolerated out-of-zone A/AAAA record MUST be logged at debug level with the zone name, the owner name, and a structured field `category = "transfer"`, `event = "out_of_zone_glue_accepted"`;
- A configuration warning `out_of_zone_glue_tolerance_enabled` MUST be emitted at startup per ODS-IF-CONF-008 when the option is enabled, to record the deviation from the default strict policy in the operator's observability surface.

Where the option is disabled (default behaviour, equivalent to v0.8 semantics), out-of-zone records of any type cause the AXFR session to be aborted per ODS-FR-AXFR-019 as in v0.8.
*Source.* RFC 1034 §6.2 (the traditional glue concept includes glue that lies outside the transferred zone); operational requirement for interoperability with primary configurations that historically emit such glue.
*Note.* The strict rejection of v0.8 corresponds to RFC 5936 §2.2.4's narrower notion of glue (only records below child-zone delegation points within the transferred zone). The option introduced here permits the broader RFC 1034 §6.2 notion when the operator explicitly opts in. The default remains strict.
*Verification.* AXFR tests with out-of-zone A/AAAA glue records, with the option both disabled and enabled; verify rejection in the former case, acceptance and additional-section inclusion in the latter; verify the configuration warning is emitted and the per-record debug log entries are produced. *Added in v0.9.*

**ODS-FR-AXFR-026.** The transfer ingestion layer MUST reject AXFR or IXFR transfer streams that present more than one DNAME RR at the same owner name within the same zone. RFC 6672 §2.4 prohibits the coexistence of multiple DNAME records at the same owner; this requirement enforces that prohibition at the secondary's ingestion boundary, abandoning the transfer per ODS-FR-AXFR-019 with the abort cause "dname_multiplicity_violation" recorded in the log entry.
*Source.* RFC 6672 §2.4.
*Note.* The same-owner-name DNAME prohibition is distinct from the DNAME chain prohibitions of RFC 6672 §3.3 (DNAMEs in the path between QNAME and the served zone), which are query-time concerns. This requirement is a zone-data structural constraint enforced at ingest. A zone delivered by a misconfigured primary that contains such a structure is rejected at transfer time; the previously-published zone version remains in service per ODS-INV-003.
*Verification.* AXFR and IXFR tests with constructed transfer streams containing multiple DNAME records at the same owner name; verify rejection, log entry, and unchanged previous zone state. *Added in v0.9.*

## 4.7 IXFR Incremental Zone Transfer

This subsection specifies the server's behaviour as an IXFR client. The governing standard is RFC 1995. IXFR transfers only the differences between two versions of a zone and is the preferred refresh mechanism where supported; it falls back to AXFR semantics either within a single response (Mode 2 fallback, RFC 1995 §3) or by retrying at the state-machine level (§4.16) after an IXFR session failure.

Most session-mechanics requirements of §4.6 apply to TCP-based IXFR sessions identically; rather than restate them, this subsection cross-references and specifies only the IXFR-specific additions and divergences.

The area code **IXFR** is allocated.

### Transport and query construction

**ODS-FR-IXFR-001.** The server MUST initiate IXFR queries exclusively over TCP. IXFR queries over UDP MUST NOT be issued. While RFC 1995 §2 permits UDP IXFR transport, modern deployments overwhelmingly use TCP because the diff stream commonly exceeds a single UDP message; supporting only TCP simplifies the implementation surface in accordance with the project's minimal-codebase target (PID §2.2) without operational loss.
*Source.* RFC 1995 §2 (TCP permitted as alternative transport); project simplification decision per the §1.4.5 decision record dated 24 May 2026.
*Note.* Inbound IXFR queries are not in scope (ODS-NEG-005 prohibits outbound transfer serving); this requirement applies only to outbound IXFR queries originated by this server toward configured primaries.
*Verification.* Connection-layer inspection during IXFR initiation; verify TCP-only behaviour. Code review confirming no UDP IXFR code path exists.

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
*Note.* The companion traceability matrix records the duplication so that future edits to §4.6 surface IXFR impact for review.
*Verification.* Per the verification of each referenced AXFR requirement.

**ODS-FR-IXFR-019.** IXFR sessions MUST be subject to the same configurable maximum cumulative ingestion size cap specified in ODS-FR-AXFR-024 (default 4 gibibytes). The limit applies to the total cumulative octets of IXFR response data received within a single session, including both Mode 1 (incremental) and Mode 2 (full-zone fallback) responses.
*Source.* Defence against memory-exhaustion attacks; parallel to ODS-FR-AXFR-024.
*Note.* For Mode 2 IXFR (which delivers AXFR-style content within the IXFR session, per ODS-FR-IXFR-011), the same cap applies. Operators tuning the cap should tune both AXFR-024 and IXFR-019 consistently; in practice both reference the same configuration value.
*Verification.* IXFR tests with primaries delivering oversized response streams.

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

**ODS-FR-NOTIFY-010.** The server MUST emit a log entry at info level for each accepted NOTIFY message, recording at minimum the source IP address, the QNAME, the embedded SOA serial (where present per ODS-FR-NOTIFY-008), and the action taken (refresh signalled, or deduplicated). Discards and rejections MUST be logged at warning level per ODS-FR-NOTIFY-004 and ODS-FR-NOTIFY-005, subject to the rate-limit logging discipline of ODS-FR-NOTIFY-011.
*Source.* Operational requirement.
*Verification.* Log inspection across acceptance, deduplication, and rejection scenarios.

**ODS-FR-NOTIFY-011.** To prevent log flooding under hostile conditions (an attacker spoofing NOTIFY messages from many source IP addresses), the server MUST apply rate-limited logging to unauthorised-source NOTIFY discards (per ODS-FR-NOTIFY-004) and TSIG-failure NOTIFY rejections (per ODS-FR-NOTIFY-005). The discipline is parallel to ODS-FR-RRL-011:
- The first warning-level log entry per (source IP /24 prefix for IPv4, /56 for IPv6, zone) tuple within a configurable rate-limit window (default 60 seconds) MUST be emitted in full.
- Subsequent identical events within the same window MUST be suppressed (counted but not individually logged).
- At the end of each window, an aggregate info-level summary MUST be emitted recording the number of suppressed events per category and the distinct source prefix count.

*Source.* Defence against log-amplification denial-of-service via spoofed NOTIFY traffic; parallel to ODS-FR-RRL-011's anti-flood discipline.
*Note.* The /24 and /56 prefix granularity matches the RRL accounting key convention. Operators investigating sustained NOTIFY-spoofing campaigns can examine the periodic summary to assess scope. The per-zone metric of ODS-FR-QRY-024 also captures discard counts for cross-reference.
*Verification.* Tests injecting bursts of unauthorised NOTIFYs from many simulated source addresses; verify the first per-prefix event is logged, subsequent events are suppressed, and the periodic summary correctly reports aggregates.

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
*Rationale.* SHA-1-based TSIG is retained for interoperability with existing primary deployments and operator configurations. HMAC-MD5 remains prohibited by ODS-FR-TSIG-004.
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
*Source.* Operational requirement; security requirement for key material confidentiality.
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

**ODS-FR-XOT-012.** The server's XoT implementation MUST NOT perform real-time certificate revocation checking via CRL (RFC 5280) or OCSP (RFC 6960) request. The server SHOULD accept and honour OCSP stapled responses (RFC 6961) presented by the primary during the TLS handshake when its TLS implementation supports stapling; where stapling support is unavailable in the underlying TLS implementation, this requirement reduces to no revocation checking.
*Source.* RFC 5280; RFC 6960; RFC 6961; operational pragmatics in zone-transfer paths.
*Rationale.* Real-time CRL or OCSP request from a DNS secondary would introduce an external network dependency on a third-party CA service into the zone-refresh hot path, with associated latency, failure-mode coupling, and privacy implications (the secondary would disclose its primary-certificate fingerprints to the CA on every transfer). OCSP stapling, where supported, provides revocation visibility without these costs because the response travels in-band on the TLS handshake. The explicit declaration here records the security posture so that operators understand the server's revocation behaviour and configure trust anchors and certificate rotation policies accordingly.
*Note.* Operators requiring stricter revocation enforcement should rotate certificates more frequently (short-lived certificates with automated renewal) rather than relying on revocation infrastructure. Decision recorded in Appendix C.5.
*Verification.* Code review confirming no outbound CRL or OCSP request is issued during XoT handshake; tests with OCSP-stapled and non-stapled primary certificates confirming behaviour.

## 4.11 EDNS0

This subsection specifies the server's implementation of Extension Mechanisms for DNS (EDNS0). The governing standards are RFC 6891 (base EDNS0), RFC 7828 (edns-tcp-keepalive option), RFC 7830 (EDNS(0) Padding option), and RFC 8914 (Extended DNS Errors). EDNS0 extends DNS messages to carry larger UDP payloads, signal protocol-version capabilities, and convey extensible options between requestor and responder.

The interaction between EDNS0 UDP payload negotiation and TCP fallback is governed jointly by this subsection and §4.12; the response truncation behaviour (TC bit setting and message construction under size constraints) is specified in §4.12, while the determination of the applicable UDP size ceiling is specified here.

EDNS options not enumerated in this subsection are recognised as unknown and handled per ODS-FR-EDNS-014. EDNS Client Subnet (RFC 7871) and EDNS Expire (RFC 7314) are not in scope per PID Appendix A. The EDNS Expire exclusion is limited to the EDNS option-code mechanism of RFC 7314; it does not remove the ordinary SOA REFRESH/RETRY/EXPIRE, AXFR/IXFR, and NOTIFY behaviours specified in §4.6, §4.7, §4.8, and §4.16. DNS Cookies (RFC 7873) is in scope and specified in §4.19. NSID (RFC 5001) is in scope and specified in ODS-FR-EDNS-016 above. Extended DNS Errors (RFC 8914) are in scope only for the bounded diagnostic profile specified in ODS-FR-EDNS-018.

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

**ODS-FR-EDNS-009.** Where an inbound query contains an OPT RR, the response OPT RR's TTL field MUST copy the query's DO bit exactly. DNSSEC augmentation remains controlled by the query DO bit per §4.13; the response DO bit is not a signal that augmentation records were included.
*Source.* RFC 6840 §5.6; RFC 3225 §3; RFC 6891 §6.1.4.
*Verification.* Wire-format inspection of response OPT RRs for DO = 0 and DO = 1 queries, including signed-zone responses, unsigned-zone responses, REFUSED responses, error responses, and truncation paths.

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

### Non-EDNS UDP responses

**ODS-FR-EDNS-015.** Where an inbound query did not contain an OPT RR (a non-EDNS query), the applied UDP payload size ceiling for the corresponding response MUST be 512 octets, per the unextended limit of RFC 1035 §2.3.4 and §4.2.1. Responses that would exceed this ceiling MUST trigger truncation as specified in §4.12. The server MUST NOT include an OPT RR in responses to non-EDNS queries (per ODS-FR-EDNS-007), and consequently MUST NOT advertise any larger UDP capability to such clients.
*Source.* RFC 1035 §2.3.4, §4.2.1; RFC 6891 §6.2.5 (EDNS-extended buffer sizes apply only when EDNS is in use).
*Note.* This requirement closes the case left implicit by ODS-FR-EDNS-006, which specifies the UDP ceiling as the lesser of (client-advertised, server-configured) — for non-EDNS clients there is no advertised value, and the implicit RFC 1035 default of 512 octets governs. Modern resolvers almost universally use EDNS; non-EDNS traffic on the production query path is rare and typically originates from legacy stub resolvers or monitoring probes.
*Verification.* Tests with non-EDNS queries soliciting responses that would exceed 512 octets; verify TC bit setting and ≤ 512 octet response size.

### Name Server Identifier (NSID, RFC 5001)

**ODS-FR-EDNS-016.** The server MUST recognise the NSID (Name Server Identifier) EDNS option (option code 3) per RFC 5001 in inbound queries. When the option is present in the query's OPT RR with zero-length OPTION-DATA (a request for the server's identifier), and the server is configured with a non-empty NSID value, the server MUST include an NSID option in the response's OPT RR carrying the configured NSID as its OPTION-DATA. When the option is present with non-zero OPTION-DATA in a query, the server MUST silently ignore the supplied data and treat the option as a request per the above; non-zero OPTION-DATA from a client is not a meaningful semantic per RFC 5001 §2.4.
*Source.* RFC 5001 §2.
*Note.* NSID is the standard mechanism for identifying which anycast or load-balanced instance answered a given query — a critical capability for debugging production deployments. The configured NSID value is opaque octet content (commonly an ASCII hostname like `dns-iad-3` or a hex-encoded site identifier); it is set by configuration per ODS-IF-CONF-003.
*Verification.* Conformance tests with NSID-requesting queries; wire-format inspection of responses confirming NSID option presence and content matches configuration.

**ODS-FR-EDNS-017.** The NSID value MUST be configurable per §6.2 as either an inline string or an octet sequence. The default value MUST be empty (no NSID configured). When no NSID is configured, NSID requests in inbound queries MUST be silently ignored — the server MUST NOT include an NSID option in responses to such queries.
*Source.* RFC 5001 §2.4 (NSID response is optional).
*Verification.* Configuration round-trip tests; behavioural tests with NSID configured and not configured.

### Extended DNS Errors (RFC 8914)

**ODS-FR-EDNS-018.** The server MUST support an operator-configurable minimal Extended DNS Errors profile per RFC 8914. The default profile MUST be `off`. When the profile is `minimal`, and the inbound query contained an OPT RR, the response OPT RR MAY include an Extended DNS Error option (option code 15) with no EXTRA-TEXT for the following server-local diagnostic conditions:
- `Not Ready` (INFO-CODE 14) when the matching zone exists but is not yet ACTIVE, including LOADING and EXPIRED zone-state-machine states;
- `Unsupported NSEC3 Iterations` (INFO-CODE 27) when NSEC3 denial-of-existence proof records are omitted because the zone's NSEC3 iteration count exceeds the configured `dnssec.nsec3_max_iterations` cap per ODS-FR-DNSSEC-014.

The EDE option MUST NOT change the base DNS RCODE selected by the underlying response condition. The server MUST NOT emit EDE in responses to non-EDNS queries. If a UDP response must be truncated to fit the applicable payload ceiling, the server MAY omit the EDE option before omitting DNS resource records.
*Source.* RFC 8914 §2, §4; RFC 9276 §2.4.
*Verification.* Wire-format tests for profile off/on, LOADING-zone SERVFAIL with INFO-CODE 14, NSEC3-over-cap negative response with INFO-CODE 27, non-EDNS omission, and truncation behaviour. *Added in v0.9 implementation alignment.*

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

**ODS-FR-TCP-011.** The server MUST enforce a configurable maximum number of concurrently in-flight queries per accepted TCP connection, with a default of 64. When this limit is reached on a connection, the server MUST cease reading new queries from that connection's socket until enough in-flight queries have been answered to bring the count below the limit. Connections persistently at the limit for a configurable duration (default equal to the read timeout of ODS-FR-TCP-004) MUST be closed by the server with a TCP FIN, with the closure logged at info level.
*Source.* RFC 7766 §7 (resource management for pipelined connections); defence against single-client query-state exhaustion via unbounded pipelining.
*Note.* Pipelining (ODS-FR-TCP-007) permits multiple in-flight queries per connection, but unbounded pipelining is a DoS vector — a single TCP connection could otherwise accumulate millions of pending queries. The 64 default is comfortably above legitimate pipelining patterns and well below resource-exhaustion thresholds. Operators serving especially aggressive pipelining clients can tune upward.
*Verification.* Tests opening a single TCP connection and pipelining queries beyond the configured limit; verify back-pressure (reads cease) rather than unbounded buffer growth.

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
*Note.* For zones signed with NSEC3 using the opt-out flag (RFC 5155 §6), unsigned delegations within an opt-out span are not explicitly proved absent by NSEC3 records — the opt-out span's NSEC3 record covers the gap. The server's behaviour follows the data delivered by the primary: where the primary's NSEC3 chain covers the delegation point with an opt-out span (no specific NSEC3 record for the delegation), the server MUST include the covering NSEC3 record and its RRSIG, which is the correct proof under RFC 5155 §6. The server does not synthesise additional proofs.
*Verification.* Lookup tests against signed parent zones with both signed-child and unsigned-child delegations, and against NSEC3-opt-out signed parent zones with unsigned children inside opt-out spans.

### Response composition (DO = 0)

**ODS-FR-DNSSEC-008.** Where DO = 0 in the query (or no OPT RR is present), the server MUST NOT include RRSIG, NSEC, or NSEC3 records in any section of the response, with the single exception that records of these types MAY be returned where they are themselves the explicitly queried QTYPE.
*Source.* RFC 4035 §3.2.1.
*Note.* The exception covers a client explicitly requesting (for example) QTYPE = RRSIG at a name: the response then contains the RRSIG RRset by virtue of being the queried type, not by virtue of DNSSEC augmentation.
*Verification.* Tests with DO = 0 queries against signed zones; verify absence of DNSSEC augmentation except in the explicit-type case.

### Header bits in responses

**ODS-FR-DNSSEC-009.** The response DO bit MUST follow ODS-FR-EDNS-009: if the query contains an OPT RR, the response OPT RR copies the query's DO bit exactly, regardless of whether DNSSEC augmentation records were ultimately included. The presence or absence of RRSIG, NSEC, NSEC3, DS, DNSKEY, or NSEC3PARAM records is governed by ODS-FR-DNSSEC-002 through ODS-FR-DNSSEC-008 and by response-size truncation, not by recomputing the response DO bit from the final response contents.
*Source.* RFC 6840 §5.6; RFC 4035 §3.2.1.
*Verification.* Wire-format inspection of response OPT RRs across signed and unsigned zone responses, explicit DNSSEC QTYPE responses, non-authoritative REFUSED responses, error responses, DO = 0 and DO = 1 queries, and truncation paths.

**ODS-FR-DNSSEC-010.** The server MUST set the AD (Authentic Data) bit to 0 in every response message regardless of query state.
*Source.* RFC 6840 §5.8 (the AD bit's meaning in authoritative responses is unspecified; this server's posture is to never assert AD).
*Note.* Resolvers ignore the AD bit on responses from authoritative servers per the same RFC clause. Setting AD = 0 unambiguously avoids any implicit claim of validation by the server (which does not validate).
*Verification.* Wire-format inspection of all response messages.

**ODS-FR-DNSSEC-011.** The server MUST set the CD (Checking Disabled) bit to 0 in every response message regardless of query state.
*Source.* RFC 4035 §3.1.6.
*Note.* RFC 4035 §3.1.6 says a security-aware authoritative name server SHOULD clear CD when composing an authoritative response. This SRS makes that stronger as a project policy because OxideDNS-Secondary is authoritative-only, performs no DNSSEC validation during query processing, and has no recursive response path where RFC 4035 §3.2.2's recursive copy rule would apply.
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

### NSEC3 iteration cap

**ODS-FR-DNSSEC-014.** Where a query against an NSEC3-signed zone requires the server to traverse NSEC3 chain records to compose a negative-existence proof (per ODS-FR-DNSSEC-004 or ODS-FR-DNSSEC-005), and the zone's NSEC3PARAM RDATA specifies an iteration count exceeding a configurable cap (per ODS-IF-CONF-015, default 100 per RFC 9276 / BCP 236 §2.4), the server MUST treat the affected response composition as follows:
- The negative response itself MUST still be returned per ODS-FR-CORE-022 (NODATA) or ODS-FR-CORE-023 (NXDOMAIN); the request is not refused;
- The NSEC3 records (and their RRSIGs) that would constitute the denial-of-existence proof MAY be omitted from the response — the response then carries the negative answer without DNSSEC authentication for the negative proof;
- Where the minimal EDE profile is enabled per ODS-FR-EDNS-018 and the inbound query contained an OPT RR, the response SHOULD include EDE INFO-CODE 27 (`Unsupported NSEC3 Iterations`) without EXTRA-TEXT to make the downgrade observable to diagnostic clients;
- The server MUST emit a warning-level log entry on the first such omission per zone since process startup, with `category = "dnssec"`, `event = "nsec3_iterations_exceed_cap"`, and structured fields recording the zone name, the iteration count present in NSEC3PARAM, and the configured cap;
- The per-zone counter `oxidedns_dnssec_nsec3_cap_exceeded_total{zone="..."}` (per §5.6) MUST be incremented for each affected response.

This requirement is a CPU-amplification defence against adversarial or misconfigured zones whose NSEC3PARAM specifies very high iteration counts. RFC 9276 §2 establishes that any iteration count greater than zero is unnecessary in practice; the §2.4 recommendation of 0 (with a soft ceiling of 100 for legacy zones) is the operational guidance. The cap value is configurable to allow operators to accept legacy zones if they are willing to absorb the CPU cost, but the default is the RFC 9276 ceiling.
*Source.* RFC 9276 §2, §2.4 (BCP 236); RFC 5155 §10.3.
*Note.* The relaxation is bounded to the negative-proof case; positive responses against NSEC3-signed zones do not require chain traversal and are not affected by the cap. Where the operator has expressly configured `nsec3_max_iterations = 0` (or any value below the zone's actual iteration count), the affected zone is served without NSEC3-authenticated negative proofs but otherwise correctly; the cap does not deny service.
*Verification.* DNSSEC conformance tests against NSEC3-signed zones with iteration counts at, below, and above the configured cap; verify response composition behaviour, warning emission cadence (once per zone per process), and metric increment. *Added in v0.9.*

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
*Note.* Where the operator configures both a parent zone (e.g., `example.com`) and a child zone (`child.example.com`) for service, queries within the child zone's namespace are resolved against the child zone per the "most specific zone wins" rule of ODS-FR-CORE-019. The parent zone's NS records at the delegation point for the child are still present and authoritatively served when queried directly, but the child zone supplies the authoritative answer for any QNAME at or below `child.example.com`. The two zones may carry inconsistent data (different apex NS RRsets, divergent glue) — this is a primary-side concern; the secondary serves each zone's data as received without cross-zone consistency enforcement.
*Verification.* Lookup tests covering each access pattern across zones with varying structure and depth, including the parent-plus-child served-zone overlap configuration.

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

**ODS-FR-ZSM-014.** SOA poll queries issued under ODS-FR-ZSM-006 MUST be constructed with QNAME equal to the zone apex name, QTYPE = 6 (SOA), QCLASS equal to the configured class of the zone, OPCODE = 0 (QUERY), RD = 0, a QID selected per ODS-FR-SPOOF-001, and (where TSIG is configured for the selected primary) a TSIG record signing the query per §4.9. The query MAY be sent over UDP or TCP; over UDP, response validation MUST apply RFC 5452 (ODS-FR-SPOOF-003 through ODS-FR-SPOOF-006) and any received truncation (TC bit set) MUST cause retry over TCP.
*Source.* RFC 1034 §4.3.5; RFC 1035 §4.1.2; this SRS §4.5, §4.9.
*Note.* Earlier draft snapshots used a suffixed ZSM label for this requirement; that label is historical only and must not be used for new traceability.
*Verification.* Wire-format inspection of outbound SOA poll queries; spoofing-resistance tests parallel to other outbound query paths.

**ODS-FR-ZSM-007.** Where a refresh attempt has been triggered by a NOTIFY message that carried an SOA record in its answer section (per ODS-FR-NOTIFY-008), the state machine MAY use that embedded SOA's serial as the primary-side input to the comparison of ODS-FR-ZSM-006, skipping a separate SOA poll. If the embedded serial is equal to or less than the secondary's held serial, the refresh is recorded as successful per ODS-FR-ZSM-004 without any further query. If greater, the configured transfer protocol is initiated.
*Source.* RFC 1996 §3.7.
*Verification.* Tests with NOTIFY messages carrying embedded SOAs at various serial relationships.

### Refresh failure

**ODS-FR-ZSM-008.** Where a refresh attempt fails — transfer abort per §4.6 or §4.7, SOA poll failure, all configured primaries exhausted without success — the state machine MUST:
- Leave the zone in its prior state (ACTIVE if previously ACTIVE, LOADING if previously LOADING, EXPIRED if previously EXPIRED), with its prior data intact, subject to the EXPIRE evaluation of ODS-FR-ZSM-009;
- Schedule the next refresh attempt at (current time + RETRY interval), where RETRY is read from the zone's currently held SOA RDATA for an ACTIVE or EXPIRED zone, or from the initial-load backoff (ODS-FR-ZSM-002) for a LOADING zone, subject to ODS-FR-ZSM-010 (jitter), ODS-FR-ZSM-011 (minimum), and the maximum effective REFRESH/RETRY ceiling of ODS-FR-ZSM-011 (paragraph 2).

*Source.* RFC 1034 §4.3.5; RFC 1035 §3.3.13.
*Verification.* Failure-injection tests across transfer abort causes, exercising prior-state preservation for each of ACTIVE, LOADING, and EXPIRED.

### Expiration

**ODS-FR-ZSM-009.** For each ACTIVE zone, the state machine MUST monitor the elapsed wall-clock time since the most recent successful refresh. When this elapsed time exceeds the zone's SOA EXPIRE value, the state machine MUST transition the zone to EXPIRED state per ODS-FR-ZONE-006. The state machine MUST continue to schedule and attempt refreshes for EXPIRED zones at intervals not exceeding the SOA RETRY value (with jitter and minimum applied per ODS-FR-ZSM-010 and ODS-FR-ZSM-011); on the first successful refresh of an EXPIRED zone, the state machine MUST transition the zone back to ACTIVE per ODS-FR-ZSM-004.
*Source.* RFC 1034 §4.3.5; RFC 1035 §3.3.13.
*Verification.* Long-running tests with simulated primary unreachability spanning the EXPIRE interval; verify state transitions to EXPIRED and recovery to ACTIVE.

### Jitter and minimum intervals

**ODS-FR-ZSM-010.** The state machine MUST apply uniform random jitter in the range ±10% to every scheduled interval (REFRESH, RETRY, initial-load backoff) before scheduling. The jitter MUST be drawn independently per zone per scheduling decision.
*Source.* Defensive operational practice against synchronised refresh storms.
*Verification.* Statistical analysis of scheduled refresh times across many zones and many cycles; the empirical distribution MUST be consistent with the specified jitter.

**ODS-FR-ZSM-011.** The state machine MUST enforce a configurable minimum effective interval for REFRESH and RETRY values read from SOA records, with a default minimum of 60 seconds. SOA REFRESH or RETRY values below the minimum MUST be treated as equal to the minimum for scheduling purposes. The original SOA values are preserved unchanged for serving.

The state machine MUST also enforce a configurable maximum effective interval for REFRESH and RETRY values, with a default maximum of 86400 seconds (24 hours). SOA REFRESH or RETRY values above the maximum MUST be treated as equal to the maximum for scheduling purposes. As with the minimum, the original SOA values are preserved unchanged for serving.
*Source.* Defensive operational practice; protection against refresh storms from pathological primary configurations (minimum); bounded staleness when primaries configure excessive intervals (maximum).
*Note.* The maximum is a useful upper bound because primaries occasionally publish very large REFRESH values (weeks or months) — without a cap, NOTIFY-less change propagation could lag by that interval. NOTIFY (§4.8) provides expedited refresh when the primary supports it, but a maximum effective REFRESH ensures eventual convergence even in NOTIFY-absent deployments. The configured minimum and maximum constrain only the state machine's scheduling; they do not modify the SOA record served to clients.
*Verification.* Tests with SOA records containing REFRESH or RETRY below the minimum, above the maximum, and within the allowed range.

### Shutdown

**ODS-FR-ZSM-012.** On process shutdown initiated by SIGTERM, the state machine MUST cease initiating new refresh attempts. Refresh timers MUST NOT trigger new transfers after the SIGTERM signal is received. In-progress transfer sessions complete or are aborted per the graceful shutdown timing specified in §5.5.
*Source.* This SRS §5.5; §6.5.
*Verification.* Shutdown tests confirming no new transfers initiated after SIGTERM.

### Long-loading detection

**ODS-FR-ZSM-013.** Where a zone has remained in LOADING state for a configurable threshold duration (default 3600 seconds = 1 hour) since process startup, the state machine MUST emit a warning-level log entry recording the zone name, the elapsed LOADING duration, the most recent failure cause across all configured primaries, and the next scheduled retry time. The state machine MUST repeat this warning at the configured threshold interval for as long as the zone remains in LOADING state. The corresponding per-zone metric ("zone in LOADING state for N seconds") MUST be exposed per §5.6 and §6.4 for orchestrator and alerting integration.
*Source.* Operational requirement; protection against silent persistent failures (misconfigured TSIG keys, unreachable primaries, certificate problems) that would otherwise be invisible to operators relying on the server's continued process-running status.
*Note.* Per ODS-FR-ZSM-002, the state machine MUST NOT abandon initial-load retries; this requirement complements that by ensuring such persistent failures are made visible. A zone permanently in LOADING produces a continuous stream of structured warnings at the threshold interval — operators wire these into alerting per their normal observability stack.
*Verification.* Tests with unreachable primaries; verify warning log emission at the threshold and at threshold-interval repetitions; verify metric exposure.

## 4.17 Response Rate Limiting

This subsection specifies Response Rate Limiting (RRL), the mechanism by which the server constrains its utility as an amplification vector for reflection attacks. RRL accounts the rate of responses produced for each accounting key (typically a source-IP prefix and a response category), and applies a configurable action — silent drop or truncation-marker response — when the rate exceeds a configured threshold.

RRL is not the subject of an IETF standard-track RFC. Similar response-rate-limiting mechanisms are documented by BIND 9, Knot DNS, and NSD, but their defaults and accounting models differ. This subsection therefore defines the OxideDNS project model explicitly: a process-wide, UDP-query-response limiter with configurable source-prefix aggregation, response-category buckets, slip behavior, key-count cap, allowlist, logs, and metrics. PID Appendix A lists RRL as a required feature without RFC citation, on the basis of its operational maturity.

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

*Source.* Operational RRL practice documented by BIND 9, Knot DNS, and NSD; project-specific category model in this SRS.
*Verification.* Tests confirming responses of each category are counted under the corresponding accounting key.

### Thresholds and bucket model

**ODS-FR-RRL-003.** For each response category, the server MUST enforce a configurable per-second rate limit, applied per accounting key. The default rate limits MUST be:
- positive responses: 20 responses per second;
- NXDOMAIN responses: 5 responses per second;
- NODATA responses: 10 responses per second;
- referral responses: 10 responses per second;
- error responses: 5 responses per second.

*Source.* OxideDNS project default baseline, recorded in `docs/rrl-release-thresholds.md`; operational review pending before formal SRS acceptance.
*Note.* These defaults are project defaults, not inherited vendor defaults. Operators serving high-traffic zones or anycast networks may need to tune upward; operators of low-traffic zones may benefit from tuning downward to detect anomalies faster.
*Verification.* Tests at and beyond the limit thresholds.

**ODS-FR-RRL-004.** The rate-limit MUST be implemented as a token-bucket per accounting key: bucket capacity equal to the configured per-second rate, refilled at the configured per-second rate (one token per (1 / rate) seconds). Each response produced for the accounting key consumes one token. When the bucket is empty, the response is subject to the action of ODS-FR-RRL-005.
*Source.* Standard rate-limiting design.
*Verification.* Burst-tolerance tests confirming the bucket model.

### Limit-exceeded action

**ODS-FR-RRL-005.** When a response would be produced for an accounting key whose token bucket is exhausted, the server MUST apply the configured "slip" policy, parameterised by an integer N with default value 2:
- If N = 0: every rate-limited response MUST be silently dropped (no message sent on the wire).
- If N ≥ 1: of every N rate-limited responses for that accounting key, on average exactly one MUST be emitted as a truncated response (TC bit set, empty answer/authority/additional sections, retaining the question section and OPT RR if applicable), and the remaining MUST be silently dropped.

The truncated response provides an escape path for legitimate clients (which can switch to TCP per §4.12 to receive the full response) while substantially reducing the amplification utility of the server to a spoofed-source attacker.
*Source.* Operational RRL practice documented by BIND 9, Knot DNS, and NSD; project-specific slip policy in this SRS.
*Note.* The "on average exactly one of N" is implemented as a per-(accounting-key) counter that increments on each rate-limited response and emits the truncated variant when the counter modulo N equals zero, then resets. Over many rate-limited responses for a key, this yields the 1/N truncation ratio. The earlier wording "of every N consecutive" suggested a stricter sliding-window semantics that is not implementable under the token-bucket model and not necessary for the RRL design goal.
*Verification.* Tests under sustained rate-limit pressure on a single accounting key; verify the empirical drop-to-truncate ratio approaches (N−1):1 as the sample size grows, and verify the counter resets correctly across long-running tests.

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
*Source.* Operational requirement; observability for rate-limit enforcement.
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
*Enforces.* ODS-INV-001; ODS-INV-007; PID §3.2.
*Verification.* Conformance tests with queries for names outside served zones; verify REFUSED and RA = 0.

**ODS-NEG-008.** The server MUST NOT forward DNS queries to any other server. Every response is determined exclusively from the server's in-memory zone store.
*Enforces.* ODS-INV-001; ODS-INV-007; PID §3.2.
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

**ODS-NEG-018.** The server MUST NOT issue IXFR queries over UDP. All outbound IXFR queries MUST use TCP per ODS-FR-IXFR-001. While RFC 1995 §2 permits UDP IXFR transport, this server does not implement that variant.
*Enforces.* ODS-FR-IXFR-001; project simplification decision per §1.4.5 dated 24 May 2026.
*Verification.* Code review confirming no UDP IXFR code path exists; outbound network-layer inspection confirming all IXFR queries are issued over TCP.

## 4.19 DNS Cookies

This subsection specifies the server's implementation of DNS Cookies per RFC 7873. DNS Cookies is a lightweight DNS transaction-security mechanism that provides limited protection against off-path spoofing, amplification, answer-forgery, and cache-poisoning attacks. The mechanism is deliberately weaker than TSIG, but it avoids TSIG's pre-arranged shared-secret and per-client key-distribution requirements.

DNS Cookies complements the RFC 5452 measures of §4.5 (QID randomisation, source-port randomisation, strict response matching). The §4.5 measures resist off-path attackers blindly guessing transaction details; a valid Server Cookie additionally indicates that the client has previously completed an exchange with this server from the claimed source address and Client Cookie. OxideDNS uses that address-confirmation property for UDP spoofing resistance and RRL exemption policy, not as general client identity or TSIG-equivalent authorization.

The area code **COOKIE** is allocated.

### Cookie option processing

**ODS-FR-COOKIE-001.** The server MUST recognise the COOKIE EDNS option (option code 10) per RFC 7873 §4 in inbound queries. The option's OPTION-DATA carries a Client Cookie (always 8 octets) and optionally a Server Cookie (8 to 32 octets per RFC 7873 §4 as updated by RFC 9018).
*Source.* RFC 7873 §4; RFC 9018.
*Verification.* Conformance tests with queries carrying Client-Cookie-only and Client-Cookie+Server-Cookie variants.

**ODS-FR-COOKIE-002.** The server MUST process inbound DNS Cookies according to the four-case logic of RFC 7873 §5.2: (a) no cookies in query; (b) Client Cookie only; (c) Client Cookie and an invalid Server Cookie; (d) Client Cookie and a valid Server Cookie. The server's response action per case MUST follow ODS-FR-COOKIE-005, ODS-FR-COOKIE-006, and ODS-FR-COOKIE-007.
*Source.* RFC 7873 §5.2.
*Verification.* Conformance tests covering each of the four cases.

### Server Cookie computation

**ODS-FR-COOKIE-003.** The Server Cookie computed by the server MUST follow the construction of RFC 9018 §4: a SipHash-2-4 (RFC 9018 §4.4) MAC over the input fields (Client Cookie, Version, Reserved, Timestamp, Client IP address) using a per-server-instance secret key. The cookie format MUST include the 1-octet Version field set to 1, the 3-octet Reserved field set to 0, the 4-octet Timestamp field encoding the cookie's generation time in seconds since the Unix epoch, and the 8-octet MAC. The total Server Cookie length is thus 16 octets.
*Source.* RFC 9018 §4, §4.3, §4.4.
*Note.* RFC 9018 replaces the RFC 7873 example Server Cookie algorithms with an interoperable Version 1 construction. OxideDNS follows that construction for locally generated and validated Server Cookies.
*Verification.* Tests for RFC 9018 field construction, fixed 16-octet Server Cookie length, timestamp handling, IPv4/IPv6 Client-IP input length, and successful validation of cookies generated by the implementation.

**ODS-FR-COOKIE-004.** The server cookie secret MUST be a 16-octet (128-bit) random value, generated from a cryptographically secure random source at process startup. The secret MUST NOT be persisted to disk (per ODS-INV-004); it lives only in process memory. Each process restart MUST generate a fresh secret.
*Source.* RFC 9018 §4; ODS-INV-004.
*Note.* Restarts invalidate all previously issued server cookies; legitimate clients re-acquire a fresh server cookie on their next exchange, costing one round-trip per client. This is operationally acceptable and avoids the security risks of persistent secret material on disk.
*Verification.* Code review confirming secret generation at startup and absence of disk persistence.

### Server response logic

**ODS-FR-COOKIE-005.** When the server receives a query with no COOKIE option (case (a) of ODS-FR-COOKIE-002), the server MUST process the query normally and the response MUST NOT contain a COOKIE option. RRL accounting (§4.17) applies normally.
*Source.* RFC 7873 §5.2.1.
*Verification.* Conformance tests with cookieless queries.

**ODS-FR-COOKIE-006.** When the server receives a query with a Client Cookie only — case (b) of ODS-FR-COOKIE-002 — the server's behaviour depends on the operator-configured "cookies-enforce" policy:
- **Default policy ("lenient"):** The server MUST process the query normally, and the response MUST include a COOKIE option containing the received Client Cookie and a freshly computed Server Cookie per ODS-FR-COOKIE-003. The response is the requested response (normal RCODE, normal data). The client now possesses a valid Server Cookie and can use it in subsequent queries.
- **"strict" policy:** The server MUST emit a BADCOOKIE response (extended RCODE 23, per RFC 7873 §5.2.3): RCODE set to BADCOOKIE encoded via the EDNS extended-RCODE mechanism, an answer-section-empty response, and a COOKIE option in the response carrying the received Client Cookie and a freshly computed Server Cookie. The client is expected to retry with the server cookie attached, at which point case (d) applies.

The "strict" policy raises the effective resistance to spoofing further (no useful response is given to a client that hasn't proved client-side address possession via a prior exchange) at the cost of one extra round-trip per new client.
*Source.* RFC 7873 §5.2.2; RFC 7873 §5.4.
*Verification.* Tests with Client-Cookie-only queries under each policy; verify response composition and BADCOOKIE encoding under strict policy.

**ODS-FR-COOKIE-007.** When the server receives a query with both a Client Cookie and a Server Cookie — cases (c) and (d) of ODS-FR-COOKIE-002 — the server MUST verify the Server Cookie by recomputing the expected MAC per ODS-FR-COOKIE-003 with the received Timestamp and the cookie secret. The MAC comparison MUST be performed in constant time per the cryptographic-hygiene requirement of ODS-FR-TSIG-009. Additionally, the Timestamp MUST be checked against the server's current time: cookies with Timestamps more than (configurable) 3600 seconds in the past or more than (configurable) 300 seconds in the future MUST be considered invalid.

- **Valid Server Cookie (case (d)):** The server MUST process the query normally, the response MUST include a COOKIE option carrying the received Client Cookie and a freshly computed Server Cookie (the cookie is refreshed on each exchange), and the response is exempt from RRL accounting (parallel to TSIG-authenticated queries per ODS-FR-RRL-008).
- **Invalid Server Cookie (case (c)):** The server MUST treat the query as if no Server Cookie were present, applying the policy of ODS-FR-COOKIE-006 (lenient or strict).

*Source.* RFC 7873 §5.2.4, §5.2.5; RFC 9018 §4.3, §4.4.
*Verification.* Tests with valid, expired, future-skewed, and tampered Server Cookies; verify constant-time comparison and correct response action under each case.

### Configuration

**ODS-FR-COOKIE-008.** DNS Cookies MUST be enabled by default with the "lenient" policy. The configuration MUST permit the operator to disable cookies entirely or to switch to "strict" policy per §6.2. The cookie secret regeneration interval (default: once per process lifetime, i.e., the secret persists until process restart) MAY be configurable for operators who want periodic rotation within a long-running process.
*Source.* Operational defaults; PID Appendix A.
*Note.* RFC 7873 §5.2.3 permits a server receiving a Client-Cookie-only query to discard the request, send BADCOOKIE, or process the request and return a Server Cookie. OxideDNS defaults to the lenient project policy because it preserves interoperability with clients that do not yet have a Server Cookie while still issuing Server Cookies to clients that request them. Operators that need a stricter UDP anti-spoofing posture can opt into BADCOOKIE enforcement.
*Verification.* Configuration round-trip tests across the three modes; behavioural tests confirming each mode's response composition.

### RRL interaction

**ODS-FR-COOKIE-009.** Responses to queries that carried a valid Server Cookie (case (d) of ODS-FR-COOKIE-002, per ODS-FR-COOKIE-007) MUST NOT be subject to RRL accounting or limit enforcement, parallel to TSIG-authenticated queries per ODS-FR-RRL-008. The valid Server Cookie is sufficient evidence for this server's RRL policy that the client completed a prior exchange from the claimed source address; it is not a general client-identity assertion.
*Source.* RFC 7873 §5.2.5; this SRS §4.17.
*Verification.* Tests with sustained valid-cookie traffic; verify no RRL action.

### Logging

**ODS-FR-COOKIE-010.** The server MUST log cookie events per the discipline of §6.3:
- Cookie secret generation at startup: info level, recording the secret's fingerprint (a non-reversible hash, NOT the secret itself);
- BADCOOKIE response emission (ODS-FR-COOKIE-006 strict): debug level, with source IP and reason;
- Aggregate cookie statistics: per the metric counters of ODS-FR-COOKIE-011.

The cookie secret value MUST NOT appear in any log entry at any level.
*Source.* Operational requirement; security requirement for secret confidentiality.
*Verification.* Log inspection across cookie event categories; static analysis of log statements.

**ODS-FR-COOKIE-011.** The server MUST maintain in-memory counters for cookies:
- queries received with no cookie (case (a));
- queries received with Client Cookie only (case (b));
- queries received with valid Server Cookie (case (d));
- queries received with invalid Server Cookie (case (c));
- BADCOOKIE responses emitted (strict policy).

These counters MUST be exposable globally and per-source-prefix per §5.6 and §6.4.
*Source.* Operational visibility for the RFC 7873 §5.2 cookie processing cases and RFC 9018 server-cookie validation profile.
*Verification.* Counter inspection under controlled cookie traffic.

## 4.20 Zone Provisioning

This subsection specifies the externally observable mechanism by which the server learns the set of zones it is to serve. Explicit secondary zones are configured with `[[zones]]`; RFC 9432 catalog zones are configured with `[[catalog_zones]]` per ODS-IF-CONF-013. Both sources are selected at startup by static configuration and may coexist in one process. Explicit zones are fixed for the process lifetime, while catalog-derived member zones are derived at runtime from a DNS Catalog Zone transferred from a configured primary. Once accepted, explicit and catalog-derived member zones follow the same externally observable zone lifecycle: transfer acquisition, ACTIVE/LOADING/EXPIRED state reporting, query serving, refresh, expiry, logging, and metrics.

Internal abstractions used to implement this behaviour are not part of the SRS. The Architecture Document records the current module and runtime design.

The area code **PROV** is allocated.

### Mode selection and shared invariants

**ODS-FR-PROV-001.** The configuration MUST select zone-provisioning sources at startup via `[[zones]]` and/or `[[catalog_zones]]` entries (per ODS-IF-CONF-013). At least one explicit zone or catalog zone MUST be configured. Changing the configured sources during operation MUST NOT be possible per ODS-INV-005; changes are applied only via process restart with updated configuration.
*Source.* ODS-INV-005; RFC 9432 §3 and §5.1.
*Verification.* Configuration round-trip tests across explicit-zone, catalog-zone, and mixed configurations; tests confirming attempts to alter configured sources during runtime (e.g., via signal, via configuration-file modification) have no effect.

**ODS-FR-PROV-002.** Regardless of source, every served zone — whether explicitly configured or catalog-derived — MUST proceed through the standard zone state machine of §4.16 (initial AXFR via §4.6, subsequent SOA polling and IXFR refresh via §4.7, NOTIFY processing per §4.8). The zone-acquisition mechanism, TSIG authentication (§4.9), XoT transport (§4.10), and externally observable functional behaviours specified elsewhere in §4 are unchanged by the source.
*Source.* RFC 9432 §5.1; preservation of existing secondary-zone behaviour.
*Verification.* Functional regression tests confirming identical query, transfer, refresh, logging, metrics, and lifecycle behaviour across explicit and catalog-derived zones for equivalent zone contents.

**ODS-FR-PROV-003.** Each served zone MUST have a zone apex name, an ordered list of primary IP addresses with optional port, the TSIG key reference where required, and the per-zone XoT configuration where configured. For explicit zones, these coordinates are taken directly from the matching `[[zones]]` entry. For catalog-derived member zones, these coordinates are inherited from the configured `[[catalog_zones]]` entry and applied uniformly to all member zones, subject to the constraint of ODS-NFR-SEC-011.
*Source.* Operational requirement; per-zone primary specification.
*Verification.* Configuration and catalog-processing tests confirming effective transfer coordinates under each source.

### Explicit Zones (`[[zones]]`)

**ODS-FR-PROV-004.** The explicit-zone set served by the process MUST be exactly the set enumerated in the `[[zones]]` configuration array (per ODS-IF-CONF-013). The set is fixed for the process lifetime per ODS-INV-005. This source corresponds to the v0.1 through v0.7 behaviour of this server.
*Source.* ODS-INV-005; backward compatibility.
*Verification.* Tests with various static zone configurations; confirmation that the served zone set matches the configuration exactly and remains unchanged across SIGHUP, configuration-file modification, and indefinite runtime.

### Catalog Zones (`[[catalog_zones]]`)

**ODS-FR-PROV-005.** For each configured catalog zone, the server MUST transfer a catalog zone (RFC 9432) from the primary specified in the matching `[[catalog_zones]]` entry (per ODS-IF-CONF-013) using the AXFR protocol per §4.6, authenticated by TSIG per §4.9 with the key referenced by that catalog entry's `tsig_key`. The catalog zone MUST be processed per RFC 9432 §3 and §4: the version property `version.<catalog-apex>` MUST be verified to contain the TXT value `"2"` (other version values cause the catalog transfer to be rejected with an error logged); member zones MUST be enumerated from the `<unique-id>.zones.<catalog-apex>` PTR records.
*Source.* RFC 9432 §3, §4.
*Verification.* Tests with catalog zones containing valid version=2 properties; tests with absent or non-"2" version properties (expecting rejection); tests with valid and invalid PTR record structures.

**ODS-FR-PROV-006.** The catalog zone itself MUST be subject to SOA-driven refresh (§4.7) and NOTIFY-driven refresh (§4.8) on the same terms as any other zone. Successful catalog refresh MUST trigger reconciliation between the previously applied member-zone set and the newly derived member-zone set. Newly accepted members MUST be added per ODS-FR-PROV-007; members no longer present MUST be removed per ODS-FR-PROV-008.
*Source.* RFC 9432 §5.1 and §5.3; design integration with §4.16 zone state machine.
*Verification.* Tests with catalog updates adding and removing member zones; confirm externally observable member-zone lifecycle, query, log, and metric changes.

**ODS-FR-PROV-007.** When a newly accepted catalog member zone is added, the server MUST initiate the standard zone-acquisition pathway per §4.16: the new zone enters the LOADING state, an initial AXFR is attempted against the primary coordinates inherited from the static `[[catalog_zones]]` entry (not from the catalog zone's own contents, per ODS-NFR-SEC-011), and successful AXFR completion transitions the zone to ACTIVE. Failure modes follow the normal zone state machine.
*Source.* Design integration with §4.16.
*Verification.* End-to-end tests adding a member zone to the catalog and observing the standard LOADING→ACTIVE transition for the new zone.

**ODS-FR-PROV-008.** When a previously accepted catalog member zone is no longer present in the applied catalog membership, the server MUST de-provision the zone: any in-progress transfer for the zone MUST be aborted (treated as a normal transfer abort per §4.6 and §4.7), the zone's entry in the in-memory zone store MUST be removed atomically per ODS-INV-003 (subsequent queries for the zone receive REFUSED or, where the orphaned zone-cut produces a non-authoritative state, the appropriate response per §4.3), and the zone state machine state for the zone MUST be discarded. The de-provisioning MUST be logged at info level with the zone name and the catalog refresh that triggered it.
*Source.* RFC 9432 §5.3; operational requirement for clean removal.
*Verification.* Tests removing a member zone from the catalog and confirming the zone becomes unservable from the secondary within one catalog-refresh interval, without affecting other zones.

**ODS-FR-PROV-009.** The catalog zone's contents — specifically the per-member PTR records and any RFC 9432 property records associated with member zones — MUST be hidden from the DNS query interface by default. The configuration parameter `serve_catalog_zone` (per ODS-IF-CONF-013) controls this policy. Where `serve_catalog_zone = false` (the default), the catalog apex and names below it are not part of the published-zone set, and queries for those names MUST receive REFUSED. Where `serve_catalog_zone = true`, the catalog zone MAY be served as ordinary authoritative zone content, but this mode SHOULD be used only on restricted management-facing deployments because RFC 9432 §7 notes that catalog zones reveal the zones served by their consumers and recommends limiting systems able to query them.
*Source.* RFC 9432 §3 and §7; operational separation of provisioning data from served data.
*Verification.* Functional tests querying the catalog apex and member-property names with `serve_catalog_zone = false` and `true`; verify default REFUSED behavior and opt-in authoritative serving behavior.

**ODS-FR-PROV-010.** Catalog membership reconciliation MUST use only a fully transferred and committed catalog zone version. A failed or partial catalog transfer MUST NOT partially add, remove, or alter member-zone service. The atomicity guarantee of ODS-INV-003 applies independently to catalog membership changes: query handlers MUST observe either the previously applied membership or the newly applied membership, never an intermediate partially reconciled state.
*Source.* ODS-INV-003; clean architectural separation.
*Verification.* Tests with deliberately failed catalog transfers confirming no partial membership changes; concurrent query tests during catalog reconciliation.

### Bootstrap and dependency ordering

**ODS-FR-PROV-011.** With configured catalog zones, process startup MUST proceed as follows: (1) each catalog zone is transferred and processed; (2) the initial member-zone set is determined; (3) the zone manager begins concurrent AXFR for the member zones up to the limit of ODS-FR-AXFR-022; (4) the `/readyz` endpoint (per ODS-NFR-OBS-004) reports `ready` once at least one configured explicit or catalog-derived zone has reached ACTIVE state per the standard criterion. If initial catalog transfer fails, the server MUST retry using the configured zone-state retry timers and `/readyz` MUST report `not-ready` until at least one zone reaches ACTIVE.
*Source.* Operational requirement; orchestrator-friendly bootstrap.
*Verification.* Startup-sequence tests with reachable and unreachable catalog primaries; verify `/readyz` transitions; verify retry behaviour.

**ODS-FR-PROV-012.** If the catalog primary becomes unreachable after the initial successful transfer, the catalog zone MUST follow the normal zone state machine: SOA-poll failures accumulate per §4.16, and after the catalog zone's own SOA EXPIRE time is exceeded, the catalog zone transitions to EXPIRED. While the catalog is in EXPIRED state, the most recently known member-zone set MUST remain in service (the server does NOT de-provision all member zones merely because the catalog has expired); each member zone independently continues its own SOA polling and lifecycle. Recovery of the catalog (successful subsequent refresh) MUST resume normal reconciliation behaviour, with any member-zone deltas that accrued during the EXPIRED period applied at recovery time.
*Source.* Operational requirement; isolation of catalog availability from member-zone availability; ODS-NFR-SEC-012.
*Verification.* Tests with catalog primary going unreachable for periods exceeding the catalog's SOA EXPIRE; verify member zones continue to refresh from their own primaries; verify recovery and reconciliation.

### Catalog content constraints

**ODS-FR-PROV-013.** The catalog zone provider MUST validate each candidate member-zone name from the catalog's PTR records per the syntactic rules of RFC 1035 §2.3.1 (allowed character set, label length 1–63 octets, total name length not exceeding 255 octets). Names failing validation MUST be rejected with a warning-level log entry identifying the offending PTR record; the rest of the catalog's contents MUST be processed normally. The validation requirements of ODS-NFR-SEC-015 (catalog-apex containment exclusion) apply additionally.
*Source.* RFC 1035 §2.3.1; defensive engineering against malformed catalog contents.
*Verification.* Tests with catalog zones containing syntactically invalid PTR targets; verify rejection-with-warning behaviour and continued processing of the remainder.

**ODS-FR-PROV-014.** The catalog zone MAY contain per-member property records permitted by RFC 9432 §5 (e.g., `primaries.<unique-id>.zones.<catalog-apex>`, `coo.<unique-id>.zones.<catalog-apex>`, `group.<unique-id>.zones.<catalog-apex>`). In this version of the server, **all such per-member property records MUST be ignored** — specifically, the `primaries` property (RFC 9432 §5.1) MUST NOT alter the primary coordinates used for member-zone transfer, per the security constraint of ODS-NFR-SEC-011. Encountered property records MUST be logged at debug level for operator awareness; their presence MUST NOT cause the catalog to be rejected. Support for selected properties may be added in a future revision subject to security review.
*Source.* RFC 9432 §5; ODS-NFR-SEC-011.
*Note.* The decision to ignore `primaries` properties is a deliberate security stance, not an oversight. Honouring `primaries` would allow a compromised catalog primary to redirect member-zone transfers to attacker-controlled hosts. The catalog-zone implementation here is intentionally narrower than the full RFC 9432 specification permits.
*Verification.* Tests with catalog zones containing `primaries` properties; verify the static-configuration defaults are used and the properties are ignored.

## 4.21 CHAOS Class Query Handling

This subsection specifies the server's response policy to queries in the `CHAOS` (CH) class: a class historically allocated for the Chaosnet protocol (RFC 1035 §3.2.4) and commonly used by DNS operational tooling to probe authoritative or recursive servers for self-identifying information. The de-facto probe names in scope here are `version.bind.` and `version.server.` for software-family identity, and `hostname.bind.` and `id.server.` for server-instance identity in anycast or load-balanced deployments.

The default policy is conservative: the server discloses nothing unless the operator explicitly configures a response. Where operators opt in, the configured values are operator-chosen strings, not automatically generated build identifiers. The recommended public-facing convention is to disclose software family and topology, for example `"OxideDNS unicast"` or `"OxideDNS anycast"`, while reserving precise build-version information for authenticated or local operational channels such as the `--version` CLI output, image metadata, release manifests, and structured startup logs.

CHAOS-class handling is a meta-query path that precedes normal zone lookup. CHAOS queries do not enter the in-memory zone store of §4.15 and do not imply that the server is authoritative for a CHAOS zone. Responses are still constructed entirely from local server state under ODS-INV-007; the server performs no recursion or external lookup to answer them.

The area code **CHAS** is allocated.

### Recognised CHAOS TXT names

**ODS-FR-CHAS-001.** The server MUST recognise inbound DNS queries with QCLASS = 3 (CHAOS / CH), QTYPE = 16 (TXT), and QNAME equal to `version.bind.` or `version.server.` (case-insensitive label comparison per RFC 1035 §2.3.3). When `chaos.version` (per ODS-IF-CONF-018) is configured to a non-empty string, the server MUST construct a response with RCODE = 0 (NOERROR), AA = 1, an answer-section RR whose owner name is the queried name, CLASS = CHAOS, TYPE = TXT, TTL = 0, and RDATA consisting of one TXT character-string carrying the configured value. When `chaos.version` is empty or absent, the server MUST respond with RCODE = 5 (REFUSED) and no answer-section RRs.
*Source.* RFC 1035 §3.2.4; RFC 1035 §3.3.14; de-facto operational practice originating with BIND.
*Note.* The configured value is bounded by the 255-octet TXT character-string limit. Operators may choose a precise build string on internal-only deployments, but public-facing deployments SHOULD prefer a soft-identifying value or the default REFUSED behaviour. TTL = 0 is used because these responses are diagnostic and should not be cached for operationally meaningful periods.
*Verification.* Conformance tests with CH/TXT queries for both QNAMEs, with and without `chaos.version` configured; wire-format inspection of class, type, TTL, TXT framing, AA, and REFUSED default behaviour. *Added in v0.9.1.*

**ODS-FR-CHAS-002.** The server MUST recognise inbound DNS queries with QCLASS = CHAOS, QTYPE = TXT, and QNAME equal to `hostname.bind.` or `id.server.` (case-insensitive). The response value MUST be selected as follows:
- if `chaos.hostname` (per ODS-IF-CONF-018) is configured to a non-empty value, that value is used;
- otherwise, if the configured NSID value (per ODS-FR-EDNS-017) is non-empty and consists only of printable ASCII octets (0x20 through 0x7E inclusive), the NSID value is used;
- otherwise, the server MUST respond with RCODE = 5 (REFUSED).

Where a value is selected, the response MUST be constructed as in ODS-FR-CHAS-001: NOERROR, AA = 1, one CHAOS/TXT answer RR with TTL = 0, and a single TXT character-string carrying the selected value.
*Source.* RFC 5001 §3; de-facto operational practice.
*Note.* The NSID fallback avoids duplicating the same node identifier in two configuration locations. The printable-ASCII restriction exists because NSID is opaque octet content and may contain values that are not suitable for TXT presentation; operators using non-printable NSID values can configure `chaos.hostname` explicitly.
*Verification.* Tests covering explicit `chaos.hostname`, printable NSID fallback, non-printable NSID refusal, and both values absent. *Added in v0.9.1.*

### Unsupported CHAOS names and types

**ODS-FR-CHAS-003.** For inbound queries with QCLASS = CHAOS, QTYPE = TXT, and QNAME other than the names enumerated in ODS-FR-CHAS-001 and ODS-FR-CHAS-002 — including `authors.bind.`, `id.authors.`, and site-specific CHAOS names — the server MUST respond with RCODE = 5 (REFUSED) and no answer-section RRs. The server MUST NOT implement `authors.bind.` or any other software-author-credit name.
*Source.* Operational minimal-disclosure policy; explicit project decision against BIND-specific authorship-credit names.
*Note.* REFUSED is preferred over NXDOMAIN because the CHAOS class is not represented as a zone in the §4.15 zone store; there is no authoritative CHAOS zone in which the name could be proven to exist or not exist.
*Verification.* CH/TXT tests for `authors.bind.`, `id.authors.`, and arbitrary CHAOS names; verify REFUSED independent of configuration. *Added in v0.9.1.*

**ODS-FR-CHAS-004.** For inbound queries with QCLASS = CHAOS and QTYPE other than TXT, the server MUST respond with RCODE = 5 (REFUSED), regardless of QNAME, with no answer-section RRs and no SOA in the authority section. The server MUST NOT attempt to construct CHAOS-class A, AAAA, ANY, AXFR, SOA, or other non-TXT data responses.
*Source.* RFC 1035 §3.2.4; operational minimal-disclosure policy.
*Verification.* Tests with CH/A, CH/AAAA, CH/ANY, CH/SOA, and CH/AXFR queries for recognised and arbitrary names; verify REFUSED in all cases. *Added in v0.9.1.*

### Class orthogonality

**ODS-FR-CHAS-005.** The CHAOS-class handler MUST NOT be reachable for queries with QCLASS = IN, even where the QNAME matches one of the recognised CHAOS names (`version.bind.`, `hostname.bind.`, etc.). IN-class queries for these names MUST follow the standard zone-lookup machinery of §4.2: if no served zone is authoritative for the name, the response is REFUSED per ODS-FR-CORE-019; if a served zone is authoritative, the response reflects that zone's actual content.
*Source.* DNS class orthogonality; ODS-INV-007.
*Verification.* IN/TXT tests for `version.bind.` and related names; verify the response is determined by zone authority and not by `[chaos]` configuration. *Added in v0.9.1.*

### Logging and metrics

**ODS-FR-CHAS-006.** The server MUST maintain in-memory counters for CHAOS-class queries, distinguishing at minimum: answered queries; queries refused because the relevant configuration value was empty or absent; queries refused because the CHAOS name was unrecognised; and queries refused because QTYPE was not TXT. These counters MUST be exposed globally via the metrics endpoint per §5.6 and §6.4. CHAOS-class queries MUST be logged at debug level only, recording at minimum source address, QNAME, QTYPE, and resulting RCODE.
*Source.* Operational observability; consistency with the low-noise counter discipline used for DNS Cookies and NOTIFY.
*Verification.* Counter inspection under controlled CHAOS-query traffic across each branch; log-output inspection at info and debug levels. *Added in v0.9.1.*

# 5. Non-Functional Requirements

This section specifies properties of the system beyond its functional behaviour: how fast it must be, how reliable, how secure, how maintainable, how portable, how observable, and what resource bounds it must respect. The functional requirements of §4 specify *what* the server does; the non-functional requirements of this section specify *under what constraints*.

Each subsection allocates an area code per the scheme of §1.4.3 (ODS-NFR-<AREA>-NNN). The standard requirement template applies, presented more compactly than the functional sections; the per-subsection identifier range follows.

The targets below are formal project acceptance targets for the OxideDNS reference verification profile. They are not a statement that the current Engineering MVP has already met every numerical value, nor that local smoke or loopback benchmarks demonstrate equivalence to NSD, Knot DNS, BIND, or any other authoritative server. Where the PID did not specify a target explicitly, proposed values consistent with the project capacity goal are recorded; these are flagged in Appendix C.5 for review.

**Reference Profile.** All quantitative performance and resource targets in this section are stated with respect to the **Reference Hardware Profile** and the **Reference Query Mix** specified in Appendix E. Verification of performance NFRs is performed on hardware matching the Reference Hardware Profile, against the Reference Query Mix; deviations from the Profile during verification (e.g., different CPU, different NIC) must be recorded and may be cause for the verification result to be qualified rather than treated as conformance evidence. Where defaults are stated in non-functional requirements, every such default is operator-configurable per §6.2 unless explicitly stated otherwise; the configuration parameter name is identified in each requirement.

For the repository's Engineering MVP, local smoke and large-catalog benchmark harnesses record measured performance and identify bottlenecks in the implemented code. Those harnesses are engineering evidence for tuning decisions; they are not formal conformance evidence for the quantitative NFR targets unless a release run explicitly executes the Reference Hardware/Profile procedure and retains the artifacts required by Appendix E.4. Full conformance to the quantitative targets below is a formal ODS-VER-008 release-acceptance activity, not a prerequisite for the bounded Engineering MVP evidence profile.

## 5.1 Performance

The area code **PERF** is allocated.

**ODS-NFR-PERF-001.** Under the Reference Query Mix of Appendix E.3, on hardware matching the Reference Hardware Profile of Appendix E.2, with the metrics endpoint enabled (per ODS-NFR-OBS-003, default 10-second scrape interval), with logging at info level (per ODS-NFR-OBS-002 default), and with RRL accounting enabled (per ODS-FR-RRL-001 default), the server MUST sustain a query-handling throughput of at least 50,000 UDP queries per second per CPU core dedicated to query handling, where TSIG verification on queries is not exercised and DNSSEC augmentation is not exercised (DO = 0 in all queries).
*Source.* Project reference-hardware throughput target; formal acceptance evidence required before asserting conformance.
*Note.* "Per CPU core dedicated to query handling" is normalised to the per-core throughput because the implementation's multi-core scaling factor is an architectural choice recorded in the Architecture Document. The Reference Profile specifies a Dual Xeon Gold 6230R (52 physical cores total); the per-core target multiplied by the cores dedicated to query handling yields the aggregate throughput target for the deployment.
*Verification.* Sustained-load benchmarking using `dnsperf` or `kxdpgun` against the Reference Query Mix on hardware matching the Reference Hardware Profile, with the operational stack (metrics, logging, RRL) enabled per the conditions above. Results are recorded with their exact hardware, kernel version, container runtime, and benchmark-tool versions for reproducibility.

**ODS-NFR-PERF-002.** Under the workload of ODS-NFR-PERF-001 at no more than 50% of the throughput target, the server MUST achieve a 99th-percentile query response latency below 1 millisecond for direct-hit lookups (queries answered without CNAME chain expansion), measured as in-process latency: the elapsed time between the kernel delivering the query packet to the server's UDP socket and the server submitting the response packet for transmission. End-to-end latency including network propagation is not specified, as it depends on factors outside the server's control.
*Source.* Operational requirement.
*Verification.* Latency-distribution inspection under controlled load on the Reference Hardware Profile; in-process latency measurement via instrumented timestamps at socket-receive and socket-send.

**ODS-NFR-PERF-003.** Under the workload of ODS-NFR-PERF-001 at up to 90% of the throughput target, the server MUST achieve a 99th-percentile query response latency below 10 milliseconds, measured per ODS-NFR-PERF-002.
*Source.* Operational requirement.
*Verification.* Latency-distribution inspection at near-capacity load on the Reference Hardware Profile.

**ODS-NFR-PERF-004.** AXFR transfer ingestion on the Reference Hardware Profile MUST sustain at least 100,000 records per second when the network bandwidth to the primary is at least 1 Gbit/s and the primary serves the transfer at line rate. Records are counted as wire-format RRs received and validated; the ingestion rate includes the validation passes specified in §4.6 and the publication step of ODS-INV-003.
*Source.* Operational requirement; bounds transfer time for large zones to operationally acceptable values.
*Verification.* AXFR ingestion timing with synthetic zones of varying sizes on the Reference Hardware Profile.

**ODS-NFR-PERF-005.** Process initialization (binding sockets, parsing configuration, initiating first transfer attempts) MUST complete within 1 second of process start on the Reference Hardware Profile with the configuration containing up to 1,000 zones. Zone-transfer completion time (loading data into ACTIVE state per §4.15) is separate and constrained by primary responsiveness and zone size; the bound here is on initialization steps alone.
*Source.* Operational requirement; orchestrator-friendly startup.
*Verification.* Startup-timing tests with configurations of varying zone counts on the Reference Hardware Profile.

**ODS-NFR-PERF-006.** Under the Reference Query Mix delivered over TCP with at least 32 in-flight queries per connection (within the limit of ODS-FR-TCP-011), on the Reference Hardware Profile and under the operational conditions of ODS-NFR-PERF-001, the server MUST sustain a TCP query throughput of at least 30% of the UDP throughput target of ODS-NFR-PERF-001 per CPU core dedicated to query handling (i.e., at least 15,000 TCP queries per second per core under the v0.4 PERF-001 target).
*Source.* Operational requirement; TCP query traffic is a meaningful fraction of authoritative-server load in DNSSEC-heavy and large-response-heavy deployments.
*Note.* TCP throughput is naturally lower than UDP throughput because of connection-state overhead, framing, and pipelining accounting. The 30% factor is operationally typical; aggressive optimisation (e.g., io_uring or epoll batching) may exceed it.
*Verification.* TCP-pipelined query benchmarking on the Reference Hardware Profile using a benchmark tool that supports pipelining (e.g., `dnsperf` with appropriate flags or a custom harness).

**ODS-NFR-PERF-007.** TSIG-authenticated message verification on the Reference Hardware Profile MUST sustain at least 10,000 verifications per second per CPU core for the HMAC-SHA256 algorithm (ODS-FR-TSIG-001), under sustained inbound TSIG-signed NOTIFY load. The cryptographic cost of TSIG verification is the principal new computational cost on the inbound transfer/notify path; this target bounds the rate at which a TSIG-configured primary can drive the secondary's authentication path.
*Source.* Operational requirement; bounds the throughput of the TSIG-protected control path.
*Note.* Outbound TSIG signing (ODS-FR-TSIG-012) is computationally equivalent to verification and follows the same target.
*Verification.* TSIG verification benchmarking on the Reference Hardware Profile using a load generator emitting TSIG-signed messages at controlled rates.

**ODS-NFR-PERF-008.** Under the Reference Query Mix against zones signed with NSEC (ODS-FR-DNSSEC-001 et seq.), where the client query carries DO = 1 and the response includes DNSSEC augmentation per ODS-FR-DNSSEC-003 through ODS-FR-DNSSEC-007, the server on the Reference Hardware Profile MUST sustain at least 60% of the throughput target of ODS-NFR-PERF-001 per CPU core (i.e., at least 30,000 DNSSEC-augmented queries per second per core under the v0.4 target). The performance reduction reflects the larger response size and additional records placed in the authority section.
*Source.* Operational requirement; DNSSEC-aware deployments must not pay an unacceptable throughput penalty.
*Note.* NSEC3-signed zones may yield slightly different numbers because of the hash computation cost — but the same target applies; NSEC3 specifics are recorded in the Architecture Document as an implementation concern.
*Verification.* Benchmarking against NSEC- and NSEC3-signed Reference Query Mix variants on the Reference Hardware Profile.

## 5.2 Reliability and Availability

The area code **REL** is allocated.

**ODS-NFR-REL-001.** On receipt of SIGTERM, the server MUST cease accepting new queries and new TCP connections, allow in-flight query processing and transfer sessions to complete within a configurable grace period (parameter `shutdown.grace_period`, default 30 seconds), then exit with status code 0. Sessions still active at the end of the grace period MUST be aborted as follows:
- Client TCP connections: closed with a graceful TCP FIN; an in-progress query response is sent if assembly completed before the grace expired, otherwise the connection is closed without response.
- In-progress AXFR or IXFR transfer sessions: aborted per ODS-FR-AXFR-019 or ODS-FR-IXFR-013 (treated as primary-side failure for state-machine accounting); discarded partial data is not retained; the next process instance, which under ODS-INV-004 starts cold, will perform fresh AXFR per ODS-FR-ZSM-001.
- In-progress XoT TLS handshakes: closed with TLS close-notify where the handshake state permits, otherwise the underlying TCP connection is closed.

After the grace period expires, the server MUST exit regardless of remaining in-flight work.
*Source.* Operational requirement; orchestrator-friendly graceful shutdown.
*Verification.* Shutdown-behaviour tests under sustained query load and active transfer sessions; verify clean TCP close on client connections and correct abort accounting on transfer sessions.

**ODS-NFR-REL-002.** A process crash MUST NOT corrupt any state on the host filesystem outside the server's standard streams (stdout, stderr per ODS-IF-LOG-001). Per ODS-INV-004, the server holds no persistent operational state to corrupt. A subsequent process start MUST initialize cleanly from configuration, performing full zone acquisition per §4.16.
*Source.* ODS-INV-004.
*Verification.* Forced-kill tests followed by restart verification; filesystem state inspection across crash-restart cycles.

**ODS-NFR-REL-003.** Steady-state memory consumption MUST be bounded across extended operation. Specifically: on the Reference Hardware Profile, under sustained workload at the throughput level of ODS-NFR-PERF-002 (50% of capacity) with zones of stable size and a stable distribution of client source IPs, the server's resident set size (RSS) at the 30-day mark of continuous runtime MUST be within a configurable percentage threshold (parameter `reliability.memory_growth_threshold_pct`, default 10%) of the RSS measured at the 24-hour mark of the same run. The 24-hour mark is taken as the steady-state baseline; the period before is allowed for warm-up (RRL state population, connection-pool growth, cache fills).

The server MUST NOT exhibit unbounded memory growth attributable to its own data structures (RRL state, connection-pool entries, in-flight query tracking) under the stable-workload conditions above.
*Source.* Operational requirement for long-running infrastructure services.
*Note.* Memory growth caused by external factors (a primary delivering progressively larger zones across the soak period, a steadily growing population of distinct client source prefixes) is not in scope; the requirement isolates growth attributable to the server's internal state management.
*Verification.* 30-day soak testing per ODS-NFR-REL-003 (as part of the formal SRS MVP release acceptance defined by ODS-VER-008) on the Reference Hardware Profile with stable workload; RSS measurements at 24-hour and 30-day marks; computation of the growth percentage against the configured threshold.

**ODS-NFR-REL-004.** Network errors on inbound or outbound connections — malformed packets, mid-transfer connection drops, kernel buffer exhaustion, transient `EAGAIN`/`EWOULDBLOCK` conditions, ICMP unreachables, peer TCP RST, TLS handshake-level failures on XoT — MUST NOT cause process termination. Errors MUST be handled per the requirements of §4.6, §4.7, §4.8, §4.10, and §4.12; the process continues serving subsequent traffic. File-descriptor exhaustion is prevented structurally by ODS-NFR-RES-004 (startup `rlimit` check); should it occur despite that check (e.g., due to FD leak), accept failures MUST be logged at error level and MUST NOT terminate the process.
*Source.* Operational requirement.
*Verification.* Fault-injection tests across the enumerated failure modes; long-running tests under simulated network-error injection.

**ODS-NFR-REL-005.** The server MUST be deployable under rolling-restart patterns. Specifically, the server's contribution to a successful rolling restart is:
- After receipt of SIGTERM, the server MUST stop accepting new client TCP connections within 100 milliseconds (the listening TCP socket is closed); inbound connection attempts during the drain period are refused at the kernel level (TCP RST in response to SYN), allowing load balancers and clients to fail over to other instances promptly.
- In-flight client queries MUST be served to completion within the grace period of ODS-NFR-REL-001; no in-flight query MUST be dropped without response unless it exceeds the grace period.
- The metrics endpoint health probe (`/readyz` per ODS-NFR-OBS-004) MUST report **draining** within 100 milliseconds of SIGTERM receipt, signalling to orchestrators that the instance is leaving service.

Whether end-to-end service continuity is achieved depends on the orchestrator's deployment strategy and the client population's retry behaviour, both outside the server's control.
*Source.* Operational requirement; container-native deployment.
*Verification.* Rolling-restart tests in a representative orchestrator environment; instrumented measurement of listen-socket-close latency and `/readyz` state-transition latency.

**ODS-NFR-REL-006.** Under inbound query load exceeding the server's serving capacity (ODS-NFR-PERF-001), the server MUST exhibit graceful degradation:
- UDP queries beyond capacity MAY be dropped at the OS kernel socket buffer level (the kernel's standard behaviour when the receive buffer fills); the server MUST NOT introduce application-level queueing of unbounded depth on the UDP query path.
- TCP connection accepts beyond ODS-FR-TCP-005 MUST be refused at the kernel level (the listen-socket backlog is configured per ODS-FR-TCP-005 and the kernel refuses excess SYNs); the server MUST NOT accept and immediately close connections in a busy loop.
- In-flight queries already accepted MUST continue to be served correctly; the per-query latency MAY rise as resources are saturated but MUST remain bounded by the configurable per-query processing timeout (parameter `query.processing_timeout_ms`, default 5000 milliseconds), beyond which the query is dropped and a per-zone metric is incremented (per ODS-NFR-OBS-005).
- The server MUST NOT exhibit cascade failure: a transient overload episode MUST result in transient degraded performance, not in a persistent unhealthy state requiring restart.

*Source.* Operational requirement; protection against cascading failures in anycast and load-balanced deployments.
*Verification.* Overload-injection tests at 1.5×, 2×, and 5× the throughput of ODS-NFR-PERF-001; observation of UDP drop counters via per-CPU `netstat`, TCP accept refusal at the kernel level via SYN-flood-style tests, in-flight query completion under load, and post-overload recovery to baseline performance.

**ODS-NFR-REL-007.** The server's correct operation requires the system clock to be synchronised within configurable tolerance windows. Specifically:
- TSIG message verification per ODS-FR-TSIG-008 tolerates clock difference up to the configured TSIG fudge value (parameter `tsig.fudge_seconds`, default 300 seconds per ODS-FR-TSIG-012). Operators valuing stricter authentication MAY reduce this; modern infrastructures running NTP or PTP typically maintain clock skew well below 1 second, and a fudge value of 5–30 seconds is commonly operationally viable.
- DNS Cookie timestamp validation per ODS-FR-COOKIE-007 tolerates Server Cookie timestamps within configurable past and future windows (parameters `cookie.timestamp_past_tolerance_seconds`, default 3600; `cookie.timestamp_future_tolerance_seconds`, default 300).
- All these tolerance windows MUST be configurable per §6.2; the defaults are chosen to accommodate environments with relatively loose time synchronisation, while supporting tightening in environments with NTP/PTP-synchronised clocks.

Clock drift exceeding the configured tolerances will cause authentication failures (BADTIME from TSIG, invalid Server Cookie from ODS-FR-COOKIE-007 case (c)), but MUST NOT cause process malfunction; the server MUST distinguish clock-related authentication failures from key-mismatch failures in log entries and per-zone metrics to support operator diagnosis.

Clock synchronisation itself is the operator's responsibility (the server does not embed an NTP client); the Operator Deployment Guide per ODS-NFR-MAINT-009 MUST document the clock-synchronisation requirement and recommended practices.
*Source.* RFC 8945 §10.4 (TSIG time-window discussion); RFC 9018 §4.3 (Server Cookie timestamp); operational practice in production DNS deployments.
*Verification.* Tests with deliberate clock-skew injection across the configured tolerance boundaries; log inspection confirming distinct logging of clock-related vs key-related authentication failures.

## 5.3 Security

The area code **SEC** is allocated.

**ODS-NFR-SEC-001.** The implementation MUST satisfy ODS-INV-006: Rust's safe subset is used for all code processing data received from the network; `unsafe` blocks are confined to documented, justified exceptions.
*Source.* ODS-INV-006.
*Verification.* `cargo geiger` enumeration plus per-block review of all `unsafe` code at release time.

**ODS-NFR-SEC-002.** Wire-format parsers — DNS message, EDNS option, RR-type-specific decoders, TSIG verification input, AXFR/IXFR stream parser — MUST be subject to continuous fuzz testing using `cargo-fuzz` or equivalent. Each release MUST be preceded by a minimum of 24 hours of fuzz testing per parser with no resulting crash, panic, or memory-safety finding.
*Source.* Defensive engineering; aligned with the project's security thesis.
*Verification.* CI pipeline integration of fuzz tests; release-process documentation.

**ODS-NFR-SEC-003.** Cryptographic key material — TSIG shared secrets, XoT client TLS private keys, DNS Cookie secrets — MUST be handled per the requirements of ODS-FR-TSIG-006, ODS-FR-XOT-007, and ODS-FR-COOKIE-004 respectively. This NFR consolidates those security guarantees into the cross-cutting security inventory; the cited functional requirements are authoritative. In summary, none of these materials may appear in any log entry at any verbosity level, in error messages or diagnostic output, and the server MUST zero in-memory key material at process termination.
*Source.* ODS-FR-TSIG-006; ODS-FR-XOT-007; ODS-FR-COOKIE-004; standard cryptographic key handling.
*Verification.* Static analysis of log-statement contents; static analysis of error-formatting code paths; memory inspection at controlled shutdown.

**ODS-NFR-SEC-004.** The server MUST be designed to run as an unprivileged operating-system user. Where binding to privileged ports (53, 853) is required, this MUST be achieved via OS-level capabilities (Linux `CAP_NET_BIND_SERVICE`) or socket activation from a supervisor, not by running the server process as root. The server MUST NOT require any capability beyond `CAP_NET_BIND_SERVICE` (per ODS-NFR-PORT-003); other capabilities (e.g., `CAP_SYS_ADMIN`, `CAP_NET_RAW`) MUST NOT be required. Where the server is invoked as root (a deployment-side decision outside its control), the server MUST drop privileges to a configurable unprivileged user (parameter `process.run_as_user`) before beginning to process untrusted input, and the privilege drop MUST be irrevocable (`setresuid` with all three IDs set to the unprivileged user, or equivalent).
*Source.* Standard security practice; least-privilege principle; resolution of v0.2 C.5 decision item.
*Verification.* Deployment tests confirming non-root execution viability; privilege-drop tests when the server is invoked as root.

**ODS-NFR-SEC-005.** The server MUST NOT listen on any TCP or UDP port beyond those required for configured DNS query service (UDP/53, TCP/53), the optional health and metrics endpoint per §6.4, and (where the metrics endpoint is configured to be a Unix domain socket rather than a TCP socket) the corresponding Unix domain socket path. Outbound XoT connections do not require listening sockets. The server MUST NOT open any administrative or debugging port at any time, in accordance with ODS-INV-005 and ODS-NEG-011. The server MUST NOT create or listen on Unix domain sockets beyond those required for the metrics endpoint when that endpoint is so configured.
*Source.* Defensive engineering; ODS-INV-005.
*Verification.* Runtime network-layer and filesystem inspection confirming bound ports and any Unix sockets match configuration.

**ODS-NFR-SEC-006.** Third-party Rust crates depended on by the server MUST be from well-maintained sources, subjected to security review at adoption time, and tracked against ongoing security advisories. The dependency set MUST be minimised consistent with functional requirements. Specific crate choices, with security justification, are recorded in the Architecture Document. Continuous monitoring MUST include an advisory/license/source gate such as `cargo deny check` or `cargo audit` plus equivalent license/source checks. In the current private-repository Engineering MVP profile this gate is `scripts/check.sh`; formal SRS release acceptance requires retained CI or release-gate logs showing the dependency gate on the accepted commit, with failures on High/Critical unmitigated advisories and on policy-disallowed licenses or sources.
*Source.* PID §7.1; standard supply-chain security practice.
*Verification.* Dependency-gate execution observed in local continuous logs, CI logs, or release-gate evidence; review of advisories at each release.

**ODS-NFR-SEC-007.** The project MUST maintain a documented vulnerability disclosure policy specifying:
- a reporting contact (`security@` email address or equivalent secure reporting channel);
- the expected response timeline: initial acknowledgement within 72 hours; fix or mitigation within a configurable target (parameter at the project policy level, default 30 days for severity High or Critical findings, 90 days for severity Medium or Low);
- the coordinated disclosure window during which the reporter is asked to refrain from public disclosure (project policy default 90 days, subject to negotiation with reporter);
- the CVE assignment process (the project is a CVE Numbering Authority candidate, or coordinates via a recognised CNA, or via MITRE direct).

The policy MUST be referenced from the project's primary repository README and published in a `SECURITY.md` file at the repository root. The policy MUST be reviewed at each release.
*Source.* Standard practice for production-grade infrastructure software; pre-emptive provision for the vulnerability handling lifecycle.
*Verification.* Repository inspection at release time; policy completeness check against the enumerated elements.

### Security additions from the v0.8 CIA threat-model analysis

The following requirements (ODS-NFR-SEC-008 through ODS-NFR-SEC-015) were introduced in v0.8 as a result of a Confidentiality / Integrity / Availability (CIA) threat-model analysis of the system, conducted in conjunction with the introduction of the Zone Provisioning subsystem (§4.20). The threat model considered the system both as it stands and with catalog-zone provisioning enabled; requirements herein are stated as applying to the relevant configured zone source(s).

**ODS-NFR-SEC-008.** *(Confidentiality of key material at rest in configuration.)* The configuration loader MUST accept TSIG shared secrets — both for the regular zone-transfer TSIG keys (§4.9) and for the catalog-zone TSIG key (ODS-FR-PROV-005, ODS-NFR-SEC-010) — from environment variables (per ODS-IF-CONF-006 and the naming convention of ODS-IF-CONF-012) in addition to inline or file-path values per ODS-IF-CONF-004. Where the secret is loaded from an environment variable, the configuration loader MUST zero the source environment-variable storage in process memory (`unsetenv` plus best-effort zeroization of the prior value via the `zeroize` crate or equivalent) immediately after copying the secret into the TSIG engine's key store. Where the secret is loaded from a file, the in-memory buffer used to read the file MUST be similarly zeroed after the secret has been copied to the key store. Operator-facing documentation (per ODS-NFR-MAINT-009) MUST identify environment-variable secret provisioning as the preferred mechanism for Kubernetes and similar orchestrated deployments.
*Source.* CIA-C1 threat analysis; standard cryptographic key-handling hygiene; ODS-FR-TSIG-006.
*Verification.* Tests loading TSIG keys via environment variables and verifying the environment is cleared post-load; memory inspection (e.g., `gcore` followed by string-search for the known secret) after process startup confirms the secret does not persist in the configuration data structures or buffer caches.

**ODS-NFR-SEC-009.** *(Integrity — transfer authentication advisory.)* For every configured (zone, primary) tuple where TSIG authentication is NOT configured per §4.9, the server MUST emit a warning-level log entry at process startup identifying the affected tuple and noting that the zone transfer is unauthenticated. The server MUST additionally expose a configuration parameter `transfer.require_tsig` (default `false` for backward compatibility; the schema MUST recommend setting it to `true` for production deployments). Where `transfer.require_tsig = true`, the server MUST refuse to start if any configured static zone lacks a configured TSIG key, with a startup-validation failure per ODS-IF-CONF-005. The earlier draft name `zones.require_tsig` is intentionally not used because TOML already uses `[[zones]]` as the zone-array table.
*Source.* CIA-I1 threat analysis; RFC 8945 §1.
*Verification.* Tests with mixed-TSIG configurations and verification of warning emission; tests with `require_tsig = true` and incomplete TSIG configuration expecting startup failure.

**ODS-NFR-SEC-010.** *(Integrity — mandatory catalog-zone authentication.)* For every `[[catalog_zones]]` entry per §4.20.2, TSIG authentication of the catalog-zone transfer (ODS-FR-PROV-005) is MANDATORY, not optional. The server MUST refuse to start if a catalog zone's `tsig_key` is unset or references a non-existent key, with a startup-validation failure per ODS-IF-CONF-005 identifying the missing configuration. The TSIG-`require_tsig` flag of ODS-NFR-SEC-009 does NOT govern catalog zones; the catalog zone's TSIG requirement is unconditional. Additionally, if XoT (§4.10) is not configured for a catalog primary, the configuration validator MUST emit a warning per ODS-IF-CONF-008 noting that catalog contents traverse the network in cleartext (the TSIG MAC authenticates the contents but does not encrypt them).
*Source.* CIA-IX2 threat analysis; the catalog zone is a cross-cutting integrity-critical artifact whose compromise affects all member zones.
*Note.* This requirement is intentionally stricter than the general zone-transfer TSIG posture (which is operator-elected per ODS-NFR-SEC-009). The catalog zone's blast-radius asymmetry justifies the asymmetry in the requirement.
*Verification.* Tests starting the server with a catalog zone without a TSIG key (expecting startup failure with a clear diagnostic); tests with catalog TSIG configured but XoT absent (expecting startup warning); tests with both configured (expecting clean startup).

**ODS-NFR-SEC-011.** *(Integrity — catalog must not redirect member primaries.)* For catalog-derived member zones, the primary-server coordinates used for member-zone transfers (per ODS-FR-PROV-003) MUST be inherited exclusively from the statically configured `[[catalog_zones]]` entry per ODS-IF-CONF-013. Per-member primary overrides — specifically, the RFC 9432 §5.1 `primaries.<unique-id>.zones.<catalog-apex>` property — MUST NOT be honoured by this server (per ODS-FR-PROV-014). Were these to be honoured, a compromised catalog primary could redirect member-zone transfers to attacker-controlled hosts, replacing legitimate zone contents with arbitrary attacker content; this attack vector is foreclosed at specification level by the present prohibition.
*Source.* CIA-IX3 threat analysis; deliberate security narrowing of the RFC 9432 catalog mechanism.
*Verification.* Code review of the catalog-property processing path confirming `primaries` properties are ignored; tests with catalog zones containing crafted `primaries` properties (expecting the static-configuration defaults to be used and a debug-level log entry for the ignored property).

**ODS-NFR-SEC-012.** *(Availability — catalog SPOF mitigation.)* The `[[catalog_zones]]` configuration MUST permit specification of multiple primary servers for each catalog zone (`primaries` or explicit `transfer_primaries`, per ODS-IF-CONF-013), with selection semantics identical to the multi-primary behaviour for regular zones per §4.16. This permits operators to mitigate the single-point-of-failure character of a single catalog primary.
*Source.* CIA-AX1 threat analysis; standard reliability practice for critical configuration sources.
*Verification.* Tests with multi-primary catalog configurations under various primary-availability scenarios.

**ODS-NFR-SEC-013.** *(Availability — catalog resource exhaustion bound.)* The number of member zones derived from catalog zones MUST be bounded by a configurable maximum (`max_member_zones` on each `[[catalog_zones]]` entry or equivalent, per ODS-IF-CONF-013, default 10,000). Catalog contents specifying member zones beyond this limit MUST cause the excess PTR records to be ignored (the first N accepted, the remainder dropped) and an error-level log entry to be emitted naming the limit and the count of dropped entries. The configured limit MUST be enforced jointly with ODS-NFR-RES-003 (10,000 zones at 16 GiB RAM); operators raising one should consider raising the other.
*Source.* CIA-AX2 threat analysis; defence against a compromised or misconfigured catalog primary/source.
*Verification.* Tests with synthetic catalogs exceeding the limit; verify cap enforcement, error logging, and continued operation with the accepted subset.

**ODS-NFR-SEC-014.** *(Availability — slow-transfer tarpit defence.)* Every individual AXFR or IXFR transfer session — both regular zone transfers (§4.6, §4.7) and each catalog zone's own transfer — MUST be subject to a configurable per-session maximum duration (parameter `transfer.session_timeout_seconds`, default 300 seconds). When the timeout expires, the session MUST be aborted as per the normal abort path of §4.6 or §4.7 (the session counts as a failure for state-machine accounting). The timeout is independent of the connection-level idle timeouts of §4.12 and applies to the wall-clock duration of the transfer regardless of activity. This bounds the resource cost of a hostile or pathologically slow primary occupying the limited concurrent-transfer slots of ODS-FR-AXFR-022.
*Source.* CIA-AX3 threat analysis; defence against TCP-slow-loris-style attacks adapted to zone transfer.
*Verification.* Tests with a slow primary emulator (deliberately introducing delays in AXFR response stream); verify session abort at the configured timeout; verify the transfer slot is released for use by other transfers; verify state-machine accounting treats the timeout as a failure.

**ODS-NFR-SEC-015.** *(Integrity — catalog member-zone name validation.)* Every candidate member-zone name derived from a catalog zone's PTR records MUST be subjected to syntactic and semantic validation before being surfaced to the zone manager per ODS-FR-PROV-007:
- syntactic validation per RFC 1035 §2.3.1 (per ODS-FR-PROV-013);
- the member-zone name MUST NOT be equal to, nor subordinate to, the catalog zone's own apex name (preventing pathological recursive provisioning);
- the member-zone name MUST NOT be the root zone (`.`) nor any of the IANA-reserved zone names enumerated in the schema documentation;
- the member-zone name MUST NOT contain wildcard labels (`*`).

Names failing any of these checks MUST be rejected with an error-level log entry identifying the rejection reason and the offending PTR record. The remainder of the catalog's contents MUST continue to be processed normally; one bad PTR MUST NOT cause the whole catalog to be rejected.
*Source.* CIA-IX2 / IX3 threat analysis; defensive engineering against catalog-injection variants.
*Verification.* Tests with catalogs containing each prohibited name pattern; verify rejection with appropriate diagnostic.

## 5.4 Maintainability

The area code **MAINT** is allocated.

**ODS-NFR-MAINT-001.** The total source-line count of first-party Rust code SHOULD remain within the range 5,000 to 15,000 lines, excluding tests, dependencies, and generated code. The release process MUST measure and record the actual line count in the release notes for each release. Where the count exceeds 15,000 lines, the release notes MUST include a `Rationale for exceeding LOC target` section explaining the necessary increase, the features that drove it, and the maintainability-protection measures (modularisation, documentation, test coverage) compensating for it.
*Source.* PID §2.2.
*Verification.* Source-line measurement at release time using `tokei` or equivalent; release notes inspection.

**ODS-NFR-MAINT-002.** The codebase MUST be organised into between 8 and 20 clearly-named, single-purpose modules at the top level of the crate hierarchy. Each major functional area of §4 MUST be mappable to one or more identifiable modules. The mapping is recorded in the Architecture Document.
*Source.* Maintainability and auditability per PID design principle.
*Verification.* Code review against the documented module mapping at release time.

**ODS-NFR-MAINT-003.** Every `unsafe` block in first-party Rust code MUST carry a comment stating the reason `unsafe` is necessary and the invariants on which its soundness depends, per ODS-INV-006.
*Source.* ODS-INV-006.
*Verification.* Static analysis confirming each `unsafe` block has an accompanying comment satisfying the form.

**ODS-NFR-MAINT-004.** Implementation of functional requirements of §4 MUST include code-level comments referencing the requirement identifier (e.g., `// Implements ODS-FR-CORE-014: AA bit setting`) at the principal site implementing each requirement. Where a requirement is implemented across multiple sites, at least one site per requirement MUST carry the reference. The Appendix A traceability matrix is the canonical mapping; in-code references aid review and serve as cross-validation against the matrix. CI MUST verify that every functional requirement identifier in §4 appears as a code-level reference in at least one source file; missing references MUST fail the build.
*Source.* Maintainability; review efficiency; auditable implementation traceability.
*Verification.* CI-integrated grep across the source tree for each requirement identifier in §4; build failure on missing references.

**ODS-NFR-MAINT-005.** The build process MUST produce deterministic, reproducible binaries given a fixed source tree and pinned dependency set. The reproducibility approach (e.g., `cargo build --locked`, container build with pinned base image and tooling) is recorded in the Architecture Document. Two independent builds from the same commit and the same toolchain MUST produce bit-identical binaries.
*Source.* Supply-chain security; auditable releases.
*Verification.* Two independent builds from the same source produce bit-identical binaries.

**ODS-NFR-MAINT-006.** The server's externally observable interfaces MUST be considered stable under semantic versioning. The interfaces in scope of this stability commitment are:
- the configuration schema per ODS-IF-CONF-001 and ODS-IF-CONF-002;
- the command-line interface (process invocation arguments);
- the process exit codes;
- the environment variable names per ODS-IF-CONF-006;
- the signals accepted per §6.5;
- the metric names and label keys per ODS-NFR-OBS-003;
- the health endpoint paths and response structure per ODS-NFR-OBS-004.

Removal or semantic change of any element of these interfaces requires a major-version increment. Addition of new optional configuration fields, new metric labels (where labels are additive), new optional command-line arguments, and new metric series is permitted at minor-version increments. The release notes for each release MUST document which interface elements (if any) have changed, distinguishing additions, deprecations, and breaking changes.
*Source.* Operational stability for in-place upgrades; semantic versioning practice; coordination with ODS-IF-CONF-002.
*Verification.* Release-notes review at each release; CI-integrated interface-diff checks against the previous release.

**ODS-NFR-MAINT-007.** Unit test coverage for first-party Rust code MUST be at least 70% line coverage as measured by `cargo-llvm-cov` or an equivalent coverage tool. Wire-format parsers (DNS message parser, EDNS option parser, RR-type decoders, TSIG verifier, AXFR/IXFR stream parser, DNS Cookie cryptographic computation, TLS/X.509 handling for XoT) MUST individually achieve at least 85% line coverage. Coverage is measured at release time and recorded in release notes alongside the LOC measurement of ODS-NFR-MAINT-001.
*Source.* Maintainability; defensive engineering; aligned with ODS-NFR-SEC-002 (fuzz testing applies orthogonally and is not a substitute for unit-test coverage).
*Note.* The 70% / 85% thresholds are achievable for well-structured Rust code; coverage tools measure executed lines under tests, not branches, so achievable percentages are higher than equivalent branch-coverage targets.
*Verification.* CI-integrated coverage measurement; release-notes inspection.

**ODS-NFR-MAINT-008.** Released binaries and container images MUST be cryptographically signed. The signing mechanism MUST be either Sigstore/Cosign (preferred) or detached OpenPGP signatures with a clearly published signing key; the choice is recorded in the Architecture Document. Signature verification instructions MUST appear in the project's release documentation. The signing key's public part MUST be published in the project repository under `SECURITY.md` or an equivalent prominent location. Key rotation MUST follow a documented schedule.
*Source.* Supply-chain security; release artifact integrity.
*Verification.* Release-process inspection; signature verification by a third party at release time.

**ODS-NFR-MAINT-009.** An **Operator Deployment Guide** MUST be maintained as a project deliverable, separate from this SRS. The Guide MUST cover at minimum:
- installation procedures for each deployment mode of §2.4 (native process, OCI container, VM image);
- configuration reference with worked examples for typical scenarios (single-zone single-primary; multi-zone multi-primary; TSIG-protected; XoT-protected; DNSSEC-served);
- TSIG and XoT key/certificate provisioning workflows including the secure-handling expectations of ODS-FR-TSIG-006, ODS-FR-XOT-007, and ODS-FR-COOKIE-004;
- monitoring integration examples (Prometheus scrape configuration, Grafana dashboard skeletons, common alert rules);
- the explicit ICMP/firewall requirement of ODS-IF-NET-006;
- the security posture statements of ODS-FR-XOT-012 (no real-time revocation checking);
- the clock-synchronisation requirement of ODS-NFR-REL-007;
- the operational implications of ODS-FR-ZSM-013 (long-LOADING zones);
- the privilege-drop expectations of ODS-NFR-SEC-004;
- the vulnerability-disclosure contact per ODS-NFR-SEC-007.

The Guide MUST be updated at each release to reflect introduced features and changed defaults.
*Source.* Operational deliverable necessary for external operator acceptance per ODS-VER-008.
*Verification.* Document review at each release; external operator acceptance per §7.1.

## 5.5 Portability

The area code **PORT** is allocated.

**ODS-NFR-PORT-001.** The server MUST build and run on current LTS releases of major Linux distributions: Ubuntu LTS, Debian stable, Red Hat Enterprise Linux / Rocky Linux / AlmaLinux current major version, and Alpine current release. No distribution-specific configuration MUST be required.
*Source.* PID §2.4; operational requirement.
*Verification.* Per-distribution smoke tests in CI or retained release-gate
automation evidence.

**ODS-NFR-PORT-002.** The server MUST build and run on the x86_64 (amd64) and aarch64 (arm64) processor architectures. Additional architectures MAY be supported on a best-effort basis without commitment.
*Source.* Operational requirement; modern Linux server architecture diversity.
*Verification.* Per-architecture build and smoke-test CI pipelines or retained
release-gate automation evidence.

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

**ODS-NFR-OBS-003.** The server MUST expose its in-memory counters — the query-handling counters of ODS-FR-QRY-024, the RRL counters of ODS-FR-RRL-012, the NOTIFY counters of §4.8, the TSIG counters per §4.9, the transfer-session counters per §4.6 and §4.7, the cookie counters of ODS-FR-COOKIE-011 — via a metrics endpoint per §6.4. The exposition format MUST be compatible with the Prometheus / OpenMetrics text format.

Metric names MUST follow Prometheus naming conventions:
- the project prefix `oxidedns_secondary_` MUST be applied to every metric;
- counter metrics MUST carry the `_total` suffix (e.g., `oxidedns_secondary_queries_total`);
- explicit unit suffixes MUST be used where applicable: `_seconds` for duration, `_bytes` for size, `_ratio` for unitless ratios;
- per-zone, per-response-category, per-RCODE, and per-source-prefix dimensions MUST be expressed via Prometheus labels (e.g., `oxidedns_secondary_queries_total{zone="example.com",rcode="NOERROR"}`), not via name multiplication;
- the canonical metric type (Counter, Gauge, Histogram, Summary) MUST be declared via the `# TYPE` directive in the exposition output;
- the canonical help text MUST be provided via the `# HELP` directive.

Label cardinality MUST be bounded: per-source-prefix labels use the same /24 (IPv4) / /56 (IPv6) granularity as RRL accounting (ODS-FR-RRL-002), capped per ODS-FR-RRL-010 (configurable, default 100,000 distinct prefixes).
*Source.* Operational requirement; ecosystem compatibility; Prometheus naming conventions.
*Verification.* Endpoint inspection; format-parsing tests against Prometheus and OpenMetrics scrapers; naming-convention conformance review.

**ODS-NFR-OBS-004.** The server MUST expose two separate health endpoints per §6.4, following Kubernetes liveness-vs-readiness conventions:

- **`/livez` (liveness probe).** Reports whether the process is running and responsive: returns HTTP 200 with a small JSON or plain-text body whenever the process can answer the probe at all. Returns failure (HTTP 5xx or no response) only if the process is unable to respond within a configurable liveness-probe timeout (parameter `health.livez_timeout_ms`, default 1000 ms). The intent is to support orchestrator restart-on-deadlock semantics; a healthy process answers `/livez` even when zones are still in LOADING state or during graceful shutdown.

- **`/readyz` (readiness probe).** Reports whether the server should receive traffic, in one of three states:
  - **ready** (HTTP 200): at least one configured explicit or catalog-derived zone is in ACTIVE state (per ODS-FR-ZONE-006), and the process is not draining. When only catalog zones are configured, **ready** requires that initial catalog acquisition has completed and at least one member zone derived from it has reached ACTIVE state per the same criterion.
  - **not-ready** (HTTP 503): no configured explicit or catalog-derived zone is yet in ACTIVE state (i.e., all zones are LOADING or EXPIRED). Before initial catalog acquisition in a catalog-only deployment, readiness reports **not-ready**.
  - **draining** (HTTP 503): SIGTERM has been received and graceful shutdown is in progress per ODS-NFR-REL-001 and ODS-NFR-REL-005.

State transitions MUST be observable on `/readyz` within 100 milliseconds of the actual state change (e.g., the transition to **draining** within 100 ms of SIGTERM receipt per ODS-NFR-REL-005).
*Source.* Operational requirement; orchestrator-friendly health probing; Kubernetes liveness/readiness pattern.
*Note.* The two-endpoint split follows the dominant orchestration convention and avoids the ambiguity of "starting" vs "draining" both reporting non-ready while requiring different operator responses. `/healthz` is additionally supported as a readiness alias per ODS-IF-HEALTH-002.
*Verification.* Endpoint inspection across state transitions; orchestrator-integration tests confirming correct liveness vs readiness behaviour under SIGTERM, LOADING zones, and EXPIRED zones.

**ODS-NFR-OBS-005.** The metrics endpoint MUST expose per-zone status as Prometheus-format metrics: zone state (LOADING / ACTIVE / EXPIRED per ODS-FR-ZONE-006, as a `oxidedns_secondary_zone_state` gauge with a `state` label), currently held SOA serial (as `oxidedns_secondary_zone_soa_serial`), Unix timestamp of most recent successful refresh (as `oxidedns_secondary_zone_last_refresh_seconds`), Unix timestamp of next scheduled refresh (as `oxidedns_secondary_zone_next_refresh_seconds`), count of refresh failures since the most recent success (as `oxidedns_secondary_zone_refresh_failures`), and count of queries served for the zone since process start (as `oxidedns_secondary_queries_total{zone="..."}`).
*Source.* Operational requirement.
*Verification.* Per-zone metric inspection.

**ODS-NFR-OBS-006.** The metrics endpoint MUST expose a build-information metric:
```
oxidedns_secondary_build_info{version="<version>",commit="<commit>",rust_version="<rustc-version>",build_timestamp="<build-timestamp>"} 1
```
The metric is a gauge with constant value 1, carrying the version, build commit hash, build timestamp, and Rust compiler version as labels. The labels' values are populated at build time and MUST be embedded in the binary; runtime modification MUST NOT be possible.
*Source.* Operational practice; standard convention for build metadata exposition.
*Verification.* Endpoint inspection; label-value verification against the actual build artifact metadata.

**ODS-NFR-OBS-007.** Query response latency MUST be exposed as a Prometheus histogram metric (`oxidedns_secondary_query_duration_seconds`), with bucket boundaries operator-configurable (parameter `metrics.latency_histogram_buckets`, default `[0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.1]` seconds = 100 µs, 250 µs, 500 µs, 1 ms, 2.5 ms, 5 ms, 10 ms, 25 ms, 100 ms).

Separate histogram series MUST be maintained for the following query categories, expressed as label values on the `query_category` label:
- `udp_direct`: UDP queries answered without CNAME chain expansion;
- `udp_cname_chain`: UDP queries with CNAME or DNAME chain expansion;
- `tcp_direct`: TCP queries answered without CNAME chain expansion;
- `tcp_cname_chain`: TCP queries with CNAME or DNAME chain expansion;
- `dnssec_augmented`: queries with DO = 1 against signed zones (augmented response composition per §4.13);
- `cookie_validated`: queries with valid Server Cookie (ODS-FR-COOKIE-007 case (d)).

A per-zone disaggregated variant SHOULD be available via a `zone` label, subject to label-cardinality bounds (recommended: omit the `zone` label for deployments serving more than 1,000 zones to avoid label explosion). The label inclusion is operator-configurable (parameter `metrics.latency_histogram_per_zone`, default `false`).
*Source.* Operational requirement; ODS-NFR-PERF-002 and ODS-NFR-PERF-003 verification depends on a histogram metric.
*Verification.* Endpoint inspection; histogram-percentile calculation against the published buckets.

**ODS-NFR-OBS-008.** *(Catalog-zone observability.)* When `[[catalog_zones]]` are configured per §4.20.2, the metrics endpoint MUST additionally expose the following metrics, each labelled with the catalog apex name (`catalog="<apex>"`) to permit future support for multiple catalogs:

- `oxidedns_secondary_catalog_member_zones` (Gauge) — current count of member zones derived from the catalog;
- `oxidedns_secondary_catalog_last_transfer_timestamp_seconds` (Gauge) — Unix timestamp of most recent successful catalog transfer (AXFR or IXFR);
- `oxidedns_secondary_catalog_transfer_failures_total` (Counter) — cumulative count of catalog transfer failures, with a `reason` label (`tsig`, `network`, `parse`, `version`, `timeout`);
- `oxidedns_secondary_catalog_member_additions_total` (Counter) — cumulative count of member zones added via catalog updates since process start;
- `oxidedns_secondary_catalog_member_removals_total` (Counter) — cumulative count of member zones removed via catalog updates since process start;
- `oxidedns_secondary_catalog_members_rejected_total` (Counter) — cumulative count of catalog PTR records rejected for validation failure per ODS-NFR-SEC-015, with a `reason` label (`syntax`, `catalog_apex_overlap`, `reserved`, `wildcard`);
- `oxidedns_secondary_catalog_state` (Gauge with `state` label) — the catalog zone's own zone-state-machine state (LOADING / ACTIVE / EXPIRED), reported on the same convention as the per-zone state metric of ODS-NFR-OBS-005.

When no catalog zones are configured, these metrics MUST NOT be emitted (their absence signals to monitoring that catalog provisioning is not active). The metric naming follows the conventions of ODS-NFR-OBS-003.
*Source.* CIA threat analysis observability requirements; standard practice for operationally significant subsystems.
*Verification.* Endpoint inspection in both modes; functional tests inducing each counter increment and gauge state change.

**ODS-NFR-OBS-009.** The metrics endpoint MUST expose a DNSSEC counter for responses where NSEC3 denial-of-existence proof records were omitted because the configured iteration cap was exceeded. The Engineering MVP implementation metric is `oxidedns_dnssec_nsec3_iterations_exceed_cap_total`; release acceptance SHOULD additionally provide the per-zone series required by ODS-FR-DNSSEC-014 or document why the global counter is sufficient for the deployed zone-count model.
*Source.* ODS-FR-DNSSEC-014; ODS-FR-EDNS-018.
*Verification.* Metric endpoint inspection after a query that triggers EDE INFO-CODE 27. *Added in v0.9 implementation alignment.*

## 5.7 Resource Limits

The area code **RES** is allocated.

**ODS-NFR-RES-001.** The published container image MUST NOT exceed 20 megabytes uncompressed.
*Source.* PID §6.1.
*Verification.* Image size measurement at release time.

**ODS-NFR-RES-002.** Memory consumption per zone SHOULD scale approximately linearly with the number of records in the zone, with a target per-record overhead (including indices and metadata) of less than 500 bytes.
*Source.* Operational requirement; informed by typical secondary deployment sizing.
*Note.* For the current straightforward in-memory implementation recorded in
the Architecture Document, the 500-byte target is aspirational and may not be
met; verification at the formal SRS MVP release gate is performed against the
actual measured value, with the value recorded in release notes. The post-MVP
packed-binary zone store of Appendix C.6.2, once introduced, is expected to meet
or substantially exceed this target. Operators sizing memory for large
zone-count deployments should consult the actual per-release figure.
*Verification.* Memory profiling with zones of varying record counts on the Reference Hardware Profile.

**ODS-NFR-RES-003.** The server MUST support concurrent service of at least 10,000 zones with a combined record count up to 10 million records on a host with 16 GiB of available memory.
*Source.* Operational requirement; large-secondary deployment sizing.
*Verification.* Capacity benchmarking with synthetic zone sets at the specified scale, on hardware allocated 16 GiB of RAM (a constrained subset of the Reference Hardware Profile; the Profile's full 192 GiB is not required for this test).

**ODS-NFR-RES-004.** The server's steady-state file-descriptor consumption MUST be bounded by approximately 2 × (the configured concurrent client TCP connection limit per ODS-FR-TCP-005 + the configured concurrent outbound TCP connection limit + 100 reserve for listening sockets and process overhead). The server MUST verify at startup that the OS-provided file-descriptor `rlimit` is sufficient for the configured limits, and MUST fail to start with a clear error message if not. The 2× factor accounts for the implementation possibly using two file descriptors per logical connection (e.g., one for socket I/O, one for an event-notification ancillary).
*Source.* Operational requirement.
*Verification.* Startup checks under varied `rlimit` settings; runtime file-descriptor count inspection.

**ODS-NFR-RES-005.** The total number of concurrent zone-transfer sessions (AXFR plus IXFR) MUST be bounded by the limit established in ODS-FR-AXFR-022, with the default of 4.
*Source.* ODS-FR-AXFR-022.
*Note.* This NFR is a re-statement of the functional limit of ODS-FR-AXFR-022 for completeness of the resource-limit catalogue; no additional normative content is introduced here. The functional requirement is authoritative.
*Verification.* Per ODS-FR-AXFR-022.

**ODS-NFR-RES-006.** At zero query load — i.e., no inbound queries arriving for at least 60 consecutive seconds — with all zones in ACTIVE state, configured for 1,000 zones each holding 1,000 records (one million records total), on the Reference Hardware Profile, the server's CPU consumption MUST remain below 1% of one CPU core averaged over a 5-minute window. This bounds the cost of background tasks: refresh-timer scheduling, metrics aggregation, log emission, and connection-pool reaping. The bound on idle CPU consumption is operationally significant because in anycast deployments many instances run continuously; an idle-CPU cost above 1% multiplied by many instances becomes a meaningful aggregate.
*Source.* Operational requirement; anycast deployment economics.
*Verification.* Idle CPU measurement on the Reference Hardware Profile with the specified zone count and no inbound query load, sustained for at least 1 hour after warm-up; 5-minute moving averages of process CPU time computed via `/proc/<pid>/stat` or equivalent.

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

**ODS-IF-NET-005.** The server MUST support the configuration of distinct logical interface roles, each bound to a separate set of addresses:

- **DNS query interface** (`interface.dns`): the address or addresses on which the server receives and answers DNS queries (UDP and TCP, default port 53). This is the high-traffic, externally reachable interface. It MUST be possible to configure it independently of the other interfaces. The DNS query interface also receives inbound NOTIFY messages from primaries (NOTIFY is delivered to UDP/53 or TCP/53 per RFC 1996).
- **Management interface** (`interface.mgmt`): the address or addresses associated with operator-facing access. The health and metrics endpoint of §6.4 binds to this address by default; the operator MAY override the health endpoint's bind address via the explicit `health.bind_address` configuration parameter (see ODS-IF-HEALTH-001), in which case the override takes precedence. The management interface MUST NOT bind the DNS query port (53) unless the operator explicitly sets `interface.dns` and `interface.mgmt` to the same address, which signals intentional co-location.
- **Transfer interface** (`interface.transfer`) *(optional)*: the source address used for ALL outbound DNS-protocol traffic the secondary initiates toward configured primaries: AXFR queries, IXFR queries, SOA poll queries, and XoT-tunnelled variants of these. When configured, the server MUST bind outbound transfer sockets to this address. When omitted, the operating system selects the outbound source address as per ODS-IF-NET-003. The name reflects the broader scope (formerly `interface.xot` in v0.2–v0.4, which misleadingly suggested XoT-only applicability); the renaming is a schema breaking change recorded in the v0.5 revision history and addressed prior to MVP release. The old key name `interface.xot` MUST NOT be silently accepted by the configuration parser; if present, the parser MUST emit an error and exit per ODS-IF-CONF-005, directing the operator to the new name.

All three interface roles MAY be satisfied by the same address (wildcard or specific), which reproduces the single-interface behaviour and is the default. Separate addresses become effective only when configured explicitly.
*Source.* Operational requirement for production deployments; performance and security isolation between query, management, and transfer traffic planes. Decisions recorded in DTK review sessions 24 May 2026 (v0.2 introduction; v0.5 rename and clarifications).
*Verification.* Configuration tests with separate bind addresses per role; network-layer inspection confirming DNS traffic reaches only the DNS interface, health/metrics traffic reaches only the management interface (modulo the optional `health.bind_address` override), and outbound transfer traffic uses the configured transfer interface; error-emission tests confirming the obsolete `interface.xot` key is rejected.

**ODS-IF-NET-006.** The DNS query interface MUST NOT suppress ICMPv4 Fragmentation Needed messages (type 3, code 4) or ICMPv6 Packet Too Big messages (type 2) destined for addresses on that interface. In the current kernel-managed socket deployment model, these messages are generated and processed by the host operating system; the server has no application-level ICMP handling to implement. The server's Operator Deployment Guide MUST explicitly document this requirement so that operators configuring host-level or infrastructure firewalls on the DNS query interface do not inadvertently suppress these message types, which would break Path MTU Discovery and degrade or block large EDNS responses over UDP.
*Source.* RFC 8900 (IP Fragmentation Considered Fragile); RFC 4821 (Packetisation Layer Path MTU Discovery); operational requirement for EDNS0 UDP response delivery. The requirement is documentation-enforcement, not application code, in the MVP; it preponderantly becomes implementation-level in any future kernel-bypass (XDP) variant — see Appendix C.6.
*Verification.* Deployment Guide review confirming explicit statement of the ICMP requirement for the DNS query interface; firewall-configuration checklist inspection.

**ODS-IF-NET-007.** The configuration schema (§6.2) MUST provide an `[interfaces]` section with sub-keys `dns`, `mgmt`, and `transfer` — all optional, defaulting to wildcard / OS-selected as specified in ODS-IF-NET-005. Each key accepts a list of (address, port) pairs. The server MUST validate that addresses assigned to `dns` and `mgmt` do not overlap unless the operator explicitly sets them equal (signalling intentional co-location), emitting a warning at startup when overlap is detected. Overlapping `transfer` with `dns` or `mgmt` is permitted without warning, as the transfer interface is outbound-only and does not bind a listening socket.
*Source.* ODS-IF-NET-005; ODS-IF-NET-008; ODS-IF-CONF-003 (configuration schema completeness).
*Verification.* Schema validation tests covering disjoint, intentionally overlapping, and unintentionally overlapping address assignments; warning-log inspection for the overlap case; error-emission tests for the notify-vs-dns same-socket conflict.

**ODS-IF-NET-008.** The MVP configuration MUST NOT expose a fourth active **NOTIFY interface** role. NOTIFY reception is part of the DNS query interface for this release, and accepted sources are restricted by the zone's configured primaries and `notify_sources`. If an operator supplies `interface.notify` or `interfaces.notify`, the configuration parser MUST reject it per ODS-IF-CONF-005 and direct the operator to receive NOTIFY on `interfaces.dns`.

A future revision MAY reintroduce a separate NOTIFY listener role if the project explicitly accepts the operational complexity and documents its firewalling, overlap, and query-handling semantics. That future work is not part of the MVP interface model.
*Source.* MVP interface-scope decision; security isolation is provided by source authorization, TSIG where configured, and network firewalling around the DNS listener rather than by a fourth configured listener role.
*Verification.* Configuration tests with `interface.notify` and `interfaces.notify` present; verify both are rejected. Runtime tests verify authorized NOTIFY messages are accepted on DNS listeners.

## 6.2 Configuration Interface

The area code **CONF** is allocated.

**ODS-IF-CONF-001.** All operational configuration MUST be supplied via a single TOML-formatted configuration file, the path of which is specified to the process at startup via a command-line argument (default path: `/etc/oxidedns-secondary/config.toml`). Include-directive composition across multiple files is NOT supported (TOML does not define such a mechanism natively, and various ad-hoc extensions exist that this server does not adopt). Operators requiring multi-file configuration management SHOULD use external templating tools (Helm, Jinja, Ansible templates, Kustomize) to produce the single canonical file before passing it to the server. This constraint preserves the configuration model's simplicity and avoids the precedence-resolution and circular-include edge cases that include-directive systems require.
*Source.* ODS-INV-005; operational simplicity.
*Note.* TOML is selected for ecosystem alignment with the Rust toolchain (Cargo). YAML and JSON are alternative formats; TOML's restricted, unambiguous syntax avoids the YAML edge cases (Norway-problem booleans, indentation-sensitive structure, multiple parser implementations producing different results) that have produced production incidents in other DNS server projects.
*Verification.* Configuration parsing tests; round-trip tests confirming idempotent serialisation where applicable; tests confirming any include-like directive is rejected as an unknown key.

**ODS-IF-CONF-002.** The configuration schema MUST be documented in a versioned schema specification maintained alongside the project. Schema changes between server versions MUST follow a backward-compatibility policy: addition of new optional fields is permitted at any release; removal or semantic change of existing fields requires a major-version increment per semantic versioning.
*Source.* Operational stability for in-place upgrades.
*Verification.* Schema documentation maintained per project release;
version-compatibility tests in the active continuous gate or retained
release-gate automation evidence.

**ODS-IF-CONF-003.** The configuration MUST be capable of expressing, at minimum:
- the set of zones designated for service, each with zone name, class, and ordered list of primary servers (IP addresses with optional port);
- per-zone TSIG configuration: key reference and applicability (queries, transfers, NOTIFY);
- per-(zone, primary) XoT configuration: trust anchors, expected SNI, optional client certificate;
- TSIG key definitions: key name, algorithm, secret value (inline or by file reference per ODS-IF-CONF-004);
- network bind configuration per ODS-IF-NET-001, ODS-IF-NET-002, and ODS-IF-NET-005 through ODS-IF-NET-008, including the `[interfaces]` section with `dns`, `mgmt`, and `transfer` sub-keys; the active MVP configuration MUST NOT expose a fourth `notify` role, because NOTIFY reception is part of `interfaces.dns` per ODS-IF-NET-008; network interface bindings MUST be expressed as IP addresses (literal IPv4 or IPv6), not as interface names (`eth0`, `ens192`, etc.); operators who want to bind to "whatever address is currently on eth0" SHOULD resolve the address at configuration-generation time via a template tool or wrapper script, avoiding the OS-portability concern of interface naming conventions;
- logging configuration per §6.3;
- health and metrics endpoint configuration per §6.4;
- tunable parameters (timeouts, limits, RRL thresholds, jitter, keepalive intervals) with override of defaults.

*Source.* The configuration prerequisites stated by §4 requirements; operational completeness.
*Verification.* Schema completeness review against the enumerated categories.

**ODS-IF-CONF-004.** TSIG shared secrets and XoT client TLS private keys MAY be specified inline within the configuration file or by reference to a separate file path. Where referenced by file path, the server MUST verify at startup that the referenced file is readable by the server process and is not world-readable (file mode permitting access by the "other" class). Either failure MUST prevent startup with a clear error message.

Direct integration with external secret stores (HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets API) is NOT supported in this version. Operators using such stores SHOULD project secrets into the filesystem (e.g., Kubernetes Secret volume mounts at well-known paths, Vault Agent template rendering to a tmpfs location) and reference them by file path. This pattern is operationally well-supported across all major secret-store integrations and avoids embedding multiple secret-store client libraries in the server, which would expand the dependency surface and the security review surface beyond the project's minimal-codebase target.
*Source.* ODS-FR-TSIG-006; ODS-FR-XOT-007; ODS-FR-COOKIE-004; operational security for key material.
*Note.* The world-readable check (POSIX file mode "other" class) is Linux-specific. Per ODS-NFR-PORT-001 the target platform is Linux; portability to other operating systems would require this check to be redefined or relaxed for the target's permission model.
*Verification.* Startup tests with various secret-file permission modes; verify external-secret-store integration is achievable via file-path projection.

**ODS-IF-CONF-005.** The server MUST validate the entire configuration at startup before binding any listening sockets. Validation MUST include schema conformance, TSIG algorithm support per §4.9, XoT trust-anchor parseability per §4.10, network-address parseability, and value-range checks for numeric parameters (port numbers, timeout values, rate limits). Any validation failure MUST cause the server to log a clear error message identifying the specific configuration defect and exit with non-zero status; the server MUST NOT begin partial operation with partially valid configuration.
*Source.* Fail-fast configuration discipline; ODS-INV-005.
*Verification.* Tests with deliberately invalid configurations across each validation category.

**ODS-IF-CONF-006.** The server SHOULD also accept a documented subset of configuration parameters via environment variables. Where supported, environment variables MUST take precedence over the corresponding configuration file value. Not every configuration parameter requires an environment-variable equivalent; the supported subset is documented per ODS-IF-CONF-002.
*Source.* Container-native operational convenience.
*Verification.* Tests confirming environment-variable precedence for supported parameters.

**ODS-IF-CONF-007.** The server MUST NOT install a SIGHUP handler that re-reads configuration, in accordance with ODS-INV-005 and ODS-NEG-011. Configuration changes are applied only by process restart.
*Source.* ODS-INV-005; ODS-NEG-011.
*Verification.* SIGHUP signal tests confirming no configuration change behaviour.

**ODS-IF-CONF-008.** The server SHOULD detect operationally suspicious but technically valid configurations and emit warning-level log entries at startup describing each concern, WITHOUT preventing startup. The catalogue of suspicious patterns the server SHOULD detect includes at minimum:
- TSIG fudge value larger than 60 seconds (RFC 8945 §10.4 recommends short fudges; per ODS-NFR-REL-007 operationally tipical is 5–30 seconds);
- SOA REFRESH or RETRY values approaching the maximum effective ceiling of ODS-FR-ZSM-011 (suggesting the operator may have intended a smaller value);
- RRL allowlist (ODS-FR-RRL-006) containing `0.0.0.0/0` or `::/0` (effectively disabling RRL);
- DNS Cookies disabled in configuration (operationally significant security regression);
- XoT trust anchors expiring within 30 days (certificate-rotation reminder);
- TSIG keys configured with HMAC-SHA1 (RFC 8945 §6 marks SHA-1 as legacy; SHA-256 is preferred);
- TCP idle timeout larger than 120 seconds (resource-holding risk);
- AXFR/IXFR ingestion size cap (ODS-FR-AXFR-024) below 100 MiB (likely operationally insufficient);
- `chaos.version` configured to a precise build-version-shaped value, making an operator-visible software-build disclosure choice.

The exhaustive list and individual messages are part of the Operator Deployment Guide per ODS-NFR-MAINT-009. Warnings MUST be emitted as structured log entries with distinct categorisation (e.g., `category: configuration_warning`) to support operator filtering and orchestrator gating. The server MUST also expose a configuration-warning count via the metrics endpoint per ODS-NFR-OBS-005, allowing operators to alert on the count being non-zero.
*Source.* Operational requirement; resolution of v0.4 audit finding about non-aborting configuration concerns.
*Verification.* Tests with deliberate suspicious configurations across each enumerated pattern; verify warning emission, structured categorisation, and metric counter increment; verify the server starts despite the warnings.

**ODS-IF-CONF-009.** The server MUST support a `--dump-config` command-line invocation mode that reads and validates the configuration (including environment-variable overrides per ODS-IF-CONF-006) and emits the effective configuration to standard output in canonical TOML form, then exits with code 0. The dumped configuration MUST have all secret material redacted: TSIG shared secrets replaced with the literal `<redacted>`, XoT private key contents replaced with `<redacted>`, DNS Cookie secrets replaced with `<redacted>`. File-path references to secret files MUST be preserved verbatim (paths are not secret). The configuration-warning catalogue of ODS-IF-CONF-008 MUST be evaluated and any triggered warnings emitted to standard error before the configuration dump.

This mode MUST NOT bind any sockets, MUST NOT contact any primary, MUST NOT initiate any transfer, and MUST NOT open any file other than the configuration file and the secret files referenced by it.
*Source.* Operational requirement; resolution of v0.4 audit finding about effective-configuration dump.
*Verification.* Tests with various configurations including env-var overrides; verify dumped output matches the effective configuration, secrets are redacted, and exit code is 0; verify no socket binding or network activity occurs during dump.

**ODS-IF-CONF-010.** The server MUST support a `--validate-config` command-line invocation mode that performs the full configuration validation of ODS-IF-CONF-005 against a configuration file specified on the command line (or the default path), then exits with code 0 if valid and the appropriate non-zero exit code per ODS-IF-PROC-001 if invalid, with diagnostic output to standard error. Warning-level concerns per ODS-IF-CONF-008 MUST be emitted to standard error but MUST NOT cause non-zero exit. This mode MUST NOT bind any sockets, MUST NOT contact any primary, and MUST NOT perform any operation other than configuration file reading and validation.
*Source.* Operational requirement; CI/CD pipeline pre-deployment validation; resolution of v0.4 audit finding about standalone configuration validation.
*Verification.* Tests with valid configurations (expecting exit 0), invalid configurations across each validation category (expecting exit 2 per ODS-IF-PROC-001), and configurations triggering warnings (expecting exit 0 with diagnostic output).

**ODS-IF-CONF-011.** Configuration parameter names within the TOML configuration file MUST follow a uniform convention:

- Lowercase `snake_case` for individual key segments (e.g., `fudge_seconds`, `grace_period_seconds`, NOT `fudgeSeconds` or `FudgeSeconds`).
- Hierarchical organisation via TOML section headers `[section]` and dotted-key references in inline tables (e.g., `[tsig]` section containing `fudge_seconds`, referenced externally as `tsig.fudge_seconds`).
- Explicit unit suffix for numeric values where applicable: `_seconds` for time in seconds, `_ms` for milliseconds, `_bytes` for byte counts, `_pct` for percentages expressed as integers 0–100, `_per_minute` for rate expressed as count per minute.
- Positive integer counts without a unit suffix where the unit is implicit from category (port numbers, counts of records, counts of zones).
- Boolean parameters named with a verb form indicating the affirmative (e.g., `rrl.enabled = true`, NOT `rrl.disable = false`).

The complete naming convention, plus the per-parameter type and default value, is part of the schema documentation maintained per ODS-IF-CONF-002. The schema MUST also document the operator-facing parameter name for each NFR-introduced parameter referenced in §5 (e.g., `shutdown.grace_period_seconds`, `tsig.fudge_seconds`, `cookie.timestamp_past_tolerance_seconds`, `health.livez_timeout_ms`, etc.).
*Source.* Operational requirement; resolution of v0.4 audit finding about configuration parameter naming consistency.
*Verification.* Schema documentation review confirming uniform conformance; configuration parsing tests rejecting parameters violating the convention as unknown keys per the schema.

**ODS-IF-CONF-012.** Environment variable names corresponding to configuration parameters per ODS-IF-CONF-006 MUST follow the pattern `ODS_<SECTION>_<KEY>`, with both `<SECTION>` and `<KEY>` uppercased and dots replaced by underscores. Examples:
- `[tsig] fudge_seconds = 300` becomes `ODS_TSIG_FUDGE_SECONDS=300`.
- `[shutdown] grace_period_seconds = 30` becomes `ODS_SHUTDOWN_GRACE_PERIOD_SECONDS=30`.
- `[health] livez_timeout_ms = 1000` becomes `ODS_HEALTH_LIVEZ_TIMEOUT_MS=1000`.

Where a configuration parameter is nested deeper than two levels (per-zone or per-key tables), environment-variable equivalents are NOT supported; such parameters are configured only via the file.

Unrecognised environment variables matching the `ODS_*` pattern but not corresponding to any known configuration parameter MUST be detected at startup and emitted as warnings per ODS-IF-CONF-008 (likely operator typo), but MUST NOT prevent startup. Environment variables not matching the `ODS_*` pattern are ignored regardless of content.
*Source.* Operational requirement; resolution of v0.4 audit finding about environment variable naming.
*Verification.* Configuration tests with each parameter overridden via the corresponding `ODS_*` environment variable; tests with deliberately misspelled `ODS_*` variables (expecting warning); tests with non-`ODS_*` variables (expecting silent ignore).

**ODS-IF-CONF-013.** *(Zone Provisioning configuration schema.)* The configuration MUST express explicit secondary zones via `[[zones]]` and RFC 9432 catalog zones via `[[catalog_zones]]`. This schema intentionally avoids a single wrapper subtree because TOML already has natural array tables for repeatable zone definitions and because explicit zones and catalog zones may coexist in the same process. The schema is:

```toml
[[zones]]
name = "example.com."
primaries = ["10.0.0.1", "10.0.0.2"]
tsig_key = "key-example."     # optional unless transfer.require_tsig = true

[[zones.transfer_primaries]]
addr = "10.0.0.1:853"
transport = "xot"
server_name = "primary.example.com"
trust_anchors = ["/etc/oxidedns/xot-ca.pem"]

[[catalog_zones]]
name = "catalog.dns.example.com."
primaries = ["10.0.0.1:53", "10.0.0.2:53"]  # per ODS-NFR-SEC-012
tsig_key = "catalog-tsig-key."               # MANDATORY per ODS-NFR-SEC-010
serve_catalog_zone = false
# max_member_zones = 10000                   # per ODS-NFR-SEC-013 when implemented
```

The configuration validator (per ODS-IF-CONF-005) MUST verify:
- at least one `[[zones]]` or `[[catalog_zones]]` entry is present;
- each `[[zones]]` entry has an absolute apex name and at least one `primaries` or `transfer_primaries` target;
- each `[[catalog_zones]]` entry has an absolute catalog apex name, at least one `primaries` or `transfer_primaries` target, and a `tsig_key`;
- explicit `transfer_primaries` entries satisfy the per-primary XoT validation rules of §4.10 where `transport = "xot"`;
- catalog member zones inherit the catalog entry's transfer primaries, TSIG key, NOTIFY source policy, transfer source binding, and transfer limits; catalog per-member `primaries` properties MUST NOT override those inherited coordinates per ODS-NFR-SEC-011.

The interaction with TSIG key definitions (the separately-defined `[[tsig_keys]]` table, unchanged from prior revisions) is by reference: `tsig_key` values in `[[zones]]` and `[[catalog_zones]]` name keys defined in the TSIG key table.
*Source.* §4.20; ODS-NFR-SEC-010 through ODS-NFR-SEC-013.
*Verification.* Configuration round-trip tests for explicit-zone, catalog-zone, and mixed configurations; tests for each validator condition expecting startup failure with a clear diagnostic in each case.

**ODS-IF-CONF-014.** After applying environment-variable overrides per ODS-IF-CONF-012 to the configuration parsed from the TOML configuration file per ODS-IF-CONF-001, the configuration validator (per ODS-IF-CONF-005) MUST re-run all structural and cross-field validation against the post-override configuration. Environment-variable overrides MUST NOT bypass the validation envelope established at TOML parse time: a value that would have been rejected if present in the TOML file (e.g., a numeric value below an established minimum, a string outside an enumerated set, a cross-field combination violating a stated constraint) MUST equally be rejected when supplied via environment variable. The process MUST fail to start with a clear diagnostic identifying the offending parameter name (including its `ODS_*` environment variable spelling), the supplied value, and the constraint that was violated.
*Source.* Resolution of Alpha audit finding F4 (environment-override post-validation gap); coherence with ODS-IF-CONF-005 validation envelope.
*Note.* The original TOML-only validation occurred before environment-variable overrides were applied, allowing an override to place a structurally valid TOML configuration into an out-of-envelope state. This requirement closes that gap. Implementations MAY satisfy this requirement by structuring the validator as a single function over the post-merge configuration value, rather than running the validator twice.
*Verification.* Tests with TOML configurations that validate cleanly and environment-variable overrides that introduce out-of-envelope values; verify startup failure with the expected diagnostic. *Added in v0.9.*

**ODS-IF-CONF-015.** The server MUST accept a configurable maximum NSEC3 iteration count (per ODS-FR-DNSSEC-014) under the `[dnssec]` configuration subtree or equivalent. The parameter name MUST be `nsec3_max_iterations`, an unsigned integer in the inclusive range 0–65535. The default value MUST be 100, the soft ceiling recommended by RFC 9276 / BCP 236 §2.4 for legacy NSEC3 zones. Where the configured value exceeds 100, the configuration warning `nsec3_iterations_large` MUST be emitted at startup per ODS-IF-CONF-008, recording the configured value and the BCP 236 ceiling.
*Source.* ODS-FR-DNSSEC-014; RFC 9276 §2.4.
*Note.* A value of 0 means that NSEC3 chain proofs are omitted from negative responses for any zone whose NSEC3PARAM iteration count is greater than zero — i.e., the strictest setting, consistent with RFC 9276's recommendation that new NSEC3 deployments use zero iterations.
*Verification.* Configuration round-trip tests across the range; warning emission test for values above 100; tests for the boundary values (0, 100, 101). *Added in v0.9.*

**ODS-IF-CONF-016.** The server MUST accept a configurable boolean parameter that, when enabled, relaxes the strict out-of-zone owner-name rejection of ODS-FR-AXFR-012 as specified in ODS-FR-AXFR-025. The parameter name MUST be `accept_out_of_zone_glue`, under the `[transfer]` configuration subtree or equivalent. The default value MUST be `false` (strict v0.8 behaviour). Where the parameter is set to `true`, the configuration warning `out_of_zone_glue_tolerance_enabled` MUST be emitted at startup per ODS-IF-CONF-008 to make the deviation from the default policy observable in the operator's observability surface.
*Source.* ODS-FR-AXFR-025.
*Note.* The parameter is process-global for the Engineering MVP; per-zone selectivity is a deliberate non-goal and would be evaluated in a future revision should an operational need arise.
*Verification.* Configuration round-trip tests for both values; warning emission test for the `true` case; behavioural test confirming the AXFR-time effect per ODS-FR-AXFR-025. *Added in v0.9.*

**ODS-IF-CONF-017.** The server MUST accept a configurable Extended DNS Errors profile under the `[edns]` configuration subtree or equivalent. The parameter name MUST be `extended_dns_errors`; accepted values are `off` and `minimal`. The default value MUST be `off`. The `minimal` value enables only the bounded diagnostic mappings specified in ODS-FR-EDNS-018 and MUST NOT enable arbitrary policy disclosure or free-form EXTRA-TEXT.
*Source.* ODS-FR-EDNS-018; RFC 8914 §2.
*Verification.* Configuration round-trip tests for both values; environment-override tests; wire-format tests confirming that `off` suppresses EDE and `minimal` enables only the specified mappings. *Added in v0.9 implementation alignment.*

**ODS-IF-CONF-018.** The server MUST accept optional CHAOS-class self-identification values under a `[chaos]` configuration subtree. The schema is:

```toml
[chaos]
# Response to `version.bind.` / `version.server.` CH/TXT queries
# (ODS-FR-CHAS-001). Empty or absent means REFUSED.
version = ""

# Response to `hostname.bind.` / `id.server.` CH/TXT queries
# (ODS-FR-CHAS-002). Empty or absent means fall back to [server].nsid
# when NSID is configured and printable; otherwise REFUSED.
hostname = ""
```

The configuration validator (per ODS-IF-CONF-005) MUST verify that `chaos.version` and `chaos.hostname`, when present, are strings whose encoded value fits in one DNS TXT character-string (0 through 255 octets). The `[chaos]` section itself is optional. Where `chaos.version` is configured to a precise build-version-shaped value, for example a semantic-version prefix matching `^[0-9]+\.[0-9]+\.[0-9]+`, the server SHOULD emit the `chaos_version_discloses_build` startup warning per ODS-IF-CONF-008. The warning is informational and MUST NOT prevent startup.
*Source.* §4.21; ODS-FR-CHAS-001; ODS-FR-CHAS-002.
*Note.* The incoming v0.9.1 SRS attachment allocated this configuration requirement as `ODS-IF-CONF-017`; this repository already uses `ODS-IF-CONF-017` for the bounded Extended DNS Errors profile. The CHAOS configuration requirement is therefore numbered `ODS-IF-CONF-018` to preserve identifier stability and avoid collision.
*Verification.* Configuration round-trip tests across absent, empty, populated, and oversized values; environment-override tests where supported; warning emission test for build-version-shaped `chaos.version`. *Added in v0.9.1.*

## 6.3 Logging Interface

The area code **LOG** is allocated.

**ODS-IF-LOG-001.** The server MUST write log entries to standard output and standard error: entries at the info and debug levels to stdout, entries at the warning and error levels to stderr. The server MUST NOT open, create, or write to any log file directly. Persistent log storage is the responsibility of the supervising process or log-collection infrastructure.
*Source.* Container-native logging convention; ODS-INV-004 (no persistent state, no filesystem writes beyond standard streams).
*Verification.* Log-output stream verification across log levels.

**ODS-IF-LOG-002.** Log entry format MUST be either JSON or logfmt, as selected by configuration per §6.2. The default format MUST be JSON. Format selection is global to the process and applies uniformly to stdout and stderr output. The chosen format MUST conform to the structured-logging requirements of ODS-NFR-OBS-001.
*Source.* ODS-NFR-OBS-001.
*Verification.* Per ODS-NFR-OBS-001.

**ODS-IF-LOG-003.** Log level MUST be configurable via the configuration file per §6.2 and via environment variable (`ODS_LOGGING_LEVEL` or equivalent) per ODS-IF-CONF-006. The default log level MUST be info per ODS-NFR-OBS-002.
*Source.* ODS-NFR-OBS-002.
*Verification.* Per ODS-NFR-OBS-002.

**ODS-IF-LOG-004.** The server MUST NOT integrate directly with syslog, systemd-journald, Windows Event Log, or any other host-specific logging mechanism. Operators requiring such integration are expected to use standard tools (e.g., `systemd-cat`, log shipping agents) to redirect or transform the server's standard-stream output.
*Source.* Container-native logging convention; portability per §5.5.
*Verification.* Code review confirming no syslog/journald linkage; dependency review confirming no such libraries.

**ODS-IF-LOG-005.** Structured log entries emitted per ODS-NFR-OBS-001 MUST use a uniform set of canonical field names for the entities they describe. The canonical field set, applicable across all log emission sites, is:

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | RFC 3339 timestamp |
| `level` | string | `debug`, `info`, `warning`, `error` |
| `message` | string | Free-text descriptive message |
| `zone` | string | Zone apex name (lowercase, no trailing dot) |
| `peer_ip` | string | Peer IP address (IPv4 or IPv6 literal) |
| `peer_port` | integer | Peer port number |
| `transport` | string | `udp` or `tcp` |
| `qid` | integer | DNS query ID |
| `qname` | string | Query name (lowercase, no trailing dot) |
| `qtype` | string | Query type mnemonic (`A`, `AAAA`, `MX`, etc.) |
| `qclass` | string | Query class mnemonic (`IN`) |
| `rcode` | string | Response code mnemonic (`NOERROR`, `NXDOMAIN`, etc.) |
| `request_id` | string | Per-process unique request identifier |
| `correlation_id` | string | Identifier propagated across multi-step operations (transfer sessions, refresh cycles) |
| `category` | string | Coarse category for filtering (`query`, `transfer`, `notify`, `tsig`, `xot`, `rrl`, `cookie`, `configuration_warning`, `signal`, `startup`, `shutdown`) |
| `error` | string | Where present, a concise error description |
| `duration_ms` | number | Where present, an operation's elapsed time in milliseconds |
| `bytes` | integer | Where present, a byte count (transfer size, message size) |

Implementations MAY add further fields beyond this canonical set; the canonical fields, when applicable to a log entry, MUST use these names and types exactly. The intent is parser interoperability: log-aggregation tooling (Elastic, Loki, Splunk) can be configured against the canonical field set without per-version reconciliation.
*Source.* Operational requirement; log-aggregation ecosystem compatibility; parallel to the metric-naming convention of ODS-NFR-OBS-003.
*Verification.* Static analysis of log-emission sites confirming use of canonical field names where applicable; log-parser tests against representative log corpus.

**ODS-IF-LOG-006.** From process start until the configuration is successfully parsed and validated per ODS-IF-CONF-005, the server's bootstrap logging MUST use the JSON format and the `info` verbosity level, emitting at minimum the following structured entries:

- process start: `{"timestamp":"...","level":"info","category":"startup","message":"process started","version":"<version>","commit":"<commit>","rust_version":"<rust_version>"}`;
- configuration file read: `{"timestamp":"...","level":"info","category":"startup","message":"reading configuration","config_path":"<path>"}`;
- configuration validation result: success at info level; failure at error level with the specific defect identified per ODS-IF-CONF-005.

After successful configuration validation, the server applies the configured log format (per ODS-IF-LOG-002) and verbosity (per ODS-IF-LOG-003) for all subsequent emissions. Bootstrap log entries themselves are not retroactively re-formatted.
*Source.* Operational requirement; resolution of v0.4 audit finding about logging before configuration is parsed.
*Verification.* Log capture during startup confirming bootstrap entries in JSON at info level prior to configuration apply.

**ODS-IF-LOG-007.** Individual log entries MUST NOT exceed a configurable maximum length (parameter `logging.max_entry_length_bytes`, default 16384 bytes). Entries exceeding the limit MUST be truncated with a clearly visible truncation marker (the string `...<truncated>` appended to the message body) and a `truncated: true` field in the structured form. Truncation at this layer is a defensive measure against accidental large emissions (e.g., a programming error attempting to log a whole zone); intentional emission of large content (zone dumps, full configuration) is performed via dedicated CLI operations (ODS-IF-CONF-009) not via the logging path.
*Source.* Defensive operational engineering; protection against log aggregation pipeline saturation.
*Verification.* Tests with deliberately oversized log entries; verify truncation marker and `truncated` field; verify the entry remains parseable as valid JSON or logfmt despite truncation.

**ODS-IF-LOG-008.** Log emission at the `debug` level MUST use lazy message-construction: the log message string (including formatted fields) MUST NOT be constructed when the active log verbosity (per ODS-IF-LOG-003) filters out `debug` entries. The standard `tracing` crate provides this behaviour through macro-based level-check inlining; this requirement records the expectation. The hot DNS query path (ODS-FR-QRY-* requirements) MAY emit at `debug` level for per-query operational visibility without paying per-query formatting cost in production deployments (which default to `info` per ODS-NFR-OBS-002). This requirement MUST be verified at the implementation level: profiling under production-level (`info`) verbosity MUST show no measurable cost from debug-level log statements in the query path.
*Source.* Performance requirement; intersection of observability and the throughput targets of §5.1.
*Verification.* Profiling under `info` verbosity confirming debug-level statements have zero allocation; code review confirming use of macro-based level-check rather than runtime-formatted-then-discarded patterns.

## 6.4 Health and Metrics Endpoint

The area code **HEALTH** is allocated.

**ODS-IF-HEALTH-001.** The server MUST expose a combined health and metrics endpoint over plain HTTP/1.1 (no TLS, no authentication). The endpoint is activated by configuration per §6.2; when not configured to be active, no HTTP listening socket MUST be opened.

When activated, the endpoint's bind address is determined as follows:
- If the operator explicitly configures `health.bind_address` and `health.bind_port` in the `[health]` section, the endpoint binds to those values exactly.
- Otherwise, the endpoint binds to the address(es) configured under `interface.mgmt` (per ODS-IF-NET-005) at a default port (parameter `health.default_port`, default 8080).
- If neither `health.bind_address` nor `interface.mgmt` is configured, the endpoint binds to localhost (`127.0.0.1` and `::1`) at the default port.

This layered default makes the common case ("expose health alongside other operator access on the management interface") trivial to configure while preserving the operator's option to place the endpoint on its own dedicated address.
*Source.* Operational requirement; orchestrator-friendly probing; resolution of v0.4 audit finding about ambiguity between `interface.mgmt` and the health endpoint's own bind configuration.
*Note.* HTTP/1.1 without TLS is the dominant pattern for in-cluster service probes. Operators requiring secure exposure are expected to bind the endpoint to a private interface or deploy it behind a reverse proxy at the orchestrator level.
*Verification.* Endpoint reachability tests across enabled and disabled configurations; tests confirming the bind address precedence (explicit override > interface.mgmt default > localhost default).

**ODS-IF-HEALTH-002.** When activated, the endpoint MUST serve the following HTTP paths in response to GET requests, with the response body content as specified:

**`/livez`** — liveness probe per ODS-NFR-OBS-004. HTTP status 200 whenever the process is able to respond to the probe at all (regardless of zone-load state or draining state). Response body (JSON, MIME type `application/json`):

```json
{"status":"alive","version":"<version>","uptime_seconds":12345}
```

The `uptime_seconds` field reports elapsed wall-clock time since process start. Returns HTTP failure (5xx) or no response only if the process is unable to respond within the configurable liveness-probe timeout (parameter `health.livez_timeout_ms`, default 1000 ms).

**`/readyz`** — readiness probe per ODS-NFR-OBS-004. HTTP status 200 with the following body when in the **ready** state (at least one zone in ACTIVE state per ODS-FR-ZONE-006, and not draining):

```json
{"status":"ready","version":"<version>","zones_active":1234,"zones_loading":12,"zones_expired":0}
```

HTTP status 503 with the following body when **not-ready** (no zone yet ACTIVE). The `reason` field is a stable machine-readable reason such as `loading` when at least one zone is loading or `no_active_zones` when no active zone is present:

```json
{"status":"not-ready","reason":"loading","version":"<version>","zones_active":0,"zones_loading":42,"zones_expired":0}
```

HTTP status 503 with the following body when **draining** (SIGTERM received, graceful shutdown per ODS-NFR-REL-001):

```json
{"status":"draining","version":"<version>","grace_period_remaining_seconds":15}
```

**`/healthz`** — readiness alias. Behaviour, status codes, and body content are identical to `/readyz`. This endpoint is supported in the MVP.

**`/metrics`** — returns server metrics in the Prometheus / OpenMetrics text exposition format per ODS-NFR-OBS-003. HTTP status 200 with the metrics text body, MIME type `text/plain; version=0.0.4` (Prometheus exposition convention).

All other paths — return HTTP status 404 with a minimal JSON body `{"error":"not_found","path":"<requested_path>"}`.
Methods other than GET MUST receive HTTP status 405 with body `{"error":"method_not_allowed","method":"<received_method>"}`.

The JSON body field names are part of the externally observable interface stability commitment per ODS-NFR-MAINT-006; additions of new optional fields are permitted at minor version increments, removals or semantic changes require a major version increment.
*Source.* Operational requirement; Kubernetes probe conventions; Prometheus scraping convention; ODS-NFR-OBS-004; resolution of v0.4 audit finding about probe body content.
*Verification.* HTTP request tests against each path and method combination; body schema validation; state-transition tests verifying `/livez` and `/readyz` exhibit independent semantics under SIGTERM and LOADING conditions; tests confirming response body field names match the specification.

**ODS-IF-HEALTH-003.** The endpoint MUST be accessible without authentication. Network-layer access control — firewall rules, network policy, or binding to a private interface — is the operator's responsibility.
*Source.* Operational simplicity.
*Note.* This is an opinionated stance: authentication on a probe endpoint is operationally fraught (key distribution to probes, token rotation, etc.) and adds complexity disproportionate to the security benefit. The standard mitigation — bind to a private interface, or place the endpoint behind a reverse proxy that handles authentication at the orchestrator's edge — is the appropriate boundary.
*Verification.* Endpoint access tests without credentials confirming response.

**ODS-IF-HEALTH-004.** The endpoint MUST be served from a separate thread or asynchronous task isolated from the main DNS query-handling path, such that endpoint scraping load — including high-frequency metric scraping by aggressive Prometheus configurations — MUST NOT measurably impact DNS query latency as measured against ODS-NFR-PERF-002 and ODS-NFR-PERF-003.
*Source.* Operational isolation.
*Verification.* Load tests with high-frequency metrics scraping concurrent with sustained DNS query load.

**ODS-IF-HEALTH-005.** Response time bounds:
- The `/livez`, `/readyz`, and `/healthz` endpoints MUST respond within 100 milliseconds under all conditions other than the explicit liveness-probe-timeout case of ODS-IF-HEALTH-002. The probe response time is the elapsed time between TCP-level request receipt and the start of response transmission.
- The `/metrics` endpoint SHOULD respond within 500 milliseconds for deployments serving up to 1,000 zones. For larger deployments, the response time scales approximately linearly with the number of exposed metric series; the upper bound is operationally evaluated rather than normatively specified.
- The `/metrics` endpoint MUST support response compression: when the client request carries `Accept-Encoding: gzip`, the response MUST be transmitted with `Content-Encoding: gzip`. Gzip compression substantially reduces response size for large-zone-count deployments (10× compression ratio is typical for repetitive metrics text).
*Source.* Operational requirement; orchestrator probe timeout discipline (Kubernetes default 1-second probe timeout).
*Verification.* Probe response-time measurement under load; gzip-compressed response verification; `/metrics` response-time scaling tests across zone counts.

**ODS-IF-HEALTH-006.** The `/metrics` path MUST support an operator-configurable per-source-IP rate limit (parameter `health.metrics_rate_limit_per_minute`, default 60 — i.e., one scrape per second per source on average). Requests exceeding the limit MUST receive HTTP status 429 (Too Many Requests) with a `Retry-After` header indicating seconds to wait, and a JSON body `{"error":"rate_limited","retry_after_seconds":<n>}`. The rate limit applies independently to the `/metrics` path; `/livez`, `/readyz`, and `/healthz` MUST NOT be rate-limited (probe traffic must always be permitted to reach the server even under metric-scrape overload).

Rate-limit accounting is per source IP address (no prefix aggregation, as monitoring tools typically scrape from a small known set of addresses). The accounting state is bounded; entries are evicted via LRU after a configurable idle period (parameter `health.metrics_rate_limit_idle_seconds`, default 300 seconds).
*Source.* Operational requirement; resolution of v0.4 audit finding about metrics endpoint scrape protection.
*Verification.* Sustained metrics scrape at rates beyond the configured limit; verify HTTP 429 with `Retry-After`; verify probes continue to be served during the scrape rate-limiting.

## 6.5 Process Signals

The area code **SIG** is allocated.

**ODS-IF-SIG-001.** The server MUST handle SIGTERM by initiating graceful shutdown in accordance with ODS-NFR-REL-001 and ODS-NFR-REL-005. The 100-millisecond signal-to-action latency of ODS-NFR-REL-005 — listening sockets closed within 100 ms of SIGTERM receipt, `/readyz` reporting `draining` within 100 ms — applies regardless of the server's load state at the moment of signal receipt.
*Source.* ODS-NFR-REL-001; ODS-NFR-REL-005; container orchestrator convention.
*Verification.* SIGTERM tests confirming graceful shutdown behaviour; instrumented measurement of listen-socket-close and `/readyz` transition latency.

**ODS-IF-SIG-002.** The server MUST handle SIGINT identically to SIGTERM, initiating graceful shutdown.
*Source.* Interactive operator convenience (Ctrl+C during foreground execution).
*Verification.* SIGINT tests.

**ODS-IF-SIG-003.** The server MUST NOT install a handler for SIGHUP. Receipt of SIGHUP MUST be ignored in accordance with ODS-INV-005 and ODS-NEG-011.
*Source.* ODS-INV-005; ODS-NEG-011.
*Verification.* SIGHUP signal tests; observe no behavioural change.

**ODS-IF-SIG-004.** The server MUST NOT install handlers for SIGUSR1, SIGUSR2, SIGQUIT, or any other signal not enumerated in this subsection, with the single exception of SIGPIPE, which MUST be ignored (signal disposition set to `SIG_IGN`) to prevent process termination when stdout, stderr, or any other broken pipe condition occurs. SIGPIPE handling is not "installing a handler" in the registry-of-actions sense — it is signal disposition setup performed once at process startup. Any signal not enumerated in ODS-IF-SIG-001 through ODS-IF-SIG-003 and not covered by the SIGPIPE exception MUST follow operating-system default behaviour (typically process termination with core dump for SIGQUIT, termination for SIGUSR1 and SIGUSR2).
*Source.* Minimal signal-handling surface; principle of least operational interface; resolution of v0.4 audit finding about SIGPIPE and consumer-death-induced server termination.
*Verification.* Code review confirming the signal-handler registrations exactly match the enumeration of ODS-IF-SIG-001 through ODS-IF-SIG-003 plus the SIGPIPE ignore disposition; runtime tests with stdout/stderr consumers terminated mid-stream confirming the server continues operation rather than dying from SIGPIPE.

## 6.6 Process Lifecycle and Command-Line Interface

This subsection specifies the server's process-level interface beyond signal handling: the command-line invocation modes, the exit codes used to communicate termination cause to supervisors, and the version and help facilities standard for production-grade Unix software.

The area code **PROC** is allocated.

**ODS-IF-PROC-001.** The server MUST use the following exit code convention, consistent with the BSD `sysexits.h` (FreeBSD <sysexits.h>) and POSIX convention where applicable:

| Exit code | Symbolic name | Meaning |
|---|---|---|
| 0 | `EX_OK` | Successful termination (graceful shutdown completed per ODS-NFR-REL-001; `--dump-config`, `--validate-config`, `--version`, `--help` modes completed successfully). |
| 1 | `EX_GENERAL` | General error (runtime failure not classified under a more specific code; panic with controlled exit; uncategorised internal error). |
| 2 | `EX_CONFIG_INVALID` | Configuration validation failure (per ODS-IF-CONF-005 or ODS-IF-CONF-010): the configuration file was read but contained errors. |
| 64 | `EX_USAGE` | Command-line usage error: invalid arguments, conflicting flags, missing required argument. |
| 70 | `EX_SOFTWARE` | Internal software error: a panic occurred and was caught before exit, indicating an implementation bug; operators SHOULD report this with the surrounding log context. |
| 71 | `EX_OSERR` | Operating system error: privilege drop failed, `setresuid` failed, `rlimit` insufficient and not raisable, etc. |
| 73 | `EX_CANTCREAT` | Cannot create or bind a required output: listen socket failed to bind per ODS-IF-NET-004; secret file unreadable per ODS-IF-CONF-004. |
| 74 | `EX_IOERR` | I/O error reading the configuration file or secret files referenced by it. |
| 78 | `EX_CONFIG` | Configuration file unparseable (syntax error in TOML, file not found, or file unreadable due to permissions): distinct from `EX_CONFIG_INVALID` (which is syntactically valid but semantically incorrect). |

Where a graceful path of execution leads to a deliberate non-zero exit (e.g., `--validate-config` finding an invalid configuration), the appropriate symbolic exit code MUST be used per the table above. The server MUST NOT use exit codes outside this enumeration; codes returned by panic-recovery paths that cannot be cleanly mapped MUST default to `EX_GENERAL` (1) with an error-level log entry identifying the unmapped cause.

The exit code MUST be observable by orchestrators (Kubernetes container restart policy, systemd `Restart=` directives) and used to inform appropriate operator action: `EX_CONFIG_INVALID` and `EX_CONFIG` typically warrant configuration review rather than restart; `EX_OSERR` and `EX_CANTCREAT` typically warrant environment review (privileges, port conflicts); `EX_SOFTWARE` typically warrants bug reporting.
*Source.* BSD `sysexits.h` (System V/BSD UNIX programming convention); operational requirement for orchestrator-friendly process exit semantics; resolution of v0.4 audit finding about exit code convention.
*Verification.* Exit-code tests across each enumerated failure scenario; orchestrator integration tests confirming correct interpretation.

**ODS-IF-PROC-002.** The server MUST support `--version` and `-V` command-line flags that print version information to standard output and exit with code 0 (`EX_OK` per ODS-IF-PROC-001). The output format MUST include, in human-readable multi-line plain text:
- the server name and version (matching the `version` label of the `oxidedns_secondary_build_info` metric per ODS-NFR-OBS-006);
- the Rust compiler version used to build;
- the build commit hash (Git short SHA or equivalent);
- the build timestamp (RFC 3339).

Example output:

```
oxidedns <version>
build commit: <commit>
build timestamp: <build-timestamp>
rustc: <rustc-version>
SRS: OxideDNS Secondary SRS v0.9.1
Role: secondary-only authoritative DNS server
License: MIT OR Apache-2.0
```

The server MAY support an additional `--version --json` invocation form that emits the same information in JSON for tooling integration. The flag MUST NOT bind any sockets, MUST NOT read the configuration file, and MUST NOT contact any external service.
*Source.* Standard CLI convention; operational requirement for version inspection.
*Verification.* `--version` and `-V` invocation tests confirming output format and exit code 0.

**ODS-IF-PROC-003.** The server MUST support `--help` and `-h` command-line flags that print usage information to standard output and exit with code 0. The usage output MUST include at minimum:
- the synopsis of process invocation (executable name, summary of accepted arguments and flags);
- a description of each command-line flag with its purpose and default value where applicable;
- a brief description of the configuration file mechanism (referencing ODS-IF-CONF-001's default path);
- a pointer to the Operator Deployment Guide per ODS-NFR-MAINT-009 for fuller documentation;
- a reference to the project's primary information source (repository URL, documentation URL).

Invocation with an unrecognised flag MUST emit a brief error message to standard error and exit with code 64 (`EX_USAGE` per ODS-IF-PROC-001).
*Source.* Standard CLI convention.
*Verification.* `--help` and `-h` invocation tests confirming output content and exit code 0; unrecognised-flag tests confirming exit code 64.

**ODS-IF-PROC-004.** The server MAY support an `--example-config` command-line invocation mode that emits a fully commented example configuration to standard output and exits with code 0. The example MUST cover all required configuration sections and the most commonly used optional sections, with inline comments documenting each parameter's purpose and default value. This invocation mode MUST NOT bind any sockets, MUST NOT read any input file, and MUST NOT contact any external service. The example output, when redirected to a file and used as configuration, MUST be a valid configuration that the server accepts under ODS-IF-CONF-005.

This requirement is MAY rather than MUST because the example-configuration content is also maintained in the Operator Deployment Guide per ODS-NFR-MAINT-009. Where implemented in the binary, it serves as a quick-start convenience.
*Source.* Operational convenience; resolution of v0.4 audit finding about example configuration generation.
*Verification.* Where implemented: `--example-config` invocation produces output that, when validated per `--validate-config`, succeeds with exit code 0.

# 7. Verification Strategy

This section specifies how the requirements of §3 through §6 are verified. It does *not* enumerate concrete test cases — that is the function of the Test Plan, a sibling document per §1.6.1. Rather, this section specifies the methods by which verification is performed, the scope of interoperability testing, the structure of RFC-compliance assessment, the acceptance criteria mapping requirements to PID milestones, and the boundary between the SRS and the Test Plan.

The requirement category for this section is **ODS-VER-NNN** for verification requirements; the AREA component is omitted, following the pattern of ODS-INV-NNN and ODS-NEG-NNN. The category is registered in §1.4.3 and Appendix D.5.1.

## 7.1 Verification Methods

The following methods are used, individually or in combination, to verify the requirements of this SRS:

**Inspection.** Manual static code review, documentation review, and structured walkthrough by a qualified reviewer. Used for requirements verifiable by human examination of source code or static artifacts: architectural invariants, requirements concerning code structure or design discipline, prohibitions where automated detection is impractical.

**Static analysis.** Automated source-code analysis by tooling, runnable without human intervention and producing build-blocking pass/fail results in the active continuous gate (`scripts/check.sh` during the private-repository Engineering MVP profile, hosted CI once enabled for release). Tools in scope include: `cargo clippy` (style and common-mistake linting), `cargo geiger` (enumeration of `unsafe` blocks per ODS-NFR-MAINT-003 and ODS-INV-006), `cargo deny` / `cargo audit` class dependency advisory checks per ODS-NFR-SEC-006, `cargo-llvm-cov` (line coverage measurement per ODS-NFR-MAINT-007), and dependency-tree audits. Distinct from manual Inspection; runs continuously per ODS-VER-011.

**Unit test.** Automated, code-level tests of individual functions or modules in isolation. Used for parser correctness on bounded input sets, RR-type decoding, algorithmic logic (SOA serial arithmetic per RFC 1982, RRL token-bucket arithmetic), and any requirement whose verification can be made deterministic without external dependencies.

**Property-based test.** Hypothesis-style testing using `proptest`, `quickcheck`, or equivalent: generates randomised inputs satisfying specified properties and asserts implementation invariants hold across the generated space (e.g., "round-trip parse-serialize yields the original bytes for any well-formed input", "RRL token-bucket accounting is monotonic"). Used as supplementary verification for wire-format parsers and algorithmic components, complementary to Unit test (which covers specific known cases) and Fuzz test (which seeks crashes on adversarial input).

**Integration test.** Automated, in-process tests exercising multiple modules together — for example, a query handler running against an in-memory zone store loaded from a synthetic AXFR response. Used for end-to-end behaviour within a single server process, without external network peers.

**Conformance test.** Tests deriving inputs from RFC-specified wire-format test vectors and verifying outputs against RFC-specified expected behaviour. Used for protocol-correctness requirements throughout §4.

**Differential test.** Side-by-side execution of two implementations on identical inputs, comparing outputs for semantic equivalence. Used as supplementary verification of protocol correctness; the reference implementation against which differential testing is performed (NSD, Knot DNS, or BIND 9) is recorded with each test result. Differential test is complementary to Interoperability test: the latter exercises peer-to-peer protocol communication, the former cross-checks response composition for identical query inputs.

**Interoperability test.** Tests of the server running against real implementations of peer roles — primary servers (NSD, Knot DNS, BIND 9) for inbound zone transfer and NOTIFY, TSIG-capable peers for authenticated transfers, DNS clients (`dig`, `kdig`, `drill`) for query response semantics. Used for any requirement whose verification depends on real-world peer behaviour and not just specification reading.

**Fuzz test.** Coverage-guided fuzzing using `cargo-fuzz`, AFL++, or equivalent, applied to wire-format parsers and any code path consuming untrusted input. Used for ODS-NFR-SEC-002 and as supporting evidence for parser-related functional requirements. Short-cadence fuzz compile/smoke checks (≤ 1 hour per parser) run through the active continuous gate where enabled; long-cadence runs (≥ 24 hours per parser) are gated to release per ODS-NFR-SEC-002.

**Performance test.** Sustained-load benchmarking, latency-distribution measurement, capacity-scaling tests. Used for §5.1 (PERF) and the capacity-related requirements of §5.7 (RES). Reproducibility requires execution on the Reference Hardware Profile of Appendix E.2 against the Reference Query Mix of Appendix E.3 for normative conformance assertions.

**Soak test.** Long-duration runtime tests (days to weeks) under realistic workload, measuring memory consumption, file-descriptor stability, and detection of slow leaks or accumulating state. Used for ODS-NFR-REL-003 and supporting verification for §5.2 (REL).

**Operational test.** Deployment in representative environments (containers, virtual machines), exercising startup, signal handling, configuration parsing, and orchestrator integration. Used for §5.5 (PORT), §6.1, §6.2, §6.4, §6.5, §6.6.

**Security audit.** Periodic third-party review of the codebase, dependency set, and operational posture by security specialists external to the project team. Recommended at major release boundaries and following any ODS-NFR-SEC-007 disclosure. Findings are tracked under the vulnerability disclosure policy of ODS-NFR-SEC-007; remediation actions are recorded in release notes.

**External operator acceptance.** Independent deployment and verification by operators outside the project team. Used during PID Phase 4 (MVP testing) and as ongoing post-release validation per ODS-VER-008; constitutes the highest-confidence form of operational verification because it exercises the deployment guide, the configuration interface, and the operational interfaces under conditions the project team did not design.

**ODS-VER-001.** Every requirement in §3 through §6 carries a *Verification* field naming the method or methods by which it is verified. These named methods MUST be drawn exclusively from the catalogue enumerated in §7.1 above (Inspection, Static analysis, Unit test, Property-based test, Integration test, Conformance test, Differential test, Interoperability test, Fuzz test, Performance test, Soak test, Operational test, Security audit, External operator acceptance). Where a requirement's *Verification* field uses informal phrasing (e.g., "code review", "endpoint inspection"), the phrasing MUST be mappable to one of the named methods; ambiguous mappings are an SRS defect requiring revision. The catalogue is the single source of truth for verification method nomenclature; ad-hoc method names introduced in §3-§6 *Verification* fields MUST NOT be used.
*Source.* SRS internal consistency; foundation for the Test Plan's method-by-method test harness organisation.
*Verification.* Self-referential at the SRS level (an SRS internal consistency check performed at each release as part of the SRS review process); automated verification at the Test Plan level (each test case is tagged with the method it implements; CI verifies every requirement has at least one test case covering its declared method).

**ODS-VER-002.** Verification evidence — test outputs, benchmark results, code-review records, fuzz-test summaries, interop test logs, security audit reports — MUST be captured by the project's continuous integration system and retained for each release. Evidence retention period MUST be at least the longer of: (a) two years after the release; (b) the lifetime of the major version of which the release is part.
*Source.* Audit and reproducibility; PID §7.
*Verification.* CI pipeline review at release time; sample-based retrieval of evidence from past releases.

**ODS-VER-010.** Each release MUST be preceded by execution of the verification suite per ODS-VER-001 against the release candidate. Results MUST be captured in the release notes including, at minimum:
(a) per-requirement-category counts of Verified, Deferred, and Failed (using the verification status terminology of ODS-VER-009);
(b) any new Failed results compared to the previous release on the same major version;
(c) any newly Deferred results compared to the previous release on the same major version;
(d) the version identifiers and exact configurations of the primary implementations used in Interoperability test execution (per ODS-VER-013).

A release with any ODS-FR, ODS-NFR, ODS-IF, ODS-INV, or ODS-NEG requirement marked Failed (verification was expected to succeed but did not) MUST NOT proceed without an explicit project decision recorded in the release notes with rationale and target remediation release.
*Source.* Release-process discipline; resolution of v0.6 audit finding about absent pre-release verification gate.
*Verification.* Release-notes review at each release; sampling of past release notes confirming the required content.

**ODS-VER-011.** Verification methods are classified by execution cadence into three categories:
- **Continuous** — executed by the active continuous gate for the project stage, with results being build-blocking for accepted changes. During the private-repository Engineering MVP profile this gate is the local `scripts/check.sh` command; before formal SRS release acceptance, hosted CI or an equivalent retained release-gate automation record must cover the accepted commit. Continuous methods comprise: Static analysis, Unit test, Property-based test where present, Integration test, Conformance test, short-cadence Fuzz test (≤ 1 hour per parser), dependency security audit (per ODS-NFR-SEC-006).
- **Periodic** — executed on a documented schedule independently of commits. Periodic methods comprise: long-cadence Fuzz test (≥ 24 hours per parser per ODS-NFR-SEC-002, scheduled at least weekly), Performance test (weekly performance-regression run per ODS-VER-012), Soak test (continuous, with weekly snapshot reports), Differential test against current primary releases (scheduled at least monthly).
- **Gate** — executed at release acceptance gates only, the results forming the basis for release approval. Gate methods comprise: full Interoperability matrix per ODS-VER-003 against all three primaries; full Performance test on Reference Hardware Profile of Appendix E.2 against Reference Query Mix of Appendix E.3 for all ODS-NFR-PERF requirements; 30-day Soak test on the Reference Hardware Profile for the formal SRS MVP release gate per ODS-NFR-REL-003; Security audit at major release boundaries; External operator acceptance for the formal SRS MVP release gate per ODS-VER-008.

The classification of each requirement's verification (per its declared method per ODS-VER-001) into Continuous, Periodic, or Gate cadence MUST be recorded in the Test Plan. The active verification automation for the current project stage MUST enact the Continuous classification, and the Test Plan MUST document how Periodic and Gate classifications are scheduled, delegated, or retained when they are not yet automated. During the private-repository Engineering MVP profile, `scripts/check.sh` enacts the Continuous class; Periodic and Gate rows are release/operations handoff obligations until hosted CI, scheduled jobs, or formal release-gate automation are enabled. Inspection and Operational test fall under Gate cadence by default; Static analysis falls under Continuous; the remaining methods may be Continuous, Periodic, or Gate depending on the specific requirement and per-test cost.
*Source.* Operational requirement; release-engineering discipline; resolution of v0.6 audit finding about CI vs gate verification distinction.
*Verification.* Test Plan review at each release confirming method-cadence classification is documented; active automation and release/operations handoff review confirming Continuous execution and Periodic/Gate scheduling or delegation are represented accurately.

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
- XoT-secured transfers per §4.10, against each primary in the list whose tested version supports XoT. The tested primary version and the XoT capability decision MUST be recorded per ODS-VER-013; a primary is exempt from the XoT row only when the retained version evidence shows that the tested version lacks server-side XoT support or the relevant package build disables it. Current release planning MUST NOT treat BIND 9 or Knot DNS XoT as optional when the selected test versions expose XoT configuration, and SHOULD include NSD XoT evidence when the selected NSD version exposes TLS-protected `provide-xfr`/`request-xfr` configuration.

*Source.* PID §6; operational requirement for production interoperability; RFC 9103; BIND 9, Knot DNS, and NSD operator documentation for XoT-capable test-version selection. *XoT-against-BIND-9 coverage added in v0.9; NSD XoT exemption wording corrected in v0.9.1 documentation alignment.*
*Verification.* Interop test pipeline execution per the matrix.

**ODS-VER-004.** The interoperability matrix MUST exercise zones of operationally representative complexity:
- at least one small zone (< 1,000 records) for baseline correctness;
- at least one medium zone (10,000–100,000 records) for typical-load behaviour;
- at least one large zone (> 1,000,000 records) for scaling validation;
- at least one DNSSEC-signed zone using NSEC; and one DNSSEC-signed zone using NSEC3.

*Source.* Coverage of the operational range for which the server is intended.
*Verification.* Test corpus inventory at release time.

**ODS-VER-013.** Each interoperability test execution per ODS-VER-003 MUST record the exact primary implementation versions tested, including:
- implementation name (NSD, Knot DNS, BIND 9, or other primary in the matrix);
- exact version string (e.g., "NSD 4.10.2", "Knot DNS 3.4.0", "BIND 9.20.0");
- the host operating system and version (e.g., "Debian 12.5", "Ubuntu 24.04.2 LTS");
- the relevant configuration (TSIG algorithm if used, XoT certificate authority if used, IXFR enablement, NOTIFY enablement);
- the timestamp of test execution.

The interop pass/fail assertion is bound to this specific configuration. Re-testing against a different primary version requires a new verification run; previous results MUST NOT be assumed transitive to a different version. The recorded version information MUST appear in the release notes per ODS-VER-010 and in the verification evidence retained per ODS-VER-002.
*Source.* Reproducibility; resolution of v0.6 audit finding about interop version pinning.
*Verification.* Release-notes inspection at each release; sampling of interop test logs confirming version information is captured.

## 7.3 RFC Compliance Assessment

**ODS-VER-005.** For each RFC listed in PID Appendix A, the project MUST maintain a clause-level traceability mapping from each requirement-bearing RFC clause to one or more requirements in §3 through §6. The current project mapping is maintained in the Appendix A companion traceability document referenced from this SRS. Compliance with an RFC is asserted only when all in-scope requirement-bearing clauses of that RFC are mapped to verifying SRS requirements, and all those SRS requirements have been verified per ODS-VER-001.
*Source.* PID §2.3 (RFC compliance target).
*Verification.* Traceability matrix review at release time.

**ODS-VER-006.** Where an RFC referenced by PID Appendix A contains normative clauses that fall outside this server's scope — for example, primary-side requirements within an RFC that also covers secondary-side behaviour, or resolver-side requirements within an RFC primarily about authoritative service — the traceability matrix MUST mark those clauses as out-of-scope with a brief rationale referencing ODS-INV-001 (secondary-only) or PID §3.2. The RFC is then assessed for compliance limited to the in-scope clauses, and the compliance claim is documented accordingly (for example, "Compliant with RFC X, secondary-side clauses only; primary-side clauses out of scope per ODS-INV-001").
*Source.* Accurate scoping of compliance claims.
*Verification.* Traceability matrix review.

**ODS-VER-014.** RFC compliance assertions per ODS-VER-005 and ODS-VER-006 MUST be published in the project's release notes for each release as a structured list. Each entry MUST identify:
- the RFC number and title;
- the compliance status: **Fully Compliant**, **Partially Compliant** (with scope qualifier), **Not Compliant** (with rationale), or **Informative Only** (the RFC is referenced for guidance, not for normative compliance);
- the scope qualifier where applicable (e.g., "secondary-side clauses only", "wire-format aspects only", "selected clauses: §N.M, §P.Q");
- any unresolved compliance gaps with target resolution release (for example, a future-scope transport RFC or an explicitly deferred primary-side clause);
- the SRS revision against which the assertion is made (the SRS version current at the release).

The same structured list MUST be reproduced — verbatim or via single-source synchronisation — in the project's primary documentation (the Operator Deployment Guide per ODS-NFR-MAINT-009 at minimum; optionally also the repository README) so that potential operators can assess the project's compliance posture without parsing release notes.
*Source.* Operator-facing transparency; resolution of v0.6 audit finding about RFC compliance assertion publication.
*Verification.* Release-notes inspection confirming structured-list presence and content; cross-check against Operator Deployment Guide synchronisation.

## 7.4 Acceptance Criteria for PID Milestones

The PID establishes Alpha and MVP milestones. The acceptance criteria for each are stated below in terms of SRS requirement coverage. These formal gates define minimum coverage for a named milestone; they do not prohibit an implementation from delivering and testing later-scope features earlier. The repository's Engineering MVP may therefore include implemented post-Alpha slices while still tracking the full ODS-VER-008 release-acceptance evidence separately.

**ODS-VER-007 — Alpha Milestone.** The Alpha milestone is achieved when the following are demonstrably satisfied:

- All ODS-INV requirements (§3), including the v0.6-introduced ODS-INV-007, ODS-INV-008, ODS-INV-009;
- Functional requirements: §4.1 (CORE) in full; §4.2 (QRY) in full, including the RFC 8482 subset-of-available-RRsets minimal-ANY policy in ODS-FR-QRY-003 through ODS-FR-QRY-007; §4.3 (NRESP) in full; §4.4 (URR) in full; §4.5 (SPOOF) in full; §4.6 (AXFR) in full; §4.8 (NOTIFY) in full; §4.11 (EDNS) in full including NSID per ODS-FR-EDNS-016/-017 and the bounded EDE profile in ODS-FR-EDNS-018; §4.12 (TCP) in full; §4.14 (RR) restricted to RFC 1035 types plus AAAA; §4.15 (ZONE) in full; §4.16 (ZSM) in full;
- TSIG (§4.9): minimum subset sufficient for HMAC-SHA256 interop with at least one TSIG-configured primary (ODS-FR-TSIG-001, -005 through -012, -017);
- Interface requirements: §6.1 in full — three-interface segregation per ODS-IF-NET-005 through -007, plus the ODS-IF-NET-008 prohibition on exposing a fourth active NOTIFY interface role. §6.2 (CONF) in full, including the v0.5-introduced CONF-008 (warning catalogue), CONF-009 (`--dump-config`), CONF-010 (`--validate-config`), CONF-011 (parameter naming convention), CONF-012 (environment variable naming convention). §6.3 in full, including the v0.5-introduced LOG-005 through LOG-008. §6.4 (HEALTH) in full, including `/livez`, `/readyz`, the `/healthz` readiness alias, response time bounds, and metrics rate limiting. §6.5 in full, including the v0.5-introduced SIGPIPE handling clarification. §6.6 (PROC): ODS-IF-PROC-001 (exit code convention), ODS-IF-PROC-002 (`--version`), and ODS-IF-PROC-003 (`--help`) are required for Alpha; ODS-IF-PROC-004 (`--example-config`, MAY-level) is optional in Alpha as it is in MVP.
- Non-functional requirements: §5.2 (REL) -001 to -005 (REL-006 overload behaviour, REL-007 clock-skew tolerance deferred to MVP), §5.3 (SEC) -001 to -005 (SEC-006 continuous dependency audit, SEC-007 CVE policy deferred to MVP), §5.4 (MAINT) -001, -003, -004 (MAINT-002 module organisation, MAINT-005 reproducible builds, MAINT-006 backward-compat, MAINT-007 test coverage, MAINT-008 signed releases, MAINT-009 Operator Deployment Guide deferred to MVP), §5.5 (PORT) -001 to -004 (PORT-005 init-system independence verified at MVP), §5.6 (OBS) -001, -002, -004, -005, -006, and -007, §5.7 (RES) -001 (container image size);
- Interoperability per §7.2 with **at least one** of {NSD, Knot DNS, BIND 9} as primary; the specific primary version tested MUST be recorded per ODS-VER-013.
- Zone Provisioning (§4.20): ODS-FR-PROV-001, -002, -003, -004 covering explicit `[[zones]]` (i.e., backward-compatible behaviour with v0.1 through v0.7) are required for Alpha; catalog-zone requirements ODS-FR-PROV-005 through ODS-FR-PROV-014 and the catalog-related security NFRs ODS-NFR-SEC-010 through ODS-NFR-SEC-015 are not required for Alpha but remain in scope for the formal SRS MVP release gate. ODS-NFR-SEC-008 (TSIG environment-variable loading) and ODS-NFR-SEC-009 (TSIG advisory and `require_tsig`) are required for Alpha as part of the Alpha SEC subset.

Not required for Alpha, but required by the formal SRS MVP release gate: §4.7 (IXFR), §4.9 (full TSIG), §4.10 (XOT), §4.13 (DNSSEC serving), §4.17 (RRL), §4.19 (DNS Cookies), §4.14 expanded RR catalogue, all ODS-NFR-PERF performance targets (full conformance), full security/maintainability verification (ODS-NFR-SEC-006/-007, ODS-NFR-MAINT-002/-005/-006/-007/-008/-009), reliability NFRs ODS-NFR-REL-006/-007, observability extension ODS-NFR-OBS-008 (catalog metrics), resource extensions ODS-NFR-RES-002/-003/-004/-005/-006, second and third primary interop, ODS-IF-PROC-004 (`--example-config`), and §4.20 catalog-zone requirements and associated NFRs as enumerated above. Implementations may deliver any of these before the formal SRS MVP release gate; when they do, remaining work is tracked as evidence and acceptance coverage rather than as an automatic feature deferral.
*Source.* PID §6.
*Verification.* Acceptance review at the Alpha milestone gate per the cadence policy of ODS-VER-011 (Gate methods).

**ODS-VER-008 — MVP Milestone.** This requirement defines the formal SRS MVP release gate. It is separate from the repository's bounded Engineering MVP profile used for local implementation readiness. The formal MVP milestone is achieved when the following are demonstrably satisfied:

- All requirements of §3 through §6 to their full normative content;
- Interoperability per §7.2 with all three primaries (NSD, Knot DNS, BIND 9);
- All ODS-NFR-PERF performance targets met under benchmarking on the Reference Hardware Profile of Appendix E.2 against the Reference Query Mix of Appendix E.3;
- A 30-day soak test per ODS-NFR-REL-003 completed without anomaly on the Reference Hardware Profile;
- Fuzz testing per ODS-NFR-SEC-002 executed for ≥ 24 hours per parser without finding;
- Dependency security audit per ODS-NFR-SEC-006 clean;
- Vulnerability disclosure policy per ODS-NFR-SEC-007 published;
- Test coverage targets per ODS-NFR-MAINT-007 met (70% overall, 85% for wire-format parsers);
- Signed release artifacts per ODS-NFR-MAINT-008 produced for the MVP release;
- Documentation complete: this SRS, the Architecture Document, the Test Plan, and the Operator Deployment Guide (per ODS-NFR-MAINT-009);
- External operator acceptance per §7.1 by at least one production-representative operator.

*Source.* PID §6.
*Verification.* Acceptance review at the formal SRS MVP release gate.

## 7.5 Verification Evidence and Traceability

**ODS-VER-009.** The project traceability matrix MUST record, for each requirement in §3 through §6, the verification status: **Not Verified**, **Verified** (with date and reference to the evidence), or **Deferred** (with target milestone). The companion traceability matrix and verification ledger are the canonical records of verification progress for the current repository state; Appendix A in this SRS defines the required structure and mapping rules.

The traceability matrix MUST be updated synchronously with each release: at the moment a release artifact is produced, the matrix MUST reflect the verification status of every requirement against that release. Inter-release matrix updates are permitted and encouraged when verification results become available between releases (e.g., when a previously Deferred requirement is verified mid-cycle); the matrix is the canonical source of current verification status at any given time, not solely a release-time artefact. The matrix MAY be maintained as a separate Markdown, CSV, JSON, or database artifact alongside the SRS in the project repository, in which case that artifact is the canonical authority and any Appendix A rendering inside the SRS is a documentation snapshot.
*Source.* Audit and project tracking; resolution of v0.6 audit finding about matrix update cadence.
*Verification.* Matrix review at each release; spot-check of inter-release updates against verification evidence per ODS-VER-002.

**ODS-VER-012.** Verification MUST detect regressions. A *regression* is defined as either:
(a) a requirement previously marked Verified now failing verification (functional regression);
(b) a performance NFR metric (an ODS-NFR-PERF-* or ODS-NFR-RES-* requirement) previously meeting target now degraded beyond a configurable threshold (parameter `regression.performance_threshold_pct`, default 10%), measured against the median of the last 5 release measurements for the same metric on the Reference Hardware Profile.

Each detected regression MUST be triaged within the release process: root-cause analysis recorded, and either a fix applied OR the regression explicitly accepted with rationale recorded in release notes alongside the per-release verification summary of ODS-VER-010. A release with un-triaged regressions MUST NOT proceed.

Regression baseline: the rolling window of the last 5 release measurements is used to absorb measurement noise; the first release of a major version, having no prior history, establishes the initial baseline rather than triggering regression detection. New requirements introduced in a release have no prior verification result and thus cannot regress; they are simply Verified or Failed against the new requirement's acceptance criterion.
*Source.* Release-process discipline; resolution of v0.6 audit finding about absent regression policy.
*Verification.* Periodic Performance test per ODS-VER-011 captures rolling metrics; release-notes inspection at each release for regression triage documentation.

**ODS-VER-015.** Verification execution roles are allocated as follows:
- **Continuous methods** per ODS-VER-011 are executed through the active continuous gate for the project stage. During the private-repository Engineering MVP profile this is local `scripts/check.sh`; for formal release acceptance the results are retained as CI or equivalent release-gate automation evidence.
- **Periodic methods** per ODS-VER-011 are scheduled by CI where available or executed manually by the project's release engineer at the documented cadence (long-cadence Fuzz test, Performance test, Differential test, Soak test snapshots), with retained evidence paths recorded in release notes.
- **Gate methods** per ODS-VER-011 are executed by the project's release engineer at release acceptance gates; the release engineer is a project role recorded in the Architecture Document.
- **Verification result review at release time** is the responsibility of the project's Architecture Owner; for v0.1 through MVP, this role is held by DT.
- **External operator acceptance** per ODS-VER-008 (formal SRS MVP release gate) introduces a third-party verifier; the acceptance signature, the identity of the accepting operator, and the operator's accepted scope statement are recorded in the MVP release notes.
- **Security audit** per the §7.1 method definition is procured from a third-party security specialist firm; the engagement is recorded in the Architecture Document with the auditor identity, scope, and findings tracking process.

Where a single individual fills multiple roles (typical for the project's small team), the role accountability is unaffected; the individual signs off in each capacity. Where a role is unfilled (e.g., the release-engineer role is shared rotationally), the rotation schedule is recorded in the Architecture Document.
*Source.* Project governance clarity; resolution of v0.6 audit finding about absent verification responsibility allocation.
*Verification.* Architecture Document review confirming role allocations; release-notes inspection confirming sign-off attestations against allocated roles.

## 7.6 Test Plan Boundary

The Test Plan is a sibling document per §1.6.1, maintained independently of this SRS. Its scope and relationship to this SRS is as follows:

- The SRS specifies *what* is to be verified, *by what method* (per the catalogue of §7.1), *at what cadence* (per the classification of ODS-VER-011), and *for what acceptance criterion* (per the milestone definitions of ODS-VER-007 and ODS-VER-008).
- The Test Plan specifies *the concrete test cases* — fixtures, inputs, expected outputs, harness configuration, tooling versions, the per-method test infrastructure.
- Each test case in the Test Plan MUST reference one or more SRS requirement identifiers, establishing bidirectional traceability via Appendix A.
- Changes to the SRS that affect verification approach (modifications to *Verification* fields, additions or modifications of requirements) trigger review of the corresponding Test Plan content; the project's change-management process governs the coordination.

The separation prevents the SRS from accumulating test-case detail that does not serve the SRS's normative purpose, while ensuring that the SRS's verification statements are realised in executable artifacts.

## 7.7 Audit Cycle Closure

The SRS was subjected to a structured per-section audit cycle initiated in v0.2 and concluded in v0.7. Each section's audit closure resulted in precision refinements, gap closures, and (where appropriate) new requirements:

| Audit cycle | SRS revision | Section | Principal outcomes |
|---|---|---|---|
| Functional | v0.3 | §4 | Closed specification gaps (non-EDNS UDP ceiling, AA bit completeness, CNAME chain semantics, TCP in-flight cap, AXFR/IXFR size cap, pseudo-RR rejection); new MVP-scope §4.19 DNS Cookies (RFC 7873/9018) and NSID (RFC 5001). |
| Non-functional | v0.4 | §5 | Reference Hardware Profile and Reference Query Mix introduced (Appendix E); 13 new NFRs covering TCP/TSIG/DNSSEC throughput targets, overload behaviour, clock-skew tolerance, CVE policy, test coverage, signed releases, Operator Deployment Guide deliverable, build_info and latency-histogram metrics, idle-CPU bound. |
| Interface | v0.5 | §6 | `interface.xot` -> `interface.transfer` rename; explicit rejection of a fourth active NOTIFY interface role for the MVP; CLI helper modes (`--dump-config`, `--validate-config`, `--version`, `--help`); canonical logging field names; new PROC area code (§6.6) with exit-code convention. |
| Architectural invariants | v0.6 | §3 | Precision refinements to ODS-INV-001 through -006; three new foundational invariants (Authoritative-Only Response Composition, Single-Process Architecture, Static Composition). |
| Verification | v0.7 | §7 | Method catalogue expanded with Property-based test, Differential test, Static analysis (distinct), Security audit; ODS-VER-001 reformulated; six new VER requirements (gate verification, cadence classification, regression policy, interop version recording, compliance publication, responsibility allocation). |

The audit cycle is complete with v0.7. Future revisions to this SRS are expected to address: (a) Pending items in Appendix C.5 as project decisions are made; (b) C.6 post-MVP scope items as they are promoted into scope; (c) operational learnings from Alpha and formal SRS MVP release-gate executions; (d) RFC errata published after the active revision's publication date. Audit cycles of equivalent depth are not anticipated unless triggered by substantive architectural change.

The SRS body is considered structurally stable from v0.7 onward; subsequent revisions are expected to be additive (new requirements within the established framework) or corrective (defect fixes), not structurally transformative.

# Appendix A — Requirement-to-RFC Traceability Matrix

## A.1 Purpose

Appendix A defines the required bidirectional mapping between RFCs (and other normative references) and the requirements of this SRS. The live repository mapping is maintained in the companion Appendix A traceability artifact. Its purposes are:

- to demonstrate, for each RFC in the project's compliance target (PID Appendix A), that all in-scope normative clauses are realised by one or more SRS requirements;
- to identify, for each RFC, those clauses that fall outside this server's scope, with reference to the architectural invariant or PID scope clause that excludes them;
- to provide, for each SRS requirement, the source RFC(s) and clause(s) from which it derives;
- to define how verification status is tracked per requirement, supporting the milestone acceptance criteria of ODS-VER-007 and ODS-VER-008.

Appendix A is intentionally split between this SRS and the companion traceability artifact. This SRS records the normative conventions, scope categories, and representative clause mappings; the companion artifact records the checked current coverage and evidence state. Clause-level refinement is conducted in that companion artifact and reviewed against this SRS during release preparation.

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
- **Deferred** — verification is deferred to a specific milestone (typically the formal SRS MVP release gate per ODS-VER-008).
- **Not Applicable** — the requirement has been Deprecated or replaced; the row is retained for identifier stability.

Status tracking is maintained per A.6 and in the companion traceability and verification-ledger documents.

### A.2.4 Mapping granularity

Two granularities of mapping are supported:

- **Coarse-grained.** RFC → SRS subsection (for example, RFC 5936 → §4.6). Sufficient for project-level compliance assertion when the SRS subsection covers the RFC fully.
- **Fine-grained.** RFC clause → SRS requirement identifier (for example, RFC 5936 §2.2.1 → ODS-FR-AXFR-005, ODS-FR-AXFR-007). Required for partial-scope RFCs and for clause-level audit.

The coarse-grained mapping is provided in A.3 below. Fine-grained mapping is illustrated for representative RFCs in A.4 and is refined in the companion traceability artifact during implementation and release review.

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
*Key clauses.* §5 (RRset semantics) → CORE-026, CORE-027, except for the RRSIG-specific RFC 4035 §2.2 carve-out; §5.2 (TTL uniformity) → CORE-027; §6.1 (SOA at apex) → RR-002; §7 (NODATA) → CORE-022; §9 (response size, truncation) → TCP-008; §10.1 (CNAME exclusivity) → RR-005; §11 (name format) → CORE-028.
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
*Key clauses.* §6.1.1 (OPT RR placement and multiplicity) → EDNS-002, EDNS-003; §6.1.2 (RDATA option encoding) → EDNS-001; §6.1.3 (extended RCODE, VERSION) → EDNS-004, EDNS-010; §6.1.4 (Z bits other than DO) → EDNS-008; §6.2.3 (UDP payload size handling) → EDNS-005; §6.2.5 (response size) → EDNS-006; §7 (response OPT semantics) → EDNS-007, EDNS-008. DO-bit reply copying is specified by RFC 6840 §5.6 and mapped below.

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
*Key clauses.* §2 (DNSKEY) → DNSSEC-001, RR catalogue; §3 (RRSIG format, Type Covered, and Original TTL fields) → DNSSEC-001, DNSSEC-003, CORE-026, CORE-027; §4 (NSEC) → DNSSEC-001, DNSSEC-004, DNSSEC-005; §5 (DS) → DNSSEC-001, DNSSEC-007; §6.2 (canonical form) → RR catalogue (RRSIG, NSEC).
*Out-of-scope clauses.* Signing aspects (primary-side) — ODS-NEG-002.

**RFC 4035 — Protocol Modifications for the DNS Security Extensions** (Arends et al., 2005).
*Scope.* Partial (serve-only, no validation).
*Implementing sections.* §4.13 (DNSSEC).
*Key clauses.* §2.2 (RRSIG records do not form ordinary RRsets and do not follow normal RRset TTL rules) → CORE-026, CORE-027; §3.1 (response composition with DNSSEC RRs) → DNSSEC-003..007; §3.1.3 (negative response proofs) → DNSSEC-004, DNSSEC-005; §3.1.3.4 (wildcard proofs) → DNSSEC-006; §3.1.4 (referral proofs) → DNSSEC-007; §3.1.6 (AD and CD bits in authoritative responses) → DNSSEC-010, DNSSEC-011; §3.2.1 (recursive DO handling; useful for the DO = 0 stripping rule) → DNSSEC-002, DNSSEC-008.
*Out-of-scope clauses.* §4 (resolver-side validation) — ODS-INV-001.

**RFC 5155 — DNS Security (DNSSEC) Hashed Authenticated Denial of Existence (NSEC3)** (Laurie, Sisson, Arends, Blacka, 2008).
*Scope.* Partial (serve-only, no generation).
*Implementing sections.* §4.13 (DNSSEC), §4.14 (RR).
*Key clauses.* §3 (NSEC3 RR format) → DNSSEC-001, RR catalogue; §4 (NSEC3PARAM RR format) → DNSSEC-001, RR catalogue; §7.2.2 (NXDOMAIN proofs) → DNSSEC-004; §7.2.3, §7.2.4 (NODATA proofs) → DNSSEC-005; §7.2.5 (wildcard proofs) → DNSSEC-006; §7.2.7 (referral proofs) → DNSSEC-007.
*Out-of-scope clauses.* §7.1 (chain generation, primary-side) — ODS-NEG-002.

**RFC 6840 — Clarifications and Implementation Notes for DNS Security (DNSSEC)** (Weiler & Blacka, 2013).
*Scope.* Partial (serve-only clarifications).
*Implementing sections.* §4.13 (DNSSEC).
*Key clauses.* §5.6 (DO bit copying in replies) → DNSSEC-009 and EDNS-009; §5.8 (AD bit in validating-resolver replies, used here to justify conservative AD = 0 posture) → DNSSEC-010. Authoritative CD clearing is mapped to RFC 4035 §3.1.6 above; RFC 6840 §5.9 concerns validating resolvers' upstream queries and is not a requirement source for this authoritative-only server.
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
*Implementing sections.* Informative input to response-behavior and test-design requirements in §4.1, §4.2, §4.11, and §7.3; not a source for logging or metrics requirements.

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

The SRS deliberately does not embed live status rows. Earlier draft examples
became misleading as IXFR, DNSSEC serving, XoT, and other post-Alpha protocol
families gained Engineering MVP evidence before formal SRS release acceptance.
Current status is maintained in the companion documents:

- `docs/verification-ledger.md` records the coarse evidence state by requirement
  family.
- `docs/appendix-a-traceability-matrix.md` records range-level and selected
  per-requirement evidence mappings.
- `docs/mvp-gap-register.md` records remaining implementation and
  release-acceptance gaps.

Population of the live tracking table is the responsibility of the test and
review team; the SRS records the conventions and column definitions but does
not include the live tracking content.

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
| 4.11 EDNS0 | EDNS | 6891, 7828, 7830, 5001 |
| 4.12 TCP Transport | TCP | 7766, 1035, 2181 |
| 4.13 DNSSEC Serving | DNSSEC | 4033, 4034, 4035, 5155, 6840, 6944 |
| 4.14 RR Type Catalogue | RR | 1035, 1982, 2782, 3403, 3596, 3597, 6604, 6672, 6698, 7553, 9460 |
| 4.15 Zone Store | ZONE | 1034, 4592 |
| 4.16 Zone State Machine | ZSM | 1034, 1996, 1982 |
| 4.17 RRL | RRL | (no IETF RFC; Vixie/Schryver operational design) |
| 4.18 Negative Requirements | NEG | (cross-references to enforcing requirements) |
| 4.19 DNS Cookies | COOKIE | 7873, 9018 |

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

# Appendix C — Out-of-Scope Items and Post-MVP Scope

## C.1 Purpose

Appendix C catalogues items outside this server's scope, with rationale for each exclusion and reference to the SRS clause that records or enforces it. The intent is that a reader of the SRS alone can understand where the project's boundaries lie without needing to consult the PID for context.

Three kinds of entry are distinguished:

- **Foundational exclusions (C.2).** Items whose inclusion would violate an architectural invariant of §3 (typically ODS-INV-001, the secondary-only invariant). These cannot be brought into scope without redefining the project's identity.
- **Current-scope exclusions (C.3).** Items deliberately left out of the current version's scope for reasons of complexity, codebase size, or focus, but which could be added in a future version without architectural-invariant violation.
- **Post-MVP / v2 scope items (C.6).** Future OxideDNS server optimisation tracks recorded with re-entry conditions and current-architecture constraints. These tracks are outside the current Engineering MVP runtime unless a later SRS revision and unsafe-boundary update explicitly bring them into scope.

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

*Numbering note.* This catalogue retained its v0.1 numbering for stability. As of v0.3, the entry previously at C.3.1 (DNS Cookies, RFC 7873) has been brought into MVP scope and is specified at §4.19; its former slot is preserved as an explicit recorded transition for traceability rather than renumbered.

### C.3.1 DNS Cookies (RFC 7873) — *withdrawn (now in MVP scope)*

*Disposition.* Brought into MVP scope per v0.3 of this SRS. Specified at §4.19 (ODS-FR-COOKIE-001 through ODS-FR-COOKIE-011). Removed from §4.11's out-of-scope closing note. Removed from C.5 decision queue. The decision to include DNS Cookies in MVP was recorded on 24 May 2026 following the v0.2 functional audit recommendation; the rationale is that DNS Cookies add useful UDP off-path spoofing resistance with modest operational complexity and no per-client shared-secret distribution.

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

### C.3.9 DNS Catalog Zones (RFC 9432) — *promoted to in-scope in v0.8*

*Status.* This item was excluded in v0.1 through v0.7 on the grounds that ODS-INV-005 (Static Configuration) precluded catalog-driven dynamic zone provisioning. The v0.8 introduction of §4.20 Zone Provisioning resolves the exclusion by isolating statically configured `[[catalog_zones]]` coordinates from the *derived member-zone set* (runtime-derived state, expressly admitted by the updated ODS-INV-005). Catalog zones are now supported under `[[catalog_zones]]` per ODS-FR-PROV-005 et seq., with the security narrowings of ODS-NFR-SEC-010 through ODS-NFR-SEC-015 (mandatory TSIG on the catalog, prohibition of `primaries` property honouring, bounded member count, validation of member-zone names, mandatory per-transfer timeout).

The entry is preserved in this register, with this updated status, per the identifier-stability discipline of §1.4.4 — readers of earlier revisions following a reference to C.3.9 reach a current statement of where the topic now lives.

### C.3.10 EDNS Expire (RFC 7314)

*Description.* An experimental EDNS option for zone maintenance queries (typically SOA, AXFR, and IXFR) that lets a primary or intermediate secondary convey remaining expire-timer information to a secondary. RFC 7314 is intended to preserve SOA EXPIRE semantics across indirect secondary-to-secondary transfer graphs; it is not a replacement for ordinary SOA refresh polling, NOTIFY, AXFR, or IXFR.

*Rationale for exclusion.* Minor operational optimisation for indirect transfer topologies; out of PID scope.

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

### C.3.15 EDNS Extended DNS Errors (RFC 8914)

*Description.* The EDE (Extended DNS Errors) EDNS option carries fine-grained error-condition information from the responder to the requestor, complementing the coarse-grained RCODE field. Defined error codes cover conditions such as "Stale Answer" (RFC 8767), "DNSSEC Bogus", "DNSKEY Missing", "Stale NXDomain", "Filtered", and many others.

*Current scope.* Partially implemented as a bounded, operator-enabled diagnostic profile in ODS-FR-EDNS-018. The current profile emits only INFO-CODE 14 (`Not Ready`) for zone-state-machine not-ready responses and INFO-CODE 27 (`Unsupported NSEC3 Iterations`) for NSEC3 cap downgrades. It deliberately omits EXTRA-TEXT and does not expose policy, filtering, validator, stale-cache, or recursive-resolution EDE mappings that are outside this secondary-only authoritative scope.

*Enforcement.* Implemented only for ODS-FR-EDNS-018. Other RFC 8914 codes remain out of current scope unless explicitly added by a future requirement.

*Note.* Operators should treat EDE as diagnostic metadata only; it does not alter the DNS RCODE and must not be required by clients for correctness.

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
| 8484 | DNS-over-HTTPS | Current-scope exclusion | C.3.4 |
| 9250 | DNS-over-QUIC | Current-scope exclusion | C.3.5 |

*Note.* RFC 7873 (DNS Cookies) was listed in this table in v0.1 and v0.2 as a current-scope exclusion. As of v0.3 it has been brought into MVP scope (§4.19) and is therefore removed from this table.

*Note.* RFC 9432 (DNS Catalog Zones) was listed in this table in v0.1 through v0.7 as a current-scope exclusion incompatible with ODS-INV-005. As of v0.8 it has been brought into scope (§4.20.2, `[[catalog_zones]]`) under the architectural reconciliation described in the updated ODS-INV-005 and in Appendix C.3.9; it is therefore removed from this table.

## C.5 Items Flagged for Project Decision

The following items were specifically flagged during SRS drafting for explicit team decision rather than implicit endorsement. Each was raised at a particular subsection's closing notes; the decisions are collected here for traceability and to support review.

| Item | Flagged at | Recommendation | Decision |
|---|---|---|---|
| DNS Cookies (RFC 7873) | §4.5, §4.11 | Bring into scope | **Resolved (v0.3): in MVP scope, §4.19** |
| EDNS Extended DNS Errors (RFC 8914) | §4.11, §4.13, C.3.15 | Add minimal authoritative diagnostics | **Resolved (v0.9 implementation alignment): bounded profile added; ODS-FR-EDNS-018, ODS-IF-CONF-017** |
| NOTIFY-over-TLS reception | §4.10 | Remain out of scope (current) | **Resolved (v0.9.1 spec alignment): out of scope; ODS-NEG-017 prohibits inbound XoT/NOTIFY-over-TLS listeners** |
| Per-zone RRL configuration | §4.17 | Remain out of scope (current) | **Resolved (v0.9.1 spec alignment): out of current scope; §4.17 keeps RRL process-wide for the current version** |
| mTLS for XoT as MUST | §4.10 | Remain MAY | **Resolved (v0.9.1 spec alignment): remains MAY-level per ODS-FR-XOT-007** |
| CAA / ZONEMD / CDS / CDNSKEY as known types | §4.14, B.4 | Remain handled as unknown via §4.4 | **Resolved (v0.9.1 spec alignment): remain outside the type-aware catalogue and are handled under unknown-RR semantics** |
| DANE TLSA validation for XoT certs | §4.10 | Out of scope (PKIX only) | **Resolved (v0.9.1 spec alignment): DANE validation remains out of scope; TLSA is served as data only** |
| XoT TLS revocation posture (no CRL/OCSP request; OCSP stapling honoured) | §4.10, ODS-FR-XOT-012 | Confirm posture | **Resolved (v0.3): confirmed; ODS-FR-XOT-012** |
| UDP IXFR support | §4.7, ODS-FR-IXFR-001 | Remove (TCP only) | **Resolved (v0.3): UDP IXFR removed; ODS-NEG-018** |
| Non-root execution as MUST | §5.3 | Strengthen to MUST | **Resolved (v0.4): elevated to MUST; ODS-NFR-SEC-004** |
| In-code requirement reference SHOULD → MUST | §5.4 | Elevate with CI enforcement | **Resolved (v0.4): elevated to MUST; ODS-NFR-MAINT-004** |
| Per-record memory overhead target (500 bytes) | §5.7, ODS-NFR-RES-002 | SHOULD MVP, MUST post-MVP | **Resolved (v0.4): SHOULD in MVP, deferred MUST aligned with C.6.2** |
| `/livez` and `/readyz` health-endpoint split | §5.6, §6.4 | Split per K8s convention | **Resolved (v0.4): split per ODS-NFR-OBS-004 and ODS-IF-HEALTH-002** |
| Reference Hardware Profile (Dual Xeon Gold 6230R) | §5.1, §5.7, Appendix E | Confirm Profile | **Resolved (v0.4): confirmed; Appendix E** |
| Reference Query Mix (Zipf 80/5; A/AAAA/MX/NS/TXT/SRV distribution) | §5.1, Appendix E | Confirm Mix | **Resolved (v0.4): confirmed; Appendix E.3** |
| `interface.xot` rename to `interface.transfer` | §6.1, ODS-IF-NET-005 | Rename for accurate scope | **Resolved (v0.5): renamed; ODS-IF-NET-005** |
| Separate inbound NOTIFY interface | §6.1, ODS-IF-NET-008 | Decide whether to expose a fourth NOTIFY role | **Resolved for MVP: not exposed; ODS-IF-NET-008 requires rejection of `interface.notify` / `interfaces.notify` and receives NOTIFY on `interfaces.dns`** |
| Health endpoint default bind precedence (explicit > `interface.mgmt` > localhost) | §6.4, ODS-IF-HEALTH-001 | Layered default | **Resolved (v0.5): specified; ODS-IF-HEALTH-001** |
| Exit code convention (sysexits.h-style) | §6.6, ODS-IF-PROC-001 | Adopt BSD sysexits convention | **Resolved (v0.5): adopted; ODS-IF-PROC-001** |
| SIGPIPE ignore disposition exception | §6.5, ODS-IF-SIG-004 | Permit SIG_IGN for SIGPIPE | **Resolved (v0.5): permitted; ODS-IF-SIG-004** |
| `--dump-config` and `--validate-config` CLI modes | §6.2, ODS-IF-CONF-009, ODS-IF-CONF-010 | Add both | **Resolved (v0.5): added; ODS-IF-CONF-009 / -010** |
| `--version` and `--help` CLI flags | §6.6, ODS-IF-PROC-002 / -003 | Standard CLI convention | **Resolved (v0.5): added; ODS-IF-PROC-002 / -003** |
| `--example-config` CLI flag | §6.6, ODS-IF-PROC-004 | Optional (MAY) | **Resolved (v0.5): MAY-level; ODS-IF-PROC-004** |
| Configuration parameter naming convention | §6.2, ODS-IF-CONF-011 | Specify snake_case + unit suffix | **Resolved (v0.5): specified; ODS-IF-CONF-011** |
| Environment variable naming convention (`ODS_<SECTION>_<KEY>`) | §6.2, ODS-IF-CONF-012 | Specify | **Resolved (v0.5): specified; ODS-IF-CONF-012** |
| Configuration warning catalogue (non-aborting) | §6.2, ODS-IF-CONF-008 | Implement | **Resolved (v0.5): specified; ODS-IF-CONF-008** |
| Canonical log field names | §6.3, ODS-IF-LOG-005 | Specify uniform field set | **Resolved (v0.5): specified; ODS-IF-LOG-005** |
| Bootstrap (pre-config) logging | §6.3, ODS-IF-LOG-006 | JSON + info level by default | **Resolved (v0.5): specified; ODS-IF-LOG-006** |
| Log entry size limit | §6.3, ODS-IF-LOG-007 | Configurable, default 16 KiB | **Resolved (v0.5): specified; ODS-IF-LOG-007** |
| Lazy debug-level log formatting | §6.3, ODS-IF-LOG-008 | Macro-based filtering | **Resolved (v0.5): specified; ODS-IF-LOG-008** |
| Health endpoint body content schema | §6.4, ODS-IF-HEALTH-002 | Specify JSON bodies | **Resolved (v0.5): specified; ODS-IF-HEALTH-002** |
| Health endpoint response time bounds | §6.4, ODS-IF-HEALTH-005 | ≤ 100 ms probes, ≤ 500 ms metrics, gzip | **Resolved (v0.5): specified; ODS-IF-HEALTH-005** |
| `/metrics` per-source rate limit | §6.4, ODS-IF-HEALTH-006 | 60/minute default | **Resolved (v0.5): specified; ODS-IF-HEALTH-006** |
| Include directives in configuration | §6.2, ODS-IF-CONF-001 | NOT supported | **Resolved (v0.5): excluded; ODS-IF-CONF-001** |
| External secret store integration | §6.2, ODS-IF-CONF-004 | NOT supported (file-path projection only) | **Resolved (v0.5): excluded; ODS-IF-CONF-004** |
| Interface-name binding (`eth0`-style) | §6.2, ODS-IF-CONF-003 | NOT supported (IP addresses only) | **Resolved (v0.5): excluded; ODS-IF-CONF-003** |
| `health.default_port` (default 8080) | §6.4, ODS-IF-HEALTH-001 | Confirm | **Resolved (v0.9.1 code alignment): implemented default is 8080 in `HealthConfig` and documented in the Operator Deployment Guide** |
| `health.metrics_rate_limit_per_minute` (default 60) | §6.4, ODS-IF-HEALTH-006 | Confirm | **Resolved (v0.9.1 code alignment): implemented default is 60 per minute in `HealthConfig` and documented in the Operator Deployment Guide** |
| `logging.max_entry_length_bytes` (default 16384) | §6.3, ODS-IF-LOG-007 | Confirm | **Resolved (v0.9.1 code alignment): implemented default is 16384 bytes in `LoggingConfig` and documented in the Operator Deployment Guide** |
| Configuration warning catalogue contents | §6.2, ODS-IF-CONF-008 | Confirm enumerated patterns | **Resolved (v0.9.1 code alignment): current warning catalogue is implemented and documented in the Operator Deployment Guide; future additions require documentation sync** |
| `EX_CONFIG_INVALID = 2` and `EX_CONFIG = 78` choice | §6.6, ODS-IF-PROC-001 | Confirm | **Resolved (v0.9.1 code alignment): exit-code convention retained as specified and covered by CLI/runtime tests** |
| Multi-delta IXFR atomicity model (N transitions vs 1) | §3.3, ODS-INV-003 | N atomic transitions permitted | **Resolved (v0.6): N transitions permitted; ODS-INV-003** |
| /tmp / tmpfs requirement during runtime | §3.4, ODS-INV-004 | Server runnable without writable /tmp | **Resolved (v0.6): specified; ODS-INV-004** |
| Configuration sources additive (file + env) | §3.5, ODS-INV-005 | Both, env precedence | **Resolved (v0.6): specified; ODS-INV-005** |
| Runtime-derived state vs. "configuration" boundary | §3.5, ODS-INV-005 | Explicit exclusion list | **Resolved (v0.6): specified; ODS-INV-005** |
| Third-party `unsafe` boundary (first-party scope only) | §3.6, ODS-INV-006 | First-party only | **Resolved (v0.6): clarified; ODS-INV-006** |
| Panic discipline in query path | §3.6, ODS-INV-006 | Panic-free on untrusted input | **Resolved (v0.6): specified; ODS-INV-006** |
| Authoritative-only response composition as invariant | §3.7, ODS-INV-007 | Elevate from NEG-007/-008 | **Resolved (v0.6): elevated; ODS-INV-007** |
| Single-process architecture as invariant | §3.8, ODS-INV-008 | New invariant | **Resolved (v0.6): introduced; ODS-INV-008** |
| Static composition / no runtime code loading | §3.9, ODS-INV-009 | New invariant | **Resolved (v0.6): introduced; ODS-INV-009** |
| Two-invariant conflict resolution policy | §3 intro | Specify | **Resolved (v0.6): specified; §3 intro** |
| VER category formal registration in §1.4.3 + D.5.1 | §7 intro | Register | **Resolved (v0.7): note in §7 intro updated; §1.4.3 and D.5.1 already had VER** |
| ODS-VER-001 tautological wording | §7.1 | Reformulate as coherence requirement | **Resolved (v0.7): reformulated; ODS-VER-001** |
| Property-based test as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Differential test as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Static analysis distinct from Inspection | §7.1 | Separate methods | **Resolved (v0.7): separated; §7.1** |
| Security audit as distinct method | §7.1 | Add to catalogue | **Resolved (v0.7): added; §7.1** |
| Pre-release verification gate | §7, ODS-VER-010 | Specify | **Resolved (v0.7): specified; ODS-VER-010** |
| Verification cadence classification (Continuous/Periodic/Gate) | §7, ODS-VER-011 | Specify | **Resolved (v0.7): specified; ODS-VER-011** |
| Regression detection and triage policy | §7, ODS-VER-012 | Specify | **Resolved (v0.7): specified; ODS-VER-012** |
| Interop primary version recording | §7.2, ODS-VER-013 | Specify | **Resolved (v0.7): specified; ODS-VER-013** |
| RFC compliance assertion publication | §7.3, ODS-VER-014 | Specify | **Resolved (v0.7): specified; ODS-VER-014** |
| Verification responsibility allocation | §7.5, ODS-VER-015 | Specify | **Resolved (v0.7): specified; ODS-VER-015** |
| Traceability matrix update cadence | §7.5, ODS-VER-009 | Synchronous with each release | **Resolved (v0.7): specified; ODS-VER-009** |
| ODS-VER-007 Alpha milestone PROC scope | §7.4 | PROC-001/-002/-003 in Alpha | **Resolved (v0.7): specified; ODS-VER-007** |
| ODS-VER-007 Alpha milestone v0.3 reference precision | §7.4 | Clarify to v0.1–v0.3 | **Resolved (v0.7): clarified; ODS-VER-007** |
| NSEC3 iteration count cap (RFC 9276 / BCP 236) | §4.13, ODS-FR-DNSSEC-014 | Add as defence against CPU amplification | **Resolved (v0.9): added; ODS-FR-DNSSEC-014, ODS-IF-CONF-015** |
| DNAME synthesis name-length overflow (RFC 6672 §5.3.1) | §4.2, ODS-FR-QRY-014 / ODS-FR-QRY-025 | Specify YXDOMAIN response | **Resolved (v0.9): specified; ODS-FR-QRY-025** |
| DNAME multiplicity at the same owner (RFC 6672 §2.4) | §4.6, ODS-FR-AXFR-026 | Reject at ingest | **Resolved (v0.9): specified; ODS-FR-AXFR-026** |
| Out-of-zone glue tolerance (compatibility option) | §4.6, ODS-FR-AXFR-025; §6.2, ODS-IF-CONF-016 | Add optional, off-by-default tolerance | **Resolved (v0.9): added; ODS-FR-AXFR-025, ODS-IF-CONF-016** |
| Environment-variable override re-validation gap | §6.2, ODS-IF-CONF-014 | Re-run validator after override | **Resolved (v0.9): specified; ODS-IF-CONF-014** |
| XoT interoperability coverage against BIND 9 | §7.2, ODS-VER-003 | Add BIND 9 to XoT row of matrix | **Resolved (v0.9): added; ODS-VER-003** |
| CHAOS class self-identification | §4.21, ODS-FR-CHAS-001..006; §6.2, ODS-IF-CONF-018 | Add conservative, opt-in CH/TXT `version.bind` and `id.server` profile | **Resolved in specification (v0.9.1); implemented locally with config, metrics/logging, unit tests, and UDP/TCP client E2E coverage** |
| Property-based testing in Alpha scope | §7.1 | Add `proptest`-based invariant rules to parser/zone-lookup paths | **Pending: non-normative quality-improvement candidate; tracked in Test Plan** |
| Server module decomposition (server/lib.rs monolith) | §5.4, ODS-NFR-MAINT-002 | Decompose `server::health` and `server::transfer` from monolithic `server/lib.rs` | **Pending: non-normative maintainability candidate; module organisation per ODS-NFR-MAINT-002 to be tracked in Architecture Document** |
| `regression.performance_threshold_pct` default 10% | §7.5, ODS-VER-012 | Confirm | **Resolved (v0.9.1 doc/tool alignment): default remains 10%, implemented by `scripts/check-perf-regression.py` and documented in the Test Plan and release-notes template** |
| PowerDNS Authoritative in interop matrix | §7.2 | Consider adding | **Resolved (v0.9.1 doc alignment): not added to the mandatory ODS-VER-003 NSD/Knot/BIND matrix; retained as supplemental RFC 9432 catalog-producer interop evidence with PostgreSQL/gpgsql** |
| External operator acceptance as MVP criterion | §7.4 | Confirm as MVP criterion | **Resolved (v0.9.1 doc alignment): required for the formal ODS-VER-008 SRS MVP release gate and release-notes sign-off, but explicitly outside the bounded Engineering MVP profile** |
| Strict default for ANY-query mode ("minimal") | §4.2 | Confirm | **Resolved (v0.9.1 code alignment): `QuerySettings` defaults to minimal ANY responses per ODS-FR-QRY-006** |
| Minimal-ANY deterministic selection algorithm | §4.2, ODS-FR-QRY-005 | Specify (CNAME-first, then lowest-type) | **Resolved (v0.3): specified in ODS-FR-QRY-005** |
| 4 concurrent transfer sessions (default) | §4.6 | Confirm | **Resolved (v0.9.1 code alignment): `limits.max_concurrent_transfers` defaults to 4** |
| 60-second initial-load retry default | §4.16 | Confirm | **Resolved (v0.9.1 code alignment): `limits.zsm_initial_retry_secs` defaults to 60** |
| 1232-octet max UDP response default | §4.11 | Confirm | **Resolved (v0.9.1 code alignment): `limits.max_udp_payload` defaults to 1232** |
| 1024 concurrent TCP connections (default) | §4.12 | Confirm | **Resolved (v0.9.1 code alignment): `limits.max_tcp_connections` defaults to 1024** |
| 64 in-flight queries per TCP connection (default) | §4.12, ODS-FR-TCP-011 | Confirm | **Resolved (v0.9.1 code alignment): `limits.max_tcp_inflight_queries_per_connection` defaults to 64** |
| 4 GiB max ingestion per AXFR/IXFR session (default) | §4.6, §4.7, ODS-FR-AXFR-024 | Confirm | **Resolved (v0.9.1 code alignment): `limits.max_transfer_ingest_bytes` defaults to 4 GiB** |
| 86400-second max effective REFRESH (default) | §4.16, ODS-FR-ZSM-011 | Confirm | **Resolved (v0.9.1 code alignment): `limits.zsm_max_interval_secs` defaults to 86400** |
| 3600-second LOADING warning threshold (default) | §4.16, ODS-FR-ZSM-013 | Confirm | **Resolved (v0.9.1 code alignment): `limits.zsm_loading_warning_threshold_secs` defaults to 3600** |
| 30-second SIGTERM grace period (default) | §5.2, ODS-NFR-REL-001 | Confirm | **Resolved (v0.9.1 code alignment): `limits.graceful_shutdown_secs` defaults to 30** |
| 10% memory growth threshold over 30 days (default) | §5.2, ODS-NFR-REL-003 | Confirm | **Resolved (v0.9.1 tool alignment): 10% remains the formal soak threshold and is the default in `scripts/capture-soak-handoff.sh`; actual 30-day soak execution remains ODS-VER-008 release acceptance, not Engineering MVP evidence** |
| 5000 ms per-query processing timeout (default) | §5.2, ODS-NFR-REL-006 | Confirm | **Pending: no current `query.processing_timeout_ms` config or per-zone timeout-drop metric exists; tracked in the MVP gap register for implementation or SRS revision** |
| 300 s TSIG fudge / 3600+300 s cookie tolerance (defaults) | §5.2, ODS-NFR-REL-007 | Confirm clock-skew defaults | **Resolved (v0.9.1 code alignment): TSIG fudge defaults to 300 seconds; DNS Cookie past/future timestamp tolerances default to 3600/300 seconds** |
| 1000 ms `/livez` probe timeout (default) | §5.6, §6.4 | Confirm | **Pending: no current `health.livez_timeout_ms` config exists; tracked in the MVP gap register for implementation or SRS revision against orchestrator-managed probe timeouts** |
| 70%/85% test coverage minimum (defaults) | §5.4, ODS-NFR-MAINT-007 | Confirm | **Resolved (v0.9.1 tool alignment): thresholds retained; `scripts/capture-coverage-evidence.sh` enforces 70% overall and 85% parser/XoT-file line coverage when release coverage evidence is captured** |
| Sigstore/Cosign vs detached OpenPGP for release signing | §5.4, ODS-NFR-MAINT-008 | Confirm preferred mechanism | **Resolved (v0.9.1 doc alignment): Sigstore/Cosign preferred; detached OpenPGP allowed as fallback; recorded in the Architecture Document and Security Policy** |
| 30-day / 90-day CVE response targets (defaults) | §5.3, ODS-NFR-SEC-007 | Confirm | **Resolved (v0.9.1 doc alignment): Security Policy records 30-day Critical/High and 90-day Medium/Low remediation targets, with release-specific exceptions recorded as evidence** |
| 1% idle CPU bound for 1000 zones (default) | §5.7, ODS-NFR-RES-006 | Confirm | **Pending: formal Reference Hardware/Profile acceptance target; local tooling can sample idle CPU, but the 1% bound still needs release-gate confirmation or SRS revision** |
| Latency histogram bucket boundaries (defaults) | §5.6, ODS-NFR-OBS-007 | Confirm | **Resolved (v0.9.1 code alignment): default buckets are implemented in `MetricsConfig` and configurable via `[metrics].latency_histogram_buckets`** |
| Multi-primary randomised initial selection | §4.6, ODS-FR-AXFR-016 | Confirm | **Resolved (v0.9.1 code alignment): `TransferPlan::from_config` samples a per-zone initial primary with unbiased rejection sampling, rotates the configured primary list once for the process lifetime, and preserves stable failover order; covered by transfer-plan rotation tests and Appendix A traceability** |
| Slip = 2 (RRL default) | §4.17 | Confirm | **Resolved (v0.9.1 code alignment): `rrl.slip` defaults to 2; release threshold evidence still tracks operational review separately** |
| Three-state zone lifecycle model (LOADING/ACTIVE/EXPIRED) | §4.15 | Confirm | **Resolved (v0.9.1 code alignment): zone state machine and readiness/metrics use LOADING, ACTIVE, and EXPIRED** |
| DNS Cookies default policy ("lenient") | §4.19, ODS-FR-COOKIE-008 | Confirm | **Resolved (v0.9.1 code alignment): `cookie.policy` defaults to `lenient`** |
| NSID default empty (no NSID configured) | ODS-FR-EDNS-017 | Confirm | **Resolved (v0.9.1 code alignment): `[server].nsid` defaults to the empty string and suppresses NSID responses** |
| Logging format default JSON vs logfmt | §5.6, §6.3 | Confirm JSON | **Resolved (v0.9.1 code alignment): `[server].log_format` defaults to JSON; logfmt remains optional** |
| TOML configuration format | §6.2 | Confirm | **Resolved (v0.9.1 code alignment): configuration file format is TOML and the example config is TOML** |
| Combined `/metrics` + health endpoint host vs separate | §6.4 | Confirm combined host (paths split) | **Resolved (v0.9.1 code alignment): management listener exposes `/livez`, `/readyz`, `/healthz`, and `/metrics` as separate paths on the same management host** |
| Verification category VER prefix (extends §1.4.3) | §7 | Confirm | **Resolved (v0.9.1 doc alignment): VER is registered in §1.4.3 and Appendix D.5.1 and checked by the identifier-registry audit** |
| SLO publication as informative content in Operator Deployment Guide | ODS-NFR-MAINT-009 | Add SLO section to Deployment Guide | **Resolved (v0.9.1 doc alignment): informative SLO section added to the Operator Deployment Guide** |

The Decision column records project decisions as the review process reaches each
item. **Resolved** entries are retained for audit trail; their decisions are
normative within the SRS revision in which they were resolved. **Pending**
entries remain active review items until a later SRS revision resolves them or
the associated requirement is revised.

## C.6 Post-MVP / v2 Scope Items

This section records future OxideDNS server optimisation tracks that remain
outside the current Engineering MVP runtime. They are retained so the current
architecture does not foreclose later packet-I/O, zone-store, or response-cache
work, but they are not hidden MVP requirements. Current implementation status
and unsafe-boundary ownership are maintained by the Architecture Document,
`docs/unsafe-boundaries.tsv`, and `docs/unsafe-prone-dependencies.tsv`.

### C.6.1 XDP/eBPF Kernel-Bypass on the DNS Query Interface

*Description.* Future deployment of an XDP (eXpress Data Path) program on the
OxideDNS server DNS query interface. A future implementation may use a
kernel-side classifier for simple DNS/UDP responses and an AF_XDP userspace path
for packets requiring full application processing, but the current OxideDNS
server runtime uses Tokio UDP/TCP sockets and has no XDP/eBPF or AF_XDP packet
backend.

*Scope boundary.* The current `oxide-gun` crate has an explicit AF_XDP backend
for load-generation on Linux lab hosts. That code is test-tool scope only and
does not satisfy or activate this OxideDNS server optimisation track.

*Rationale for deferral.* XDP/eBPF and AF_XDP require deployment-specific
kernel, NIC, queue, capability, attach/detach, and fallback handling. The
current Engineering MVP deployment model is a general Linux/POSIX process or
container profile using ordinary kernel sockets. Bringing XDP/eBPF into the
server would require a separate privileged deployment profile and targeted
adapter safety evidence.

*Entry condition for re-evaluation.* Benchmarks of the current implementation
show that the Tokio socket path, rather than zone lookup or response assembly,
prevents the server from meeting the relevant performance target, or a
deployment profile with dedicated XDP-capable network hardware becomes a
standard target.

*Architectural constraints on any future implementation.*
- The DNS query socket layer MUST be encapsulated behind a documented packet-I/O boundary so that an XDP/AF_XDP implementation can replace the standard UDP socket implementation without changes to the query-processing layers above it.
- The DNS query interface bind addresses (ODS-IF-NET-005, `interface.dns`) MUST be expressed as (address, interface-name) pairs in the configuration schema so that a future XDP implementation can attach to the correct NIC by name; the interface-name sub-field MAY be optional and ignored in the MVP.
- When ODS-IF-NET-006 is re-evaluated for the XDP variant, packet-size and path-MTU behaviour that is currently delegated to the kernel socket path MUST be covered by explicit implementation and tests for the bypass path.
- Runtime loading of operator-supplied eBPF programs remains prohibited by ODS-INV-009. Any future kernel-side program MUST be built as a versioned project artifact and attached only through the audited adapter path.
- First-party `unsafe` and unsafe-prone dependencies for this backend MUST remain confined to the registry-listed packet-I/O adapter boundary and MUST carry `/// # Safety` / `// SAFETY:` rationale and backend fault evidence before production enablement.

*Note.* The concrete eBPF userspace library choice, such as Aya versus a
libbpf-based crate, is not fixed by this SRS revision. It must be selected and
reviewed when this feature is brought into scope.

### C.6.2 Optimised Packed-Binary In-Memory Zone Store

*Description.* Replacing the current Engineering MVP zone store with a
packed-binary region layout modelled on NSD-style memory locality. In this
model, all RRs for a zone may be serialised in DNS wire format into a contiguous
memory arena built at transfer-ingestion time; the lookup index would store
integer offsets into the arena rather than pointers to heap-allocated objects.
Zone replacement on refresh would remain atomic by publishing a complete arena
plus index snapshot.

*Rationale for deferral.* The current implementation uses a simple
memory-resident snapshot store that publishes complete zone versions. This is
easy to inspect, has direct functional coverage, and is already benchmarked
before any packed-store work is justified. The packed-binary layout is a
performance and memory-locality optimisation whose benefit must be demonstrated
against measured bottlenecks.

*Entry condition for re-evaluation.* MVP benchmarking shows that cache-miss rate on the zone store is a significant fraction of query latency at target load, or that per-record memory overhead exceeds the 500-byte target of ODS-NFR-RES-002.

*Architectural constraints on any future implementation.*
- The zone store MUST be accessed through a documented storage boundary so the packed-binary implementation can substitute without changes to the query-processing or zone-transfer layers.
- The AXFR ingestion path MUST be clearly separated from the query-serving path; ingestion builds a new store instance which is atomically published, never modified in place.
- The current implementation MUST record per-record memory overhead in benchmarking output so that the entry condition above can be evaluated against measured data.

*Note.* An additional optimisation within this item is pre-computing NSEC/NSEC3 denial-of-existence responses at ingestion time rather than generating them at query time. This is independent of the arena layout and may be profitably evaluated separately.

### C.6.3 Pre-Baked Response Cache for Hot Query Patterns

*Description.* A future in-process cache of serialised authoritative DNS
response packets (wire format, ready to send) keyed on the fields that affect
response composition, at minimum `(QNAME, QTYPE, DO-bit)`. On a cache hit, the
server would copy the pre-built packet, patch the QID field, and send it,
bypassing zone-store lookup and response assembly. Cache sizing and admission
policy would be driven by measured query distribution rather than fixed in this
SRS revision. Cache invalidation on zone refresh must purge all entries
belonging to the refreshed zone.

*Rationale for deferral.* The current Engineering MVP already serves zones
entirely from memory (§4.15). The marginal benefit of a response cache over the
current in-memory zone store and response path is measurable only after
benchmarking identifies response assembly as a bottleneck. The cache introduces
complexity (invalidation logic, DO-bit interaction, DNSSEC TTL decay) that is
unjustified before measured evidence of need.

*Entry condition for re-evaluation.* MVP benchmarking shows that response assembly (name compression, RR serialisation, EDNS OPT construction) accounts for a significant fraction of per-query CPU time at target load.

*Architectural constraints on the current implementation.*
- The response-assembly path MUST be cleanly separated from the send path, so that a cached pre-built buffer can be substituted for the assembled buffer transparently.
- DNSSEC-signed responses cached in this layer MUST be subject to TTL decay: the cache MUST NOT serve a pre-built response whose minimum RRSIG expiration minus current time is less than a configurable floor (suggested: 60 seconds). Alternatively, the cache may be restricted to unsigned responses only in the initial implementation.
- The cache MUST be keyed on the DO-bit value (DO=0 and DO=1 responses differ in the presence of DNSSEC records) and MUST treat them as separate entries.

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

**BADCOOKIE.** DNS extended RCODE 23 (RFC 7873 §5.2.3). Returned by a server operating under the "strict" cookies policy when a client query lacks a valid Server Cookie. The response carries a freshly computed Server Cookie that the client uses on retry. See §4.19 (ODS-FR-COOKIE-006).

**BADKEY.** TSIG error code 17. Returned when no matching key is configured for the TSIG's owner name.

**BADSIG.** TSIG error code 16. Returned when the TSIG MAC verification fails.

**BADTIME.** TSIG error code 18. Returned when the time-signed field deviates from current time by more than the fudge value.

**BADTRUNC.** TSIG error code 22 (RFC 8945; RFC 4635). Returned when the MAC truncation is below the algorithm's minimum.

**BADVERS.** EDNS extended error code 16 (RFC 6891 §6.1.3). Returned when an inbound OPT RR carries an EDNS VERSION the server does not support.

**Bailiwick.** A name is "in bailiwick" of another name when the former is at or below the latter in the DNS hierarchy. Used to qualify glue records (in-bailiwick glue is included by the secondary; out-of-bailiwick glue is not relevant to this server).

**BCP.** Best Current Practice — an IETF document category. Cited examples in this SRS: BCP 14 (RFC 2119, RFC 8174), BCP 195 (RFC 9325).

**CAA.** Certification Authority Authorization record (type 257, RFC 8659). Handled as an unknown type per §4.4.

**CD bit.** Checking Disabled bit (RFC 4035). Used primarily between security-aware resolvers and recursive name servers. For OxideDNS authoritative responses, RFC 4035 §3.1.6 says the bit is mostly irrelevant and that security-aware authoritative name servers SHOULD clear it; this server makes clearing CD mandatory by project policy (ODS-FR-DNSSEC-011).

**CHAOS class.** DNS resource class 3 (CH), historically allocated for Chaosnet and now commonly used by DNS tooling for diagnostic TXT probes such as `version.bind.` and `id.server.`. OxideDNS support is specified in §4.21.

**Class.** DNS resource class (RFC 1035 §3.2.4). This server primarily handles class IN (Internet, class 1) and the bounded CHAOS-class meta-query profile in §4.21. *See also.* QCLASS.

**Client Cookie.** The 8-octet portion of the DNS COOKIE EDNS option supplied by the client; an unpredictable token that the server echoes back so the client can verify response binding to the original query. See §4.19 and RFC 7873 §4.

**CNAME.** Canonical Name record (type 5, RFC 1035 §3.3.1). Specifies a canonical name to which the owner name aliases.

**Cold start.** A process start in which no prior state is recovered. Per ODS-INV-004, every start of this server is a cold start.

**Compression.** DNS name compression (RFC 1035 §4.1.4). The encoding of repeated domain names within a DNS message as 14-bit pointers into earlier in the message. The compression policy per RR type is specified in §4.14 and Appendix B.

**Cookie, DNS Cookies.** The EDNS COOKIE option (option code 10, RFC 7873) carrying a Client Cookie (always 8 octets) and optionally a Server Cookie (16 octets per RFC 9018). Provides lightweight transaction-security and source-address confirmation against off-path UDP spoofing, without TSIG-equivalent client authorization. Implemented per §4.19. *See also.* Client Cookie, Server Cookie.

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

**EDE.** Extended DNS Errors (RFC 8914). An EDNS option carrying fine-grained error condition information from the responder to the requestor. Implemented only for the bounded profile in ODS-FR-EDNS-018.

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

**NSID.** Name Server Identifier (RFC 5001). An EDNS option allowing a client to request and a server to return an opaque identifier of the responding server instance, used for diagnostic purposes in anycast and load-balanced deployments. Implemented in §4.11 (ODS-FR-EDNS-016 / ODS-FR-EDNS-017).

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

**Server Cookie.** The optional 16-octet portion of the DNS COOKIE EDNS option (8 to 32 octets in RFC 7873; constrained to exactly 16 octets by RFC 9018) computed by the server as a MAC over the (Client Cookie, version, timestamp, client IP, server secret) tuple. Provides source-address confirmation for this server's UDP spoofing and RRL decisions; it does not authenticate a durable client identity. See §4.19 (ODS-FR-COOKIE-003) and RFC 9018.

**SHA-1, SHA-256, SHA-384, SHA-512.** Secure Hash Algorithm variants. Used as TSIG algorithm primitives (RFC 4635).

**SIGHUP, SIGINT, SIGTERM, SIGUSR1, SIGUSR2.** POSIX signals; handled per §6.5.

**SipHash.** A keyed pseudo-random function (Aumasson, Bernstein, 2012; cryptographic-quality though not a hash function in the SHA-family sense) used for Server Cookie MAC computation per RFC 9018. Cited at ODS-FR-COOKIE-003.

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
| VER | Verification Requirement | Omitted | §7 |

The category rows above are the current canonical category registry and mirror the §1.4.3 category enumeration.

### D.5.2 Area code registry (normative)

Area codes are short uppercase mnemonics (3–6 characters) registered in the table below. Each area code is unique across the SRS and is associated with one subsection. New area codes are allocated only by SRS revision; per the identifier-stability rule of §1.4.4, area codes are never reused for different concerns. Categories with omitted AREA components, such as `ODS-NEG-NNN`, are registered in D.5.1 rather than in the area-code tables below.

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
| COOKIE | §4.19 | DNS Cookies (RFC 7873, RFC 9018) |
| PROV | §4.20 | Zone Provisioning (explicit zones and RFC 9432 catalog zones) |
| CHAS | §4.21 | CHAOS class query handling (`version.bind`, `hostname.bind`, etc.) |

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
| PROC | §6.6 | Process lifecycle and command-line interface |

### D.5.3 Reserved category prefixes

The following prefixes are reserved for future use and MUST NOT be allocated as area codes in any category:

- **TODO**, **TBD**, **REQ**, **REQ-** — reserved against accidental collision with informal notation.
- **TEST**, **VER**, **VRF** — reserved; VER is used as a category (D.5.1).

### D.5.4 Maintenance discipline

Adding a new area code requires editing this registry in the same SRS revision as the area code's first allocation. Area codes follow the identifier-stability rule of §1.4.4: once allocated, they MUST NOT be reused for a different concern, and MUST NOT be removed even if the subsection they describe is removed (the registry row is preserved with a "Deprecated" annotation).

---

# Appendix E — Reference Hardware Profile and Reference Query Mix

## E.1 Purpose

Appendix E specifies the reference environment against which the quantitative non-functional requirements of §5 (the ODS-NFR-PERF-* and ODS-NFR-RES-* targets) are stated and verified. Without a concrete reference, performance numbers are unfalsifiable: "50,000 queries per second per core" on a 2008 server is a very different commitment from the same number on a 2026 server. The reference profile fixes the verification environment so that conformance claims are objective.

The Profile reflects a deliberate choice: it is more powerful than strictly necessary for the secondary's expected production workload, but it is selected as the project's standard verification platform. Production deployments on weaker hardware are supported and operationally common; their performance will depend on CPU, memory, NIC, kernel, container, and traffic-mix details. Conformance to the §5 numerical targets is asserted only against this Profile after the Appendix E.4 recordkeeping artifacts are retained.

## E.2 Reference Hardware Profile

### E.2.1 Compute

- **CPU:** Dual Intel Xeon Gold 6230R processors. Each socket: 26 physical cores / 52 hardware threads, base clock 2.10 GHz, max turbo 4.00 GHz, AVX-512 capable, 35.75 MB L3 cache. Total: 52 physical cores / 104 hardware threads. Released Q1 2020 (Cascade Lake Refresh); widely available in enterprise hardware as of 2026.
- **Memory:** 192 GiB DDR4-2933 ECC, populated to use all six memory channels per socket (typical: 12 × 16 GiB DIMMs).
- **NUMA topology:** Two NUMA nodes (one per socket); the container is started with NUMA affinity to a single socket for performance verification, leaving the other socket for the host operating system and the management interface. This produces a verification configuration of 26 cores / 96 GiB RAM available to the container, which is the value used in the per-core targets of §5.1.

### E.2.2 Network

- **DNS query interface:** Dedicated to the secondary's DNS query traffic per ODS-IF-NET-005, attached directly to the container as an SR-IOV Virtual Function or via NIC passthrough. Recommended NICs for verification: Intel E810 (`ice` driver) or Mellanox ConnectX-5 / ConnectX-6 (`mlx5` driver), at 25 Gbit/s line rate. Native XDP driver-mode support is a requirement of the hardware so that the post-MVP optimisation of Appendix C.6.1 can be verified on the same Profile without hardware change; for MVP verification (which does not use XDP), driver-mode support is not exercised but the NIC choice is unchanged for continuity.
- **Management interface:** Dedicated to operator access, monitoring scraping, and (where the operator's network architecture so requires) zone-transfer traffic per ODS-IF-NET-005. Connected to the host operating system, not to the container directly. Speed is not critical; 1 Gbit/s suffices.
- **Zone-transfer interface (optional, if configured per ODS-IF-NET-005):** Where the operator separates XoT traffic onto its own physical interface, a separate NIC port. For verification purposes the management interface carries this traffic.

### E.2.3 Operating environment

- **Host operating system:** Ubuntu 24.04 LTS or Red Hat Enterprise Linux 9 (or compatible: Rocky Linux 9, AlmaLinux 9). Linux kernel 6.x LTS series.
- **Container runtime:** containerd 1.7+ with the runc OCI runtime. (Equivalent runtimes — Podman, CRI-O — are supported per ODS-NFR-PORT-003 but the verification environment uses containerd.)
- **Container resource allocation:** the container is granted exclusive access to the cores of one NUMA node (26 physical cores), with `cpuset` and `cpus` limits configured to prevent CPU sharing with host processes during measurement. The dedicated DNS query NIC is attached to the container via SR-IOV VF; the management interface is attached to the host.
- **Kernel tuning:** `net.core.rmem_max`, `net.core.wmem_max`, `net.core.netdev_max_backlog`, and similar UDP/TCP socket parameters tuned per the Operator Deployment Guide (ODS-NFR-MAINT-009). These are operational tunings, not server configuration; their values are recorded with each verification run.
- **Clock source:** the host clock is synchronised via PTP (Precision Time Protocol) where the verification environment supports it, or NTP otherwise. Clock skew at the measurement node is recorded with each run and SHOULD be below 100 milliseconds for repeatable ODS-NFR-REL-007 verification.

### E.2.4 Storage

The secondary makes no use of persistent storage per ODS-INV-004. Local disk on the host is used for:
- container image storage (the OCI image, ≤ 20 MB per ODS-NFR-RES-001);
- host OS and container runtime;
- log aggregation downstream of the container's stdout/stderr (ODS-IF-LOG-001).

Verification runs use NVMe SSD for the host; SATA or other slower storage does not affect server performance (no I/O on the query path per ODS-INV-002) but does affect log throughput if logs are persisted locally.

## E.3 Reference Query Mix

### E.3.1 Reference zone

A synthetic test zone is used for performance verification. It has the following characteristics:

- **Zone size:** 100,000 records (RR count), structured as:
  - 50,000 A records (50%)
  - 25,000 AAAA records (25%)
  - 10,000 MX records (10%)
  - 5,000 NS records (5%, scattered at sub-zone delegation points)
  - 5,000 TXT records (5%)
  - 5,000 SRV records (5%)
- **Name structure:** Owner names follow a realistic distribution: a mix of two-, three-, and four-label names under a single zone apex, with occasional deeper names for delegation testing. The zone contains both regular owner names and wildcard owner names (approximately 100 wildcards distributed across the zone).
- **DNSSEC variant:** A signed variant of the same zone (using NSEC) is maintained for DNSSEC-augmented verification per ODS-NFR-PERF-008. The signed variant uses Ed25519 (algorithm 15) or RSA-SHA-256 (algorithm 8) at the project's verification convenience.

### E.3.2 Query distribution

The query distribution applied to the reference zone is Zipfian, reflecting the empirically observed distribution of authoritative DNS traffic:

- **QNAME distribution:** Approximately 80% of queries target the top 5% of owner names; the remaining 20% are distributed across the long tail. The exact Zipf parameter is recorded with each verification run.
- **QTYPE distribution:** A weighted mix:
  - 60% A
  - 25% AAAA
  - 5% MX
  - 5% NS
  - 5% other (TXT, SRV in proportion to their presence in the zone)
- **Source IP distribution:** Queries are issued from at least 100,000 distinct simulated source IP addresses (across IPv4 /24 and IPv6 /56 prefixes), to exercise the RRL accounting layer (ODS-FR-RRL-002, ODS-FR-RRL-010) realistically; no single source generates more than 0.01% of total query volume.
- **EDNS state:** All queries carry an OPT RR with class field 1232 (the default UDP payload size of ODS-FR-EDNS-006) and DO = 0 unless the verification scenario specifically targets DNSSEC augmentation (per ODS-NFR-PERF-008).
- **Cookie state:** For ODS-FR-COOKIE-related verification, the appropriate cookies are carried; for baseline PERF-001 verification (no cookies in scope), queries carry no Cookie option.

### E.3.3 Variants

The Reference Query Mix supports the following named variants, invoked by specific NFR verifications:

- **Baseline (PERF-001, PERF-002, PERF-003):** Default mix as above; UDP transport; no TSIG; DO=0.
- **TCP-pipelined (PERF-006):** Same QNAME/QTYPE distribution but delivered over TCP with 32 in-flight queries per connection; 1,000 distinct source connections.
- **TSIG-load (PERF-007):** TSIG-signed NOTIFY messages delivered at controlled rate; the NOTIFY processing path is exercised including the cryptographic verification.
- **DNSSEC-augmented (PERF-008):** Default mix against the signed zone variant; queries carry DO = 1.
- **Cookie-enabled (ODS-FR-COOKIE-related verification):** Default mix with cookies attached; baseline (no cookie), Client-Cookie-only, valid-server-cookie, and invalid-server-cookie sub-variants.

## E.4 Verification recordkeeping

Each NFR verification run MUST record:
- the exact hardware configuration (CPU model and count, RAM, NIC model and driver version, container runtime version);
- the exact software stack version (server binary version per ODS-NFR-OBS-006, kernel version, Linux distribution version, container runtime version);
- the benchmark tool used and its version (`dnsperf`, `kxdpgun`, or equivalent);
- the Reference Query Mix variant used (baseline, TCP-pipelined, TSIG-load, etc.);
- the measured values for the relevant NFR target;
- any deviations from the Reference Profile and an assessment of their impact on the measurement.

The Test Plan (a sibling document per §1.6.1) specifies the concrete test harness implementations.

## E.5 Profile evolution

The Reference Hardware Profile may be revised over time as commodity hardware evolves. Each revision of the Profile MUST be approved as part of an SRS revision; the NFR targets MAY be revised in the same SRS revision to track the Profile's new capacity, with the new targets stated against the new Profile. Historical SRS versions retain their original Profile references for traceability of past verification claims.

---

*End of document.*
