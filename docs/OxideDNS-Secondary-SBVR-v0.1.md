# OxideDNS-Secondary — SBVR Structured English Specification

## v0.1 (Draft 1) — Companion to SRS v0.1

**Date:** 23 May 2026
**Source document:** *OxideDNS-Secondary Software Requirements Specification*, v0.1
**Standard followed:** OMG *Semantics of Business Vocabulary and Business Rules* (SBVR), Annex C — Structured English notation

---

## 0. Notation Conventions

This document expresses the OxideDNS-Secondary requirements in SBVR Structured English, an OMG-standardised controlled natural language for vocabulary and rules. Because plain Markdown cannot render the four-colour SBVR font convention, this document adopts the following ASCII-renderable approximations, applied uniformly throughout:

| SBVR concept | Standard SBVR rendering | Convention used here | Example |
|---|---|---|---|
| **Noun concept** (term) | green, underlined | *italics* | *server*, *zone*, *resource record* |
| **Verb concept** (fact type) | blue italics | underlined italics, or rendered as a verb in rule context | *receives*, *parses*, *transfers* |
| **Individual concept** (name) | bold italics | ***bold italics*** | ***OxideDNS-Secondary***, ***LOADING***, ***RFC 5936*** |
| **Keyword** (modal, quantifier, logical) | orange, bold | **bold** | **It is obligatory that**, **each**, **at least one** |

The principal SBVR keywords used in this document, with their meaning:

| Keyword | Category | Meaning |
|---|---|---|
| **It is necessary that** | alethic modal | structural rule: definitional, holds in all possible worlds |
| **It is impossible that** | alethic modal | the negation of necessity |
| **It is obligatory that** | deontic modal | operative rule: the system is obliged to satisfy the predicate |
| **It is prohibited that** | deontic modal | operative rule: the system is forbidden from satisfying the predicate |
| **It is permitted that** | deontic modal | operative rule: the system may but is not obliged to satisfy the predicate |
| **It is recommended that** | deontic modal (extension) | operative rule of recommendation: SBVR-equivalent rendering of RFC 2119 SHOULD |
| **each** | universal quantifier | for every instance |
| **some** | existential quantifier | for at least one instance |
| **at least one**, **at most one**, **exactly one** | numeric quantifiers | with their natural reading |
| **if … then**, **and**, **or**, **not** | logical connectives | with their classical-logic reading |

Each rule carries an SBVR identifier of the form `[R-CATEGORY-AREA-NNN]` mirroring the SRS requirement identifier `ODS-CATEGORY-AREA-NNN` from which it is derived. The bidirectional traceability is one-to-one for most requirements; where a single SRS requirement decomposes into multiple SBVR rules, the identifier is suffixed with a letter (e.g., `[R-FR-TSIG-008a]`, `[R-FR-TSIG-008b]`).

Cross-references to RFCs follow the form *RFC NNNN §S.S*, matching the SRS convention. Cross-references between SBVR rules use the rule identifier in square brackets.

The rules in this document are normative-by-derivation: they restate the normative content of the SRS in SBVR form. Where this document and the SRS disagree on substance, the SRS prevails; this document should then be updated to match. The SBVR document is intended for stakeholders working in rule-based or formal-vocabulary frameworks; the SRS remains the project's primary normative artefact.

---

## 1. Vocabulary

The vocabulary establishes the terms, individual concepts, and fact types from which the rules of §2 and §3 are composed. Entries are listed alphabetically within each subsection. Definitions are concise; full definitions of DNS-protocol terms are in SRS Appendix D and the cited RFCs.

### 1.1 Noun Concepts (Terms)

A **noun concept** is a type — a class of things that share defining characteristics. In rules, noun concepts are rendered in *italics* and represent universals over instances.

*authoritative answer* — a *response* produced by an *authoritative server* for a *zone* it serves, with the AA bit set per [R-FR-CORE-014].

*authoritative server* — a *server* holding *zone data* for one or more *zones*. The ***OxideDNS-Secondary*** is an *authoritative server*.

*accounting key* — a key under which *Response Rate Limiting* accounts *responses*; a tuple of *source IP prefix* and *response category* per [R-FR-RRL-002].

*additional section* — the fourth section of a *DNS message*, carrying records auxiliary to the answer.

*answer section* — the second section of a *DNS message*, carrying records that directly satisfy the *query*.

*architectural invariant* — a property the ***OxideDNS-Secondary*** maintains at all times during operation; specified in §2.

*authority section* — the third section of a *DNS message*, carrying records identifying authoritative servers or denial-of-existence proofs.

*AXFR query* — a *DNS query* with *QTYPE* = 252, requesting full zone transfer per ***RFC 5936***.

*AXFR response* — the multi-message reply to an *AXFR query*, delivering complete *zone data*.

*AXFR session* — the TCP-borne exchange constituting one full zone transfer between the ***OxideDNS-Secondary*** and a *primary*.

*BADALG response* — a *TSIG error response* carrying error code 21.

*BADKEY response* — a *TSIG error response* carrying error code 17.

*BADSIG response* — a *TSIG error response* carrying error code 16.

*BADTIME response* — a *TSIG error response* carrying error code 18.

*BADTRUNC response* — a *TSIG error response* carrying error code 22.

*BADVERS response* — an EDNS error response carrying extended RCODE 16.

*CD bit* — the Checking Disabled bit in the *DNS header* (***RFC 4035***).

*class* — the resource record class field (*RFC 1035 §3.2.4*); for this system, principally ***IN*** (value 1).

*CNAME chain* — a sequence of *CNAME records* followed during *query processing*, terminating in a non-CNAME target or at a *served-zone* boundary.

*compression pointer* — a 14-bit pointer used in DNS name compression per *RFC 1035 §4.1.4*.

*configuration* — the operator-supplied parameters governing the ***OxideDNS-Secondary***, established at *process startup*.

*configuration file* — the single TOML-format file containing the *configuration*, per [R-IF-CONF-001].

*deduplication interval* — the time window during which duplicate *NOTIFY messages* for one *zone* are coalesced per [R-FR-NOTIFY-009].

*difference sequence* — a unit of incremental change in an *IXFR Mode 1 response*, comprising an old-SOA, deletions, a new-SOA, and additions.

*DNS client* — an entity sending *DNS queries* to the ***OxideDNS-Secondary***.

*DNS header* — the fixed 12-octet structure at the start of every *DNS message*.

*DNS message* — a wire-format DNS protocol unit per *RFC 1035 §4*.

*DNSSEC record* — a *resource record* of type ***DNSKEY***, ***RRSIG***, ***NSEC***, ***NSEC3***, ***DS***, or ***NSEC3PARAM***.

*DO bit* — the DNSSEC OK bit in the *OPT pseudo-RR*.

*EDNS option* — an option pair appearing in the *RDATA* of an *OPT pseudo-RR*.

*EDNS payload size* — the maximum UDP response size advertised by either party to a DNS exchange.

*empty non-terminal* — an owner name within a *served zone* that has descendant names with *resource records* but no *resource record* of its own.

*EXPIRE interval* — the value of the EXPIRE field in a *zone's* *SOA record*, the maximum age of unrefreshed *zone data* before transition to ***EXPIRED***.

*EXPIRED zone* — a *zone* in the ***EXPIRED*** *zone state*.

*FORMERR response* — a *response* with RCODE = 1, indicating a format error in the query.

*fudge value* — the permitted absolute time-difference between the *time signed* of a *TSIG record* and the receiver's current time.

*glue record* — an A or AAAA *resource record* in a parent *zone* whose owner name lies within a child *zone* delegated from that parent, supplied to bootstrap resolution of the delegation.

*graceful shutdown* — the *process* termination mode in which in-flight work is allowed to complete within a configured grace period before exit; specified in [R-NFR-REL-001].

*health endpoint* — the HTTP endpoint exposing *health states* and metrics, configurable per [R-IF-HEALTH-001].

*HMAC-MD5* — the TSIG algorithm explicitly prohibited by [R-NEG-013].

*HMAC-SHA1* — a TSIG algorithm required per [R-FR-TSIG-002].

*HMAC-SHA256* — the principal TSIG algorithm required per [R-FR-TSIG-001].

*HMAC-SHA384*, *HMAC-SHA512* — TSIG algorithms recommended per [R-FR-TSIG-003].

*IXFR query* — a *DNS query* with *QTYPE* = 251, requesting incremental zone transfer per ***RFC 1995***.

*IXFR response* — the reply to an *IXFR query*, delivered in one of three modes per [R-FR-IXFR-004].

*IXFR session* — an exchange of *IXFR query* and *IXFR response* between the ***OxideDNS-Secondary*** and a *primary*.

*listening socket* — a UDP or TCP socket on which the ***OxideDNS-Secondary*** accepts inbound traffic.

*log entry* — a structured record emitted to standard output or standard error per [R-IF-LOG-001].

*MAC* — the message authentication code computed by a *TSIG algorithm* for a *DNS message*.

*master file* — the presentation-format zone-data file defined in *RFC 1035 §5*; the ***OxideDNS-Secondary*** does not read *master files*.

*metric* — a runtime counter or gauge exposed via the *health endpoint* per [R-IF-HEALTH-002].

*NODATA response* — a *response* with RCODE = NOERROR, empty *answer section*, and a *SOA record* in the *authority section*, indicating the *QNAME* exists but the *QTYPE* does not.

*NOTIFY message* — a *DNS message* with OPCODE = 4, defined by *RFC 1996*.

*NOTIFY response* — the reply to a *NOTIFY message* per [R-FR-NOTIFY-006].

*NXDOMAIN response* — a *response* with RCODE = 3, indicating the *QNAME* does not exist in the *served zone*.

*operator* — the human administrator responsible for the ***OxideDNS-Secondary***'s *configuration* and lifecycle.

*OPT pseudo-RR* — the EDNS0 record type 41 conveying EDNS metadata.

*orchestrator* — an automated process supervisor (container orchestrator, init system) that starts, stops, and probes the ***OxideDNS-Secondary***.

*owner name* — the domain name to which a *resource record* belongs.

*pipelined query* — a *DNS query* sent on a TCP connection while a prior query on the same connection has not yet been answered.

*primary* — the *authoritative server* holding the master copy of a *zone*, from which the ***OxideDNS-Secondary*** transfers.

*process* — an executing instance of the ***OxideDNS-Secondary*** binary.

*process startup* — the period from process creation to the completion of *configuration* loading and *listening socket* binding.

*pseudo-RR* — a record type carrying protocol metadata rather than zone content (***OPT***, ***TSIG***, ***TKEY***).

*QCLASS* — the class field of the question section of a *DNS query*.

*QID* — the 16-bit ID field in the *DNS header*.

*QNAME* — the name field of the question section of a *DNS query*.

*QTYPE* — the type field of the question section of a *DNS query*.

*query* — a *DNS message* with QR = 0, requesting information.

*RCODE* — the response code field in the *DNS header* (and extended in *OPT pseudo-RR*).

*REFRESH interval* — the value of the REFRESH field in a *zone's* *SOA record*, the period between scheduled refresh attempts.

*refresh attempt* — an action of the *zone state machine* aimed at confirming or updating *zone data*.

*REFUSED response* — a *response* with RCODE = 5, indicating the *server* declines to answer.

*resource record* (*RR*) — a single record of zone data per *RFC 1035 §3.2*.

*response* — a *DNS message* with QR = 1, replying to a *query*.

*response category* — one of the five categories used in *Response Rate Limiting* accounting per [R-FR-RRL-002].

*Response Rate Limiting* (*RRL*) — the mechanism specified in §4.17 of the SRS for constraining *responses* per *accounting key*.

*RETRY interval* — the value of the RETRY field in a *zone's* *SOA record*, the period between retries after a failed *refresh attempt*.

*RRset* — the set of *resource records* sharing *owner name*, *class*, and type per *RFC 2181 §5*.

*SERVFAIL response* — a *response* with RCODE = 2, indicating server-side failure.

*served zone* — a *zone* designated for service by the ***OxideDNS-Secondary*** through *configuration*.

*server* — the ***OxideDNS-Secondary*** instance; equivalent throughout this document to the named individual ***OxideDNS-Secondary***.

*signal* — a POSIX process signal; the ***OxideDNS-Secondary*** handles ***SIGTERM*** and ***SIGINT***.

*slip* — the *Response Rate Limiting* parameter governing the ratio of truncated to dropped *responses* per [R-FR-RRL-005].

*SOA record* — a *resource record* of type 6, mandated to exist exactly once per *zone* at the *zone apex*.

*SOA serial* — the 32-bit serial number field in *SOA record* RDATA; compared per RFC 1982 arithmetic.

*source IP prefix* — the network prefix of a source IP address used in *Response Rate Limiting* accounting.

*structural rule* — a definitional necessity, expressed with the alethic modal **It is necessary that**.

*operative rule* — a behavioural obligation, prohibition, permission, or recommendation, expressed with a deontic modal.

*supported TSIG algorithm* — an algorithm enumerated in [R-FR-TSIG-001] through [R-FR-TSIG-003].

*time signed* — the timestamp field in a *TSIG record*'s RDATA.

*token bucket* — the rate-limiting state structure maintained per *accounting key* per [R-FR-RRL-004].

*transfer session* — an *AXFR session* or *IXFR session*.

*truncated response* — a *response* with the TC bit set, indicating the client should retry over TCP.

*TSIG algorithm* — an HMAC algorithm used to compute *MAC* values for *TSIG records*.

*TSIG error response* — a *response* with RCODE = NOTAUTH and a *TSIG record* in the additional section carrying a non-zero error code.

*TSIG key* — a tuple of key name, *TSIG algorithm*, and shared secret, configured statically.

*TSIG record* — a *pseudo-RR* of type 250, conveying transaction signature data.

*unknown RR type* — a resource record type not enumerated in §4.14 of the SRS (Appendix B of the SRS).

*VERSION field* — the EDNS protocol version field encoded in the *OPT pseudo-RR* TTL field.

*wildcard owner name* — an *owner name* whose leftmost label is `*`, treated per *RFC 4592*.

*XoT connection* — a TLS-protected TCP connection used for a *transfer session* per ***RFC 9103***.

*zone* — a contiguous portion of the DNS namespace administered as a unit.

*zone apex* — the topmost owner name in a *zone*, where the *SOA record* and apex NS RRset reside.

*zone class* — the DNS class of a *served zone*; principally ***IN***.

*zone data* — the set of *resource records* constituting a *zone*.

*zone refresh* — the process of updating a *zone*'s in-memory *zone data* from a *primary*; performed by *AXFR session* or *IXFR session*.

*zone state* — one of the three states ***LOADING***, ***ACTIVE***, ***EXPIRED*** per [R-FR-ZONE-006].

*zone state machine* — the timing-and-decision component governing *refresh attempts*; specified in §4.16 of the SRS.

### 1.2 Individual Concepts (Names)

An **individual concept** denotes a specific, named instance. Individuals are rendered in ***bold italics***.

***OxideDNS-Secondary*** — the named software product, equivalent to *server*/*authoritative server* in rule context.

***LOADING***, ***ACTIVE***, ***EXPIRED*** — the three *zone states*.

***IN*** — DNS class Internet (value 1).

***SIGTERM***, ***SIGINT***, ***SIGHUP***, ***SIGUSR1***, ***SIGUSR2*** — POSIX signals named in [R-IF-SIG] rules.

***A***, ***NS***, ***CNAME***, ***SOA***, ***PTR***, ***HINFO***, ***MX***, ***TXT***, ***AAAA***, ***SRV***, ***NAPTR***, ***DNAME***, ***DS***, ***RRSIG***, ***NSEC***, ***DNSKEY***, ***NSEC3***, ***NSEC3PARAM***, ***TLSA***, ***SVCB***, ***HTTPS***, ***URI***, ***OPT***, ***TSIG***, ***TKEY*** — named resource-record types per SRS Appendix B.

***RFC 1034***, ***RFC 1035***, ***RFC 1982***, ***RFC 1995***, ***RFC 1996***, ***RFC 2119***, ***RFC 2181***, ***RFC 2308***, ***RFC 2782***, ***RFC 3403***, ***RFC 3596***, ***RFC 3597***, ***RFC 4034***, ***RFC 4035***, ***RFC 4343***, ***RFC 4592***, ***RFC 4635***, ***RFC 5155***, ***RFC 5246***, ***RFC 5280***, ***RFC 5452***, ***RFC 5936***, ***RFC 6066***, ***RFC 6604***, ***RFC 6672***, ***RFC 6698***, ***RFC 6840***, ***RFC 6891***, ***RFC 6895***, ***RFC 6944***, ***RFC 7553***, ***RFC 7766***, ***RFC 7828***, ***RFC 7830***, ***RFC 7858***, ***RFC 8020***, ***RFC 8174***, ***RFC 8446***, ***RFC 8482***, ***RFC 8906***, ***RFC 8945***, ***RFC 9103***, ***RFC 9325***, ***RFC 9460*** — IETF standards normatively referenced.

***BCP 14***, ***BCP 195*** — IETF Best Current Practices normatively referenced.

***PID v0.1***, ***SRS v0.1*** — the source project documents.

### 1.3 Verb Concepts (Fact Types)

Fact types are the verbs of the vocabulary: they describe how noun concepts relate to one another. The fact types below are grouped by their primary subject. In rule expressions, fact types are realised as natural verbs in sentence context.

**Server-message fact types.** *server* *receives* *DNS message*. *server* *parses* *DNS message*. *server* *constructs* *response*. *server* *emits* *response* (to *DNS client*). *server* *discards* *DNS message*. *server* *rejects* *DNS message* with *RCODE*.

**Server-zone fact types.** *server* *serves* *zone*. *server* *holds* *zone data* for *zone*. *server* *publishes* *zone data* for *zone*. *zone* *is in state* *zone state*.

**Server-transfer fact types.** *server* *initiates* *AXFR session* with *primary*. *server* *initiates* *IXFR session* with *primary*. *server* *aborts* *transfer session*. *server* *completes* *transfer session*. *primary* *delivers* *AXFR response* / *IXFR response*.

**Server-NOTIFY fact types.** *server* *accepts* *NOTIFY message*. *server* *rejects* *NOTIFY message*. *server* *signals* *zone state machine* for *zone*.

**Server-TSIG fact types.** *server* *signs* *DNS message* with *TSIG key*. *server* *verifies* *TSIG record* in *DNS message*. *server* *produces* *TSIG error response* with error code.

**Server-XoT fact types.** *server* *establishes* *XoT connection* with *primary*. *server* *validates* *certificate* of *primary*.

**Query-zone fact types.** *query* *references* *QNAME*. *QNAME* *falls within* *served zone*. *query* *matches* *RRset* at *QNAME*. *query* *matches* *wildcard owner name*.

**Record fact types.** *resource record* *belongs to* *RRset*. *RRset* *has* *owner name*, *type*, *class*, *TTL*. *RRset* *appears in* *answer section* / *authority section* / *additional section*.

**Header bit fact types.** *DNS header* *has* QR bit, AA bit, TC bit, RD bit, RA bit, AD bit, CD bit, Z bits, DO bit. *server* *sets* bit to value.

**Zone state machine fact types.** *zone state machine* *triggers* *refresh attempt*. *refresh attempt* *succeeds* / *fails*. *refresh attempt* *uses* *AXFR session* / *IXFR session*.

**RRL fact types.** *server* *accounts* *response* under *accounting key*. *accounting key* *token bucket* *is exhausted*. *server* *drops* / *truncates* *response*.

**Logging fact types.** *server* *emits* *log entry* with level.

**Configuration fact types.** *server* *loads* *configuration* from *configuration file*. *server* *validates* *configuration*.

**Signal fact types.** *server* *receives* *signal*. *server* *initiates* *graceful shutdown*.

---

## 2. Structural Rules

Structural rules are *definitional necessities* — properties that hold by virtue of the system's design. They are expressed with the alethic modal **It is necessary that**. The rules in §2.1 are the architectural invariants of SRS §3; the rules in §2.2 are conceptual necessities derived from the SRS body.

### 2.1 Architectural Invariants

**[R-INV-001]** Secondary-only operation.
**It is necessary that** **each** *zone data* held by the *server* is *acquired* exclusively through an *AXFR session* per ***RFC 5936*** or an *IXFR session* per ***RFC 1995*** initiated by the *server* toward an operator-configured *primary*.
**It is necessary that** the *server* **not** *accept* *zone data*, *zone* modification, or any change to its authoritative state through any channel other than such *transfer sessions*.
*Source.* SRS ODS-INV-001.

**[R-INV-002]** Memory-resident zone data.
**It is necessary that** **each** *zone data* served by the *server* resides in *process* memory.
**It is necessary that** the *query*-serving execution path of the *server* **not** perform disk I/O.
*Source.* SRS ODS-INV-002.

**[R-INV-003]** Atomic zone refresh.
**It is necessary that** **each** *query* against a *zone* is *answered* from exactly one internally consistent version of that *zone's* *zone data*.
**It is necessary that**, during a *zone refresh*, **each** *query* *observes* either the pre-refresh state in its entirety **or** the post-refresh state in its entirety; partial observation is **impossible**.
*Source.* SRS ODS-INV-003.

**[R-INV-004]** No persistent operational state.
**It is necessary that** the *server* **not** *write* operational state — including *zone data*, transfer history, *query* statistics, *configuration*, or any data intended to survive *process* restart — to persistent storage.
*Source.* SRS ODS-INV-004.

**[R-INV-005]** Static configuration.
**It is necessary that** **each** *configuration* is *supplied* to the *server* at *process startup* and remains immutable for the *process* lifetime.
**It is necessary that** the *server* **not** *re-read* or otherwise *alter* its *configuration* during operation.
*Source.* SRS ODS-INV-005.

**[R-INV-006]** Memory safety discipline.
**It is necessary that** **each** code path of the *server* that *processes* data received from the network is implemented in Rust's safe subset.
**It is necessary that** **each** `unsafe` block in the *server*'s implementation carries a comment stating the reason the block is necessary and the invariants on which its soundness depends.
*Source.* SRS ODS-INV-006.

### 2.2 Conceptual Necessities

**[R-DEF-001]** Identifier scheme.
**It is necessary that** **each** requirement of the SRS carries an identifier of the form `ODS-CATEGORY-AREA-NNN`, with *CATEGORY* ∈ {`FR`, `NFR`, `IF`, `INV`, `NEG`, `VER`}, *AREA* a 3–6-character uppercase mnemonic (omitted for `INV`, `NEG`, `VER`), and `NNN` a zero-padded three-digit sequence number unique within `(CATEGORY, AREA)`.
*Source.* SRS §1.4.3.

**[R-DEF-002]** Identifier immutability.
**It is necessary that** **each** allocated requirement identifier is never *reused*, *renumbered*, or *reassigned* to a different requirement.
*Source.* SRS §1.4.4.

**[R-DEF-003]** Zone uniqueness.
**It is necessary that** **each** *served zone* is identified uniquely by the tuple (*zone apex*, *zone class*) with *zone apex* comparison case-insensitive per ***RFC 4343***.
*Source.* SRS [ODS-FR-ZONE-001].

**[R-DEF-004]** SOA uniqueness.
**It is necessary that** **each** *zone* contains **exactly one** *SOA record* and that *SOA record*'s *owner name* equals the *zone apex* of the *zone*.
*Source.* SRS [ODS-FR-RR-002].

**[R-DEF-005]** Apex NS presence.
**It is necessary that** **each** *zone* contains **at least one** NS *resource record* at its *zone apex*.
*Source.* SRS [ODS-FR-RR-003].

**[R-DEF-006]** RRset semantics.
**It is necessary that** **each** set of *resource records* sharing *owner name*, *class*, and type constitutes exactly one *RRset*.
**It is necessary that** **each** *RRset* has a single *TTL* applied to all its members.
*Source.* SRS [ODS-FR-CORE-026], [R-FR-CORE-027].

**[R-DEF-007]** CNAME exclusivity.
**It is necessary that** **each** *owner name* carrying a ***CNAME*** *RRset* in a *served zone* **not** carry **any** other *RRset* at that *owner name*, with the exception of ***RRSIG***, ***NSEC***, and ***NSEC3*** *resource records*.
*Source.* SRS [ODS-FR-RR-005].

**[R-DEF-008]** DNAME / CNAME exclusion.
**It is necessary that** **each** *owner name* carrying a ***DNAME*** *RRset* **not** carry a ***CNAME*** *RRset* at that same *owner name*, with the exception of ***RRSIG***, ***NSEC***, and ***NSEC3*** *resource records*.
*Source.* SRS [ODS-FR-RR-006].

**[R-DEF-009]** SOA serial arithmetic.
**It is necessary that** **each** comparison of two *SOA serial* values is performed per ***RFC 1982*** §3.2 modular arithmetic.
*Source.* SRS [ODS-FR-RR-004].

**[R-DEF-010]** Zone state exhaustiveness.
**It is necessary that** **each** *served zone* is at any given time in **exactly one** of the *zone states* ***LOADING***, ***ACTIVE***, or ***EXPIRED***.
*Source.* SRS [ODS-FR-ZONE-006].

**[R-DEF-011]** EXPIRE-state transition.
**It is necessary that** **each** *zone* transitions from ***ACTIVE*** to ***EXPIRED*** when and only when the elapsed wall-clock time since the most recent successful *refresh attempt* exceeds the *EXPIRE interval* of the *zone*.
*Source.* SRS [ODS-FR-ZSM-009].

**[R-DEF-012]** Process-startup state.
**It is necessary that** at *process startup* **each** *served zone* enters the ***LOADING*** state.
*Source.* SRS [ODS-FR-ZSM-001].

---

## 3. Operative Rules

Operative rules are *behavioural rules* expressed with deontic modals. **It is obligatory that** corresponds to RFC 2119 MUST; **It is prohibited that** to MUST NOT; **It is recommended that** to SHOULD; **It is permitted that** to MAY.

### 3.1 Functional Rules

The functional rules transcribe SRS §4 (ODS-FR-* identifiers) into SBVR form. The 17 areas of SRS §4 are reproduced in the 17 subsections below. Each rule's identifier `[R-FR-AREA-NNN]` mirrors the source `ODS-FR-AREA-NNN`.

#### 3.1.1 Core DNS Protocol — area CORE

**[R-FR-CORE-001]** **It is obligatory that** **each** *DNS message* that the *server* *receives* on a configured *listening socket* is *parsed* by the *server* according to the wire format of *RFC 1035* §4.

**[R-FR-CORE-002]** **It is obligatory that** **each** *DNS message* that the *server* *receives* with octet length less than 12 is *silently discarded* by the *server* without generating a *response*.

**[R-FR-CORE-003]** **It is obligatory that** **each** *DNS header* field — ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT — *parsed* by the *server* is interpreted in network byte order.

**[R-FR-CORE-004]** **It is obligatory that** **each** *DNS message* that the *server* *receives* on a *query*-serving *listening socket* with the QR bit set to 1 is *silently discarded* by the *server*.

**[R-FR-CORE-005]** **It is obligatory that** **each** *DNS message* that the *server* *receives* with OPCODE other than 0 (QUERY) or 4 (NOTIFY) is *rejected* by the *server* with RCODE = 4 (NOTIMP).

**[R-FR-CORE-006]** **It is obligatory that** **each** *DNS message* that the *server* *receives* with QDCOUNT not equal to 1 is *rejected* with RCODE = 1 (FORMERR).

**[R-FR-CORE-007]** **It is obligatory that** **each** *QNAME* *parsed* by the *server* is treated as a sequence of length-prefixed labels terminating in a zero-length label, with **each** label length **at most** 63 octets and total uncompressed length **at most** 255 octets; **if** these limits are violated **then** the *DNS message* is *rejected* with RCODE = 1 (FORMERR).

**[R-FR-CORE-008]** **It is obligatory that** **each** compression pointer in a *QNAME* is *resolved* by the *server* per *RFC 1035* §4.1.4; **if** the *DNS message* contains a compression loop **or** an out-of-bounds pointer target **then** the *DNS message* is *rejected* with RCODE = 1 (FORMERR).

**[R-FR-CORE-009]** **It is obligatory that** the *server* *compares* domain names case-insensitively for ASCII letters A–Z and a–z, and treats all other octet values literally and bit-for-bit.

**[R-FR-CORE-010]** **It is obligatory that** the *server* *preserves* the case of *QNAME* octets in the question section of **each** *response* it *emits*, echoing them exactly as received in the *query*.

**[R-FR-CORE-011]** **It is obligatory that** in **each** *response* the *server* *emits*, the QR bit is set to 1 **and** the OPCODE, ID, and RD bit values are echoed from the originating *query*.

**[R-FR-CORE-012]** **It is obligatory that** in **each** *response* the *server* *emits*, the RA bit is set to 0.

**[R-FR-CORE-013]** **It is obligatory that** in **each** *response* the *server* *emits*, the Z bits are set to 0.

**[R-FR-CORE-014]** **It is obligatory that** in **each** *response* the *server* *emits*, the AA bit is set to 1 **if** the *response* is an authoritative answer (direct match, *NODATA response*, *NXDOMAIN response*, or *wildcard* synthesis within a *served zone*) **and** set to 0 **if** the *response* is a referral to a delegated child *zone*.

**[R-FR-CORE-015]** **It is obligatory that** in **each** *response* the *server* *emits*, QDCOUNT, ANCOUNT, NSCOUNT, and ARCOUNT contain the exact number of records the *server* has placed in each respective section.

**[R-FR-CORE-016]** **It is obligatory that** the *server* *processes* **each** *query* with QCLASS = 1 (IN) by matching against ***IN***-class *zone data*.

**[R-FR-CORE-017]** **It is obligatory that** the *server* *processes* **each** *query* with QCLASS = 255 (ANY) by matching against *zone data* of any *served* *class*.

**[R-FR-CORE-018]** **It is obligatory that** **each** *query* with a QCLASS value other than IN or ANY, for which no *zone* of the requested *class* is *served*, is *rejected* with RCODE = 5 (REFUSED).

**[R-FR-CORE-019]** **It is obligatory that** the *server* *identifies*, for **each** *query*, the most specific *served zone* that is an ancestor of the *QNAME* or equal to it; **if** no such *zone* exists **then** the *query* is *rejected* with RCODE = 5 (REFUSED).

**[R-FR-CORE-020]** **It is obligatory that**, where the *QNAME* falls within a *served zone*, the *server* *searches* the *zone* for the *RRset* whose *owner name* equals the *QNAME* (case-insensitively per [R-FR-CORE-009]) **and** whose type equals the *QTYPE*; or, where *QTYPE* = 255 (ANY), for all *RRsets* at the *owner name*.

**[R-FR-CORE-021]** **It is obligatory that** where the *QTYPE* matches an *RRset* at the *QNAME*, the *server* *places* all records of that *RRset* in the *answer section* of the *response*.

**[R-FR-CORE-022]** **It is obligatory that** where the *QNAME* exists in the *served zone* but no *RRset* of the *QTYPE* exists at that *owner name*, the *server* *returns* a *NODATA response*: empty *answer section*, AA = 1, RCODE = 0 (NOERROR), **and** the *SOA record* of the containing *zone* in the *authority section*.

**[R-FR-CORE-023]** **It is obligatory that** where the *QNAME* does not exist in the *served zone* and no *wildcard owner name* match applies, the *server* *returns* an *NXDOMAIN response*: empty *answer section*, AA = 1, RCODE = 3 (NXDOMAIN), **and** the *SOA record* of the containing *zone* in the *authority section*.

**[R-FR-CORE-024]** **It is obligatory that** where the *QNAME* matches a *wildcard owner name* in the *served zone* per *RFC 1034* §4.3.3 as clarified by *RFC 4592*, the *server* *synthesises* the answer from the *wildcard* *RRset*, with synthesised *owner name* set to the *QNAME* **and** *TTL* inherited from the *wildcard* *RRset*.

**[R-FR-CORE-025]** **It is obligatory that** where the *QNAME* falls within a child *zone* delegated from a *served zone*, the *server* *returns* a referral *response* with empty *answer section*, AA = 0, RCODE = 0 (NOERROR), the child *zone*'s NS *RRset* in the *authority section*, **and** any associated A and AAAA *glue records* in the *additional section*.

**[R-FR-CORE-026]** **It is obligatory that** the *server* *treats* all *resource records* sharing *owner name*, *class*, and type as a single *RRset* **and** **never** *returns* a proper subset of an *RRset* in the *answer section* of a positive *response*.

**[R-FR-CORE-027]** **It is obligatory that** the *server* *applies* a single *TTL* to all members of **each** *RRset* in its *zone data*; **if** a *transfer session* delivers an *RRset* with differing *TTLs* **then** the *server* *adopts* the lowest *TTL* among them per *RFC 2181* §5.2 **and** *emits* a warning-level *log entry*.

**[R-FR-CORE-028]** **It is obligatory that** the *server* *treats* the octet values in domain name labels as opaque except for case-insensitive ASCII letter comparison per [R-FR-CORE-009], **neither** *rejecting* **nor** *normalising* octets outside the LDH set.

#### 3.1.2 Query Processing — area QRY

**[R-FR-QRY-001]** **It is obligatory that** the *server* *processes* **each** *query* authoritatively regardless of the RD bit; the RD bit affects only its echo per [R-FR-CORE-011] **and** does **not** alter resolution behaviour.

**[R-FR-QRY-002]** **It is prohibited that** *processing* of a *query* *alters* *zone data* **or** any operational state observable to other *queries*, except statistics counters per [R-FR-QRY-024] **and** *RRL* accounting state per §3.1.17.

**[R-FR-QRY-003]** **It is obligatory that** the *server* *supports* an "any-response" *configuration* option taking values "full" and "minimal", governing the *response* policy for *queries* with *QTYPE* = 255 (ANY).

**[R-FR-QRY-004]** **It is obligatory that** in "full" any-response mode, for **each** ANY *query* against a name with **at least one** *RRset* present, the *server* *returns* all *RRsets* present at the *QNAME* in the *answer section*.

**[R-FR-QRY-005]** **It is obligatory that** in "minimal" any-response mode, for **each** ANY *query* against a name with **at least one** *RRset* present, the *server* *returns* **exactly one** *RRset* selected deterministically from those present at the *QNAME* per *RFC 8482* §4.1.

**[R-FR-QRY-006]** **It is obligatory that** the default value of the "any-response" *configuration* option is "minimal".

**[R-FR-QRY-007]** **It is prohibited that** the *server* *uses* the synthesised ***HINFO*** *response* style of *RFC 8482* §4.2.

**[R-FR-QRY-008]** **It is obligatory that** **each** *query* with *QTYPE* = 253 (MAILB) **or** *QTYPE* = 254 (MAILA) is *rejected* with RCODE = 4 (NOTIMP).

**[R-FR-QRY-009]** **It is obligatory that** **each** *query* with *QTYPE* ∈ {41 (OPT), 250 (TSIG), 249 (TKEY), 0, 65535} is *rejected* with RCODE = 1 (FORMERR).

**[R-FR-QRY-010]** **It is obligatory that** where the *QNAME* has a ***CNAME*** *RRset* in the *served zone* **and** the *QTYPE* is neither ***CNAME*** **nor** ***ANY***, the *server* *includes* the ***CNAME*** record in the *answer section* **and then** attempts to resolve the ***CNAME*** target within the same *response*.

**[R-FR-QRY-011]** **It is obligatory that** when chasing a *CNAME chain* within a single *response*, the *server* *follows* the chain only as far as the next target *falls within* a *served zone*; **if** the chain leaves the *served zones* **then** the *server* *ceases* appending records **and** *completes* the *response*.

**[R-FR-QRY-012]** **It is obligatory that** the *server* *terminates* *CNAME chain* resolution at a configurable maximum chain length, default 8 records; on exceeding the limit the *response* is *delivered* as constructed **and** the event is *logged* at warning level.

**[R-FR-QRY-013]** **It is obligatory that** the *server* *detects* *CNAME chain* loops (a target name already present in the *answer section*) **and** *terminates* processing of the chain at the point of detection.

**[R-FR-QRY-014]** **It is obligatory that** where the *QNAME* falls strictly beneath a name carrying a ***DNAME*** *RRset* in the *served zone*, the *server* *includes* the ***DNAME*** record in the *answer section* **and** *synthesises* a ***CNAME*** record per *RFC 6672* §3.2 mapping the *QNAME* to a substituted target name.

**[R-FR-QRY-015]** **It is obligatory that** after ***CNAME*** synthesis from a ***DNAME***, the *server* *proceeds* with *CNAME chain* resolution per [R-FR-QRY-010] through [R-FR-QRY-013].

**[R-FR-QRY-016]** **It is obligatory that** where the *QNAME* exists in the *served zone* only as an *empty non-terminal*, the *server* *returns* a *NODATA response* per [R-FR-CORE-022] **and** **never** *expands* a *wildcard owner name* that would otherwise match at or above the *empty non-terminal*.

**[R-FR-QRY-017]** **It is obligatory that** where an NS *RRset* appears in the *authority section* or *answer section* of a *response* **and** any NS target name falls within a *served zone*, the *server* *includes* the target's A and AAAA *RRsets* in the *additional section*, subject to message-size constraints of §3.1.11.

**[R-FR-QRY-018]** **It is obligatory that** where an ***MX***, ***SRV***, or ***NAPTR*** record appears in the *answer section* with target name within a *served zone*, the *server* *includes* the target's A and AAAA *RRsets* in the *additional section*, subject to message-size constraints.

**[R-FR-QRY-019]** **It is obligatory that** where ***SVCB*** or ***HTTPS*** records appear in the *answer section* containing TargetName within a *served zone*, the *server* *includes* the TargetName's A and AAAA *RRsets* in the *additional section* per *RFC 9460* §5.

**[R-FR-QRY-020]** **It is prohibited that** the *server* *includes* in any section of a *response* a record sourced from outside the *zone data* of *served zones*.

**[R-FR-QRY-021]** **It is obligatory that** **each** *query* against an ***EXPIRED*** *zone* is *rejected* with RCODE = 2 (SERVFAIL).

**[R-FR-QRY-022]** **It is obligatory that** **each** *query* whose *processing* encounters an internal condition preventing construction of a correct *response* is *rejected* with RCODE = 2 (SERVFAIL).

**[R-FR-QRY-023]** **It is obligatory that** the *server* *applies* DNS name compression per *RFC 1035* §4.1.4 in *response* messages where compression reduces size; compression of names in RDATA is restricted to *resource record* types for which *RFC 3597* §4 **and** type-specific RFCs permit it.

**[R-FR-QRY-024]** **It is obligatory that** the *server* *maintains* in-memory counters for: *queries* received; *queries* answered with **each** *RCODE* value emitted; *queries* terminated by *CNAME chain* limit; *queries* terminated by *CNAME chain* loop detection; *queries* truncated due to message-size limits.

#### 3.1.3 Negative Responses — area NRESP

**[R-FR-NRESP-001]** **It is obligatory that** the *TTL* of the *SOA record* placed in the *authority section* of **each** *NXDOMAIN response* or *NODATA response* is set to the lesser of the *SOA* *RRset*'s *TTL* **and** the *SOA* RDATA MINIMUM field value.

**[R-FR-NRESP-002]** **It is obligatory that** when an *SOA* *RRset* is returned in the *answer section* in *response* to a direct *query* for the *SOA* at the *zone apex*, its *TTL* is the *SOA* *RRset*'s *TTL* unmodified by the MINIMUM field.

**[R-FR-NRESP-003]** **It is prohibited that** the *server* *returns* an *NXDOMAIN response* for a *QNAME* under which named descendants with *RRsets* exist in the *zone*; the correct *response* is a *NODATA response* per [R-FR-QRY-016].

**[R-FR-NRESP-004]** **It is obligatory that** where a *CNAME chain* or ***DNAME*** chain followed within a single *response* terminates within a *served zone* at a name that does not exist in that *zone*, the *server* *sets* RCODE = 3 (NXDOMAIN), *retains* the chain records in the *answer section*, **and** *includes* the *SOA record* of the terminal *zone* in the *authority section* per [R-FR-NRESP-001].

**[R-FR-NRESP-005]** **It is obligatory that** where the chain terminates at a name within a *served zone* lacking an *RRset* of the original *QTYPE*, the *server* *sets* RCODE = 0 (NOERROR), *retains* the chain records, **and** *includes* the *SOA record* of the terminal *zone* per [R-FR-NRESP-001].

**[R-FR-NRESP-006]** **It is obligatory that** where the chain leaves the *served zones*, the *server* *sets* RCODE = 0 (NOERROR), *sets* the AA bit to 1, **and** *includes* **no** *SOA record* in the *authority section*; the chain records up to departure are retained.

#### 3.1.4 Unknown RR Handling — area URR

**[R-FR-URR-001]** **It is obligatory that** the *server* *accepts* *resource records* of any RR TYPE value during a *transfer session*, treating the RDATA of unrecognised types as opaque octet sequences of length RDLENGTH.

**[R-FR-URR-002]** **It is obligatory that** the *zone data* *preserves* the RDATA of *unknown RR types* bit-for-bit identical to the octets received from the *primary*.

**[R-FR-URR-003]** **It is obligatory that** the *server* *accepts* *resource records* of *unknown RR types* with RDLENGTH = 0 **and** *serves* such records with RDLENGTH = 0 in *response* messages.

**[R-FR-URR-004]** **It is obligatory that** **each** *query* whose *QTYPE* matches the numeric type code of an *unknown RR type* *RRset* at the *QNAME* is answered using the standard lookup of §3.1.1 and §3.1.2.

**[R-FR-URR-005]** **It is obligatory that** when *emitting* an *unknown RR type* record, the *server* *sets* the RDLENGTH field to the exact octet count of the stored RDATA **and** *emits* the RDATA verbatim without modification, reordering, or normalisation.

**[R-FR-URR-006]** **It is prohibited that** the *server* *applies* DNS name compression to any octet sequence within the RDATA of an *unknown RR type* when *emitting* a *response*.

**[R-FR-URR-007]** **It is prohibited that** the *server* *interprets* any octet pattern within the RDATA of a received *unknown RR type* as a compression pointer; the RDATA is consumed as a contiguous opaque sequence of exactly RDLENGTH octets.

**[R-FR-URR-008]** **It is obligatory that** *RRset* membership for *unknown RR types* is determined by bit-for-bit RDATA comparison; the *server* *applies* no case folding, ordering normalisation, or other transformation.

**[R-FR-URR-009]** **It is obligatory that** **each** *transfer session* containing a *resource record* of RR TYPE 0 **or** 65535 is *aborted* by the *server*; types in other ranges (including IANA Private Use **and** unassigned future codes) are accepted.

#### 3.1.5 Anti-Spoofing — area SPOOF

**[R-FR-SPOOF-001]** **It is obligatory that** when the *server* *originates* a *DNS query*, the *QID* is selected from a cryptographically secure random source, sampling the full 16-bit ID space uniformly.

**[R-FR-SPOOF-002]** **It is obligatory that** when the *server* *originates* a UDP *DNS query*, the source UDP port is selected from a cryptographically secure random source drawing from the unprivileged ephemeral port range; **it is recommended that** a source port not be reused for an outbound *query* to the same destination while any prior *query* to that destination remains outstanding.

**[R-FR-SPOOF-003]** **It is obligatory that** **each** *response* received in reply to an outbound *query* whose source IP address does not equal the destination IP address of the originating *query* is *silently discarded*.

**[R-FR-SPOOF-004]** **It is obligatory that** **each** UDP *response* received in reply to an outbound UDP *query* whose source UDP port does not equal the destination UDP port of the originating *query* is *silently discarded*.

**[R-FR-SPOOF-005]** **It is obligatory that** **each** *response* received in reply to an outbound *query* whose *QID* does not equal the *QID* of the originating *query* is *silently discarded*.

**[R-FR-SPOOF-006]** **It is obligatory that** **each** *response* received in reply to an outbound *query* whose question section does not equal that of the originating *query* (compared case-insensitively per [R-FR-CORE-009]) is *silently discarded*.

**[R-FR-SPOOF-007]** **It is obligatory that** **each** discard under [R-FR-SPOOF-003] through [R-FR-SPOOF-006] is *recorded* via a *log entry* at warning level containing **at least** the source IP, the failed validation check, **and** a correlation identifier for the originating *query*.

#### 3.1.6 AXFR Zone Transfer Client — area AXFR

**[R-FR-AXFR-001]** **It is obligatory that** **each** *AXFR query* originated by the *server* is sent over TCP. **It is prohibited that** the *server* *issues* an *AXFR query* over UDP.

**[R-FR-AXFR-002]** **It is obligatory that** **each** *AXFR query* is constructed with *QNAME* equal to the *zone apex*, *QTYPE* = 252, *QCLASS* equal to the *zone class*, OPCODE = 0, RD = 0, **and** *QID* selected per [R-FR-SPOOF-001].

**[R-FR-AXFR-003]** **It is obligatory that** the *server* *establishes* a TCP connection to the *primary*'s configured port (default 53) for **each** *AXFR session*; an existing TCP connection to the *primary* MAY be reused per *RFC 7766*.

**[R-FR-AXFR-004]** **It is obligatory that** the *server* *processes* **each** *AXFR response* as a sequence of one or more *DNS messages* received in order on the TCP connection; message boundaries within the stream carry no semantic significance.

**[R-FR-AXFR-005]** **It is obligatory that** **each** message in an *AXFR response* stream carries a *QID* equal to that of the originating *AXFR query* **and** OPCODE = 0; failure of either check on any message causes the *AXFR session* to be *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-006]** **It is obligatory that** the *server* *ignores* the AA, TC, RD, RA, AD, **and** CD bit values in *AXFR response* messages.

**[R-FR-AXFR-007]** **It is obligatory that** the first record in the *answer section* of the first *AXFR response* message is an *SOA record* whose *owner name* equals the *zone apex* **and** whose *class* equals the *zone class*; on failure the *AXFR session* is *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-008]** **It is obligatory that** the *server* *recognises* the *AXFR response* as complete upon receipt of a second *SOA record* in the stream; all records between (exclusive) the initial **and** terminating *SOA records* constitute the transferred *zone data*.

**[R-FR-AXFR-009]** **It is obligatory that** the terminating *SOA record* is bit-for-bit identical to the initial *SOA record* in *owner name*, *class*, type, *TTL*, **and** RDATA; any difference causes the *AXFR session* to be *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-010]** **It is prohibited that** any *SOA record* other than the initial **and** terminating *SOA records* appears in the *AXFR response* stream; receipt of an additional *SOA record* causes the *AXFR session* to be *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-011]** **It is obligatory that** **each** record in the *AXFR response* stream has *class* equal to the *zone class*; records of a different *class* cause the *AXFR session* to be *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-012]** **It is obligatory that** **each** record in the *AXFR response* stream has an *owner name* at or below the *zone apex*; out-of-zone records cause the *AXFR session* to be *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-013]** **It is obligatory that** the *server* *accepts* *glue records* (A **and** AAAA at owner names below child-zone delegation points) as part of the *AXFR response* stream **and** *stores* them in *zone data* for use in additional-section composition per [R-FR-QRY-017].

**[R-FR-AXFR-014]** **It is permitted that** the *server* *retains* occluded data per *RFC 5936* §2.2.4 (other than permitted *glue records*) in *zone data*; **it is prohibited that** the *server* *returns* such occluded data in *query* *responses* generated per §3.1.2.

**[R-FR-AXFR-015]** **It is obligatory that** **each** compression pointer within an *AXFR response* message references only positions within that same *DNS message*; cross-message pointer targets cause the *AXFR session* to be *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-016]** **It is obligatory that** when a *zone* is configured with more than one *primary*, the *server* *attempts* *AXFR session*s in the configured order; on failure or error RCODE per [R-FR-AXFR-020] the *server* *proceeds* to the next *primary*; on exhaustion the retry semantics of §3.1.16 apply.

**[R-FR-AXFR-017]** **It is obligatory that** where TSIG is configured for the selected *primary*, the *server* *signs* the outbound *AXFR query* with the configured *TSIG key* per §3.1.9.

**[R-FR-AXFR-018]** **It is obligatory that** for TSIG-signed *AXFR sessions*, the *server* *verifies* TSIG signatures across the multi-message *AXFR response* per *RFC 8945* §5.3.1 **and** §3.1.9; **at least** the first **and** last messages **must** carry valid signatures; failure causes the *AXFR session* to be *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-019]** **It is obligatory that** upon any of the failure conditions enumerated in this subsection — validation failure, TSIG verification failure, premature TCP close before terminating *SOA record*, session timeout exceedance, error RCODE — the *server* *aborts* the *AXFR session*, *closes* the TCP connection, *discards* all partially received data without modifying *zone data*, *emits* a warning-level *log entry*, **and** *applies* the retry semantics of §3.1.16.

**[R-FR-AXFR-020]** **It is obligatory that** **each** *AXFR response* message with RCODE other than 0 (NOERROR) causes the *AXFR session* to be *aborted* per [R-FR-AXFR-019]; the specific *RCODE* is recorded in the *log entry*.

**[R-FR-AXFR-021]** **It is obligatory that** the *server* *enforces* a configurable timeout on *AXFR sessions*, default 300 seconds, measured from TCP connection establishment to receipt of the terminating *SOA record*; exceedance causes the session to be *aborted* per [R-FR-AXFR-019].

**[R-FR-AXFR-022]** **It is obligatory that** the *server* *limits* the number of concurrently outstanding *AXFR sessions* across all *served zones* to a configurable maximum, default 4; *AXFR* initiations exceeding this limit are queued FIFO **and** initiated as in-flight sessions complete.

**[R-FR-AXFR-023]** **It is obligatory that** upon successful completion of an *AXFR session* the *server* *constructs* the new *zone data* in memory **and** *publishes* it atomically per [R-INV-003]; the previous *zone data* remains in service until publication completes.

#### 3.1.7 IXFR Incremental Zone Transfer — area IXFR

**[R-FR-IXFR-001]** **It is permitted that** the *server* *initiates* an *IXFR query* over UDP; **it is obligatory that** the *server* *retries* over TCP **if** the UDP *response* has TC set **or** does not constitute a complete *IXFR response* in one of the three modes of [R-FR-IXFR-004].

**[R-FR-IXFR-002]** **It is obligatory that** TCP *IXFR sessions* are conducted under the same connection-handling and multi-message reassembly requirements as *AXFR sessions* per [R-FR-AXFR-003], [R-FR-AXFR-004], and [R-FR-AXFR-005].

**[R-FR-IXFR-003]** **It is obligatory that** **each** *IXFR query* is constructed with *QNAME* equal to the *zone apex*, *QTYPE* = 251, *QCLASS* equal to the *zone class*, OPCODE = 0, RD = 0, *QID* per [R-FR-SPOOF-001], **and** the *SOA record* currently held for the *zone* placed in the *authority section* of the *query*.

**[R-FR-IXFR-004]** **It is obligatory that** the *server* *determines* the *IXFR response* mode per *RFC 1995* §4, distinguishing: Mode 1 (incremental) — first two records are *SOA records* with subsequent difference sequences; Mode 2 (full-zone fallback) — first record is *SOA record*, second is non-SOA, structured as full zone; Mode 3 (no update available) — exactly one *SOA record* whose serial equals the *query*'s *SOA serial*.

**[R-FR-IXFR-005]** **It is obligatory that** for a Mode 1 *IXFR response*, the *server* *processes* difference sequences in order; **each** sequence: old-*SOA record*, zero or more records to delete, new-*SOA record*, zero or more records to add — applied transforming the *zone data* from old serial to new serial.

**[R-FR-IXFR-006]** **It is obligatory that** the first difference sequence's old-*SOA record* has serial equal to the *query*'s sent *SOA serial*; mismatch causes the *IXFR session* to be *aborted* per [R-FR-IXFR-013].

**[R-FR-IXFR-007]** **It is obligatory that** in multi-sequence Mode 1 *responses*, the new-*SOA record* of **each** sequence equals the old-*SOA record* of the next, **and** the final sequence's new-*SOA record* equals the outer terminating *SOA record*; failure causes *abort* per [R-FR-IXFR-013].

**[R-FR-IXFR-008]** **It is obligatory that** within each difference sequence, **each** *resource record* listed for deletion is currently present in the working *zone data*; deletion of an absent record causes *abort* per [R-FR-IXFR-013].

**[R-FR-IXFR-009]** **It is obligatory that** within each difference sequence, **each** *resource record* listed for addition is not currently present in the working *zone data*; addition of an already-present record causes *abort* per [R-FR-IXFR-013].

**[R-FR-IXFR-010]** **It is obligatory that** upon successful application of all sequences with all validations passing, the resulting *zone data* is *published* atomically per [R-INV-003].

**[R-FR-IXFR-011]** **It is obligatory that** for a Mode 2 *IXFR response*, the *server* *processes* the *response* under the *AXFR* semantics of §3.1.6, applying [R-FR-AXFR-004] through [R-FR-AXFR-023].

**[R-FR-IXFR-012]** **It is obligatory that** for a Mode 3 *IXFR response*, the *server* *treats* the session as successfully completed with no *zone* change; *zone data* is not modified **and** refresh timing per §3.1.16 advances.

**[R-FR-IXFR-013]** **It is obligatory that** upon any *IXFR* failure condition — validation failure, TSIG failure, premature TCP close, session timeout, non-zero RCODE, or diff-state inconsistency per [R-FR-IXFR-008] or [R-FR-IXFR-009] — the *server* *aborts* the *IXFR session*, *closes* the TCP connection, *discards* all partial data, *emits* a warning-level *log entry*, **and** *applies* the retry semantics of §3.1.16.

**[R-FR-IXFR-014]** **It is permitted that** after an aborted *IXFR session* the *zone state machine* directs the next *refresh attempt* to use *AXFR* rather than *IXFR*, **and** **it is recommended that** this behaviour apply where the failure cause indicates non-support of *IXFR* by the *primary* (RCODE = 4 or 1).

**[R-FR-IXFR-015]** **It is obligatory that** where TSIG is configured for the *primary*, the *server* *signs* outbound *IXFR queries* **and** *verifies* TSIG on inbound *IXFR response* messages per §3.1.9; failure causes *abort* per [R-FR-IXFR-013].

**[R-FR-IXFR-016]** **It is obligatory that** the *server* *enforces* a configurable timeout on *IXFR sessions*, default 60 seconds; exceedance causes *abort* per [R-FR-IXFR-013].

**[R-FR-IXFR-017]** **It is obligatory that** *IXFR sessions* count against the same concurrent transfer pool as *AXFR sessions* per [R-FR-AXFR-022].

**[R-FR-IXFR-018]** **It is obligatory that**, except as specified or modified in this subsection, *IXFR sessions* are subject to [R-FR-AXFR-006], [R-FR-AXFR-011], [R-FR-AXFR-012], [R-FR-AXFR-013], [R-FR-AXFR-014], [R-FR-AXFR-015], **and** [R-FR-AXFR-016] with "IXFR session" substituted for "AXFR session".

#### 3.1.8 NOTIFY Handling — area NOTIFY

**[R-FR-NOTIFY-001]** **It is obligatory that** the *server* *accepts* *NOTIFY messages* on its configured UDP **and** TCP *listening sockets*, identifying *NOTIFY* by OPCODE = 4; *DNS messages* with QR = 1 are *silently discarded* per [R-FR-CORE-004].

**[R-FR-NOTIFY-002]** **It is obligatory that** **each** *NOTIFY message* with QDCOUNT ≠ 1 **or** question-section *QTYPE* ≠ 6 (SOA) receives a *FORMERR response* per [R-FR-NOTIFY-006].

**[R-FR-NOTIFY-003]** **It is obligatory that** **if** the *QNAME* **and** *QCLASS* of a *NOTIFY message* do not match any *served zone* **then** the *server* *rejects* with RCODE = 5 (REFUSED) **and** takes no further action.

**[R-FR-NOTIFY-004]** **It is obligatory that** **each** *NOTIFY message* from an IP address not configured as an authorised notifier for the named *zone* is *silently discarded* without any *response*; the discard is *logged* at warning level with source IP **and** *QNAME*.

**[R-FR-NOTIFY-005]** **It is obligatory that** where TSIG is configured for an authorised notifier, **each** *NOTIFY message* from that notifier is signed; the *server* *verifies* TSIG per §3.1.9; failure causes rejection per the TSIG-specific response of §3.1.9 **and** a warning-level *log entry*.

**[R-FR-NOTIFY-006]** **It is obligatory that** upon successful validation, the *server* *emits* a *NOTIFY response* on the same transport with: *QID* echoed; QR = 1; OPCODE = 4; AA = 1; RCODE = 0; question section copied verbatim; **and** a freshly computed TSIG record per §3.1.9 where the inbound message was signed.

**[R-FR-NOTIFY-007]** **It is obligatory that** upon successful acceptance of a *NOTIFY message*, **and** subject to dedup of [R-FR-NOTIFY-009], the *server* *signals* the *zone state machine* to perform an expedited *refresh attempt* for the named *zone*.

**[R-FR-NOTIFY-008]** **It is obligatory that** where a *NOTIFY message* contains an *SOA record* in the *answer section* per *RFC 1996* §3.7, the *server* *verifies* that *owner name* matches *QNAME* **and** *class* matches *QCLASS*; **it is permitted that** the *SOA serial* be used by the *zone state machine* per [R-FR-ZSM-007]; **it is prohibited that** fields other than serial (REFRESH, RETRY, EXPIRE, MINIMUM) be applied to timer state.

**[R-FR-NOTIFY-009]** **It is obligatory that** the *server* *responds* to **each** well-formed *NOTIFY message* but does **not** *signal* a new *refresh attempt* **if** a *refresh attempt* for the *zone* is in progress **or** completed within a configurable *deduplication interval*, default 1 second.

**[R-FR-NOTIFY-010]** **It is obligatory that** **each** accepted *NOTIFY message* is *logged* at info level with source IP, *QNAME*, embedded *SOA serial* (where present), **and** action taken; rejections **and** discards are *logged* at warning level per [R-FR-NOTIFY-004] **and** [R-FR-NOTIFY-005].

#### 3.1.9 TSIG Authentication — area TSIG

**[R-FR-TSIG-001]** **It is obligatory that** the *server* *implements* **and** *accepts* the *HMAC-SHA256* algorithm.

**[R-FR-TSIG-002]** **It is obligatory that** the *server* *implements* **and** *accepts* the *HMAC-SHA1* algorithm.

**[R-FR-TSIG-003]** **It is recommended that** the *server* *implements* **and** *accepts* the *HMAC-SHA384* **and** *HMAC-SHA512* algorithms.

**[R-FR-TSIG-004]** **It is prohibited that** the *server* *implements* the *HMAC-MD5* algorithm; **each** received *DNS message* bearing TSIG with this algorithm name receives a *BADALG response* per [R-FR-TSIG-013].

**[R-FR-TSIG-005]** **It is obligatory that** **each** *TSIG key* is *configured* at *process startup* per §3.3.2 **and** is immutable for the *process* lifetime per [R-INV-005]; each comprises key name, *TSIG algorithm*, **and** shared secret.

**[R-FR-TSIG-006]** **It is prohibited that** shared secret material appears in any *log entry*, error message, or diagnostic output at any verbosity level; **it is obligatory that** such material be zeroed in *process* memory at *process* termination.

**[R-FR-TSIG-007]** **It is obligatory that** in **each** received *DNS message* bearing a TSIG record, the TSIG record appears as the last record in the *additional section*; messages with TSIG in another position or with multiple TSIG records are *rejected* with RCODE = 1 (FORMERR).

**[R-FR-TSIG-008]** **It is obligatory that** upon detecting a TSIG record in a received *DNS message*, the *server* performs verification in the following order, terminating at the first failure with the corresponding *TSIG error response* per [R-FR-TSIG-013]:
(a) locate the matching *TSIG key* by the TSIG record's *owner name*; absence produces *BADKEY response*;
(b) verify the algorithm name in TSIG RDATA matches the configured *TSIG algorithm*; mismatch produces *BADKEY response*;
(c) verify the absolute difference between current time and the *time signed* does not exceed the *fudge value*; exceedance produces *BADTIME response*;
(d) compute the expected *MAC* over the message (with TSIG removed and header ID restored from the TSIG RDATA's original-ID);
(e) compare computed *MAC* with received *MAC*; mismatch produces *BADSIG response*.
A message is authenticated only when all five checks pass.

**[R-FR-TSIG-009]** **It is obligatory that** *MAC* comparison during TSIG verification is performed using a constant-time function that does not leak timing information about byte mismatch positions.

**[R-FR-TSIG-010]** **It is obligatory that** for **each** multi-message TSIG-signed *response*, at least one TSIG-signed message appears within every window of 100 consecutive envelopes of the *response* stream; a gap exceeding 100 envelopes causes the session to be *aborted* with TSIG verification failure logged at warning level.

**[R-FR-TSIG-011]** **It is obligatory that** for multi-message TSIG-signed *responses*, the *server* *maintains* the cumulative *MAC* envelope context per *RFC 8945* §5.3.1: the *MAC* of the originating signed query is the prior-MAC input to the first signed *response* message's *MAC* computation; each subsequently verified *MAC* becomes the prior-MAC input to the next signed message.

**[R-FR-TSIG-012]** **It is obligatory that** when the *server* *originates* a *DNS message* destined for a peer with TSIG configured, the *server* *signs* the message by appending a TSIG record to the *additional section*, with: algorithm name **and** secret from the configured *TSIG key*; *time signed* set to current time; *fudge value* default 300 seconds (configurable); original ID equal to *QID*; *MAC* computed per §5.3 **and** [R-FR-TSIG-011]; error **and** other-len fields zero.

**[R-FR-TSIG-013]** **It is obligatory that** when the *server* *detects* a TSIG verification failure on an inbound *DNS message* from an authorised source, the *server* *responds* per *RFC 8945* §5.2.2 with: RCODE = 9 (NOTAUTH); TSIG record in *additional section* carrying the appropriate error code; for *BADTIME response*, the *server*'s current time in "other data"; for other errors, MAC field MAY be zero-length.

**[R-FR-TSIG-014]** **It is obligatory that** the *server* *accepts* inbound TSIG records with MAC sizes within the per-algorithm range of *RFC 8945* §5.2.2.1 **and** *RFC 4635* §3.1; MACs below the minimum produce *BADTRUNC response* per [R-FR-TSIG-013].

**[R-FR-TSIG-015]** **It is obligatory that** when the *server* *signs* an outbound *DNS message*, the TSIG record carries the *MAC* at full algorithm output length, without truncation.

**[R-FR-TSIG-016]** **It is obligatory that** where a TSIG-signed *response* message would exceed the available UDP message size, the *server* *sets* the TC bit, *omits* the TSIG record, **and** *responds* with the truncated header.

**[R-FR-TSIG-017]** **It is obligatory that** TSIG events are *logged* as follows: successful inbound verification at debug level (key name, source IP); successful outbound signing at debug level (key name, destination IP); any TSIG error at warning level (key name, error type, peer IP, direction, timestamp). MAC values, secrets, and key-derived material **never** appear in any *log entry*.

#### 3.1.10 Zone Transfer over TLS — area XOT

**[R-FR-XOT-001]** **It is obligatory that** the *server* *implements* TLS 1.2 (*RFC 5246*) for *XoT connections*; **it is recommended that** the *server* *implements* TLS 1.3 (*RFC 8446*); where both endpoints support TLS 1.3, it **shall** be selected.

**[R-FR-XOT-002]** **It is obligatory that** TLS cipher-suite selection conforms to ***BCP 195*** (*RFC 9325*): AEAD cipher suites only; NULL, anonymous, RC4, 3DES, **and** export-grade suites are **prohibited** from being offered or accepted.

**[R-FR-XOT-003]** **It is obligatory that** the *server* *initiates* *XoT connections* to the configured *primary* on TCP port 853 by default; the destination port is overridable per (zone, primary) tuple.

**[R-FR-XOT-004]** **It is obligatory that** *XoT connections* present the ALPN protocol identifier `dot` during TLS negotiation; failure of the *primary* to confirm `dot` ALPN causes the *XoT* session to be *aborted* per [R-FR-XOT-010].

**[R-FR-XOT-005]** **It is obligatory that** the *server* *authenticates* the *primary*'s TLS certificate via X.509 PKIX path validation per *RFC 5280* against configured trust anchors; the configured *primary* hostname is presented as TLS SNI per *RFC 6066*, **and** the certificate must present a matching SubjectAltName; validation failure for any reason causes the *XoT* session to be *aborted* per [R-FR-XOT-010].

**[R-FR-XOT-006]** **It is obligatory that** where *XoT* is configured for a (zone, primary) tuple, the *server* *applies* the Strict Profile of *RFC 9103* §9.1; **it is prohibited that** the *server* *establishes* an *XoT* session without successful TLS handshake **and** certificate authentication; **it is prohibited that** the *server* *uses* the Opportunistic Privacy Profile of *RFC 9103* §9.2; **it is prohibited that** the *server* *falls back* to unencrypted TCP transport on TLS failure.

**[R-FR-XOT-007]** **It is permitted that** the *server* *presents* a client certificate (mTLS) per *RFC 9103* §9.4 where configured per (zone, primary); client certificate **and** private key are configured per §3.3.2 **and** are subject to key-material handling analogous to [R-FR-TSIG-006].

**[R-FR-XOT-008]** **It is permitted that** *XoT* and TSIG be configured concurrently for the same (zone, primary); where both are configured, both TSIG processing per §3.1.9 **and** TLS protection apply; neither supersedes the other.

**[R-FR-XOT-009]** **It is permitted that** the *server* *reuses* an established *XoT* TCP connection for successive *transfer sessions* with the same *primary*, applying connection-persistence semantics of §3.1.12 within the TLS tunnel.

**[R-FR-XOT-010]** **It is obligatory that** TLS handshake failures, certificate validation failures, ALPN negotiation failures, **and** TLS-protocol errors during an *XoT* session cause the *transfer session* to be *aborted* per [R-FR-AXFR-019] or [R-FR-IXFR-013]; the state-machine retry semantics of §3.1.16 apply unchanged.

**[R-FR-XOT-011]** **It is obligatory that** *XoT* events are *logged* as follows: successful handshake at info level (peer IP, SNI, TLS version, cipher suite); handshake/certificate/ALPN failure at warning level (peer IP, SNI, cause); session termination at info level (peer IP, duration, bytes). Certificate material, private keys, session keys, master secrets, and TLS key-derivation material **never** appear in any *log entry*.


#### 3.1.11 EDNS0 — area EDNS

**[R-FR-EDNS-001]** **It is obligatory that** the *server* *parses* the *OPT pseudo-RR* per *RFC 6891* §6.1, decoding the fixed fields **and** RDATA option pairs; RDATA whose options are not bit-exact consumable up to RDLENGTH causes the *DNS message* to be *rejected* with RCODE = 1 (FORMERR).

**[R-FR-EDNS-002]** **It is obligatory that** **each** inbound *DNS message* contains **at most one** *OPT pseudo-RR*; messages with two or more are *rejected* with RCODE = 1 (FORMERR).

**[R-FR-EDNS-003]** **It is obligatory that** an *OPT pseudo-RR* in an inbound *DNS message* appears in the *additional section* with root *owner name* **and** TYPE = 41; violations cause RCODE = 1 (FORMERR).

**[R-FR-EDNS-004]** **It is obligatory that** the *server* *accepts* *OPT pseudo-RRs* with *VERSION field* = 0; *OPT pseudo-RRs* with *VERSION field* > 0 cause the *server* to *respond* with extended RCODE = 16 (BADVERS), carrying an *OPT pseudo-RR* whose *VERSION field* = 0.

**[R-FR-EDNS-005]** **It is obligatory that** the *server* *treats* an inbound *OPT pseudo-RR* class-field value below 512 as equal to 512 in subsequent processing; values at 512 and above are used as advertised, subject to [R-FR-EDNS-006].

**[R-FR-EDNS-006]** **It is obligatory that** the *server* *enforces* a configurable maximum UDP response size, default 1232 octets; the applied UDP ceiling for **each** *response* is the lesser of the requestor's advertised *EDNS payload size* (per [R-FR-EDNS-005]) **and** the *server*'s configured maximum; *responses* exceeding this ceiling trigger truncation per §3.1.12.

**[R-FR-EDNS-007]** **It is obligatory that** where an inbound *query* contained an *OPT pseudo-RR*, the *response* includes an *OPT pseudo-RR*; where it did not, the *response* does **not** include an *OPT pseudo-RR*.

**[R-FR-EDNS-008]** **It is obligatory that** **each** *OPT pseudo-RR* in a *response* has *owner name* = root, TYPE = 41, class = configured maximum *EDNS payload size*, *VERSION field* = 0, **and** Z bits (other than DO) = 0.

**[R-FR-EDNS-009]** **It is obligatory that** the *DO bit* in the *response* *OPT pseudo-RR*'s TTL field is set per §3.1.13.

**[R-FR-EDNS-010]** **It is obligatory that** where the *response* uses an *RCODE* in the extended range (≥ 16), the high 8 bits of the *response* *OPT pseudo-RR*'s TTL field encode the upper 8 bits of the 12-bit extended *RCODE*; for *RCODEs* in the range 0–15 the extended-RCODE field is 0.

**[R-FR-EDNS-011]** **It is obligatory that** the *server* *recognises* the edns-tcp-keepalive option (option code 11) per *RFC 7828* in TCP-borne *queries*; the option is **silently ignored** when received over UDP.

**[R-FR-EDNS-012]** **It is obligatory that** in *responses* to TCP *queries* that included the edns-tcp-keepalive option, the *server* *includes* an edns-tcp-keepalive option in the *response* *OPT pseudo-RR* RDATA advertising the *server*'s idle-timeout policy in 100-millisecond units; default 300 (= 30 s); configurable.

**[R-FR-EDNS-013]** **It is obligatory that** the *server* *recognises* the Padding option (option code 12) per *RFC 7830* in inbound *DNS messages*; **it is permitted that** the *server* *includes* a Padding option in *responses* when configured; default policy is no padding.

**[R-FR-EDNS-014]** **It is obligatory that** the *server* **silently ignores** *OPT pseudo-RR* options whose option codes it does not recognise; unknown options **never** cause the *DNS message* to be *rejected*.

#### 3.1.12 TCP Transport — area TCP

**[R-FR-TCP-001]** **It is obligatory that** *DNS messages* exchanged over TCP are framed with a 2-octet length prefix in network byte order, followed by the *DNS message* of exactly the indicated length; a length prefix value of 0 causes the connection to be closed with a warning-level *log entry*.

**[R-FR-TCP-002]** **It is obligatory that** the *server* *keeps* accepted TCP connections open until any of: idle timeout per [R-FR-TCP-003]; read/write timeout per [R-FR-TCP-004]; client-initiated close; concurrent-connection-limit reclamation per [R-FR-TCP-005]; or *server* shutdown.

**[R-FR-TCP-003]** **It is obligatory that** the *server* *enforces* a configurable TCP idle timeout on accepted connections, default 30 seconds; the applied timeout MAY be reduced for individual connections where the client advertises a shorter timeout via edns-tcp-keepalive per [R-FR-EDNS-012]; idle is measured from the last message exchange; connections idle beyond the timeout are closed with TCP FIN.

**[R-FR-TCP-004]** **It is obligatory that** the *server* *enforces* configurable read **and** write timeouts on accepted TCP connections, default 30 seconds each; reads failing to receive data within the read timeout **or** writes failing to progress within the write timeout cause the connection to be closed with TCP RST.

**[R-FR-TCP-005]** **It is obligatory that** the *server* *limits* concurrently accepted TCP connections to a configurable maximum, default 1024; new connections at the limit are either refused at the TCP layer or accepted and immediately closed; refusals are *logged* at warning level.

**[R-FR-TCP-006]** **It is permitted that** the *server* *enforces* a configurable per-source-IP TCP connection limit; default is no per-IP limit; configured refusals are *logged* at info level.

**[R-FR-TCP-007]** **It is obligatory that** the *server* *accepts* multiple in-flight *queries* on a single TCP connection (pipelining); the *server* MAY *emit* *responses* in any order, matched by *QID*; **it is prohibited that** the *server* *imposes* implicit ordering between independent *queries* on the same connection.

**[R-FR-TCP-008]** **It is obligatory that** where a UDP *response* would exceed the UDP ceiling per [R-FR-EDNS-006], the *server* *constructs* a truncated *response* per *RFC 1035* §4.2.1 with TC = 1; records are removed in the order (a) *additional section* (except the *OPT pseudo-RR*); (b) *authority section* (except any *SOA record* required by §3.1.3); (c) *answer section*; until the *response* fits.

**[R-FR-TCP-009]** **It is obligatory that** TCP connections initiated by the *server* toward *primaries* use the framing of [R-FR-TCP-001]; **it is permitted that** the *server* *reuses* a single TCP connection for multiple outbound *queries* per *RFC 7766*.

**[R-FR-TCP-010]** **It is obligatory that** the *server* *enforces* a configurable timeout on outbound TCP connection establishment, default 10 seconds; failures are abandoned **and** treated as transfer or *query* failure per §3.1.6, §3.1.7, or §3.1.16.

#### 3.1.13 DNSSEC Record Serving — area DNSSEC

**[R-FR-DNSSEC-001]** **It is obligatory that** the *server* *implements* type-aware parsing, storage, **and** serving of the following *DNSSEC records*: ***DNSKEY*** (48), ***RRSIG*** (46), ***NSEC*** (47), ***DS*** (43), ***NSEC3*** (50), ***NSEC3PARAM*** (51); type-aware handling **must** include identification of each ***RRSIG***'s "type covered" field to permit matching to covered *RRsets*.

**[R-FR-DNSSEC-002]** **It is obligatory that** the *server* *inspects* the *DO bit* in **each** inbound *query* per *RFC 4035* §3.2.1; DO = 1 triggers DNSSEC augmentation per [R-FR-DNSSEC-003] through [R-FR-DNSSEC-007]; DO = 0 triggers composition per [R-FR-DNSSEC-008].

**[R-FR-DNSSEC-003]** **It is obligatory that** where DO = 1 **and** the *response* references a DNSSEC-signed *zone*, the *server* *includes* ***RRSIG*** records covering **each** *RRset* placed in the *response*, provided the ***RRSIG*** records exist in *zone data* **and** message size permits.

**[R-FR-DNSSEC-004]** **It is obligatory that** in **each** *NXDOMAIN response* with DO = 1 **and** signed *zone*, the *server* *includes* in the *authority section* the ***NSEC*** **or** ***NSEC3*** records (and their ***RRSIGs***) authenticating non-existence of the *QNAME* per *RFC 4035* §3.1.3 or *RFC 5155* §7.2.2.

**[R-FR-DNSSEC-005]** **It is obligatory that** in **each** *NODATA response* with DO = 1 **and** signed *zone*, the *server* *includes* in the *authority section* the ***NSEC*** **or** ***NSEC3*** records (and their ***RRSIGs***) authenticating existence of the *QNAME* together with absence of the queried type per *RFC 4035* §3.1.3.1 or *RFC 5155* §7.2.3/§7.2.4.

**[R-FR-DNSSEC-006]** **It is obligatory that** where a positive *response* is synthesised from a *wildcard owner name* with DO = 1 **and** signed *zone*, the *server* *includes* in the *authority section* the ***NSEC*** **or** ***NSEC3*** records (and ***RRSIGs***) authenticating non-existence of the *QNAME* as a non-wildcard match per *RFC 4035* §3.1.3.4 or *RFC 5155* §7.2.5.

**[R-FR-DNSSEC-007]** **It is obligatory that** in **each** referral *response* with DO = 1 **and** signed parent *zone*, the *server* *includes* in the *authority section* either the ***DS*** *RRset* (and ***RRSIGs***) for the child *zone* where ***DS*** records exist, **or** the ***NSEC***/***NSEC3*** records (and ***RRSIGs***) authenticating absence of ***DS*** where the child *zone* is unsigned, per *RFC 4035* §3.1.4 or *RFC 5155* §7.2.7.

**[R-FR-DNSSEC-008]** **It is prohibited that** the *server* *includes* ***RRSIG***, ***NSEC***, **or** ***NSEC3*** records in any section of a *response* where DO = 0, except where they are themselves the explicitly queried *QTYPE*.

**[R-FR-DNSSEC-009]** **It is obligatory that** the *DO bit* in the *response* *OPT pseudo-RR*'s TTL field is set to 1 where the *response* contains DNSSEC augmentation per [R-FR-DNSSEC-003] through [R-FR-DNSSEC-007]; in all other cases (DO = 0 *queries* **and** *responses* to unsigned *zones*) DO = 0.

**[R-FR-DNSSEC-010]** **It is obligatory that** the *server* *sets* the AD bit to 0 in **each** *response* regardless of *query* state.

**[R-FR-DNSSEC-011]** **It is obligatory that** the *server* *sets* the *CD bit* to 0 in **each** *response* regardless of *query* state.

**[R-FR-DNSSEC-012]** **It is obligatory that** the *server* *accepts* *DNSSEC records* bearing **any** algorithm number, including reserved or unassigned numbers; **it is prohibited that** the *server* *performs* algorithm-validity checks during transfer, storage, or serving.

**[R-FR-DNSSEC-013]** **It is prohibited that** the *server* *generates* ***RRSIG*** records, *generates* ***NSEC*** or ***NSEC3*** records, *generates* or *maintains* ***DNSKEY*** records or DNSSEC key material, *performs* DNSSEC signature verification or validation, or *participates* in any DNSSEC key rollover protocol; all *DNSSEC records* served are received via *transfer session*.

#### 3.1.14 RR Type Parsing and Serving — area RR

**[R-FR-RR-001]** **It is obligatory that** the *server* *implements* type-aware parsing, storage, **and** serving for the *resource record* types enumerated in the catalogue (SRS §4.14 / Appendix B) per the wire-format specification of each type's referenced RFC; types not in the catalogue are handled per §3.1.4 (URR).

**[R-FR-RR-002]** **It is necessary that** **each** *served zone* contains **exactly one** *SOA record* whose *owner name* equals the *zone apex*; transferred *zones* with zero, multiple, or non-apex *SOA records* cause the *transfer session* to be *aborted*. *(Restated as conceptual necessity in §2.2 [R-DEF-004].)*

**[R-FR-RR-003]** **It is necessary that** **each** *served zone* contains **at least one** NS *resource record* at its *zone apex*; absence causes the *transfer session* to be *aborted*. *(Restated as conceptual necessity in §2.2 [R-DEF-005].)*

**[R-FR-RR-004]** **It is necessary that** **each** *SOA serial* comparison is performed per *RFC 1982* §3.2 arithmetic. *(Restated in §2.2 [R-DEF-009].)*

**[R-FR-RR-005]** **It is necessary that** **each** *owner name* carrying a ***CNAME*** *RRset* contains no other *RRset* at that *owner name* except ***RRSIG***, ***NSEC***, ***NSEC3***; violating *transfer sessions* are *aborted*. *(Restated in §2.2 [R-DEF-007].)*

**[R-FR-RR-006]** **It is necessary that** **each** *owner name* carrying a ***DNAME*** *RRset* contains no ***CNAME*** *RRset* at that name except ***RRSIG***, ***NSEC***, ***NSEC3***; violating *transfer sessions* are *aborted*. *(Restated in §2.2 [R-DEF-008].)*

**[R-FR-RR-007]** **It is obligatory that** during a *transfer session*, the *server* *validates* **each** known-type record's RDATA for wire-format conformance per the specifying RFC, including: RDLENGTH equal to expected fixed size for fixed-size types (***A***: 4 octets, ***AAAA***: 16 octets); domain-name fields parse as valid wire-format names within RDATA bounds; character-string fields have length octets within RDATA bounds **and** ≤ 255 octets per string; multi-field RDATA's decoded size equals RDLENGTH exactly; failing records cause the *transfer session* to be *aborted*.

#### 3.1.15 In-Memory Zone Store — area ZONE

**[R-FR-ZONE-001]** **It is necessary that** **each** *served zone* is identified uniquely by (zone apex, zone class) with case-insensitive comparison per [R-FR-CORE-009]; the *served zones* set is established at *process startup* per [R-INV-005] **and** is immutable for the *process* lifetime. *(See [R-DEF-003].)*

**[R-FR-ZONE-002]** **It is obligatory that** the *zone data* supports lookup by (*owner name*, type) → *RRset*, with case-insensitive *owner name* comparison; lookup also supports longest-suffix-match for zone-cut determination, *wildcard owner name* matching per *RFC 4592*, **and** direct equality for *RRset* retrieval.

**[R-FR-ZONE-003]** **It is necessary that** for **each** *query*, the *zone data* presents a single internally consistent *zone* version throughout the *query*'s processing; atomic publication per [R-INV-003] ensures the refresh transition does not produce mixed observations within any single *query*. *(See [R-INV-003].)*

**[R-FR-ZONE-004]** **It is obligatory that** *wildcard owner names* are *stored* as regular records; *wildcard* semantics are applied at *query* time per [R-FR-CORE-024] **and** [R-FR-QRY-016], not at storage.

**[R-FR-ZONE-005]** **It is obligatory that** *glue records* are *stored* in *zone data* **and** are *distinguishable* from authoritative-data records of the parent *zone* for purposes of [R-FR-AXFR-014] **and** [R-FR-CORE-014].

**[R-FR-ZONE-006]** **It is necessary that** **each** *served zone* is at any time in **exactly one** of the *zone states* ***LOADING***, ***ACTIVE***, ***EXPIRED***:
- ***LOADING***: no *transfer session* has completed; *queries* receive RCODE = 2 (SERVFAIL).
- ***ACTIVE***: at least one *transfer session* has succeeded **and** the time since most recent success ≤ *EXPIRE interval*; *queries* are processed normally.
- ***EXPIRED***: time since most recent success > *EXPIRE interval*; *queries* receive RCODE = 2 (SERVFAIL) per [R-FR-QRY-021].
*(See [R-DEF-010].)*

#### 3.1.16 Zone State Machine — area ZSM

**[R-FR-ZSM-001]** **It is necessary that** at *process startup* **each** *served zone* enters the ***LOADING*** state; the *server* *initiates* an *AXFR session* (not *IXFR*) for **each** ***LOADING*** *zone*, subject to [R-FR-AXFR-022]. *(See [R-DEF-012].)*

**[R-FR-ZSM-002]** **It is obligatory that** where an initial *AXFR session* for a ***LOADING*** *zone* fails, the *server* *schedules* a retry; the first retry delay is configurable, default 60 seconds; each subsequent failed retry doubles the delay (exponential backoff) up to a configurable maximum, default 3600 seconds; the *zone* remains ***LOADING***; **it is prohibited that** the *server* *abandons* initial-load retries while running.

**[R-FR-ZSM-003]** **It is obligatory that** the *zone state machine* *triggers* a *refresh attempt* for an ***ACTIVE*** or ***EXPIRED*** *zone* under either: (a) wall-clock reaching the next scheduled refresh time; or (b) acceptance of a *NOTIFY message* whose signal has cleared the dedup interval of [R-FR-NOTIFY-009].

**[R-FR-ZSM-004]** **It is obligatory that** upon successful completion of a *refresh attempt*, the *server* *transitions* the *zone* to ***ACTIVE*** (from any prior state), *records* the timestamp as "last successful refresh", **and** *schedules* the next *refresh attempt* at (last + *REFRESH interval*) subject to [R-FR-ZSM-011] **and** [R-FR-ZSM-010].

**[R-FR-ZSM-005]** **It is obligatory that** for **each** *refresh attempt* against a *zone* already holding data, the *zone state machine* *attempts* *IXFR* by default; where the *primary* has, within the IXFR-disabled cooldown (default 3600 seconds, configurable), returned RCODE = 4 (NOTIMP) or RCODE = 1 (FORMERR) to an *IXFR query* for the *zone*, *AXFR* is used instead.

**[R-FR-ZSM-006]** **It is permitted that** prior to initiating *IXFR* or *AXFR* for a *refresh attempt*, the *zone state machine* *performs* an SOA query against the selected *primary* to compare serials; serial comparison per [R-FR-RR-004]; if primary serial ≤ held serial, the *refresh attempt* is recorded as successful per [R-FR-ZSM-004] without transfer.

**[R-FR-ZSM-007]** **It is permitted that** where a *refresh attempt* was triggered by a *NOTIFY message* carrying an *SOA record* per [R-FR-NOTIFY-008], the *zone state machine* *uses* the embedded *SOA serial* as the primary-side input to the comparison of [R-FR-ZSM-006].

**[R-FR-ZSM-008]** **It is obligatory that** where a *refresh attempt* fails, the *zone state machine* *leaves* the *zone* in its prior state (subject to [R-FR-ZSM-009]) with prior *zone data* intact, **and** *schedules* the next *refresh attempt* at (current + *RETRY interval*) for ***ACTIVE*** *zones*, or per initial-load backoff for ***LOADING*** *zones*, subject to [R-FR-ZSM-010] **and** [R-FR-ZSM-011].

**[R-FR-ZSM-009]** **It is obligatory that** for **each** ***ACTIVE*** *zone*, the *zone state machine* *monitors* elapsed wall-clock time since the most recent successful *refresh attempt*; on exceedance of *EXPIRE interval* the *zone* transitions to ***EXPIRED***; *refresh attempts* continue at intervals ≤ *RETRY interval*; on the first successful refresh of an ***EXPIRED*** *zone* it transitions back to ***ACTIVE***.

**[R-FR-ZSM-010]** **It is obligatory that** the *zone state machine* *applies* uniform random jitter in the range ±10% to **each** scheduled interval (*REFRESH*, *RETRY*, initial-load backoff) before scheduling; jitter is drawn independently per *zone* per scheduling decision.

**[R-FR-ZSM-011]** **It is obligatory that** the *zone state machine* *enforces* a configurable minimum effective interval for *REFRESH* **and** *RETRY* values read from *SOA records*, default 60 seconds; SOA values below the minimum are treated as equal to the minimum for scheduling; original SOA values are preserved unchanged for serving.

**[R-FR-ZSM-012]** **It is obligatory that** on *process* shutdown initiated by ***SIGTERM***, the *zone state machine* *ceases* initiating new *refresh attempts*; refresh timers MUST NOT trigger new transfers after ***SIGTERM***; in-progress *transfer sessions* complete or are *aborted* per the graceful-shutdown timing of §3.2.

#### 3.1.17 Response Rate Limiting — area RRL

**[R-FR-RRL-001]** **It is obligatory that** the *server* *implements* *Response Rate Limiting* per this subsection, applied to *responses* produced for *DNS clients*; RRL is enabled by default; the *operator* MAY disable RRL by *configuration*.

**[R-FR-RRL-002]** **It is obligatory that** RRL *accounts* *responses* per a tuple (*source IP prefix*, *response category*); IPv4 prefix length default /24, IPv6 default /56, both configurable. *Response categories* are: (a) positive (NOERROR with non-empty answer); (b) NXDOMAIN; (c) NODATA; (d) referral (NOERROR with NS authority, empty answer); (e) error (other RCODEs).

**[R-FR-RRL-003]** **It is obligatory that** for **each** *response category*, the *server* *enforces* a configurable per-second rate limit per *accounting key*. Defaults: positive 20; NXDOMAIN 5; NODATA 10; referral 10; error 5.

**[R-FR-RRL-004]** **It is obligatory that** the rate limit is implemented as a *token bucket* per *accounting key* with capacity equal to the configured rate **and** refill of one token per (1 / rate) seconds; **each** *response* consumes one token; an empty bucket triggers [R-FR-RRL-005].

**[R-FR-RRL-005]** **It is obligatory that** when a *response* would be produced for an *accounting key* whose bucket is exhausted, the *server* *applies* the configured *slip* policy (integer N, default 2): N = 0 — every limited *response* is silently dropped; N ≥ 1 — of every N consecutive limited *responses*, exactly one is emitted truncated (TC = 1, empty sections, retaining question and *OPT pseudo-RR*) and N−1 are silently dropped.

**[R-FR-RRL-006]** **It is obligatory that** the *server* *supports* a configurable allowlist of source IPs/prefixes exempt from RRL accounting; *responses* to allowlisted clients **never** consume tokens or trigger [R-FR-RRL-005].

**[R-FR-RRL-007]** **It is prohibited that** *responses* to TCP *queries* are subject to RRL; RRL accounting and action apply only to UDP *responses*.

**[R-FR-RRL-008]** **It is prohibited that** *responses* to *queries* authenticated via TSIG are subject to RRL.

**[R-FR-RRL-009]** **It is obligatory that** in this version, RRL *configuration* is process-wide; per-zone or per-view RRL is **not** supported.

**[R-FR-RRL-010]** **It is obligatory that** the *server* *enforces* a configurable maximum number of concurrently tracked *accounting keys*, default 100000; on reaching the limit the least-recently-used key is evicted; eviction does not affect serving.

**[R-FR-RRL-011]** **It is obligatory that** the *server* *logs* RRL events: first entry into rate-limited state per *accounting key* at warning level (key, threshold); periodic aggregate summary at info level (default every 60 seconds) reporting dropped, truncated, and currently-rate-limited counts. **It is prohibited that** per-event drop/truncate logging occurs at info level or above.

**[R-FR-RRL-012]** **It is obligatory that** the *server* *maintains* in-memory counters for: total *responses* subject to RRL; total dropped; total emitted as truncated; currently tracked *accounting keys*; key evictions per [R-FR-RRL-010].

### 3.4 Prohibitive Rules — area NEG

The negative requirements of SRS §4.18 are restated as **It is prohibited that** rules. They consolidate prohibitions whose positive enforcement is elsewhere in §3.1, §3.2, §3.3, or in §2.1 (architectural invariants).

**[R-NEG-001]** **It is prohibited that** the *server* *processes* DNS UPDATE messages (OPCODE = 5, *RFC 2136*); inbound messages with OPCODE = 5 are *rejected* with RCODE = 4 (NOTIMP). *Enforces.* [R-INV-001].

**[R-NEG-002]** **It is prohibited that** the *server* *generates*, *modifies*, or *maintains* any *DNSSEC record* (***RRSIG***, ***NSEC***, ***NSEC3***, ***NSEC3PARAM***, ***DNSKEY***, or any other DNSSEC type whose generation is a primary-role activity); all *DNSSEC records* served originate from the *primary* via *transfer session*. *Enforces.* [R-INV-001]; [R-FR-DNSSEC-013].

**[R-NEG-003]** **It is prohibited that** the *server* *accepts* *zone data*, *zone* modification, or any change to its authoritative state through any channel other than authenticated *transfer session* from configured *primary*. *Enforces.* [R-INV-001].

**[R-NEG-004]** **It is prohibited that** the *server* *originates* *NOTIFY messages*; NOTIFY origination is a primary-role function; the *server*'s role per §3.1.8 is exclusively *NOTIFY message* reception. *Enforces.* [R-INV-001].

**[R-NEG-005]** **It is prohibited that** the *server* *serves* outbound *AXFR* or *IXFR* *responses* to inbound zone-transfer *queries*; *queries* with *QTYPE* = 252 or 251 received by the *server* are *rejected* with RCODE = 5 (REFUSED). *Enforces.* [R-INV-001].

**[R-NEG-006]** **It is prohibited that** the *server* *reads* *zone data* from presentation-format (*master file*) per *RFC 1035* §5; all *zone data* is received in wire format via *transfer session*. *Enforces.* [R-INV-001].

**[R-NEG-007]** **It is prohibited that** the *server* *performs* recursive resolution; the RA bit in *responses* is 0 unconditionally per [R-FR-CORE-012]; *queries* for names outside any *served zone* are *rejected* with RCODE = 5 (REFUSED) per [R-FR-CORE-019]. *Enforces.* [R-INV-001].

**[R-NEG-008]** **It is prohibited that** the *server* *forwards* *DNS queries* to any other server; **each** *response* is determined exclusively from *zone data*. *Enforces.* [R-INV-001].

**[R-NEG-009]** **It is prohibited that** the *server* *performs* DNSSEC signature validation on inbound or outbound *DNS messages*; the AD bit in *responses* is 0 unconditionally per [R-FR-DNSSEC-010] regardless of whether the queried *zone* is signed. *Enforces.* [R-INV-001].

**[R-NEG-010]** **It is prohibited that** the *server* *writes* operational state (*zone data*, transfer history, *query* statistics, *configuration* data, or any data intended to survive *process* restart) to persistent storage; *log entry* output to standard streams is not "operational state" within this prohibition. *Enforces.* [R-INV-004].

**[R-NEG-011]** **It is prohibited that** the *server* *re-reads* configuration sources after *process startup*; **it is prohibited that** the *server* *installs* a ***SIGHUP*** handler or equivalent mechanism that re-reads configuration; configuration changes are applied only via *process* restart. *Enforces.* [R-INV-005].

**[R-NEG-012]** **It is prohibited that** the *server* *serves* authoritative *zone data* for an ***EXPIRED*** *zone*; *queries* against ***EXPIRED*** *zones* receive RCODE = 2 (SERVFAIL) per [R-FR-QRY-021] **and** [R-FR-ZONE-006]. *Enforces.* [R-INV-001].

**[R-NEG-013]** **It is prohibited that** the *server* *implements* the *HMAC-MD5* TSIG algorithm; *DNS messages* bearing TSIG records with this algorithm name receive a *BADALG response* per [R-FR-TSIG-004]. *Enforces.* [R-FR-TSIG-004].

**[R-NEG-014]** **It is prohibited that** the *server* *implements* the TKEY mechanism (*RFC 2930*) for dynamic key establishment; *queries* with *QTYPE* = 249 are *rejected* with RCODE = 1 (FORMERR) per [R-FR-QRY-009]. *Enforces.* [R-INV-005].

**[R-NEG-015]** **It is prohibited that** the *server* *uses* the synthesised ***HINFO*** *response* style of *RFC 8482* §4.2 for ANY *queries*. *Enforces.* [R-FR-QRY-007].

**[R-NEG-016]** **It is prohibited that** where XoT is configured for a (zone, primary) tuple, the *server* *falls back* to unencrypted TCP zone transfer on TLS connection-establishment or certificate-authentication failure; **it is prohibited that** the *server* *uses* the Opportunistic Privacy Profile of *RFC 9103* §9.2. *Enforces.* [R-FR-XOT-006].

**[R-NEG-017]** **It is prohibited that** the *server* *accepts* inbound TLS connections for XoT (server-side XoT, including NOTIFY-over-TLS receipt); XoT in this server is outbound only per §3.1.10 scope. *Enforces.* §3.1.10 scope; [R-INV-001].


### 3.2 Non-Functional Rules

The non-functional rules transcribe SRS §5 (ODS-NFR-* identifiers).

#### 3.2.1 Performance — area PERF

**[R-NFR-PERF-001]** **It is obligatory that** the *server* *sustains* a *query*-handling throughput of **at least** 50 000 *queries* per second per CPU core under nominal workload (median DNS *query* mix against fully in-memory *zone data*, UDP transport, no TSIG verification on *queries*).

**[R-NFR-PERF-002]** **It is obligatory that** under workload **at most** 50% of the throughput of [R-NFR-PERF-001], the *server* *achieves* P99 *query* response latency **below** 1 millisecond for direct-hit lookups.

**[R-NFR-PERF-003]** **It is obligatory that** under workload **at most** 90% of the throughput of [R-NFR-PERF-001], the *server* *achieves* P99 *query* response latency **below** 10 milliseconds.

**[R-NFR-PERF-004]** **It is obligatory that** *AXFR* transfer ingestion *sustains* **at least** 100 000 records per second on a contemporary Linux host with adequate bandwidth.

**[R-NFR-PERF-005]** **It is obligatory that** *process startup* *completes* (socket binding, *configuration* parsing, initial *AXFR session* initiation) within 1 second on a contemporary Linux host with adequate resources.

#### 3.2.2 Reliability and Availability — area REL

**[R-NFR-REL-001]** **It is obligatory that** on receipt of ***SIGTERM***, the *server* *ceases* accepting new *queries* and new TCP connections, *allows* in-flight *query* processing and *transfer sessions* to complete within a configurable grace period (default 30 seconds), **then** *exits* with status code 0; sessions still active at end of grace are *aborted* and the *server* exits regardless.

**[R-NFR-REL-002]** **It is obligatory that** a *process* crash does not corrupt any persistent state on the host (per [R-INV-004], no persistent state exists to corrupt); a subsequent *process* start *initialises* cleanly from *configuration*, *performing* full *zone* acquisition per §3.1.16.

**[R-NFR-REL-003]** **It is obligatory that** steady-state memory consumption is bounded across extended operation (≥ 30 days continuous runtime); **it is prohibited that** the *server* *exhibits* unbounded memory growth under sustained *query* load with stable *zone data* and stable client population.

**[R-NFR-REL-004]** **It is obligatory that** network errors on inbound or outbound connections (malformed packets, mid-transfer connection drops, exhausted file descriptors, kernel-buffer exhaustion) **never** cause *process* termination; errors are handled per §3.1.6, §3.1.7, §3.1.8, §3.1.10, §3.1.12.

**[R-NFR-REL-005]** **It is obligatory that** the *server* is deployable under rolling-restart patterns: replacement *processes* can start while existing *processes* drain; the SIGTERM-initiated drain completes within the grace period of [R-NFR-REL-001] with no observable service interruption to clients exhibiting reasonable retry.

#### 3.2.3 Security — area SEC

**[R-NFR-SEC-001]** **It is obligatory that** the implementation *satisfies* [R-INV-006]: Rust's safe subset is used for all code processing network-received data; `unsafe` blocks are confined to documented, justified exceptions.

**[R-NFR-SEC-002]** **It is obligatory that** wire-format parsers (DNS message, EDNS option, RR-type-specific decoders, TSIG verification input, AXFR/IXFR stream parser) are subject to continuous coverage-guided fuzz testing (`cargo-fuzz` or equivalent); **each** release is preceded by **at least** 24 hours of fuzz testing per parser with no resulting crash, panic, or memory-safety finding.

**[R-NFR-SEC-003]** **It is prohibited that** cryptographic key material (TSIG shared secrets per [R-FR-TSIG-006], XoT client TLS private keys per [R-FR-XOT-007]) appears in any *log entry* at any verbosity level or in any error message; **it is obligatory that** such material be zeroed in *process* memory at *process* termination.

**[R-NFR-SEC-004]** **It is recommended that** the *server* be *designed* to run as an unprivileged operating-system user; where binding to privileged ports (53, 853) is required, this **should** be achieved via OS capabilities (Linux `CAP_NET_BIND_SERVICE`) or socket activation, not by running as root.

**[R-NFR-SEC-005]** **It is prohibited that** the *server* *listens* on any network port beyond those required for configured DNS *query* service (UDP/53, TCP/53), optional XoT outbound (no listener required), and the optional health endpoint per §3.3.4; **it is prohibited that** the *server* *opens* any administrative or debugging port at any time.

**[R-NFR-SEC-006]** **It is obligatory that** third-party Rust crates depended on by the *server* are from well-maintained sources, subjected to security review at adoption time, and tracked against ongoing security advisories; the dependency set is minimised consistent with functional requirements; specific crate choices, with security justification, are recorded in the Architecture Document.

#### 3.2.4 Maintainability — area MAINT

**[R-NFR-MAINT-001]** **It is recommended that** the total source-line count of first-party Rust code *remains* within 5 000 to 15 000 lines, excluding tests, dependencies, and generated code; feature additions or implementation choices pushing beyond 15 000 lines require explicit documented justification.

**[R-NFR-MAINT-002]** **It is obligatory that** the codebase is *organised* into a small number of clearly-named, single-purpose modules; **each** major functional area of §3.1 is *mappable* to identifiable modules.

**[R-NFR-MAINT-003]** **It is obligatory that** **each** `unsafe` block in first-party Rust code *carries* a comment stating the reason `unsafe` is necessary and the invariants on which its soundness depends per [R-INV-006].

**[R-NFR-MAINT-004]** **It is recommended that** implementation of §3.1 *includes* code-level comments referencing the requirement identifier and relevant RFC clause.

**[R-NFR-MAINT-005]** **It is obligatory that** the build process *produces* deterministic, reproducible binaries given a fixed source tree and pinned dependency set.

#### 3.2.5 Portability — area PORT

**[R-NFR-PORT-001]** **It is obligatory that** the *server* *builds and runs* on current LTS releases of Ubuntu LTS, Debian stable, RHEL / Rocky Linux / AlmaLinux current major, and Alpine current; **it is prohibited that** distribution-specific configuration be required.

**[R-NFR-PORT-002]** **It is obligatory that** the *server* *builds and runs* on x86_64 (amd64) and aarch64 (arm64); additional architectures MAY be supported best-effort.

**[R-NFR-PORT-003]** **It is obligatory that** the *server* is runnable in OCI-compatible container runtimes; the published image is runnable in Kubernetes without privileged mode, host networking, or escalated capabilities beyond `CAP_NET_BIND_SERVICE` where required.

**[R-NFR-PORT-004]** **It is obligatory that** the *server* *supports* both IPv4 and IPv6 for all network operations.

**[R-NFR-PORT-005]** **It is prohibited that** the *server* *depends* on systemd, sysvinit, OpenRC, or any specific init system; on distribution-specific package management; or on distribution-specific filesystem layouts beyond POSIX.

#### 3.2.6 Observability — area OBS

**[R-NFR-OBS-001]** **It is obligatory that** the *server* *emits* *log entries* to stdout and stderr in a structured format (JSON or logfmt, configurable, default JSON); **each** entry contains **at least** RFC 3339 timestamp, level (debug/info/warning/error), message, and contextual key-value pairs.

**[R-NFR-OBS-002]** **It is obligatory that** the *server* *supports* configurable log verbosity at the *process* level, hierarchy error < warning < info < debug; default is info.

**[R-NFR-OBS-003]** **It is obligatory that** the *server* *exposes* its in-memory counters (per [R-FR-QRY-024], [R-FR-RRL-012], NOTIFY counters of §3.1.8, TSIG counters per §3.1.9, transfer counters of §3.1.6 and §3.1.7) via a metrics endpoint per §3.3.4 in Prometheus / OpenMetrics text format.

**[R-NFR-OBS-004]** **It is obligatory that** the *server* *exposes* a health endpoint per §3.3.4 reporting status as: **starting** (initial transfers in progress); **ready** (≥ 1 *zone* ***ACTIVE***); **draining** (***SIGTERM*** received); **unhealthy** (internal error preventing service); transitions are observable within 1 second.

**[R-NFR-OBS-005]** **It is obligatory that** the metrics endpoint *exposes* per-zone status: *zone state* per [R-FR-ZONE-006], held *SOA serial*, timestamp of most recent successful refresh, timestamp of next scheduled refresh, count of refresh failures since last success, count of *queries* served since *process* start.

#### 3.2.7 Resource Limits — area RES

**[R-NFR-RES-001]** **It is obligatory that** the published container image does not exceed 20 megabytes uncompressed.

**[R-NFR-RES-002]** **It is recommended that** memory consumption per *zone* *scales* approximately linearly with record count, with target per-record overhead below 500 bytes.

**[R-NFR-RES-003]** **It is obligatory that** the *server* *supports* concurrent service of **at least** 10 000 *zones* with combined **at least** 10 million records on a host with 16 GiB available memory.

**[R-NFR-RES-004]** **It is obligatory that** steady-state file-descriptor consumption is bounded by approximately 2 × (configured concurrent client TCP limit per [R-FR-TCP-005] + configured concurrent outbound TCP limit + 100 reserve); at startup the *server* *verifies* OS `rlimit` is sufficient **and** *fails to start* with a clear error message if not.

**[R-NFR-RES-005]** **It is obligatory that** the total number of concurrent *transfer sessions* (*AXFR* + *IXFR*) is bounded by [R-FR-AXFR-022] (default 4).

### 3.3 Interface Rules

The interface rules transcribe SRS §6 (ODS-IF-* identifiers).

#### 3.3.1 Network Interfaces — area NET

**[R-IF-NET-001]** **It is obligatory that** the *server* *binds* UDP and TCP *listening sockets* at *process startup* for DNS *query* service; bind addresses are configurable per §3.3.2; defaults are 0.0.0.0 (IPv4 wildcard) and `::` (IPv6 wildcard), default port 53.

**[R-IF-NET-002]** **It is obligatory that** the *server* *supports* binding to multiple specific addresses simultaneously, including arbitrary IPv4 and IPv6 combinations; independent UDP and TCP *listening sockets* are created per (address, transport) tuple.

**[R-IF-NET-003]** **It is obligatory that** the *server* *initiates* outbound TCP connections (for zone transfer per §3.1.6, §3.1.7; SOA poll per §3.1.16; *XoT connection* per §3.1.10) from a source address selected by the operating system unless an outbound source is explicitly configured.

**[R-IF-NET-004]** **It is obligatory that** at startup, if any required *listening socket* fails to bind, the *server* *logs* the failure at error level identifying (address, port, transport) **and** *exits* with non-zero status; **it is prohibited that** the *server* *continues* operating with a partial set of sockets.

#### 3.3.2 Configuration Interface — area CONF

**[R-IF-CONF-001]** **It is obligatory that** all operational *configuration* is supplied via a single TOML-format *configuration file*, path specified at startup via command-line argument (default `/etc/oxidedns-secondary/config.toml`).

**[R-IF-CONF-002]** **It is obligatory that** the configuration schema is documented in a versioned schema specification maintained alongside the project; schema changes follow a backward-compatibility policy: addition of new optional fields permitted at any release; removal or semantic change requires major-version increment per semantic versioning.

**[R-IF-CONF-003]** **It is obligatory that** the *configuration* is *capable* of expressing, **at least**: the set of *served zones* with zone name, *class*, ordered list of *primaries* (IP/port); per-zone TSIG configuration; per-(zone, primary) XoT configuration; TSIG key definitions; network bind per [R-IF-NET-001], [R-IF-NET-002]; logging per §3.3.3; health/metrics per §3.3.4; tunable parameters (timeouts, limits, RRL thresholds, jitter, keepalive intervals).

**[R-IF-CONF-004]** **It is permitted that** TSIG shared secrets and XoT client TLS private keys be specified inline in *configuration* or by reference to a separate file path; where referenced by file, the *server* *verifies* at startup that the file is readable by the *process* **and** is not world-readable; either failure prevents startup with a clear error.

**[R-IF-CONF-005]** **It is obligatory that** the *server* *validates* the entire *configuration* at startup before binding any *listening socket*; validation includes schema conformance, TSIG algorithm support per §3.1.9, XoT trust-anchor parseability per §3.1.10, network address parseability, **and** value-range checks for numeric parameters; any failure causes the *server* to *log* a clear error and *exit*; **it is prohibited that** the *server* *begins* partial operation with partially valid configuration.

**[R-IF-CONF-006]** **It is recommended that** the *server* *accepts* a documented subset of configuration parameters via environment variables; where supported, environment variables take precedence over *configuration file* values.

**[R-IF-CONF-007]** **It is prohibited that** the *server* *installs* a ***SIGHUP*** handler that re-reads configuration per [R-INV-005] and [R-NEG-011].

#### 3.3.3 Logging Interface — area LOG

**[R-IF-LOG-001]** **It is obligatory that** the *server* *writes* *log entries* to standard streams: info and debug to stdout, warning and error to stderr; **it is prohibited that** the *server* *opens*, *creates*, or *writes to* any log file directly.

**[R-IF-LOG-002]** **It is obligatory that** *log entry* format is JSON or logfmt per [R-NFR-OBS-001], default JSON; format selection is global to the *process*.

**[R-IF-LOG-003]** **It is obligatory that** log level is configurable per *configuration file* and via environment variable per [R-IF-CONF-006]; default level is info per [R-NFR-OBS-002].

**[R-IF-LOG-004]** **It is prohibited that** the *server* *integrates* directly with syslog, systemd-journald, Windows Event Log, or any other host-specific logging mechanism.

#### 3.3.4 Health and Metrics Endpoint — area HEALTH

**[R-IF-HEALTH-001]** **It is obligatory that** the *server* *exposes* a combined health and metrics endpoint over plain HTTP/1.1 (no TLS, no authentication); the endpoint is activated by *configuration* with configurable bind address and port; when not configured, the endpoint is **not** activated and no HTTP *listening socket* is opened.

**[R-IF-HEALTH-002]** **It is obligatory that** when activated, the endpoint *serves* the following HTTP paths in response to GET: `/healthz` (plain text body, 200 when **ready**, 503 otherwise); `/readyz` (200 when **at least one** *zone* ***ACTIVE***, 503 otherwise); `/metrics` (Prometheus/OpenMetrics text body, 200); all other paths return 404; methods other than GET return 405.

**[R-IF-HEALTH-003]** **It is obligatory that** the endpoint is *accessible* without authentication; network-layer access control (firewall, private interface binding) is the *operator*'s responsibility.

**[R-IF-HEALTH-004]** **It is obligatory that** the endpoint is *served* from a separate thread or asynchronous task isolated from DNS *query* handling, such that scraping load does **not** measurably impact DNS *query* latency per [R-NFR-PERF-002] and [R-NFR-PERF-003].

#### 3.3.5 Process Signals — area SIG

**[R-IF-SIG-001]** **It is obligatory that** the *server* *handles* ***SIGTERM*** by initiating *graceful shutdown* per [R-NFR-REL-001].

**[R-IF-SIG-002]** **It is obligatory that** the *server* *handles* ***SIGINT*** identically to ***SIGTERM***.

**[R-IF-SIG-003]** **It is prohibited that** the *server* *installs* a handler for ***SIGHUP***; receipt of ***SIGHUP*** is ignored per [R-INV-005] and [R-NEG-011].

**[R-IF-SIG-004]** **It is prohibited that** the *server* *installs* handlers for ***SIGUSR1***, ***SIGUSR2***, ***SIGQUIT***, or any other signal not enumerated in this subsection; such signals follow OS default behaviour.

### 3.5 Verification Rules — area VER

The verification rules transcribe SRS §7 (ODS-VER-* identifiers). These are *project-process* rules rather than *server-behaviour* rules; they bind the project's verification procedure.

**[R-VER-001]** **It is obligatory that** verification of **each** rule in §2 through §3.4 is performed using the method(s) specified in the corresponding SRS requirement's *Verification* field; **each** verification method maps to one or more methods enumerated in SRS §7.1 (inspection, unit test, integration test, conformance test, interoperability test, fuzz test, performance test, soak test, operational test, external operator acceptance).

**[R-VER-002]** **It is obligatory that** verification evidence — test outputs, benchmark results, code-review records, fuzz summaries, interop logs — is *captured* by the project's CI system **and** *retained* for **each** release.

**[R-VER-003]** **It is obligatory that** the *server* is *tested* for interoperability as a secondary against the following *primary* implementations at their current stable major release: **NSD** (NLnet Labs); **Knot DNS** (CZ.NIC); **BIND 9** (ISC). For **each** (server, primary) pair, the test matrix covers: *AXFR* initial load and refresh per §3.1.6; *IXFR* incremental refresh and AXFR fallback per §3.1.7; NOTIFY receipt per §3.1.8; TSIG-authenticated transfers per §3.1.9 with **at least** *HMAC-SHA256*; XoT-secured transfers per §3.1.10 against any primary in the list that supports XoT.

**[R-VER-004]** **It is obligatory that** the interoperability matrix *exercises* *zones* of operationally representative complexity: **at least one** small *zone* (< 1 000 records); **at least one** medium *zone* (10 000–100 000); **at least one** large *zone* (> 1 000 000); **at least one** DNSSEC-signed *zone* using ***NSEC***; **and** **at least one** DNSSEC-signed *zone* using ***NSEC3***.

**[R-VER-005]** **It is obligatory that** for **each** RFC in PID Appendix A, the project *maintains* a clause-level traceability mapping (recorded in SRS Appendix A) from each requirement-bearing RFC clause to one or more SRS requirements; compliance with an RFC is asserted only when all in-scope requirement-bearing clauses are mapped to verifying SRS requirements **and** all those requirements have been verified per [R-VER-001].

**[R-VER-006]** **It is obligatory that** where an RFC contains normative clauses outside this server's scope, the traceability matrix *marks* those clauses as out-of-scope with brief rationale referencing [R-INV-001] or PID §3.2; the RFC's compliance claim is then limited to in-scope clauses **and** documented accordingly.

**[R-VER-007]** **Alpha Milestone.** **It is obligatory that** the Alpha milestone is achieved when:
all [R-INV-*] hold; §3.1.1 (CORE) in full; §3.1.2 (QRY) excluding [R-FR-QRY-003] through [R-FR-QRY-007]; §3.1.3 (NRESP) in full; §3.1.4 (URR) in full; §3.1.5 (SPOOF) in full; §3.1.6 (AXFR) in full; §3.1.8 (NOTIFY) in full; §3.1.11 (EDNS) in full; §3.1.12 (TCP) in full; §3.1.14 (RR) restricted to RFC 1035 types plus ***AAAA***; §3.1.15 (ZONE) in full; §3.1.16 (ZSM) in full;
TSIG minimum subset sufficient for *HMAC-SHA256* interop with **at least one** TSIG-configured *primary* ([R-FR-TSIG-001], [R-FR-TSIG-005] through [R-FR-TSIG-012], [R-FR-TSIG-017]);
§3.3.1, §3.3.2 in full, §3.3.3, §3.3.4 excluding `/readyz` distinction, §3.3.5;
NFRs: §3.2.2 in full, [R-NFR-MAINT-001] and [R-NFR-MAINT-003], [R-NFR-PORT-001] through [R-NFR-PORT-004], [R-NFR-OBS-001], [R-NFR-OBS-002], [R-NFR-OBS-004], [R-NFR-RES-001];
interoperability per [R-VER-003] with **at least one** of {NSD, Knot DNS, BIND 9}.
Deferred to MVP: §3.1.7 (IXFR), §3.1.9 (full TSIG), §3.1.10 (XOT), §3.1.13 (DNSSEC), §3.1.17 (RRL), §3.1.14 expanded RR catalogue, performance NFRs, full security/maintainability verification, multi-primary interop.

**[R-VER-008]** **MVP Milestone.** **It is obligatory that** the MVP milestone is achieved when:
all §2, §3.1, §3.2, §3.3, §3.4 rules are satisfied to their full normative content;
interoperability per [R-VER-003] with all three *primaries*;
all [R-NFR-PERF-*] targets met under benchmarking;
a 30-day soak test per [R-NFR-REL-003] completed without anomaly;
fuzz testing per [R-NFR-SEC-002] executed ≥ 24 hours per parser without finding;
dependency security audit per [R-NFR-SEC-006] clean;
documentation complete: SRS, Architecture Document, Test Plan, Operator Deployment Guide;
external operator acceptance by **at least one** production-representative operator.

**[R-VER-009]** **It is obligatory that** the SRS Appendix A traceability matrix *records*, for **each** rule in §2 through §3.4, the verification status: **Not Verified**; **Verified** (with date and evidence reference); **Deferred** (with target milestone); **Not Applicable** (Deprecated/Replaced).

---

## 4. Concordance and Cross-References

### 4.1 Rule Count Summary

| Category | Area code(s) | Rule count | Source section in SRS |
|---|---|---|---|
| Structural / invariant | — | 6 | SRS §3 |
| Structural / definitional | — | 12 | derived from SRS §1, §4 |
| Functional (FR) | CORE, QRY, NRESP, URR, SPOOF, AXFR, IXFR, NOTIFY, TSIG, XOT, EDNS, TCP, DNSSEC, RR, ZONE, ZSM, RRL | 244 | SRS §4.1–§4.17 |
| Non-functional (NFR) | PERF, REL, SEC, MAINT, PORT, OBS, RES | 36 | SRS §5 |
| Interface (IF) | NET, CONF, LOG, HEALTH, SIG | 23 | SRS §6 |
| Prohibitive (NEG) | — | 17 | SRS §4.18 |
| Verification (VER) | — | 9 | SRS §7 |
| **Total** | | **347** | |

(The total exceeds the SRS's 318 numbered requirements because the 12 conceptual necessities of §2.2 are SBVR restatements derived from across the SRS rather than 1:1 transcriptions, and a handful of TSIG sub-clauses with letter suffixes are counted as separate sub-rules.)

### 4.2 SBVR Rule Identifier → SRS Requirement Identifier

Each SBVR rule identifier `[R-XXX-YYY-NNN]` corresponds to the SRS requirement identifier `ODS-XXX-YYY-NNN`. The mapping is one-to-one with the following exceptions:

- **[R-DEF-001] through [R-DEF-012]** in §2.2 are conceptual necessities derived from SRS §1.4.3, §1.4.4, §4.14, §4.15, §4.16, and §4.18; they do not have direct 1:1 SRS counterparts but are restatements of normative content distributed across those sections.
- **[R-INV-001] through [R-INV-006]** correspond directly to ODS-INV-001 through ODS-INV-006.
- **All R-FR-*, R-NFR-*, R-IF-*, R-NEG-*, R-VER-*** correspond directly to ODS-FR-*, ODS-NFR-*, ODS-IF-*, ODS-NEG-*, ODS-VER-* with identical numbering.

### 4.3 RFC 2119 keyword → SBVR modal mapping

| RFC 2119 keyword (in SRS) | SBVR modal (in this document) |
|---|---|
| MUST, SHALL, REQUIRED | **It is obligatory that** |
| MUST NOT, SHALL NOT | **It is prohibited that** |
| SHOULD, RECOMMENDED | **It is recommended that** |
| SHOULD NOT, NOT RECOMMENDED | **It is recommended that** [the negative form] |
| MAY, OPTIONAL | **It is permitted that** |
| (architectural invariant) | **It is necessary that** |
| (impossibility, alethic) | **It is impossible that** |

### 4.4 SBVR Compliance Notes

This document presents the SRS requirements in SBVR Structured English (OMG SBVR, Annex C) form. It does not include the full machine-readable SBVR-XMI representation that the OMG standard also defines. For tooling that ingests SBVR vocabulary and rules (e.g., RuleSpeak / Object Management Group reference implementations, OntoREC), the §1 Vocabulary and §2–§3 Rules sections provide the source material from which an XMI representation can be mechanically derived.

The document deliberately uses *Structured English* rather than full *predicate calculus* expression: SBVR permits both, and Structured English is the form intended for human reader consumption and stakeholder review. Where stronger formal expression is required (for example, for theorem-proving or formal-methods verification), the rules of §3 can be re-expressed in SBVR's predicate-calculus form, which preserves the same vocabulary.

### 4.5 Relationship to Source Documents

This SBVR document is *derived from* and *normatively subordinate to* the *OxideDNS-Secondary Software Requirements Specification* v0.1. Where this document and the SRS disagree on substantive content, the SRS prevails; this document is then updated to match.

The SRS itself remains subordinate to the *OxideDNS-Secondary Project Initiation Document* (PID) v0.1 for matters of scope and stakeholder assignment.

---

*End of document.*
