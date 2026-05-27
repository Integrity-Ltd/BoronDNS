#!/usr/bin/env python3
"""Check the current SRS for review-derived hygiene regressions."""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SRS = ROOT / "docs" / "OxideDNS-Secondary-SRS-v0.9.1.md"
REFERENCE_PROFILE = ROOT / "docs" / "reference-verification-profile.md"
FUTURE_OPTIMIZATION_TRACKS = ROOT / "docs" / "future-optimization-tracks.md"
RFC_TRACEABILITY_POLICY = ROOT / "docs" / "rfc-traceability-policy.md"

FORBIDDEN_TEXT = {
    "RDS denotes": "old rename namespace artifact",
    "ZoneProvider": "architecture internals do not belong in the SRS",
    "ZoneSpec": "architecture internals do not belong in the SRS",
    "ZoneSetDelta": "architecture internals do not belong in the SRS",
    "HealthConfig": "Rust configuration type names belong in source or architecture docs, not the SRS",
    "LoggingConfig": "Rust configuration type names belong in source or architecture docs, not the SRS",
    "MetricsConfig": "Rust configuration type names belong in source or architecture docs, not the SRS",
    "QuerySettings": "Rust implementation type names belong in source or architecture docs, not the SRS",
    "`catch_unwind` at task spawn boundaries": "SRS must specify task-panic isolation, not a concrete unwinding mechanism absent from runtime code",
    "Code-review checks confirm `catch_unwind` is in place": "SRS must align with Tokio JoinError handling used by the runtime",
    "Tokio task": "runtime implementation details belong in the Architecture Document, not the SRS",
    "Tokio runtime": "runtime implementation details belong in the Architecture Document, not the SRS",
    "supervised Tokio task": "runtime implementation details belong in the Architecture Document, not the SRS",
    "ordinary Tokio UDP/TCP sockets": "socket backend implementation details belong in the Architecture Document, not the SRS",
    "ordinary Tokio sockets": "socket backend implementation details belong in the Architecture Document, not the SRS",
    "panic occurred and was caught before exit": "current CLI has no controlled panic-recovery EX_SOFTWARE path",
    "panic with controlled exit": "current CLI has no controlled panic-recovery EX_SOFTWARE path",
    "panic-recovery paths": "current CLI has no controlled panic-recovery exit mapping",
    "TransferPlan::from_config": "Rust implementation function names belong in source or architecture docs, not the SRS",
    "trait PacketIo": "trait names belong in architecture, not SRS requirements",
    "trait ZoneStore": "trait names belong in architecture, not SRS requirements",
    "`HashMap`": "concrete store type belongs in architecture, not SRS requirements",
    "Arc<": "concrete pointer type belongs in architecture, not SRS requirements",
    "`RwLock`": "concrete lock type belongs in architecture, not SRS requirements",
    "atomic pointer swap": "concrete publication mechanism belongs in architecture",
    "seqlock": "concrete publication mechanism belongs in architecture",
    "response DO bit should be set": "wrong RFC 6840 response-DO wording",
    "response contains DNSSEC augmentation": "wrong RFC 6840 response-DO wording",
    "excluding RFC 8482 minimal-ANY": "minimal-ANY is implemented current scope",
    "does not generate denial-of-existence proofs": "DNSSEC serve-only wording must distinguish record generation from selecting transferred proof records",
    "Reference Hardware Profile of Appendix E.1": "stale Appendix E reference",
    "Reference Query Mix of Appendix E.2": "stale Appendix E reference",
    "Reference Hardware Profile (E.1)": "stale Appendix E heading",
    "Reference Query Mix (E.2)": "stale Appendix E heading",
    "concrete, atomic, testable requirements": "SRS no longer claims strict atomicity",
    "decomposed into atomic requirements": "SRS no longer claims strict atomicity",
    "the Test Plan's CI configuration MUST enact the classification": "private Engineering MVP does not claim hosted CI enacts every cadence",
    "CI verifies every requirement has at least one test case covering its declared method": "private Engineering MVP traceability is artifact-owned, not current hosted-CI per-requirement proof",
    "CI MUST verify that every functional requirement identifier in §4 appears": "private Engineering MVP uses the active continuous gate, not necessarily hosted CI",
    "*Verification.* CI-integrated grep across the source tree for each requirement identifier in §4; build failure on missing references.": "private Engineering MVP uses the active continuous gate, not necessarily hosted CI",
    "MUST be captured by the project's continuous integration system and retained for each release": "evidence capture may be CI or equivalent retained release-gate automation",
    "*Verification.* CI pipeline review at release time; sample-based retrieval of evidence from past releases.": "release evidence review is broader than hosted CI during the private Engineering MVP",
    "*Source.* Operational visibility; RFC 8906.\n*Verification.* Counter inspection under controlled cookie traffic.": "DNS Cookie counters should cite DNS Cookie RFCs, not RFC 8906 alone",
    "RFC 8906 (operational visibility)": "RFC 8906 is response-behavior guidance, not a logging/metrics standard",
    "Operational requirement informed by RFC 8906; security": "RFC 8906 is response-behavior guidance, not a TSIG logging source",
    "Operational requirement informed by RFC 8906.\n*Verification.* Counter inspection": "RFC 8906 is response-behavior guidance, not a generic counter source",
    "DNS Cookies is widely deployed in BIND 9, NSD, Knot DNS, and PowerDNS": "avoid unsourced implementation-deployment claims",
    "provides anti-spoofing benefit comparable to TSIG": "DNS Cookies are not TSIG-equivalent authentication",
    "dominant default in widely deployed implementations": "avoid unsourced implementation-default claims",
    "dominant operational practice among existing implementations": "avoid unsourced implementation-practice claims",
    "reference values from BIND and Knot": "implementation-specific cookie references need retained interop evidence",
    "strongest improvement-per-codebase-octet": "avoid marketing-style rationale in the SRS",
    "RFC 9018 §2 (Server Cookie timestamp)": "RFC 9018 server-cookie timestamp is section 4.3",
    "RFC 9018 §3.2": "RFC 9018 server-cookie construction is section 4",
    "As of 2026 this comprises Knot DNS": "avoid time-frozen XoT implementation claims",
    "NSD does not implement XoT server-side at the time of writing": "NSD XoT support is version/build dependent and must be tested",
    "stable XoT server support since": "avoid unsourced release-history claims in normative SRS text",
    "The design specified below follows the Vixie / Schryver model implemented in BIND 9": "RRL implementation models differ; define the OxideDNS model directly",
    "Vixie / Schryver RRL design; BIND 9 RRL implementation": "avoid treating BIND behavior as the direct source for OxideDNS RRL semantics",
    "Vixie/Schryver operational design": "RRL semantics are OxideDNS project policy, not a vendor-derived design claim",
    "BIND 9 default RRL configuration": "OxideDNS RRL thresholds are project defaults, not BIND defaults",
    "consistent with operational practice in NSD, Knot, and BIND": "avoid broad implementation-practice claims without retained evidence",
    "Operational RRL practice documented by BIND 9, Knot DNS, and NSD": "RRL semantics are OxideDNS project policy, not a vendor-derived standard",
    "Similar response-rate-limiting mechanisms are documented by BIND 9, Knot DNS, and NSD": "avoid broad RRL vendor-practice claims in normative SRS text",
    "operational benchmarking against existing secondary-only authoritative servers (NSD, Knot DNS)": "performance targets must not be presented as existing cross-server benchmark evidence",
    "comparable to NSD and Knot on equivalent hardware": "performance targets require retained OxideDNS benchmark evidence before conformance claims",
    "performance is expected to scale roughly with available CPU and network resources": "avoid unsupported performance scaling claims",
    "Implementations, operational surveys, and guidance documents not formally required for compliance are listed in Appendix D": "Appendix D is the glossary and area-code registry, not an informative bibliography",
    "under the v0.4 PERF-001 target": "current SRS requirements must reference the current PERF-001 target",
    "under the v0.4 target": "current SRS requirements must reference the current PERF-001 target",
    "The 30% factor is operationally typical": "TCP target ratio is an OxideDNS formal acceptance ratio, not an unsourced practice claim",
    "NSEC3 specifics are recorded in the Architecture Document as an implementation concern": "NSEC3 benchmark parameters belong in retained benchmark artifacts unless architecture owns them explicitly",
    "final audit cycle revision": "review cycles must remain open to corrective code/RFC alignment",
    "Audit cycles of equivalent depth are not anticipated": "review cycles must remain open to corrective code/RFC alignment",
    "The SRS body is considered structurally stable from v0.7 onward": "identifier stability must not block corrective SRS restructuring",
    "catalog-specific Prometheus metrics catalogue": "SRS must not require unimplemented catalog-specific counter families",
    "ODS-NFR-OBS-008 (catalog metrics)": "catalog observability wording must match implemented membership metric plus ordinary metrics",
    "oxidedns_secondary_catalog_member_zones": "SRS must align with implemented catalog membership metric",
    "oxidedns_secondary_catalog_last_transfer_timestamp_seconds": "SRS must align with implemented catalog membership metric",
    "oxidedns_secondary_catalog_transfer_failures_total": "SRS must align with implemented catalog membership metric",
    "oxidedns_secondary_catalog_member_additions_total": "SRS must align with implemented catalog membership metric",
    "oxidedns_secondary_catalog_member_removals_total": "SRS must align with implemented catalog membership metric",
    "oxidedns_secondary_catalog_members_rejected_total": "SRS must align with implemented catalog membership metric",
    "oxidedns_secondary_catalog_state": "SRS must align with implemented catalog membership metric",
    "Prometheus / OpenMetrics text format": "current implementation emits Prometheus text exposition 0.0.4, not OpenMetrics",
    "Prometheus/OpenMetrics": "current implementation emits Prometheus text exposition 0.0.4, not OpenMetrics",
    "OpenMetrics compatibility": "current implementation emits Prometheus text exposition 0.0.4, not OpenMetrics",
    "used for the metrics endpoint per ODS-NFR-OBS-003": "OpenMetrics is not the current metrics endpoint format",
    "the project prefix `oxidedns_secondary_` MUST be applied to every metric": "current implementation uses oxidedns_ as the first-party prefix with selected oxidedns_secondary_ stable families",
    'oxidedns_secondary_queries_total{zone="example.com",rcode="NOERROR"}': "oxidedns_secondary_queries_total is per-zone; RCODE labels belong on query response metrics",
    "de-facto operational practice": "avoid unsourced operational-practice claims in normative SRS text",
    "de-facto probe names": "CHAOS probe names are an explicit OxideDNS compatibility policy",
    "This SRS is subordinate to the PID": "unavailable historical PID must not control the checked-in SRS",
    "PID Appendix A": "RFC compliance target must be self-contained in the checked-in SRS and traceability matrix",
    "Acceptance Criteria for PID Milestones": "formal milestone criteria must not depend on an unavailable PID document",
    "PID prevails": "unavailable historical PID must not control the checked-in SRS",
    "PID Phase 4": "formal release acceptance must be described in SRS terms",
    "out of PID scope": "scope exclusions must be stated in current SRS terms",
    "not in PID scope": "scope exclusions must be stated in current SRS terms",
    "incoming v0.9.1 SRS attachment": "import-process wording belongs in review disposition, not the current SRS",
    "SRS attachment allocated": "import-process wording belongs in review disposition, not the current SRS",
    "already-adopted OxideDNS": "import-process wording belongs in review disposition, not the current SRS",
    "Implementation-alignment requirements update": "current SRS revision notes should state product changes, not import-process labels",
    "implementation alignment": "current SRS revision notes should state product changes, not import-process labels",
    "documentation alignment": "current SRS revision notes should state product changes, not import-process labels",
    "doc alignment": "current SRS revision notes should state product changes, not import-process labels",
    "spec alignment": "current SRS revision notes should state product changes, not import-process labels",
    "tool alignment": "current SRS revision notes should state product changes, not import-process labels",
    "| Property-based testing in Alpha scope |": "pending project-decision rows belong in project-decision-register.md and mvp-gap-register.md, not the SRS",
    "| Server module decomposition (`server/lib.rs` monolith) |": "pending project-decision rows belong in project-decision-register.md and mvp-gap-register.md, not the SRS",
    "| 1% idle CPU bound for 1000 zones |": "pending project-decision rows belong in project-decision-register.md and mvp-gap-register.md, not the SRS",
    "The complete normative catalogue, reproduced from §4.14": "Appendix B must not duplicate the normative §4.14 RR catalogue table",
    "The same structured list MUST be reproduced": "ODS-VER-014 must use a canonical RFC compliance register plus primary-documentation pointer, not duplicated tables",
    "MUST be reproduced — verbatim": "ODS-VER-014 must use a canonical RFC compliance register plus primary-documentation pointer, not duplicated tables",
    "single-source synchronisation": "ODS-VER-014 must use canonical register wording instead of hand-maintained duplication wording",
    "The actor classes from §2.3, reproduced here": "Appendix D must point to §2.3 actor classes instead of duplicating them",
    "reproduced compactly here for reference": "Appendix D must point to §2.3 actor classes instead of duplicating them",
    "**DNS Client (Resolver, Stub Resolver).**": "Appendix D must not duplicate the actor definitions owned by §2.3",
    "### B.2.1 A — IPv4 Address": "Appendix B must not duplicate per-type implementation notes owned by docs/rr-type-catalogue.md",
    "health.livez_timeout_ms": "SRS must not specify the removed liveness timeout configuration parameter",
    "The server MUST implement TLS 1.2 (RFC 5246) for XoT connections": "RFC 9103 requires TLS 1.3 or later for XoT conformance",
    "SHOULD implement TLS 1.3 (RFC 8446)": "RFC 9103 requires TLS 1.3 or later for XoT conformance",
    "ODS_HEALTH_LIVEZ_TIMEOUT_MS": "SRS must not document an environment override for a removed configuration parameter",
    "explicit liveness-probe-timeout": "SRS must treat liveness probe timeout policy as external to OxideDNS configuration",
    "TSIG secret loading from environment": "SRS must align ODS-NFR-SEC-008 with inline and file-backed TSIG secrets",
    "TSIG environment-variable loading": "SRS must not claim TSIG secrets load directly from environment variables",
    "environment-variable secret provisioning": "SRS must recommend file-backed external secret projection instead",
    "query.processing_timeout_ms": "SRS must not specify the removed per-query processing timeout configuration parameter",
    "oxidedns_dnssec_nsec3_cap_exceeded_total": "SRS must use the implemented global NSEC3 cap metric name",
    "per-zone counter `oxidedns_dnssec_nsec3_cap_exceeded_total": "SRS must not require a per-zone NSEC3 cap counter in the current profile",
    "RFC 9276 §2.4": "RFC 9276 section 2.4 is salt; NSEC3 iteration guidance is in sections 2.3 and 3.1",
    "RFC 9276 section 2.4": "RFC 9276 section 2.4 is salt; NSEC3 iteration guidance is in sections 2.3 and 3.1",
    "soft ceiling recommended by RFC 9276": "RFC 9276 recommends zero NSEC3 iterations; 100 is an OxideDNS compatibility default informed by Appendix A measurements",
    "default is the RFC 9276 ceiling": "RFC 9276 recommends zero NSEC3 iterations; 100 is an OxideDNS compatibility default",
    "tipical": "typo in normative SRS text",
    "Each process restart MUST generate a fresh secret.": "process-local DNS Cookie secrets are Engineering MVP behavior, not the full RFC 9018 shared-secret target",
    "DNS Cookie secrets replaced with `<redacted>`": "current configuration has no DNS Cookie secret field; future configured Server Secret material must be described conditionally",
    "MUST compile the kernel-side eBPF program at server build time and embed it in the server binary as compiled bytecode": "future eBPF packaging detail belongs in future optimization and architecture docs, not the current invariant",
    "No \"scriptable response transformation\" feature is or will be added": "SRS must describe the current invariant and revision path, not make unchangeable future product promises",
    "excluded from consideration unless they are the only types present at the QNAME": "ANY selection must align with implementation: DNSSEC support records are not selected merely by QTYPE=ANY",
    "ANY queries are predominantly used for amplification, with a small minority of legitimate uses": "RFC 8482 records legitimate uses and amplification concerns; avoid overclaiming prevalence",
    "which has been criticised as misleading": "avoid subjective criticism; explain the project boundary for rejecting HINFO synthesis",
    "allowed character set, label length 1–63 octets, total name length not exceeding 255 octets": "catalog member PTR validation must follow RFC 9432 and DNS wire-format bounds, not LDH host-name syntax",
    "The remainder of the catalog's contents MUST continue to be processed normally; one bad PTR MUST NOT cause the whole catalog to be rejected.": "RFC 9432 structural catalog errors make the candidate catalog version broken",
    "the rest of the catalog's contents MUST be processed normally": "RFC 9432 structural catalog errors make the candidate catalog version broken",
    "Permits deployment on read-only root filesystems and on scratch container images": "memory residency alone does not prove scratch/distroless compatibility",
    "New MVP scope": "bare MVP scope wording must distinguish formal SRS MVP from Engineering MVP",
    "supported in MVP scope": "bare MVP scope wording must distinguish formal SRS MVP from Engineering MVP",
    "brought into MVP scope": "bare MVP scope wording must distinguish formal SRS MVP from Engineering MVP",
    "Brought into MVP scope": "bare MVP scope wording must distinguish formal SRS MVP from Engineering MVP",
    "now in MVP scope": "bare MVP scope wording must distinguish formal SRS MVP from Engineering MVP",
    "include DNS Cookies in MVP": "bare MVP wording must distinguish formal SRS MVP from Engineering MVP",
    "in MVP scope, §4.19": "bare MVP scope wording must distinguish formal SRS MVP from Engineering MVP",
    "in the MVP": "bare MVP wording must distinguish formal SRS MVP from Engineering MVP",
    "The MVP configuration": "bare MVP configuration wording must distinguish formal SRS MVP from Engineering MVP",
    "active MVP configuration": "bare MVP configuration wording must distinguish formal SRS MVP from Engineering MVP",
    "new MVP-scope": "bare MVP scope wording must distinguish formal SRS MVP from Engineering MVP",
    "SHOULD MVP": "bare MVP scope wording must distinguish formal SRS MVP from Engineering MVP",
    "Resolved for MVP": "bare MVP resolution wording must distinguish formal SRS MVP from Engineering MVP",
    "ignored in the MVP": "bare MVP implementation wording must distinguish formal SRS MVP from Engineering MVP",
    "milestone (Alpha, MVP, post-MVP)": "bare MVP milestone wording must distinguish formal SRS MVP from Engineering MVP",
    "prior to MVP release": "bare MVP release wording must distinguish formal SRS MVP from Engineering MVP",
    "deferred to MVP": "bare MVP deferred-target wording must distinguish formal SRS MVP from Engineering MVP",
    "as it is in MVP": "bare MVP milestone wording must distinguish formal SRS MVP from Engineering MVP",
    "at MVP)": "bare MVP deferred-target wording must distinguish formal SRS MVP from Engineering MVP",
    "for MVP verification": "bare MVP verification wording must distinguish formal SRS MVP from Engineering MVP",
}

REQUIRED_TEXT = [
    "Each requirement should express a single, testable assertion.",
    "its verification text must identify the observable sub-cases to be tested.",
    "concrete, traceable, testable requirements",
    "where a requirement intentionally groups a coherent operational case",
    "the response OPT RR's TTL field MUST copy the query's DO bit exactly",
    "the response DO bit is not a signal that augmentation records were included",
    "a response OPT copies the query DO bit; the bit is not recomputed from whether DNSSEC records are included",
    "This SRS makes that stronger as a project policy",
    "MUST be isolated to the affected task by the runtime's task boundary",
    "surfaced through retained supervised-task error handling and warning logs",
    "Code review and runtime tests confirm supervised task completion-error handling",
    "Reserved for future controlled internal software-error paths",
    "The current CLI error mapping does not emit this code during normal operation.",
    "Uncaught Rust panics are implementation bugs, not graceful exit paths",
    "any future controlled `EX_SOFTWARE` path would warrant bug reporting",
    "Except for RRSIG records",
    "RRSIG records are handled by DNSSEC-specific rules",
    "RFC 4035 §2.2 exception",
    "RRSIG records do not form ordinary RRsets",
    "except where a later DNSSEC rule creates a type-specific exception such as RRSIG handling in RFC 4035 §2.2",
    "they are selected by Type Covered under RFC 4035 §2.2 and §3.1",
    "does not synthesize new denial-proof material",
    "OxideDNS may select already-transferred NSEC or NSEC3 RRsets that prove a negative response",
    "provided those proof records exist in the zone store and the response size permits inclusion",
    "The server MUST NOT synthesize missing proof records.",
    "*Source.* RFC 2181 §5; RFC 4035 §2.2; RFC 4034 §3.",
    "*Source.* RFC 2181 §5.2; RFC 4035 §2.2; RFC 4034 §3.",
    "Under the Reference Query Mix of Appendix E.3, on hardware matching the Reference Hardware Profile of Appendix E.2",
    "The published Linux release artifact targets `x86_64-unknown-linux-musl`",
    "The current release workflow publishes an Alpine-based image archive",
    "future distroless or scratch image variants only when binary inspection proves no runtime shared-library dependency",
    "Developer and distribution builds that use another target MAY dynamically link",
    "MUST NOT be described as scratch-compatible unless binary inspection proves the claim",
    "It does not by itself prove scratch or distroless image compatibility",
    "including binary inspection for runtime shared-library dependencies",
    "The active verification automation for the current project stage MUST enact the Continuous classification",
    "Periodic and Gate rows are release/operations handoff obligations until hosted CI, scheduled jobs, or formal release-gate automation are enabled",
    "Periodic methods comprise: long-cadence Fuzz test (≥ 24 hours per parser per ODS-NFR-SEC-002, scheduled at least weekly during release acceptance)",
    "periodic weekly/monthly cadences are release-acceptance-cycle obligations rather than standing private-repo calendar commitments",
    "the requirement is coverage by retained verification artifacts, not a claim that current private-repository CI already verifies every individual requirement",
    "MUST be captured by the active verification and release-evidence system for each release",
    "hosted CI or an equivalent retained release-gate automation record for the accepted commit",
    "The active continuous gate for the project stage MUST verify that every functional requirement identifier in §4 appears as a code-level reference",
    "*Verification.* Active-gate scan across the source tree for each requirement identifier in §4; gate failure on missing references.",
    "*Source.* Operational visibility for the RFC 7873 §5.2 cookie processing cases and RFC 9018 server-cookie validation profile.",
    "not a source for logging or metrics requirements",
    "DNS Cookies is a lightweight DNS transaction-security mechanism that provides limited protection against off-path spoofing",
    "not as general client identity or TSIG-equivalent authorization",
    "RFC 9018 §4, §4.3, §4.4",
    "Formal RFC 9018 release acceptance MUST provide configurable Server Secret material",
    "The current Engineering MVP DNS Cookie secret is process-local",
    "not portable across restarts, anycast instances, or load-balanced replicas",
    "not the complete formal RFC 9018 shared Server Cookie secret configurability posture",
    "This interval is not a shared anycast rollover mechanism",
    "That rationale does not remove the ODS-FR-COOKIE-004 formal acceptance gap for configured shared Server Secret material",
    "OxideDNS defaults to the lenient project policy because it preserves interoperability with clients that do not yet have a Server Cookie",
    "DNS Cookies add useful UDP off-path spoofing resistance with modest operational complexity",
    "XoT-secured transfers per §4.10, against each primary in the list whose tested version supports XoT",
    "The tested primary version and the XoT capability decision MUST be recorded per ODS-VER-013",
    "SHOULD include NSD XoT evidence when the selected NSD version exposes TLS-protected `provide-xfr`/`request-xfr` configuration",
    "This subsection therefore defines the OxideDNS project model explicitly",
    "(no IETF RFC; OxideDNS project RRL policy)",
    "OxideDNS project default baseline, recorded in `docs/rrl-release-thresholds.md`",
    "These defaults are project defaults, not inherited vendor defaults.",
    "formal project acceptance targets for the OxideDNS reference verification profile",
    "not formal conformance evidence for the quantitative NFR targets",
    "Project reference-hardware throughput target; formal acceptance evidence required before asserting conformance.",
    "under the current PERF-001 target",
    "The 30% factor is the OxideDNS formal acceptance ratio for the Reference Profile",
    "NSEC3 benchmark variants MUST record the signed-zone parameters in the retained run artifacts.",
    "RFC 9276 specifies INFO-CODE 27 for validating-resolver handling of unsupported NSEC3 iteration counts; OxideDNS uses that allocated code only as an opt-in authoritative diagnostic",
    "RFC 9276 §2.3 explains the poor cost/benefit tradeoff of additional NSEC3 iterations, and RFC 9276 §3.1 recommends an iteration count of 0 for NSEC3 zone publishers.",
    "OxideDNS uses 100 as a compatibility default, not as an RFC compliance ceiling.",
    "Current Engineering MVP evidence proves the cap metric only for responses that also emit EDE INFO-CODE 27",
    "decoupling metric increments from EDE emission when `edns.extended_dns_errors = \"off\"` remains formal SRS acceptance work",
    "Current code increments this counter by observing emitted EDE INFO-CODE 27 in serialized responses",
    "formal SRS acceptance additionally requires evidence that over-cap proof omissions increment the counter when EDE is disabled",
    "recording the configured value, the project compatibility default, and the RFC 9276 §3.1 recommendation of zero iterations for NSEC3 zone publishers",
    "RFC 7314 is Experimental and primarily improves indirect secondary-to-secondary transfer topologies",
    "RFC 7314 §§2–4 specify that a secondary using this option adds EDNS EXPIRE",
    "OxideDNS does not implement that option in the current scope, so it does not claim RFC 7314 compliance.",
    "Operators using indirect secondary chains should account for that explicitly",
    "`docs/reference-verification-profile.md`",
    "docs/reference-verification-profile.md#reference-hardware-profile",
    "docs/reference-verification-profile.md#reference-query-mix",
    "docs/reference-verification-profile.md#verification-recordkeeping",
    "The v0.7 audit pass is historical evidence, not a prohibition on later corrective review.",
    "The requirement identifier and category framework remains stable for traceability",
    "Implemented, tested protocol families that exceed a minimal static-secondary trim remain in current Engineering MVP scope",
    "New formal SRS MVP scope: DNS Cookies",
    "supported in current scope",
    "brought into formal SRS MVP scope",
    "formal SRS MVP, post-MVP",
    "formal SRS MVP configuration MUST NOT expose a fourth active **NOTIFY interface** role",
    "active formal SRS MVP configuration MUST NOT expose a fourth `notify` role",
    "This endpoint is supported in the formal SRS MVP.",
    "new formal SRS MVP scope §4.19 DNS Cookies",
    "explicit rejection of a fourth active NOTIFY interface role for the formal SRS MVP",
    "Engineering MVP benchmarking shows",
    "deferred to formal SRS MVP",
    "formal SRS MVP release",
    "Formal SRS MVP interface-scope decision",
    "oxidedns_catalog_member_info{catalog_zone=\"<catalog-apex>\",zone=\"<member-apex>\",managed=\"<true|false>\"} 1",
    "Catalog zones and their member zones MUST also appear in the ordinary zone-state and transfer metrics where those generic metrics apply",
    "ODS-NFR-OBS-008 (catalog membership metric plus ordinary zone/transfer metrics)",
    "the first-party project prefix `oxidedns_` MUST be applied to every metric",
    "stable SRS-facing families MAY retain the narrower `oxidedns_secondary_`",
    'oxidedns_secondary_query_responses_total{zone="example.com",rcode="NOERROR"}',
    "This SRS does not require a separate catalog-specific counter family for add/remove/rejection/transfer-failure events",
    "OxideDNS does not expose a server-side liveness timeout parameter.",
    "Client, reverse proxy, and orchestrator timeout configuration is outside the OxideDNS configuration model.",
    "Aligns ODS-NFR-SEC-008 with the implemented inline/`secret_file` TSIG secret model",
    "Production operator documentation (per ODS-NFR-MAINT-009) MUST recommend file-backed secret provisioning",
    "OxideDNS does not define a separate per-query CPU-processing timeout parameter.",
    "The formal RFC 9103 XoT profile MUST use TLS 1.3 (RFC 8446) or later.",
    "Any TLS 1.2 support retained for interoperability with legacy or experimental primaries MUST be explicitly documented as a compatibility mode and MUST NOT be presented as RFC 9103 XoT conformance.",
    "Current Engineering MVP builds use the Rust TLS stack with TLS 1.2 enabled for compatibility testing",
    "Compatibility-mode tests, if retained, must be separated from formal RFC 9103 evidence.",
    "This counter intentionally has no `zone` label in the current profile",
    "runtime loading of operator-supplied or configuration-specified eBPF programs is forbidden",
    "The exact packaging and adapter constraints for any project-supplied kernel-side program are owned by `docs/future-optimization-tracks.md` and the Architecture Document",
    "adding one would require an explicit SRS revision that changes this invariant",
    "for QTYPE = 255 (ANY) queries against a name with at least one first-class, non-DNSSEC-support RRset present",
    "DNSSEC supporting material is added only by the DNSSEC response rules of §4.13",
    "RRSIG, NSEC, and NSEC3 records are DNSSEC supporting data and are excluded from the ANY selection set",
    "RFC 8482 records legitimate debugging uses for QTYPE = ANY while also identifying amplification and zone-data-mining concerns",
    "OxideDNS selects the §4.1 subset-of-available-RRsets profile because it answers from transferred zone data",
    "avoids adding synthetic ANY-specific HINFO content to the authoritative response path",
    "RFC 9432 §4.1 uses PTR RDATA so all valid domain names can be represented",
    "A malformed member PTR RRset or malformed PTR RDATA makes the candidate catalog version broken",
    "previously applied catalog membership MUST remain unchanged per ODS-FR-PROV-010 and RFC 9432 §5.1",
    "The gap register records any current implementation gap between this formal SRS MVP policy and the Engineering MVP code evidence.",
    "Capitalized requirement keywords in this C.6 section are conditional promotion",
    "Engineering MVP conformance",
    "It is not stored in this repository.",
    "the checked-in SRS and its companion Architecture Document, Test Plan, Operator Deployment Guide, verification ledger, and gap register are the operative requirements and evidence authorities",
    "The RFC compliance target is defined and maintained through Appendix A, the companion traceability matrix, and the canonical RFC compliance assertion register.",
    "Primary documentation MUST NOT maintain a second hand-copied RFC compliance table.",
    "Informative operational guidance appears only where it is directly relevant to a requirement, appendix note, or companion document.",
    "Appendix D is the glossary and identifier registry, not a general bibliography.",
    "A pointer to the actor classes owned by §2.3, without duplicating those definitions",
    "This appendix keeps only the cross-reference so actor definitions are not maintained in two places.",
    "## 7.4 Acceptance Criteria for Formal Milestones",
    "For each RFC listed in Appendix A and the companion traceability matrix",
    "alignment for the catalogue is maintained in `docs/rr-type-catalogue.md`.",
    "reviews do not remove a type from the Engineering MVP scope unless the code,",
    "It does not reproduce the §4.14 table",
    "only the rule that keeps those documents synchronized.",
    "Appendix C.5 does not duplicate the decision table.",
    "The current pending subset is summarized in `docs/mvp-gap-register.md`",
]

REQUIRED_RFC_TRACEABILITY_POLICY_TEXT = [
    "# RFC Traceability Policy",
    "The purpose of this split is to keep the SRS from becoming an unchecked",
    "Scope Categories",
    "Target resolution milestone",
    "Current Feature Guardrail",
    "RFC 9432 catalog zones",
]

SUFFIXED_ID_RE = re.compile(r"\bODS-(?:FR|NFR|IF)-[A-Z0-9]{3,6}-[0-9]{3}[a-z]\b")
SECTION_4_RE = re.compile(r"^## (4\.\d+) ", re.MULTILINE)


def main() -> int:
    text = SRS.read_text(encoding="utf-8")
    reference_profile = REFERENCE_PROFILE.read_text(encoding="utf-8")
    future_optimization_tracks = FUTURE_OPTIMIZATION_TRACKS.read_text(
        encoding="utf-8"
    )
    rfc_traceability_policy = RFC_TRACEABILITY_POLICY.read_text(encoding="utf-8")
    errors: list[str] = []

    for needle, reason in FORBIDDEN_TEXT.items():
        if needle in text:
            errors.append(f"forbidden SRS text {needle!r}: {reason}")

    for needle in REQUIRED_TEXT:
        if needle not in text:
            errors.append(f"missing required SRS hygiene text: {needle!r}")

    for needle in REQUIRED_RFC_TRACEABILITY_POLICY_TEXT:
        if needle not in rfc_traceability_policy:
            errors.append(
                f"missing required RFC traceability policy text: {needle!r}"
            )

    for needle in [
        "# OxideDNS Reference Verification Profile",
        "## Reference Hardware Profile",
        "## Reference Query Mix",
        "## Verification Recordkeeping",
        "Dual Intel Xeon Gold 6230R",
        "100,000 records",
        "formal SRS MVP conformance",
        "not use XDP",
    ]:
        if needle not in reference_profile:
            errors.append(
                f"missing reference verification profile text: {needle!r}"
            )

    for needle in [
        "not hidden Engineering MVP requirements",
        "test-tool scope only",
        "Entry condition for re-evaluation: Engineering MVP benchmarking shows",
        "First-party unsafe code and unsafe-prone dependencies must remain confined",
        "Keep the zone store behind a documented lookup/publish boundary",
        "Key cached responses on the DO-bit value",
    ]:
        if needle not in future_optimization_tracks:
            errors.append(
                f"missing future optimization track text: {needle!r}"
            )

    suffixed_ids = sorted(set(SUFFIXED_ID_RE.findall(text)))
    if suffixed_ids:
        errors.append(
            "suffixed current requirement identifiers found: "
            + ", ".join(suffixed_ids)
        )

    cross_reference_index = text.split("## A.5 Cross-Reference Index", 1)[1].split(
        "# Appendix B",
        1,
    )[0]
    for section in SECTION_4_RE.findall(text):
        if f"| {section} " not in cross_reference_index:
            errors.append(
                "Appendix A cross-reference index omits current functional "
                f"section {section}"
            )

    if errors:
        for error in errors:
            print(f"srs_hygiene=failed {error}", file=sys.stderr)
        return 1

    print(f"srs_hygiene=passed path={SRS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
