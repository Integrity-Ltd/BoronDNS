# SRS Review Disposition

Status: working review register for the external SRS critique stored outside
the repository as `../gpt-pro-review.md`.

This document records how the project handles review findings against the
current code and documentation. It is intentionally non-normative: the SRS,
Architecture Document, Test Plan, and gap register remain the authoritative
project documents. The purpose here is to keep review-driven cleanup auditable
without copying external source artifacts into Git.

## Review Rules

- Protocol-correctness findings are accepted only after checking current code
  and primary sources.
- Scope-trim suggestions are not accepted automatically. Implemented,
  tested post-Alpha features remain Engineering MVP scope unless the code or
  SRS says otherwise.
- Implementation evidence belongs in verification, release-evidence, or gap
  documents, not as normative SRS requirement text.
- Archived v0.1 SRS/SBVR files are historical artifacts. Stale wording in
  those files is not current product scope unless repeated in the current SRS.

## Primary Sources Checked

| Topic | Primary source | Current disposition |
| --- | --- | --- |
| Response DO bit | RFC 6840 section 5.6 | Current SRS requires response OPT DO to copy query DO. Current implementation and old interop evidence still need alignment. |
| Authoritative CD/AD posture | RFC 4035 section 3.1.6 plus RFC 6840 section 5.8/5.9 context | SRS treats CD clearing as an authoritative-server policy stronger than the RFC SHOULD, not as resolver behavior. |
| RRSIG RRset exception | RFC 4034 section 3 and RFC 4035 DNSSEC response handling | SRS has an explicit RRSIG carve-out from normal RRset/TTL rules. |
| NSEC3 iteration cap | RFC 9276 section 2.4 | SRS treats proof omission above the cap as an availability/CPU-protection downgrade with optional diagnostic EDE, not normal authenticated denial. |
| Catalog zones | RFC 9432 sections 3, 5, and 7 | Catalog zones remain in scope because OxideDNS implements catalog transfer/parsing/reconciliation/observability. The SRS now states observable behavior and keeps implementation shape in architecture docs. |

Primary source links:

- <https://www.rfc-editor.org/rfc/rfc6840>
- <https://www.rfc-editor.org/rfc/rfc4035>
- <https://www.rfc-editor.org/rfc/rfc4034>
- <https://www.rfc-editor.org/rfc/rfc9276>
- <https://www.rfc-editor.org/rfc/rfc9432>

## Finding Disposition

| Review finding | Disposition | Evidence |
| --- | --- | --- |
| ODS/RDS namespace mismatch | Accepted and fixed in current SRS. | `docs/OxideDNS-Secondary-SRS-v0.9.md`; archived v0.1 files are explicitly non-current in `docs/README.md`. |
| Suffixed IDs such as `ODS-FR-CORE-006a` violate the numeric scheme | Accepted as a cleanup debt, not silently renumbered. Current SRS forbids new suffixed IDs and records the two existing aliases as temporary traceability debt. | `docs/OxideDNS-Secondary-SRS-v0.9.md`; `docs/zsm-engineering-mvp-matrix.tsv`; source comments in `crates/`. |
| UPDATE rejection cross-reference pointed at `CORE-007` | Accepted and fixed in current SRS. | `docs/OxideDNS-Secondary-SRS-v0.9.md`. |
| Response DO-bit semantics were wrong | Accepted as a protocol bug. Current SRS is corrected; implementation and interop scripts are still tracked as an alignment gap. | `docs/OxideDNS-Secondary-SRS-v0.9.md`; `docs/implementation-plan.md`; `docs/dnssec-conformance-matrix.tsv`; `docs/mvp-gap-register.md`. |
| CD-bit handling needed authoritative-server context | Accepted and fixed as explicit authoritative policy. | `docs/OxideDNS-Secondary-SRS-v0.9.md`. |
| RRSIG records were incorrectly covered by ordinary RRset wording | Accepted and fixed with an RRSIG carve-out. | `docs/OxideDNS-Secondary-SRS-v0.9.md`. |
| Static binary wording contradicted dynamic-link allowances | Accepted and fixed. Release artifact is the musl static target; developer/distribution builds may differ and must not be called scratch-compatible without inspection. | `docs/OxideDNS-Secondary-SRS-v0.9.md`; `docs/architecture.md`; release packaging scripts. |
| SRS prescribed `ZoneProvider`/`ZoneSpec`/`ZoneSetDelta` internals | Accepted. Current SRS now states catalog-zone observable behavior; implementation shape moved to architecture. | `docs/OxideDNS-Secondary-SRS-v0.9.md`; `docs/architecture.md`. |
| Catalog zones should be deferred from MVP | Rejected for current Engineering MVP. This is valid prioritization advice for a smaller product, but OxideDNS already implements and tests catalog-zone support, including live member add/remove and catalog observability. Remaining catalog work is release evidence and any explicit gaps in the gap register. | `crates/oxidedns-core/src/catalog.rs`; `crates/oxidedns-server/src/lib.rs`; `docs/mvp-gap-register.md`; `docs/catalog-zone-mvp-rfc9432.md`; catalog interop scripts. |
| Verification governance is too heavy for local MVP | Partially accepted. Long fuzz, soak, reference-hardware benchmarks, external operator acceptance, signed release artifacts, and similar activities are not Engineering MVP evidence. Their setup/runbooks can remain because they are later release/operations work. | `docs/engineering-mvp-scope.md`; `docs/engineering-mvp-readiness.md`; `docs/mvp-gap-register.md`; `docs/test-plan.md`. |
| Performance numbers should be targets rather than immediate local MVP blockers | Accepted for Engineering MVP boundary. The SRS still keeps formal ODS-VER-008 reference-hardware targets, while Engineering MVP records measured smoke/large-benchmark results and bottlenecks. | `docs/OxideDNS-Secondary-SRS-v0.9.md`; `docs/dns-client-benchmark.md`; `docs/mvp-gap-register.md`. |
| NSEC3 cap creates a DNSSEC authentication downgrade | Accepted. Current docs treat cap-triggered proof omission as an intentional availability policy with optional EDE diagnostics. | `docs/OxideDNS-Secondary-SRS-v0.9.md`; `docs/dnssec-conformance-matrix.tsv`; `docs/mvp-gap-register.md`. |
| SRS mixed audit findings into normative requirements | Accepted and cleaned up. Implementation audit claims were removed from the current SRS revision text and C.5 decision table. | `docs/OxideDNS-Secondary-SRS-v0.9.md`; verification/evidence documents. |
| Requirements claimed absolute atomicity while grouping many operational cases | Accepted. Current SRS now treats atomicity as maintainability guidance and requires grouped operational cases to list observable verification sub-cases. | `docs/OxideDNS-Secondary-SRS-v0.9.md`. |

## Current Intentional Code Alignment Gaps

The review exposed one known protocol-code divergence that is intentionally
tracked instead of hidden:

- Response OPT DO-bit handling: the SRS now follows RFC 6840 section 5.6, but
  code and retained interop evidence still include the older
  augmentation-derived response DO behavior. Release work must update the core
  response builder and affected interop scripts before claiming final DNSSEC
  or EDNS acceptance.

## Implemented Features Kept In Scope

The following features exceed the review's suggested minimal static-zone MVP,
but current code and evidence make them part of the Engineering MVP posture:

- IXFR with AXFR fallback.
- XoT transfer transport, including TSIG-over-XoT and focused TLS failure tests.
- Passive DNSSEC serving of transferred DNSSEC data.
- RRL.
- DNS Cookies.
- RFC 9432 catalog zones.
- Bounded EDE diagnostics.
- Opt-in CHAOS CH/TXT self-identification queries.

These features are not considered complete for formal SRS release acceptance
until their rows in `docs/mvp-gap-register.md`, `docs/verification-ledger.md`,
and the relevant traceability matrices are satisfied with release-grade
evidence.
