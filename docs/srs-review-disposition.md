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

## Scope-Trim Handling

The external review suggested a much smaller static-zone secondary DNS MVP and
listed several features to defer. That is valid product-prioritisation advice
for a project starting from zero, but it is not the current OxideDNS state. The
repository already contains first-party code, tests, and documentation for the
post-Alpha features below, so the documentation cleanup keeps them in
Engineering MVP scope and records remaining formal-acceptance evidence
separately.

| Feature family | Current code ownership | Documentation posture |
| --- | --- | --- |
| IXFR and AXFR fallback | `crates/oxidedns-core/src/axfr.rs`; `crates/oxidedns-server/src/lib.rs` | In Engineering MVP scope; release-specific interop evidence remains tracked. |
| XoT | `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | In Engineering MVP scope; TLS fault matrix and real-primary evidence remain acceptance work. |
| Passive DNSSEC serving | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/zone.rs` | In Engineering MVP scope; server serves transferred records and does not sign or validate. |
| RRL | `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | In Engineering MVP scope; release threshold confirmation remains a C.5/open evidence item. |
| DNS Cookies | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs` | In Engineering MVP scope; broader deployment interop remains release evidence. |
| RFC 9432 catalog zones | `crates/oxidedns-core/src/catalog.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | In Engineering MVP scope; `max_member_zones` remains an explicit implementation gap. |
| Bounded EDE diagnostics | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs` | In Engineering MVP scope for `Not Ready` and NSEC3-cap diagnostics only. |
| Opt-in CHAOS self-identification | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | In Engineering MVP scope; disabled-by-default posture is retained. |

The review's long-run verification and benchmark objections are handled by
boundary, not deletion: setup/runbooks may remain, but completed long fuzz,
reference-hardware benchmark, soak, signed-release, and external-operator
evidence are not Engineering MVP deliverables.

## Primary Sources Checked

| Topic | Primary source | Current disposition |
| --- | --- | --- |
| Response DO bit | RFC 6840 section 5.6 | Current SRS and implementation require response OPT DO to copy query DO. Older retained evidence that described augmentation-derived response DO is legacy only. |
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
| ODS/RDS namespace mismatch | Accepted and fixed in current SRS. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; archived v0.1 files are explicitly non-current in `docs/README.md`. |
| Suffixed functional IDs violated the numeric scheme | Accepted and cleaned up. Current SRS uses numeric replacements `ODS-FR-CORE-029` and `ODS-FR-ZSM-014`, while retaining only prose notes that earlier draft snapshots used suffixed labels. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/zsm-engineering-mvp-matrix.tsv`; source comments in `crates/`. |
| UPDATE rejection cross-reference pointed at `CORE-007` | Accepted and fixed in current SRS. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`. |
| Response DO-bit semantics were wrong | Accepted as a protocol bug. Current SRS, implementation, and focused interop scripts now use RFC 6840 query-DO copy semantics. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `crates/oxidedns-core/src/dns.rs`; `scripts/interop-edns-behavior.sh`; `scripts/interop-dnssec-serve.sh`. |
| CD-bit handling needed authoritative-server context | Accepted and fixed as explicit authoritative policy. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`. |
| RRSIG records were incorrectly covered by ordinary RRset wording | Accepted and fixed with an RRSIG carve-out. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`. |
| Static binary wording contradicted dynamic-link allowances | Accepted and fixed. Release artifact is the musl static target; developer/distribution builds may differ and must not be called scratch-compatible without inspection. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/architecture.md`; release packaging scripts. |
| SRS prescribed `ZoneProvider`/`ZoneSpec`/`ZoneSetDelta` internals | Accepted. Current SRS now states catalog-zone observable behavior; implementation shape moved to architecture. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/architecture.md`. |
| Catalog zones should be deferred from MVP | Rejected for current Engineering MVP. This is valid prioritization advice for a smaller product, but OxideDNS already implements and tests catalog-zone support, including live member add/remove and catalog observability. Remaining catalog work is release evidence and any explicit gaps in the gap register. | `crates/oxidedns-core/src/catalog.rs`; `crates/oxidedns-server/src/lib.rs`; `docs/mvp-gap-register.md`; `docs/catalog-zone-mvp-rfc9432.md`; catalog interop scripts. |
| Verification governance is too heavy for local MVP | Partially accepted. Long fuzz, soak, reference-hardware benchmarks, external operator acceptance, signed release artifacts, and similar activities are not Engineering MVP evidence. Their setup/runbooks can remain because they are later release/operations work. | `docs/engineering-mvp-scope.md`; `docs/engineering-mvp-readiness.md`; `docs/mvp-gap-register.md`; `docs/test-plan.md`. |
| Performance numbers should be targets rather than immediate local MVP blockers | Accepted for Engineering MVP boundary. The SRS still keeps formal ODS-VER-008 reference-hardware targets, while Engineering MVP records measured smoke/large-benchmark results and bottlenecks. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/dns-client-benchmark.md`; `docs/mvp-gap-register.md`. |
| NSEC3 cap creates a DNSSEC authentication downgrade | Accepted. Current docs treat cap-triggered proof omission as an intentional availability policy with optional EDE diagnostics. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/dnssec-conformance-matrix.tsv`; `docs/mvp-gap-register.md`. |
| SRS mixed audit findings into normative requirements | Accepted and cleaned up. Implementation audit claims were removed from the current SRS revision text and C.5 decision table. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; verification/evidence documents. |
| Requirements claimed absolute atomicity while grouping many operational cases | Accepted. Current SRS now treats atomicity as maintainability guidance and requires grouped operational cases to list observable verification sub-cases. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`. |

## Current Intentional Code Alignment Gaps

No protocol-code divergence from the review is intentionally being carried as
current Engineering MVP scope. Remaining items in the gap register are
release-evidence or explicitly deferred implementation items, such as the
catalog member-zone resource cap and TSIG secret loading from environment
variables.

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
