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

| Feature family | Current code ownership | Representative evidence ownership | Documentation posture |
| --- | --- | --- | --- |
| IXFR and AXFR fallback | `crates/oxidedns-core/src/axfr.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-bind-ixfr-refresh.sh`; `scripts/interop-knot-ixfr-refresh-docker.sh`; `scripts/interop-ixfr-notimp-fallback.sh` | In Engineering MVP scope; release-specific interop evidence remains tracked. |
| XoT | `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-knot-xot-docker.sh`; `scripts/interop-knot-xot-tsig-docker.sh`; `scripts/interop-bind-xot-catalog-zone-docker.sh`; `scripts/audit-xot-revocation.sh` | In Engineering MVP scope; TLS fault matrix and real-primary evidence remain acceptance work. |
| Passive DNSSEC serving | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/zone.rs` | `scripts/interop-dnssec-serve.sh`; `scripts/interop-dnssec-nsec3-serve.sh`; `scripts/interop-knot-dnssec-docker.sh`; `scripts/audit-dnssec-passive.sh`; `docs/dnssec-conformance-matrix.tsv` | In Engineering MVP scope; server serves transferred records and does not sign or validate. |
| RRL | `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-rrl-udp.sh`; `scripts/rrl-evidence-campaign.sh`; `docs/rrl-release-thresholds.md` | In Engineering MVP scope; release threshold confirmation remains a C.5/open evidence item. |
| DNS Cookies | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-dns-cookie-dig.sh` | In Engineering MVP scope; broader deployment interop remains release evidence. |
| RFC 9432 catalog zones | `crates/oxidedns-core/src/catalog.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `docs/catalog-zone-mvp-rfc9432.md`; `scripts/interop-bind-catalog-zone-docker.sh`; `scripts/interop-powerdns-postgres-catalog-tsig-docker.sh`; `scripts/interop-bind-xot-catalog-zone-docker.sh` | In Engineering MVP scope; `max_member_zones` remains an explicit implementation gap. |
| Broad EDNS response behavior | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-edns-behavior.sh` | In Engineering MVP scope for OPT parsing, BADVERS, payload ceilings, DO-copy semantics, TCP keepalive, NSID, padding, unknown-option ignore, and non-EDNS truncation behavior. |
| Bounded EDE diagnostics | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-dnssec-serve.sh`; `scripts/interop-dnssec-nsec3-serve.sh`; `docs/dnssec-conformance-matrix.tsv` | In Engineering MVP scope for `Not Ready` and NSEC3-cap diagnostics only. |
| Opt-in CHAOS self-identification | `crates/oxidedns-core/src/dns.rs`; `crates/oxidedns-core/src/config.rs`; `crates/oxidedns-server/src/lib.rs` | `scripts/interop-chaos-queries.sh` | In Engineering MVP scope; disabled-by-default posture is retained. |

The review's long-run verification and benchmark objections are handled by
boundary, not deletion: setup/runbooks may remain, but completed long fuzz,
reference-hardware benchmark, soak, signed-release, and external-operator
evidence are not Engineering MVP deliverables.

## MVP Trim Reconciliation

The review's suggested MVP trim is treated as a starting-point recommendation,
not as a deletion list for already-implemented code. The current boundary is:

| Review-suggested defer item | Current OxideDNS disposition | Code/doc alignment |
| --- | --- | --- |
| Catalog zones | Retained in Engineering MVP because RFC 9432 catalog transfer, parsing, member add/remove, and observability are implemented. | `max_member_zones` remains a named implementation gap in `docs/mvp-gap-register.md`; catalog internals stay out of normative SRS wording. |
| XoT | Retained in Engineering MVP as outbound zone-transfer transport only. | Client-query DoT and NOTIFY-over-TLS listeners remain out of scope. |
| DNS Cookies and RRL | Retained in Engineering MVP as implemented UDP abuse-resistance mechanisms. | Release evidence remains broader than local MVP evidence; DNS Cookies are not described as TSIG-equivalent authentication. |
| Extended DNS Errors | Retained only as the bounded implemented profile. | Current EDE output is limited to `Not Ready` and `Unsupported NSEC3 Iterations`; policy, filtering, validator, stale-cache, and recursive EDE mappings remain out of scope. |
| CHAOS `version.bind` / `id.server` | Retained as disabled-by-default, opt-in diagnostics. | Unsupported names/types are refused; operators must configure exposed values intentionally. |
| Full DNSSEC negative proof synthesis | Not accepted as the code boundary. | OxideDNS passively serves transferred DNSSEC RRsets and selected transferred NSEC/NSEC3 denial proofs. It does not sign, validate, generate DNSSEC records, or synthesize new denial-proof material. |
| Full Prometheus metric catalogue | Partially retained as implemented operational metrics. | The implemented metrics are in scope; release-grade retained evidence and production-depth profiling remain acceptance work. Catalog-specific metrics are narrowed to `oxidedns_catalog_member_info` plus ordinary zone/transfer metrics. Opt-in pipeline timing and response-cache candidate metrics are measurement aids, not a response-cache backend. |
| Packed zone store / pre-baked response cache | Deferred. | Current code uses memory-resident zone snapshots. The response-cache candidate counters only measure whether a future cache might be useful. |
| 30-day soak, full three-primary matrix, exact performance MUSTs, release signing, external operator acceptance | Deferred from Engineering MVP execution. | Setup/runbooks may remain in Git, but completed evidence belongs to later SRS acceptance execution. |

This scope-trim boundary is code-checked by
`scripts/check-srs-review-disposition.py`, which requires each retained
post-Alpha feature family to cite current source paths, retained evidence
paths, and implementation-specific source markers. The same check also requires
the reader-facing README, documentation index, Engineering MVP scope,
implementation plan, gap register, and verification ledger to continue naming
those families as implemented Engineering MVP scope. If a feature is removed
from code, the scope documents must change in the same patch.

The main SRS hygiene regressions from this review are also checked by
`scripts/check-srs-hygiene.py`: old namespace artifacts, suffixed requirement
IDs, implementation-internal type names in requirement text, the response DO-bit
rule, CD-bit project-policy wording, RRSIG RRset exceptions, and the
release-artifact static-linking boundary.

Support tooling follows the same boundary. The installer, release archive
scripts, Docker image archive workflow, large-zone benchmark harnesses, and
OxideGun load generator are repository tooling for deployment or evidence
capture. They do not expand the secondary-server protocol requirements unless a
current SRS, architecture, or gap-register row explicitly says so. OxideGun's
AF_XDP backend is test-tool scope only; OxideDNS server XDP/eBPF remains a
deferred unsafe-boundary track.

## Primary Sources Checked

| Topic | Primary source | Current disposition |
| --- | --- | --- |
| Response DO bit | RFC 6840 section 5.6 | Current SRS and implementation require response OPT DO to copy query DO. Older retained evidence that described augmentation-derived response DO is legacy only. |
| Authoritative CD/AD posture | RFC 4035 section 3.1.6 plus RFC 6840 section 5.8/5.9 context | SRS treats CD clearing as an authoritative-server policy stronger than the RFC SHOULD, not as resolver behavior. |
| RRSIG RRset exception | RFC 4035 section 2.2, plus RFC 4034 section 3 RRSIG field definitions | SRS has an explicit RRSIG carve-out from normal RRset/TTL rules and maps Type Covered handling to DNSSEC response rules. |
| NSEC3 iteration cap | RFC 9276 section 2.4 | SRS treats proof omission above the cap as an availability/CPU-protection downgrade with optional diagnostic EDE, not normal authenticated denial. |
| Catalog zones | RFC 9432 sections 3, 5, and 7 | Catalog zones remain in scope because OxideDNS implements catalog transfer/parsing/reconciliation/observability. The SRS now states observable behavior and keeps implementation shape in architecture docs. |
| DNS Cookies | RFC 7873 sections 2, 3, 5.2, and 5.4; RFC 9018 section 4 | SRS treats DNS Cookies as limited UDP off-path spoofing resistance and source-address confirmation, not TSIG-equivalent client authentication. The `lenient` default is a project compatibility policy; `strict` BADCOOKIE enforcement is available for stronger anti-spoofing posture. |
| XoT interop target selection | RFC 9103; BIND 9 ARM; Knot DNS documentation; NSD documentation | SRS no longer hard-codes a permanent NSD XoT exemption or release-year support claim. ODS-VER-003 requires a current-version capability decision for each primary, with XoT evidence required where the tested version exposes XoT. |
| RRL posture | BIND 9 ARM; Knot DNS documentation; NSD documentation | SRS treats RRL as operational practice rather than an RFC standard, and records the OxideDNS thresholds as project defaults instead of BIND/Knot/NSD defaults. |
| Performance target posture | Current code and benchmark harnesses | SRS treats §5 quantitative values as formal reference-hardware acceptance targets. Engineering MVP smoke and large-catalog benchmark artifacts guide tuning but do not by themselves prove conformance or equivalence to NSD, Knot DNS, BIND, or another server. |

Primary source links:

- <https://www.rfc-editor.org/rfc/rfc6840>
- <https://www.rfc-editor.org/rfc/rfc4035>
- <https://www.rfc-editor.org/rfc/rfc4034>
- <https://www.rfc-editor.org/rfc/rfc9276>
- <https://www.rfc-editor.org/rfc/rfc9432>
- <https://www.rfc-editor.org/rfc/rfc7873>
- <https://www.rfc-editor.org/rfc/rfc9018>
- <https://www.rfc-editor.org/rfc/rfc9103>
- <https://bind9.readthedocs.io/>
- <https://www.knot-dns.cz/docs/>
- <https://nsd.docs.nlnetlabs.nl/>

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
| Verification governance is too heavy for local MVP | Partially accepted. Long fuzz, soak, reference-hardware benchmarks, external operator acceptance, signed release artifacts, and similar activities are not Engineering MVP evidence. Their setup/runbooks can remain because they are later release/operations work. The SRS now distinguishes Continuous automation from Periodic/Gate handoff obligations during the private Engineering MVP profile. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/engineering-mvp-scope.md`; `docs/engineering-mvp-readiness.md`; `docs/mvp-gap-register.md`; `docs/test-plan.md`. |
| Performance numbers should be targets rather than immediate local MVP blockers | Accepted for Engineering MVP boundary. The SRS still keeps formal ODS-VER-008 reference-hardware targets, while Engineering MVP records measured smoke/large-benchmark results and bottlenecks. Those local artifacts are tuning evidence, not proof of formal target conformance or cross-server equivalence. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/dns-client-benchmark.md`; `docs/mvp-gap-register.md`. |
| NSEC3 cap creates a DNSSEC authentication downgrade | Accepted. Current docs treat cap-triggered proof omission as an intentional availability policy with optional EDE diagnostics. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/dnssec-conformance-matrix.tsv`; `docs/mvp-gap-register.md`. |
| SRS mixed audit findings into normative requirements | Accepted and cleaned up. Implementation audit claims were removed from the current SRS revision text and C.5 decision table. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; verification/evidence documents. |
| Requirements claimed absolute atomicity while grouping many operational cases | Accepted. Current SRS now treats atomicity as maintainability guidance and requires grouped operational cases to list observable verification sub-cases. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`. |
| SRS claimed v0.7 structural finality | Accepted as stale process wording. Current cleanup may restructure wording, ownership, and review boundaries when code, RFC, or external-review evidence shows drift; requirement identifiers and category names remain stable for traceability. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `scripts/check-srs-hygiene.py`. |
| Catalog metrics catalogue exceeded implemented observability surface | Accepted and corrected. Current SRS requires the implemented catalog membership metric plus ordinary zone/transfer metrics rather than unimplemented catalog-specific add/remove/failure counter families. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `crates/oxidedns-server/src/lib.rs`; `docs/catalog-zone-mvp-rfc9432.md`. |

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
- Broad EDNS response behavior.
- Bounded EDE diagnostics.
- Opt-in CHAOS CH/TXT self-identification queries.

These features are not considered complete for formal SRS release acceptance
until their rows in `docs/mvp-gap-register.md`, `docs/verification-ledger.md`,
and the relevant traceability matrices are satisfied with release-grade
evidence.
