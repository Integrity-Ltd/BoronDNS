# SRS Review Disposition

Status: non-normative review disposition register for an external SRS critique
kept outside this repository.

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

The exact retained slices are owned by `docs/implemented-feature-scope.md`:
IXFR with AXFR fallback, XoT, passive DNSSEC serving, RRL, DNS Cookies,
RFC 9432 catalog zones, broad EDNS response behavior, bounded EDE diagnostics,
and opt-in CHAOS self-identification. This disposition document owns why those
slices were retained after review; it does not duplicate their code and
evidence ownership table.

The review's long-run verification and benchmark objections are handled by
boundary, not deletion: setup/runbooks may remain, but completed long fuzz,
reference-hardware benchmark, soak, signed-release, and external-operator
evidence are not Engineering MVP deliverables.

## MVP Trim Reconciliation

The review's suggested MVP trim is treated as a starting-point recommendation,
not as a deletion list for already-implemented code. The current boundary is the
Engineering MVP scope plus the code-backed feature inventory in
`docs/implemented-feature-scope.md`; formal SRS release acceptance remains a
separate evidence gate.

The table below mirrors the review's "defer these" list item by item. "Retained"
means current code and tests already own a bounded slice; it does not mean the
feature has completed every formal ODS-VER-008 release-acceptance evidence item.
For any retained item, the governing test is current-code alignment: the feature
must have first-party source ownership, representative tests or interop
evidence, and current SRS owner identifiers. If one of those disappears, the
feature must move to a deferred or gap state in the same patch rather than
remaining in this table as aspiration.

| Review-suggested defer item | Current OxideDNS disposition | Code/doc alignment |
| --- | --- | --- |
| Catalog zones | Retained in Engineering MVP because RFC 9432 catalog transfer, parsing, member add/remove, observability, and per-catalog member caps are implemented. | Catalog internals stay out of normative SRS wording; release-specific catalog evidence remains tracked outside the SRS body. |
| XoT | Retained in Engineering MVP as outbound zone-transfer transport only. | Client-query DoT and NOTIFY-over-TLS listeners remain out of scope. Formal RFC 9103 XoT conformance still requires TLS 1.3-or-later evidence; current TLS 1.2 negotiation is compatibility evidence only. |
| DNS Cookies | Retained in Engineering MVP as an implemented UDP source-address confirmation mechanism. | Release evidence remains broader than Engineering MVP evidence; DNS Cookies are not described as TSIG-equivalent authentication. |
| RRL beyond a simple first version | Retained in Engineering MVP as the implemented process-wide UDP response limiter. | The current code owns configurable source-prefix aggregation, category buckets, slip/drop behavior, allowlists, summary logs, and metrics; per-zone RRL remains out of current scope. |
| Extended DNS Errors | Retained only as the bounded implemented profile. | Current EDE output is limited to `Not Ready` and `Unsupported NSEC3 Iterations`; policy, filtering, validator, stale-cache, and recursive EDE mappings remain out of scope. |
| CHAOS `version.bind` / `id.server` | Retained as disabled-by-default, opt-in diagnostics. | Unsupported names/types are refused; operators must configure exposed values intentionally. |
| Full DNSSEC negative proof synthesis | Not accepted as the code boundary. | OxideDNS passively serves transferred DNSSEC RRsets and selected transferred NSEC/NSEC3 denial proofs. It does not sign, validate, generate DNSSEC records, or synthesize new denial-proof material. |
| Full Prometheus metric catalogue | Partially retained as implemented operational metrics. | The implemented metrics are in scope; release-grade retained evidence and production-depth profiling remain acceptance work. Catalog-specific metrics are narrowed to `oxidedns_catalog_member_info` plus ordinary zone/transfer metrics. Opt-in pipeline timing and response-cache candidate metrics are measurement aids, not a response-cache backend. |
| Packed zone store / pre-baked response cache | Deferred. | Current code uses memory-resident zone snapshots. The response-cache candidate counters only measure whether a future cache might be useful. |
| 30-day soak test | Deferred from Engineering MVP execution. | Setup/runbooks may remain in Git, but completed evidence belongs to later SRS acceptance execution. |
| Full three-primary interop matrix | Deferred from Engineering MVP execution. | Focused BIND, Knot, and PowerDNS/PostgreSQL paths exist where implemented features need current evidence; the formal all-primary ODS-VER-003 matrix remains release acceptance. |
| Exact performance MUSTs | Deferred from Engineering MVP execution. | Local smoke and large-catalog benchmarks are tuning evidence; Reference Hardware/Profile conformance remains release acceptance. |
| Release signing | Deferred from Engineering MVP execution. | Release-signing mechanism and verification wording are documented, but signed artifact evidence is a release gate. |
| CVE governance | Retained as documentation/process scope, not protocol-code scope. | `SECURITY.md` and SRS policy text record vulnerability handling and CVE coordination; release-specific audit and exception evidence remains release acceptance. |
| External operator acceptance | Deferred from Engineering MVP execution. | Operator guide and installer artifacts can be reviewed now, but external operator sign-off remains a formal release gate. |

The exact retained implementation slices are owned by
`docs/implemented-feature-scope.md`. This scope-trim boundary is code-checked
by `scripts/check-srs-review-disposition.py`, which requires each retained
post-Alpha feature family to cite current source paths, retained evidence
paths, and implementation-specific source and test markers in that owning
document. The same check also requires the reader-facing README, documentation
index, Engineering MVP scope, implementation plan, gap register, and
verification ledger to continue naming those families as implemented
Engineering MVP scope. If a feature is removed from code, the scope documents
must change in the same patch.

The main SRS hygiene regressions from this review are also checked by
`scripts/check-srs-hygiene.py`: old namespace artifacts, suffixed requirement
IDs, implementation-internal type names in requirement text, the response DO-bit
rule, CD-bit project-policy wording, RRSIG RRset exceptions, and the
release-artifact static-linking boundary.

Support tooling follows the same boundary. The installer, release archive
scripts, Docker image archive workflow, large-zone benchmark harnesses,
BIND/PowerDNS supplemental interop scripts, and OxideGun load generator are
repository tooling for deployment or evidence capture. The retained tooling
slice and the adjacent non-claims are recorded in
`docs/implemented-feature-scope.md` under "Retained Support And Evidence
Tooling". They do not expand the secondary-server protocol requirements unless
a current SRS, architecture, or gap-register row explicitly says so. OxideGun's
AF_XDP backend is test-tool scope only; OxideDNS server XDP/eBPF remains a
deferred unsafe-boundary track.

Not every review-suggested defer item has a code-backed retained slice.
`30-day soak test`, `CVE governance`, and `External operator acceptance` are
process/evidence boundaries only: they remain documented as later
release/operations work, but they do not correspond to OxideDNS server protocol
code that should appear in `docs/implemented-feature-scope.md`.

## Primary Sources Checked

| Topic | Primary source | Current disposition |
| --- | --- | --- |
| Response DO bit | RFC 6840 section 5.6 | Current SRS and implementation require response OPT DO to copy query DO. Older retained evidence that described augmentation-derived response DO is legacy only. |
| Authoritative CD/AD posture | RFC 4035 section 3.1.6 plus RFC 6840 section 5.8/5.9 context | SRS treats CD clearing as an authoritative-server policy stronger than the RFC SHOULD, not as resolver behavior. |
| RRSIG RRset exception | RFC 4035 section 2.2, plus RFC 4034 section 3 RRSIG field definitions | SRS has an explicit RRSIG carve-out from normal RRset/TTL rules and maps Type Covered handling to DNSSEC response rules. |
| NSEC3 iteration cap | RFC 9276 section 2.4 | SRS treats proof omission above the cap as an availability/CPU-protection downgrade with optional diagnostic EDE, not normal authenticated denial. |
| Catalog zones | RFC 9432 sections 3, 5, and 7 | Catalog zones remain in scope because OxideDNS implements catalog transfer/parsing/reconciliation/observability. The SRS now states observable behavior and keeps implementation shape in architecture docs. |
| DNS Cookies | RFC 7873 sections 2, 3, 5.2, and 5.4; RFC 9018 section 4 | SRS treats DNS Cookies as limited UDP off-path spoofing resistance and source-address confirmation, not TSIG-equivalent client authentication. The `lenient` default is a project compatibility policy; `strict` BADCOOKIE enforcement is available for stronger anti-spoofing posture. |
| XoT interop target selection and TLS profile | RFC 9103; current BIND 9, Knot DNS, and NSD operator documentation for test-version capability selection only | SRS no longer hard-codes a permanent NSD XoT exemption or release-year support claim. ODS-VER-003 requires a current-version capability decision for each primary, with XoT evidence required where the tested version exposes XoT. RFC 9103 conformance requires TLS 1.3 or later; current TLS 1.2 negotiation is retained only as compatibility evidence until a release profile explicitly disables it for XoT or separates compatibility-mode runs from conformance runs. Vendor documentation is a release-test planning input, not a normative source for OxideDNS behavior. |
| RRL posture | Current implementation and OxideDNS project policy; BIND 9, Knot DNS, and NSD operator documentation for comparative review only | SRS treats RRL as a non-RFC OxideDNS project policy and records the OxideDNS thresholds as project defaults instead of BIND/Knot/NSD defaults. Vendor RRL documentation may inform later release review, but it is not a conformance target and must not be used to imply vendor-equivalent semantics. |
| Performance target posture | Current code and benchmark harnesses | SRS treats §5 quantitative values as formal reference-hardware acceptance targets. Engineering MVP smoke and large-catalog benchmark artifacts guide tuning but do not by themselves prove conformance or equivalence to NSD, Knot DNS, BIND, or another server. |
| Deferred optimization ownership | Current SRS Appendix C.6; Architecture Document; `docs/future-optimization-tracks.md`; unsafe-boundary registries | Future XDP/eBPF, packed-zone-store, and response-cache design constraints are no longer expanded in the SRS body. Appendix C.6 records scope and re-entry pointers, while the companion document owns detailed adapter and benchmark constraints. |

Primary source links:

- <https://www.rfc-editor.org/rfc/rfc6840>
- <https://www.rfc-editor.org/rfc/rfc4035>
- <https://www.rfc-editor.org/rfc/rfc4034>
- <https://www.rfc-editor.org/rfc/rfc9276>
- <https://www.rfc-editor.org/rfc/rfc9432>
- <https://www.rfc-editor.org/rfc/rfc7873>
- <https://www.rfc-editor.org/rfc/rfc9018>
- <https://www.rfc-editor.org/rfc/rfc9103>
- <https://bind9.readthedocs.io/en/v9.21.9/reference.html#response-rate-limiting>
- <https://www.knot-dns.cz/docs/latest/html/modules.html#rrl-response-rate-limiting>
- <https://nsd.docs.nlnetlabs.nl/en/latest/manpages/nsd.conf.html>

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
| Catalog zones should be deferred from MVP | Rejected for current Engineering MVP. This is valid prioritization advice for a smaller product, but OxideDNS already implements and tests catalog-zone support, including live member add/remove and catalog observability. Remaining catalog work is release evidence and any explicit gaps in the gap register. | `crates/oxidedns-core/src/catalog.rs`; `crates/oxidedns-server/src/lib.rs`; `docs/mvp-gap-register.md`; `docs/catalog-zone-rfc9432.md`; catalog interop scripts. |
| Verification governance is too heavy for local MVP | Partially accepted. Long fuzz, soak, reference-hardware benchmarks, external operator acceptance, signed release artifacts, and similar activities are not Engineering MVP evidence. Their setup/runbooks can remain because they are later release/operations work. The SRS now distinguishes Continuous automation from Periodic/Gate handoff obligations during the private Engineering MVP profile, and periodic weekly/monthly cadences are release-acceptance-cycle obligations rather than standing private-repo calendar commitments. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/engineering-mvp-scope.md`; `docs/engineering-mvp-readiness.md`; `docs/mvp-gap-register.md`; `docs/test-plan.md`. |
| Performance numbers should be targets rather than immediate local MVP blockers | Accepted for Engineering MVP boundary. The SRS still keeps formal ODS-VER-008 reference-hardware targets, while Engineering MVP records measured smoke/large-benchmark results and bottlenecks. Those local artifacts are tuning evidence, not proof of formal target conformance or cross-server equivalence. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/dns-client-benchmark.md`; `docs/mvp-gap-register.md`. |
| NSEC3 cap creates a DNSSEC authentication downgrade | Accepted. Current docs treat cap-triggered proof omission as an intentional availability policy with optional EDE diagnostics. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/dnssec-conformance-matrix.tsv`; `docs/mvp-gap-register.md`. |
| SRS mixed audit findings into normative requirements | Accepted and cleaned up. Implementation audit claims were removed from the current SRS revision text; the decision audit trail now lives in a separate register. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/project-decision-register.md`; verification/evidence documents. |
| Panic isolation wording prescribed `catch_unwind` internals | Accepted and corrected. The SRS now requires the observable panic-isolation property and supervised task error handling, rather than a concrete unwinding mechanism not used by the runtime. The Architecture Document records the current Tokio `JoinError` evidence. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/architecture.md`; `crates/oxidedns-server/src/lib.rs`; `scripts/check-srs-hygiene.py`. |
| Exit-code table claimed controlled panic recovery | Accepted and corrected. The current CLI has no controlled panic-recovery path and does not emit `EX_SOFTWARE` during normal error mapping, so the SRS now reserves that code for a future explicit internal-error path and treats uncaught panics as implementation bugs governed by ODS-INV-006. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `crates/oxidedns-cli/src/main.rs`; `scripts/check-srs-hygiene.py`. |
| Requirements claimed absolute atomicity while grouping many operational cases | Accepted. Current SRS now treats atomicity as maintainability guidance and requires grouped operational cases to list observable verification sub-cases. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`. |
| Health and metrics requirement mixed endpoint contract detail into one requirement | Accepted. The SRS now keeps stable health/metrics requirement IDs and behavior, while concrete HTTP paths, JSON bodies, headers, gzip behavior, and rate-limit bodies are owned by a focused interface document. The pass also corrected the documented 405 body from `method` to the implemented `path` field. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/health-metrics-interface.md`; `crates/oxidedns-server/src/lib.rs`. |
| SRS claimed v0.7 structural finality | Accepted as stale process wording. Current cleanup may restructure wording, ownership, and review boundaries when code, RFC, or external-review evidence shows drift; requirement identifiers and category names remain stable for traceability. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `scripts/check-srs-hygiene.py`. |
| Catalog metrics catalogue exceeded implemented observability surface | Accepted and corrected. Current SRS requires the implemented catalog membership metric plus ordinary zone/transfer metrics rather than unimplemented catalog-specific add/remove/failure counter families. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `crates/oxidedns-server/src/lib.rs`; `docs/catalog-zone-rfc9432.md`. |
| XoT TLS-version wording over-counted TLS 1.2 | Accepted and corrected. RFC 9103 §7.2 requires TLS 1.3 or later. Current code can negotiate TLS 1.2 through the rustls `tls12` feature, so the retained Engineering MVP XoT slice now records that behavior as compatibility evidence rather than RFC 9103 conformance evidence. | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/rfc-compliance-assertions.md`; `docs/implemented-feature-scope.md`; `crates/oxidedns-server/src/lib.rs`; `Cargo.toml`. |

## Current Intentional Code Alignment Gaps

The current Engineering MVP intentionally carries one reviewed implementation
behavior that must not be promoted to formal SRS conformance without another
code or release-profile decision:

| Area | Current code behavior | Documentation boundary |
| --- | --- | --- |
| XoT TLS version compatibility | The XoT client path uses rustls defaults with the Cargo `tls12` feature enabled, so a TLS 1.2-capable primary can negotiate TLS 1.2. | Engineering MVP keeps the outbound XoT slice because transfer transport, trust anchors, SNI, ALPN `dot`, optional mTLS, TSIG-over-XoT, and no-cleartext-fallback are implemented. Formal RFC 9103 evidence must either enforce TLS 1.3-or-later for XoT or retain TLS 1.2 only as explicitly separated compatibility-mode evidence. |

The gap register may still carry release-evidence and explicitly deferred
implementation items. Any future retained Engineering MVP protocol-code
divergence discovered during review must be added to this table in the same
patch that updates the SRS, RFC register, and feature-scope boundary.

## Implemented Features Kept In Scope

The retained Engineering MVP feature set is the one recorded in
`docs/implemented-feature-scope.md`. Those features exceed the review's
suggested minimal static-zone MVP, but current code and evidence make them part
of the Engineering MVP posture. They are not considered complete for formal SRS
release acceptance until their rows in `docs/mvp-gap-register.md`,
`docs/verification-ledger.md`, and the relevant traceability matrices are
satisfied with release-grade evidence.
