# SRS Review Disposition

This is the non-normative record of an external SRS review and subsequent code
alignment. It preserves the decisions behind the cleanup. Current requirements
are in the [SRS](BoronDNS-Secondary-SRS-v1.0.0.md), implemented behavior in
[feature scope](implemented-feature-scope.md), and outstanding acceptance
evidence in the [gap register](release-acceptance-gap-register.md).

## Review Rules

Check protocol claims against current code and primary sources. Keep evidence
separate from normative requirements. Historical drafts describe their own
revision, not current product behavior. A suggested smaller MVP does not remove
a feature that the project already implements and tests.

## MVP Trim Reconciliation

The review proposed a static-zone secondary with fewer features. The table
records the disposition of that proposal, using the original item names for
traceability. IXFR with AXFR fallback, EDNS response behavior, and the other features remain
in scope as bounded by `docs/implemented-feature-scope.md`; future full SRS
acceptance is a separate evidence claim.

| Review-suggested defer item | Current BoronDNS disposition | Code/doc alignment |
| --- | --- | --- |
| Catalog zones | Retained. | RFC 9432 transfer, parsing, member reconciliation, caps, and referenced transfer metadata are implemented. DNS data does not carry raw secrets. |
| XoT | Retained for outbound transfers. | TLS 1.3-only, ALPN, PKIX, optional mTLS and TSIG. No client-query DoT or NOTIFY-over-TLS listener. |
| DNS Cookies | Retained. | UDP source-address confirmation with strict/lenient policy and current/previous shared-secret rollover; not TSIG-equivalent authentication. |
| RRL beyond a simple first version | Retained. | Process-wide UDP limiter, source prefixes, categories, slip/drop, allowlists, TSIG and valid-cookie exemptions. Per-zone RRL is outside scope. |
| Extended DNS Errors | Retained bounded profile. | Only `Not Ready` and `Unsupported NSEC3 Iterations` are emitted. |
| CHAOS `version.bind` / `id.server` | Retained, disabled by default. | Opt-in configured diagnostics; unsupported names/types are refused. |
| Full DNSSEC negative proof synthesis | Not an implemented feature. | Passive DNSSEC selects transferred RRsets and denial proofs. It does not sign, validate, or generate DNSSEC records. |
| Full Prometheus metric catalogue | Retain implemented metrics. | The [HTTP contract](health-metrics-interface.md) owns the interface. Pipeline/cache-candidate counters measure behavior; they are not a response-cache backend. |
| Packed zone store / pre-baked response cache | Deferred optimization tracks. | Current snapshots support compact/sharded publication; there is no pre-baked response-cache backend. |
| Fixed 30-day soak test | Removed as a release requirement. | Duration-neutral resource/soak tooling remains available. The completed [v0.9.1 campaign](fuzz-soak-v0.9.1-2026-08.md) closes the selected 1.0 fuzz item. |
| Full three-primary interop matrix | Future full acceptance target. | The selected [v0.2 matrix](primary-interop-matrix-v0.2.0.md) is retained historical evidence; current-release claims need their own tested versions and scope. |
| Exact performance MUSTs | Future Reference Hardware/Profile acceptance targets. | Local and two-host tuning measurements are useful within their recorded setup; they do not prove every SRS performance target. |
| Release signing | Implemented release workflow. | Signed maintainer tags authorize releases; CI signs and verifies the checksum manifest with Sigstore. See [release evidence](release-evidence-guide.md). |
| CVE governance | Lightweight reporting policy. | `SECURITY.md` promises no fixed response/remediation time, hotfix, backport, embargo, or CVE. |
| External operator acceptance | Optional supporting evidence. | Third-party sign-off is not required for the 1.0 public beta. |

Implementation and test pointers live in the feature-scope document. If a
feature is removed or narrowed, update its scope, SRS ownership, and evidence
status in the same patch. Supporting installers, packages, containers, BoronGun,
BoronGen, and benchmark/interop harnesses do not expand the secondary-server
protocol requirements. BoronDNS AF_XDP ships as an experimental opt-in profile;
BoronGun's separate AF_XDP backend is test-tool scope.

## Finding Disposition

The original finding labels remain stable; the disposition describes the
current state, including fixes made after the initial review.

| Review finding | Disposition | Evidence |
| --- | --- | --- |
| BDS/RDS namespace mismatch | Fixed in the current SRS. | SRS; `scripts/check-srs-hygiene.py`. |
| Suffixed functional IDs violated the numeric scheme | Replaced by numeric IDs `BDS-FR-CORE-029` and `BDS-FR-ZSM-014`. | SRS; `docs/zsm-engineering-mvp-matrix.tsv`; source references. |
| UPDATE rejection cross-reference pointed at `CORE-007` | Corrected. | SRS UPDATE requirement. |
| Response DO-bit semantics were wrong | Fixed: response OPT copies query DO. | `crates/borondns-core/src/dns.rs`; `scripts/interop-edns-behavior.sh`; `scripts/interop-dnssec-serve.sh`. |
| CD-bit handling needed authoritative-server context | CD clearing is explicit authoritative-server policy. | SRS; `docs/rfc-compliance-assertions.md`. |
| RRSIG records were incorrectly covered by ordinary RRset wording | Added the RRSIG exception and Type Covered rules. | SRS RRset/DNSSEC requirements. |
| Static binary wording contradicted dynamic-link allowances | Official binaries use static musl; other builds need inspection before claiming scratch compatibility. | SRS; `docs/architecture.md`; packaging scripts. |
| SRS prescribed `ZoneProvider`/`ZoneSpec`/`ZoneSetDelta` internals | Replaced implementation prescriptions with observable catalog behavior. | SRS; `docs/architecture.md`. |
| Catalog zones should be deferred from MVP | Not adopted: catalog zones are implemented and tested. | `crates/borondns-core/src/catalog.rs`; `docs/catalog-zone-rfc9432.md`; catalog interop scripts. |
| Verification governance is too heavy for local MVP | Separated routine checks, public-beta gates, and future full acceptance. | SRS; `docs/test-plan.md`; gap register. |
| Performance numbers should be targets rather than immediate local MVP blockers | Reference-profile targets remain separate from local tuning results. | SRS; `docs/dns-client-benchmark.md`. |
| NSEC3 cap creates a DNSSEC authentication downgrade | Fixed: affected negative responses fail closed with SERVFAIL and AA=0; optional EDE 27 is diagnostic. | `docs/dnssec-conformance-matrix.tsv`; `crates/borondns-core/src/dns_tests/any_negative_dnssec.rs`. |
| SRS mixed audit findings into normative requirements | Moved review/evidence claims to companion registers. | SRS; `docs/project-decision-register.md`. |
| Panic isolation wording prescribed `catch_unwind` internals | Specifies observable isolation and supervised task handling. | SRS; architecture; runtime `JoinError` handling. |
| Exit-code table claimed controlled panic recovery | Removed the nonexistent recovery claim; `EX_SOFTWARE` is reserved. | SRS; `crates/borondns-cli/src/main.rs`. |
| Requirements claimed absolute atomicity while grouping many operational cases | Grouped requirements identify observable verification sub-cases. | SRS. |
| Health and metrics requirement mixed endpoint contract detail into one requirement | Moved concrete HTTP details to the interface document; corrected the 405 body field to `path`. | `docs/health-metrics-interface.md`; `crates/borondns-server/src/health_metrics.rs`. |
| SRS claimed v0.7 structural finality | Removed stale finality wording; stable IDs retain traceability through edits. | SRS; SRS hygiene checker. |
| Catalog metrics catalogue exceeded implemented observability surface | Narrowed to membership info plus ordinary zone/transfer metrics. | Catalog documentation; server metrics. |
| XoT TLS-version wording over-counted TLS 1.2 | Fixed in code: the client selects TLS 1.3 only and rejects TLS 1.2-only primaries. | `crates/borondns-server/src/transfer.rs`; `crates/borondns-server/src/tests/refresh_xot_runtime.rs`. |

## Primary sources and project policies

| Topic | Primary source | Current disposition |
| --- | --- | --- |
| Response DO | [RFC 6840 §5.6](https://www.rfc-editor.org/rfc/rfc6840#section-5.6) | Copy query DO into response OPT. |
| CD/AD | [RFC 4035 §3.1.6](https://www.rfc-editor.org/rfc/rfc4035#section-3.1.6) | BoronDNS is authoritative-only; CD clearing is a documented project policy. |
| RRSIG RRsets | [RFC 4035 §2.2](https://www.rfc-editor.org/rfc/rfc4035#section-2.2), [RFC 4034 §3](https://www.rfc-editor.org/rfc/rfc4034#section-3) | Preserve the RRSIG exception and match signatures by Type Covered. |
| NSEC3 iteration cap | [RFC 9276](https://www.rfc-editor.org/rfc/rfc9276) | Publisher recommendation is zero iterations. BoronDNS's default cap of 100 is a compatibility choice; cap-triggered failure must not produce incomplete denial proofs. |
| Catalog names | [RFC 9432 §§4.1, 5.2](https://www.rfc-editor.org/rfc/rfc9432) | Valid domain names, including special-use/example names, are permitted; configured-zone/catalog name clashes are ignored and logged. |
| DNS Cookies | [RFC 7873](https://www.rfc-editor.org/rfc/rfc7873), [RFC 9018](https://www.rfc-editor.org/rfc/rfc9018) | Limited off-path spoofing resistance; shared-secret rollover is implemented. Lenient default is project policy. |
| XoT | [RFC 9103 §7.2](https://www.rfc-editor.org/rfc/rfc9103#section-7.2) | TLS 1.3 or later is required; current client selects TLS 1.3 only. |
| RRL | BoronDNS implementation and policy | Thresholds are project defaults, not RFC requirements or claims of BIND/Knot/NSD-equivalent semantics. |
| Performance | SRS Reference Hardware/Profile; retained benchmark reports | Compare results only with their recorded hardware, query mix, and settings. |

Vendor documentation is useful for selecting capable interop test versions.
It is not a normative source for BoronDNS protocol behavior.

## Review baseline and remaining evidence

The 2026-08-15 alignment pass corrected missing `BDS-IF-CONF-019` and
`BDS-IF-CONF-020` mappings, removed the fixed 30-day soak and nonexistent
memory-growth parameter, and aligned security wording with available
maintenance capacity. Requirement counts are generated by the checkers rather
than copied here.

The source is now 1.0.0. The retained v0.9.1 two-host fuzz campaign supports its
public-beta decision; it does not test fixes made after that tag. Current
`BDS-VER-008` defines the public-beta milestone, separate from future full SRS
acceptance. Remaining mTLS, broader deployment, reference-profile, and
per-requirement evidence is listed in the gap register. Those evidence gaps
must not be described as missing TLS enforcement, missing shared-secret
support, or unimplemented artifact signing.
