# Engineering MVP and SRS Verification Ledger

This ledger is the lightweight working record for evidence against the SRS
verification requirements, especially ODS-VER-002 and ODS-VER-009. It is not a
complete per-requirement traceability matrix yet. It groups related
requirements at a high level so Engineering MVP and SRS acceptance progress has
one maintainable place to accumulate evidence while Appendix A carries the more
detailed requirement traceability record.

The SRS-defined MVP in ODS-VER-008 is treated here as a full acceptance gate,
not as the near-term engineering milestone. Rows with target `Formal SRS MVP`
refer to that release-acceptance gate unless a note explicitly says otherwise.

For the near-term Engineering MVP, completed long-running evidence is not an
Engineering MVP requirement. The boundary is defined in
`docs/engineering-mvp-scope.md`; long-run harnesses and handoff artifacts may be
retained for later release/operations work, but they are not Engineering MVP
deliverables and are not treated as Engineering MVP evidence.

Where SRS Appendix C.5 and the project decision register mark a decision
`Pending`, rows may record implemented defaults before final project
confirmation. Such evidence is implementation evidence only; it is not
release-decision approval for the pending decision item.

## Engineering MVP Interpretation

The table's `Evidence State` column is an SRS/Alpha/release-acceptance coverage
state for the listed requirement scope. `Partial` rows do not by themselves
block Engineering MVP when the missing evidence is explicitly deferred to
release/operations, broader SRS acceptance, or long-running campaigns. The
Engineering MVP readiness boundary is evaluated through
`docs/engineering-mvp-scope.md`, `docs/mvp-gap-register.md`,
`scripts/check.sh`, and the bounded default profile in
`scripts/engineering-mvp-evidence.sh`.

## Status Values

- **Not Verified**: no accepted evidence is recorded in this ledger.
- **Partial**: evidence exists, but does not yet cover the full listed scope.
- **Verified**: evidence covers the listed scope and is suitable for release
  review.
- **Deferred**: verification is intentionally targeted at a later milestone.

## Ledger

| Area | Target | Requirement Coverage | Evidence State | Evidence Pointers | Notes |
| --- | --- | --- | --- | --- | --- |
| Architectural invariants | Alpha | ODS-INV-001..ODS-INV-009 | Partial | docs/implementation-plan.md; docs/appendix-a-traceability-matrix.md; scripts/audit-invariants.sh; scripts/audit-readonly-runtime.sh; scripts/capture-malformed-query-evidence.sh | Static and runtime invariant evidence exists for the Engineering MVP profile. Broader long-run malformed-input and panic-free campaigns remain SRS acceptance work. |
| Core authoritative query behavior | Alpha plus Engineering MVP extensions | ODS-FR-CORE-001..ODS-FR-CORE-029; ODS-FR-QRY-001..ODS-FR-QRY-025; ODS-FR-NRESP-001..ODS-FR-NRESP-006; ODS-FR-URR-001..ODS-FR-URR-009; ODS-FR-RR-001..ODS-FR-RR-007; ODS-FR-ZONE-001..ODS-FR-ZONE-006 | Partial | docs/appendix-a-traceability-matrix.md; docs/mvp-gap-register.md; scripts/interop-negative-responses.sh; scripts/interop-unknown-rr.sh; scripts/interop-unknown-rr-bad-transfer.sh | Local and retained script evidence covers the main query, negative-response, unknown-RR, DNAME/CNAME, compression, and zone-state paths. Per-requirement release artifacts and remaining edge cases stay in Appendix A and the gap register. |
| AXFR and outbound response validation | Alpha plus Engineering MVP extensions | ODS-FR-SPOOF-001..ODS-FR-SPOOF-007; ODS-FR-AXFR-001..ODS-FR-AXFR-026 | Partial | docs/appendix-a-traceability-matrix.md; docs/mvp-gap-register.md; scripts/audit-spoof-evidence.py; AXFR interop scripts | Parser, anti-spoofing, primary-interop, out-of-zone glue tolerance, DNAME multiplicity, and transfer-size evidence exists. Release acceptance still needs broader fault-injection, multi-primary, and retained primary-version refresh evidence. |
| TCP, EDNS, NOTIFY, and zone state machine | Alpha plus Engineering MVP extensions | ODS-FR-TCP-001..ODS-FR-TCP-011; ODS-FR-EDNS-001..ODS-FR-EDNS-018; ODS-FR-NOTIFY-001..ODS-FR-NOTIFY-011; ODS-FR-ZSM-001..ODS-FR-ZSM-014 | Partial | docs/appendix-a-traceability-matrix.md; docs/zsm-engineering-mvp-matrix.tsv; scripts/interop-edns-behavior.sh; scripts/interop-tcp-truncation-retry.sh; scripts/interop-notify-negative.sh; NOTIFY interop scripts | Engineering MVP evidence covers the implemented TCP, EDNS/EDE, NOTIFY, and ZSM behavior without claiming long-running timing evidence. Remaining release artifacts are enumerated in Appendix A and the gap register. |
| TSIG Alpha subset | Alpha | ODS-FR-TSIG-001; ODS-FR-TSIG-005..ODS-FR-TSIG-012; ODS-FR-TSIG-017; ODS-NEG-013; ODS-NEG-014 | Partial | docs/implementation-plan.md; docs/appendix-a-traceability-matrix.md; TSIG interop scripts; crates/oxidedns-core/src/tsig.rs | HMAC-SHA256 transfer interop and focused query/stream TSIG behavior are implemented and tested. Full TSIG release matrix evidence remains formal SRS acceptance work. |
| Interfaces, shutdown, and observability | Alpha subset plus Formal SRS MVP scope | ODS-IF-NET-001..ODS-IF-NET-008; ODS-IF-CONF-001..ODS-IF-CONF-018; ODS-IF-LOG-001..ODS-IF-LOG-008; ODS-IF-HEALTH-001..ODS-IF-HEALTH-006; ODS-IF-SIG-001..ODS-IF-SIG-004; ODS-IF-PROC-001..ODS-IF-PROC-003; ODS-IF-PROC-004; ODS-NFR-REL-001..ODS-NFR-REL-007; ODS-NFR-MAINT-001; ODS-NFR-MAINT-003; ODS-NFR-PORT-001..ODS-NFR-PORT-004; ODS-NFR-OBS-001..ODS-NFR-OBS-009; ODS-NFR-RES-001 | Partial | docs/appendix-a-traceability-matrix.md; docs/health-metrics-interface.md; docs/operator-deployment-guide.md; scripts/capture-cli-evidence.sh; scripts/capture-log-evidence.sh; scripts/capture-signal-evidence.sh; scripts/capture-health-metrics-evidence.sh; scripts/interop-edns-behavior.sh | Focused local evidence covers CLI/config/interface/health/metrics/logging/signal behavior, including catalog, override revalidation, DNSSEC/EDE/glue tolerance, and CHAOS config. Production-depth and release-retained artifacts remain open. |
| Negative requirements | Alpha | ODS-NEG-001..ODS-NEG-018 | Partial | docs/implementation-plan.md; docs/appendix-a-traceability-matrix.md; scripts/check.sh | Implemented prohibitions are covered by local/static evidence where applicable. Release review must still distinguish implemented prohibitions from protocol paths that remain not applicable because the corresponding feature is absent. |
| Alpha interop gate | Alpha | ODS-VER-003; ODS-VER-004; ODS-VER-007 | Partial | docs/test-plan.md; docs/appendix-a-traceability-matrix.md; scripts/engineering-mvp-evidence.sh; BIND/NSD/Knot interop scripts | Interop harnesses exist for BIND, NSD, and Knot and record primary-version evidence when run. Engineering MVP captures the local profile and delegates real-primary release artifacts instead of running every matrix path by default. |
| Implemented post-Alpha protocol families | Formal SRS MVP | ODS-FR-IXFR-001..ODS-FR-IXFR-019; ODS-FR-XOT-001..ODS-FR-XOT-012; ODS-FR-DNSSEC-001..ODS-FR-DNSSEC-014; ODS-FR-RRL-001..ODS-FR-RRL-012; ODS-FR-COOKIE-001..ODS-FR-COOKIE-011; ODS-FR-PROV-001..ODS-FR-PROV-014; ODS-FR-CHAS-001..ODS-FR-CHAS-006 | Partial | docs/implemented-feature-scope.md; docs/srs-review-disposition.md; docs/appendix-a-traceability-matrix.md; docs/catalog-zone-rfc9432.md; docs/dnssec-conformance-matrix.tsv; docs/rrl-release-thresholds.md; feature-specific scripts named by `docs/implemented-feature-scope.md` | These exceed the review's minimal trim but are implemented Engineering MVP scope exactly as bounded in `docs/implemented-feature-scope.md`. EDNS/EDE is covered above. Remaining work is release breadth, artifact retention, and explicit gaps, not automatic deferral. |
| SRS acceptance non-functional gates | Formal SRS MVP | ODS-NFR-PERF-001..ODS-NFR-PERF-008; ODS-NFR-SEC-001..ODS-NFR-SEC-015; ODS-NFR-MAINT-001..ODS-NFR-MAINT-009; ODS-NFR-PORT-001..ODS-NFR-PORT-005; ODS-NFR-OBS-001..ODS-NFR-OBS-009; ODS-NFR-RES-001..ODS-NFR-RES-006 | Partial | docs/mvp-gap-register.md; docs/appendix-a-traceability-matrix.md; docs/operator-deployment-guide.md; docs/operational-slos.md; docs/architecture.md; SECURITY.md; release and audit scripts | Local checks and handoff scripts establish the evidence shape. Completed reference-hardware benchmarks, 30-day soak, reproducible-build comparison, signed artifacts, full portability matrix, and other long-running release evidence remain outside Engineering MVP. |
| SRS acceptance and traceability | Formal SRS MVP | ODS-VER-001..ODS-VER-015 | Partial | docs/OxideDNS-Secondary-SRS-v0.9.1.md; docs/appendix-a-traceability-matrix.md; docs/test-plan.md; docs/rfc-compliance-assertions.md; docs/release-notes-template.md; scripts/check-release-notes.sh | Appendix A is the detailed traceability artifact. This ledger records coarse state only; completed release-specific evidence and sign-off are still required before asserting formal ODS-VER-008 acceptance. |

## Maintenance Check

Run:

```sh
python3 scripts/check-verification-ledger.py
```

The check validates that requirement IDs and same-prefix ranges referenced by
this ledger exist in `docs/OxideDNS-Secondary-SRS-v0.9.1.md`. It also validates the
ledger status values in the table above. This catches typo-level drift without
pretending to prove requirement satisfaction.
