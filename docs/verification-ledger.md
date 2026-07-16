# Release and SRS Verification Ledger

This ledger is the lightweight working record for evidence against the SRS
verification requirements, especially BDS-VER-002 and BDS-VER-009. It is not a
complete per-requirement traceability matrix yet. It groups related
requirements at a high level so release-candidate and SRS acceptance progress
has one maintainable place to accumulate evidence while Appendix A carries the
more detailed requirement traceability record.

The SRS-defined MVP in BDS-VER-008 is treated here as a full acceptance gate,
not as the near-term engineering milestone. Rows with target `Formal SRS MVP`
refer to that release-acceptance gate unless a note explicitly says otherwise.

For the current release candidate, completed long-running evidence is not
automatically required by local preflight. The boundary is defined in
`docs/engineering-mvp-scope.md`; long-run harnesses and handoff artifacts may be
retained for release/operations work, but they become release evidence only
when the generated artifacts are retained and cited.

Where SRS Appendix C.5 and the project decision register mark a decision
`Pending`, rows may record implemented defaults before final project
confirmation. Such evidence is implementation evidence only; it is not
release-decision approval for the pending decision item.

## Release Candidate Interpretation

The table's `Evidence State` column is an SRS/Alpha/release-acceptance coverage
state for the listed requirement scope. `Partial` rows do not by themselves
block a release candidate when the missing evidence is explicitly deferred to
release/operations, broader SRS acceptance, or long-running campaigns. A full
`BDS-VER-008` acceptance claim remains blocked until the closeout gaps are
closed or explicitly excluded from the claim. The release-candidate readiness
boundary is evaluated through
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
| Architectural invariants | Alpha | BDS-INV-001..BDS-INV-009 | Partial | docs/engineering-mvp-scope.md; docs/appendix-a-traceability-matrix.md; scripts/audit-invariants.sh; scripts/audit-readonly-runtime.sh; scripts/capture-malformed-query-evidence.sh | Static and runtime invariant evidence exists for the release-candidate preflight profile. Broader long-run malformed-input and panic-free campaigns remain SRS acceptance work. |
| Core authoritative query behavior | Alpha plus release-candidate extensions | BDS-FR-CORE-001..BDS-FR-CORE-029; BDS-FR-QRY-001..BDS-FR-QRY-025; BDS-FR-NRESP-001..BDS-FR-NRESP-006; BDS-FR-URR-001..BDS-FR-URR-009; BDS-FR-RR-001..BDS-FR-RR-007; BDS-FR-ZONE-001..BDS-FR-ZONE-006 | Partial | docs/appendix-a-traceability-matrix.md; docs/mvp-gap-register.md; scripts/interop-negative-responses.sh; scripts/interop-unknown-rr.sh; scripts/interop-unknown-rr-bad-transfer.sh | Local and retained script evidence covers the main query, negative-response, unknown-RR, DNAME/CNAME, compression, and zone-state paths. Per-requirement release artifacts and remaining edge cases stay in Appendix A and the gap register. |
| AXFR and outbound response validation | Alpha plus release-candidate extensions | BDS-FR-SPOOF-001..BDS-FR-SPOOF-007; BDS-FR-AXFR-001..BDS-FR-AXFR-026 | Partial | docs/appendix-a-traceability-matrix.md; docs/mvp-gap-register.md; docs/primary-interop-matrix-v0.2.0.md; scripts/audit-spoof-evidence.py; AXFR interop scripts | Parser, anti-spoofing, fail-closed publication, DNAME, and transfer-size evidence exists. The v0.2.0 matrix retained BIND/NSD/Knot AXFR evidence. Remaining work is broader fault-injection and multi-primary evidence. |
| TCP, EDNS, NOTIFY, and zone state machine | Alpha plus release-candidate extensions | BDS-FR-TCP-001..BDS-FR-TCP-011; BDS-FR-EDNS-001..BDS-FR-EDNS-018; BDS-FR-NOTIFY-001..BDS-FR-NOTIFY-011; BDS-FR-ZSM-001..BDS-FR-ZSM-014 | Partial | docs/appendix-a-traceability-matrix.md; docs/zsm-engineering-mvp-matrix.tsv; docs/primary-interop-matrix-v0.2.0.md; scripts/interop-edns-behavior.sh; scripts/interop-tcp-truncation-retry.sh; scripts/interop-notify-negative.sh; NOTIFY interop scripts | TCP, EDNS/EDE, NOTIFY, and ZSM evidence covers implemented behavior. The v0.2.0 matrix retained BIND/NSD/Knot NOTIFY evidence. Long-running timing and broader release artifacts remain open. |
| TSIG Alpha subset | Alpha | BDS-FR-TSIG-001; BDS-FR-TSIG-005..BDS-FR-TSIG-012; BDS-FR-TSIG-017; BDS-NEG-013; BDS-NEG-014 | Partial | docs/engineering-mvp-scope.md; docs/appendix-a-traceability-matrix.md; docs/primary-interop-matrix-v0.2.0.md; TSIG interop scripts; crates/borondns-core/src/tsig.rs | HMAC-SHA256 transfer interop and focused query/stream TSIG behavior are implemented and tested. The v0.2.0 selected primary matrix retained BIND, NSD, Knot, and PowerDNS TSIG-backed evidence where in scope. Full TSIG truncation and transfer-stream release evidence remains formal SRS acceptance work. |
| Interfaces, shutdown, and observability | Alpha subset plus Formal SRS MVP scope | BDS-IF-NET-001..BDS-IF-NET-008; BDS-IF-CONF-001..BDS-IF-CONF-018; BDS-IF-LOG-001..BDS-IF-LOG-008; BDS-IF-HEALTH-001..BDS-IF-HEALTH-006; BDS-IF-SIG-001..BDS-IF-SIG-004; BDS-IF-PROC-001..BDS-IF-PROC-003; BDS-IF-PROC-004; BDS-NFR-REL-001..BDS-NFR-REL-007; BDS-NFR-MAINT-001; BDS-NFR-MAINT-003; BDS-NFR-PORT-001..BDS-NFR-PORT-004; BDS-NFR-OBS-001..BDS-NFR-OBS-009; BDS-NFR-RES-001 | Partial | docs/appendix-a-traceability-matrix.md; docs/health-metrics-interface.md; docs/operator-deployment-guide.md; scripts/capture-cli-evidence.sh; scripts/capture-log-evidence.sh; scripts/capture-signal-evidence.sh; scripts/capture-health-metrics-evidence.sh; scripts/interop-edns-behavior.sh | Focused local evidence covers CLI/config/interface/health/metrics/logging/signal behavior, including catalog, override revalidation, DNSSEC/EDE, strict transfer-owner policy, and CHAOS config. Production-depth and release-retained artifacts remain open. |
| Negative requirements | Alpha | BDS-NEG-001..BDS-NEG-018 | Partial | docs/engineering-mvp-scope.md; docs/appendix-a-traceability-matrix.md; scripts/check.sh | Implemented prohibitions are covered by local/static evidence where applicable. Release review must still distinguish implemented prohibitions from protocol paths that remain not applicable because the corresponding feature is absent. |
| Alpha interop gate | Alpha | BDS-VER-003; BDS-VER-004; BDS-VER-007 | Verified | docs/test-plan.md; docs/appendix-a-traceability-matrix.md; docs/primary-interop-matrix-v0.2.0.md; scripts/engineering-mvp-evidence.sh; BIND/NSD/Knot interop scripts | The selected v0.2.0 primary matrix passed 12 of 12 cases and retained current BIND, NSD, Knot, and PowerDNS version/config evidence under `target/evidence/primary-matrix-20260614T010049Z`. |
| Implemented post-Alpha protocol families | Formal SRS MVP | BDS-FR-IXFR-001..BDS-FR-IXFR-019; BDS-FR-XOT-001..BDS-FR-XOT-012; BDS-FR-DNSSEC-001..BDS-FR-DNSSEC-014; BDS-FR-RRL-001..BDS-FR-RRL-012; BDS-FR-COOKIE-001..BDS-FR-COOKIE-011; BDS-FR-PROV-001..BDS-FR-PROV-014; BDS-FR-CHAS-001..BDS-FR-CHAS-006 | Partial | docs/implemented-feature-scope.md; docs/srs-review-disposition.md; docs/appendix-a-traceability-matrix.md; docs/catalog-zone-rfc9432.md; docs/xot-release-evidence-v0.2.0.md; docs/dnssec-conformance-matrix.tsv; docs/rrl-release-thresholds.md; feature-specific scripts named by `docs/implemented-feature-scope.md` | Post-Alpha features are bounded in `docs/implemented-feature-scope.md`. Selected local XoT breadth is retained for Knot XoT, Knot XoT+TSIG, and BIND catalog-over-XoT+TSIG; broader formal acceptance gaps remain. |
| SRS acceptance non-functional gates | Formal SRS MVP | BDS-NFR-PERF-001..BDS-NFR-PERF-008; BDS-NFR-SEC-001..BDS-NFR-SEC-015; BDS-NFR-MAINT-001..BDS-NFR-MAINT-009; BDS-NFR-PORT-001..BDS-NFR-PORT-005; BDS-NFR-OBS-001..BDS-NFR-OBS-009; BDS-NFR-RES-001..BDS-NFR-RES-006 | Partial | docs/mvp-gap-register.md; docs/appendix-a-traceability-matrix.md; docs/reproducible-build-v0.2.0.md; docs/operator-deployment-guide.md; docs/operational-slos.md; docs/architecture.md; SECURITY.md; release and audit scripts | Local checks and handoff scripts establish the evidence shape, and v0.2.0 static musl binaries have matching two-build digests. Remaining closeout includes reference benchmarks, 30-day soak, signed artifacts, full portability, and long-running evidence. |
| SRS acceptance and traceability | Formal SRS MVP | BDS-VER-001..BDS-VER-015 | Partial | docs/BoronDNS-Secondary-SRS-v0.9.1.md; docs/appendix-a-traceability-matrix.md; docs/rfc-traceability-policy.md; docs/rfc-compliance-assertions.md; docs/test-plan.md; scripts/check-release-notes.sh | Appendix A defines SRS-level rules; companion docs own live traceability and RFC compliance rows. Completed release-specific evidence and sign-off are still required before asserting BDS-VER-008 acceptance. |

## Maintenance Check

Run:

```sh
python3 scripts/check-verification-ledger.py
```

The check validates that requirement IDs and same-prefix ranges referenced by
this ledger exist in `docs/BoronDNS-Secondary-SRS-v0.9.1.md`. It also validates the
ledger status values in the table above. This catches typo-level drift without
pretending to prove requirement satisfaction.
