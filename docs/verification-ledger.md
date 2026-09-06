# Release and SRS Verification Ledger

This ledger summarizes evidence by requirement family for `BDS-VER-002` and
`BDS-VER-009`. [Appendix A](appendix-a-traceability-matrix.md) contains the
detailed mappings; the [gap register](release-acceptance-gap-register.md) lists
the remaining formal acceptance work.

`Partial` means incomplete evidence for the listed scope, not necessarily a
release blocker or missing implementation. The
[release scope](engineering-mvp-scope.md) defines the public-beta gate.
Historical results keep their original version and do not certify current
code. A pending [project decision](project-decision-register.md) remains pending
even when the implemented default has test coverage.

## Status Values

- **Not Verified**: no accepted evidence is recorded.
- **Partial**: evidence covers part of the listed scope.
- **Verified**: evidence covers the stated scope and is cited.
- **Deferred**: verification is assigned to a later milestone.

## Ledger

| Area | Target | Requirement Coverage | Evidence State | Evidence Pointers | Notes |
| --- | --- | --- | --- | --- | --- |
| Architectural invariants | Implemented scope | BDS-INV-001..BDS-INV-009 | Partial | docs/appendix-a-traceability-matrix.md; scripts/audit-invariants.sh; scripts/audit-readonly-runtime.sh; docs/fuzz-soak-v0.9.1-2026-08.md | Static/runtime checks and the completed v0.9.1 fuzz campaign support the listed scope; they do not establish panic freedom for all inputs. |
| Core authoritative query behavior | Implemented scope | BDS-FR-CORE-001..BDS-FR-CORE-029; BDS-FR-QRY-001..BDS-FR-QRY-025; BDS-FR-NRESP-001..BDS-FR-NRESP-006; BDS-FR-URR-001..BDS-FR-URR-009; BDS-FR-RR-001..BDS-FR-RR-007; BDS-FR-ZONE-001..BDS-FR-ZONE-006 | Partial | docs/appendix-a-traceability-matrix.md; scripts/interop-negative-responses.sh; scripts/interop-unknown-rr.sh; scripts/interop-unknown-rr-bad-transfer.sh | Tests cover query composition, negative answers, unknown RR data, CNAME/DNAME, compression, and zone state. Remaining per-requirement acceptance work is in Appendix A. |
| AXFR and outbound response validation | Implemented scope | BDS-FR-SPOOF-001..BDS-FR-SPOOF-007; BDS-FR-AXFR-001..BDS-FR-AXFR-026 | Partial | docs/appendix-a-traceability-matrix.md; docs/primary-interop-matrix-v0.2.0.md; scripts/audit-spoof-evidence.py | Parser, anti-spoofing, publication, DNAME, and transfer-size tests exist. The v0.2 BIND/NSD/Knot results are historical; broader fault and multi-primary acceptance evidence remains. |
| TCP, EDNS, NOTIFY, and zone state machine | Implemented scope | BDS-FR-TCP-001..BDS-FR-TCP-011; BDS-FR-EDNS-001..BDS-FR-EDNS-018; BDS-FR-NOTIFY-001..BDS-FR-NOTIFY-011; BDS-FR-ZSM-001..BDS-FR-ZSM-014 | Partial | docs/appendix-a-traceability-matrix.md; docs/zsm-engineering-mvp-matrix.tsv; docs/primary-interop-matrix-v0.2.0.md | TCP, EDNS/EDE, NOTIFY, and refresh-state tests exist. Retained v0.2 NOTIFY results cover BIND/NSD/Knot. Broader timing and release-specific evidence remains. |
| TSIG Alpha subset | Implemented scope | BDS-FR-TSIG-001; BDS-FR-TSIG-005..BDS-FR-TSIG-012; BDS-FR-TSIG-017; BDS-NEG-013; BDS-NEG-014 | Partial | docs/appendix-a-traceability-matrix.md; docs/primary-interop-matrix-v0.2.0.md; crates/borondns-core/src/tsig.rs | HMAC-SHA256 interop and query/stream TSIG regressions exist. Full TSIG requirement acceptance needs its own retained results. |
| Interfaces, shutdown, and observability | Formal SRS acceptance | BDS-IF-NET-001..BDS-IF-NET-008; BDS-IF-CONF-001..BDS-IF-CONF-020; BDS-IF-LOG-001..BDS-IF-LOG-008; BDS-IF-HEALTH-001..BDS-IF-HEALTH-006; BDS-IF-SIG-001..BDS-IF-SIG-004; BDS-IF-PROC-001..BDS-IF-PROC-003; BDS-IF-PROC-004; BDS-NFR-REL-001..BDS-NFR-REL-007; BDS-NFR-MAINT-001; BDS-NFR-MAINT-003; BDS-NFR-PORT-001..BDS-NFR-PORT-004; BDS-NFR-OBS-001..BDS-NFR-OBS-009; BDS-NFR-RES-001 | Partial | docs/appendix-a-traceability-matrix.md; docs/health-metrics-interface.md; docs/operator-deployment-guide.md | Tests cover configuration, CLI, logs, health/metrics, signals, persistence, and publication policy. Broader deployment and production-load evidence remains. |
| Negative requirements | Implemented scope | BDS-NEG-001..BDS-NEG-018 | Partial | docs/appendix-a-traceability-matrix.md; scripts/check.sh | Local/static checks cover applicable prohibitions. Distinguish a verified rejection from a path outside the implemented product scope. |
| Alpha interop gate | Historical Alpha (v0.2) | BDS-VER-003; BDS-VER-004; BDS-VER-007 | Verified | docs/primary-interop-matrix-v0.2.0.md; scripts/interop-primary-matrix.sh | Historical v0.2 result only: 12/12 selected BIND, NSD, Knot, and PowerDNS cases. Versions/configs are retained under target/evidence/primary-matrix-20260614T010049Z. |
| Implemented post-Alpha protocol families | Formal SRS acceptance | BDS-FR-IXFR-001..BDS-FR-IXFR-019; BDS-FR-XOT-001..BDS-FR-XOT-012; BDS-FR-DNSSEC-001..BDS-FR-DNSSEC-014; BDS-FR-RRL-001..BDS-FR-RRL-012; BDS-FR-COOKIE-001..BDS-FR-COOKIE-011; BDS-FR-PROV-001..BDS-FR-PROV-014; BDS-FR-CHAS-001..BDS-FR-CHAS-006 | Partial | docs/implemented-feature-scope.md; docs/appendix-a-traceability-matrix.md; docs/xot-release-evidence-v0.2.0.md; docs/dnssec-conformance-matrix.tsv; docs/rrl-release-thresholds.md | IXFR, XoT, passive DNSSEC, RRL, DNS Cookies, catalog zones, and CHAOS are implemented. Broader formal evidence remains; this is not a deferred-feature list. |
| SRS acceptance non-functional gates | 1.0 public beta | BDS-NFR-PERF-001..BDS-NFR-PERF-008; BDS-NFR-SEC-001..BDS-NFR-SEC-015; BDS-NFR-MAINT-001..BDS-NFR-MAINT-009; BDS-NFR-PORT-001..BDS-NFR-PORT-005; BDS-NFR-OBS-001..BDS-NFR-OBS-009; BDS-NFR-RES-001..BDS-NFR-RES-006 | Partial | docs/release-acceptance-gap-register.md; docs/appendix-a-traceability-matrix.md; docs/fuzz-soak-v0.9.1-2026-08.md; SECURITY.md | The v0.9.1 campaign completed two 24-hour instances per target without a finding. Tagged release signing is implemented. Broader benchmark, portability, and acceptance records remain. |
| SRS acceptance and traceability | Public beta and future full acceptance | BDS-VER-001..BDS-VER-015 | Partial | docs/appendix-a-traceability-matrix.md; docs/rfc-traceability-policy.md; docs/rfc-compliance-assertions.md; docs/test-plan.md | BDS-VER-008 defines the public-beta gate. Requirement mappings and RFC assertion rules exist; the gap register separately tracks evidence for future full SRS acceptance. |

## Maintaining this ledger

Update the relevant row when behavior, evidence, or an acceptance decision
changes. Keep detailed test lists and artifact paths in Appendix A or the
feature report. A verified result needs a tested revision, scope, date, and
retained evidence; the presence of a harness alone is not a passing result.
