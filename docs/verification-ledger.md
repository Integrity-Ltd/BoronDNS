# Alpha/MVP Verification Ledger

This ledger is the lightweight working record for evidence against the SRS
verification requirements, especially ODS-VER-002 and ODS-VER-009. It is not a
complete per-requirement traceability matrix yet. The first slice groups related
requirements at a high level so Alpha/MVP progress has one maintainable place to
accumulate evidence while implementation is still moving.

## Status Values

- **Not Verified**: no accepted evidence is recorded in this ledger.
- **Partial**: evidence exists, but does not yet cover the full listed scope.
- **Verified**: evidence covers the listed scope and is suitable for release
  review.
- **Deferred**: verification is intentionally targeted at a later milestone.

## Ledger

| Area | Target | Requirement Coverage | Evidence State | Evidence Pointers | Notes |
| --- | --- | --- | --- | --- | --- |
| Architectural invariants | Alpha | ODS-INV-001..ODS-INV-006 | Partial | docs/implementation-plan.md; scripts/check.sh | Needs explicit inspection artifacts for secondary-only state flow, memory-resident serving, no persistent state, static configuration, and safe-Rust discipline. |
| Core authoritative query behavior | Alpha | ODS-FR-CORE-001..ODS-FR-CORE-028; ODS-FR-QRY-001..ODS-FR-QRY-024; ODS-FR-NRESP-001..ODS-FR-NRESP-006; ODS-FR-URR-001..ODS-FR-URR-009; ODS-FR-RR-001..ODS-FR-RR-007; ODS-FR-ZONE-001..ODS-FR-ZONE-006 | Partial | docs/implementation-plan.md; scripts/check.sh | Alpha excludes ODS-FR-QRY-003..ODS-FR-QRY-007 only where ODS-VER-007 says minimal-ANY is deferred; this row records the broad query evidence surface, not final release classification. |
| AXFR and outbound response validation | Alpha | ODS-FR-SPOOF-001..ODS-FR-SPOOF-007; ODS-FR-AXFR-001..ODS-FR-AXFR-023 | Partial | docs/implementation-plan.md; scripts/interop-bind-axfr.sh | BIND interop is represented; NSD/Knot evidence remains an MVP expansion unless Alpha chooses a different primary. |
| TCP, EDNS, NOTIFY, and zone state machine | Alpha | ODS-FR-TCP-001..ODS-FR-TCP-010; ODS-FR-EDNS-001..ODS-FR-EDNS-014; ODS-FR-NOTIFY-001..ODS-FR-NOTIFY-010; ODS-FR-ZSM-001..ODS-FR-ZSM-012 | Partial | docs/implementation-plan.md; scripts/check.sh; scripts/interop-bind-notify-refresh.sh; scripts/interop-nsd-notify-refresh-docker.sh; scripts/interop-knot-notify-refresh-docker.sh | BIND, NSD, and Knot NOTIFY refresh interop now cover real primary update paths; broader evidence artifacts still need splitting by unit, runtime, and interop checks before release review. |
| TSIG Alpha subset | Alpha | ODS-FR-TSIG-001; ODS-FR-TSIG-005..ODS-FR-TSIG-012; ODS-FR-TSIG-017; ODS-NEG-013; ODS-NEG-014 | Partial | docs/implementation-plan.md; scripts/interop-bind-tsig-axfr.sh; scripts/interop-nsd-tsig-axfr-docker.sh; scripts/interop-knot-tsig-axfr-docker.sh | ODS-VER-007 requires HMAC-SHA256 interop with at least one TSIG-configured primary; current evidence covers BIND, NSD, and Knot AXFR TSIG, while full TSIG remains MVP scope. |
| Interfaces, shutdown, and observability | Alpha | ODS-IF-NET-001..ODS-IF-NET-004; ODS-IF-CONF-001..ODS-IF-CONF-007; ODS-IF-LOG-001..ODS-IF-LOG-004; ODS-IF-HEALTH-001..ODS-IF-HEALTH-004; ODS-IF-SIG-001..ODS-IF-SIG-004; ODS-NFR-REL-001..ODS-NFR-REL-005; ODS-NFR-MAINT-001; ODS-NFR-MAINT-003; ODS-NFR-PORT-001..ODS-NFR-PORT-004; ODS-NFR-OBS-001; ODS-NFR-OBS-002; ODS-NFR-OBS-004; ODS-NFR-RES-001 | Partial | docs/implementation-plan.md; scripts/check.sh | Alpha accepts the ODS-VER-007 health `/readyz` distinction exclusion; resource and portability evidence still need concrete release artifacts. |
| Negative requirements | Alpha | ODS-NEG-001..ODS-NEG-017 | Partial | docs/implementation-plan.md; scripts/check.sh | Some negative requirements overlap deferred MVP features; release review must separate implemented prohibitions from not-yet-applicable protocol paths. |
| Alpha interop gate | Alpha | ODS-VER-003; ODS-VER-004; ODS-VER-007 | Partial | scripts/interop-bind-axfr.sh; scripts/interop-bind-tsig-axfr.sh; scripts/interop-bind-notify-refresh.sh; scripts/interop-nsd-axfr-docker.sh; scripts/interop-nsd-tsig-axfr-docker.sh; scripts/interop-nsd-notify-refresh-docker.sh; scripts/interop-knot-axfr-docker.sh; scripts/interop-knot-tsig-axfr-docker.sh; scripts/interop-knot-notify-refresh-docker.sh; scripts/interop-ixfr-notimp-fallback.sh | Current scripts cover AXFR, HMAC-SHA256 TSIG AXFR, and NOTIFY refresh with BIND, NSD, and Knot. Alpha requires at least one of NSD, Knot DNS, or BIND 9; MVP still needs IXFR and remaining deferred protocol evidence. |
| Deferred protocol families | MVP | ODS-FR-IXFR-001..ODS-FR-IXFR-018; ODS-FR-XOT-001..ODS-FR-XOT-011; ODS-FR-DNSSEC-001..ODS-FR-DNSSEC-013; ODS-FR-RRL-001..ODS-FR-RRL-012 | Partial | docs/implementation-plan.md; scripts/interop-bind-ixfr-refresh.sh; scripts/interop-ixfr-notimp-fallback.sh; scripts/interop-knot-xot-docker.sh; scripts/interop-knot-xot-tsig-docker.sh; scripts/interop-knot-dnssec-docker.sh; scripts/interop-rrl-udp.sh; scripts/interop-dnssec-serve.sh; scripts/interop-dnssec-nsec3-serve.sh; config/oxidedns.example.toml; scripts/check.sh | IXFR has parser, true incremental BIND refresh, and fallback evidence; DNSSEC has unit foundations plus runtime fake-primary DO-sensitive RRSIG/NSEC/NSEC3/DNSKEY/NSEC3PARAM and Knot signed-primary NSEC3 evidence; RRL has unit and runtime UDP drop/slip evidence across all response categories; and XoT now has configuration, startup TLS-file validation, in-process TLS transport, XoT+TSIG, mTLS client-certificate, certificate-name, untrusted-cert, expired-cert, ALPN-failure, missing-client-cert tests, and Knot XoT plus XoT+TSIG interop evidence. ODS-VER-007 still defers broader IXFR matrix evidence, broader XoT real-primary evidence beyond Knot, DNSSEC release conformance traceability, and broader RRL release evidence to MVP. |
| MVP non-functional gates | MVP | ODS-NFR-PERF-001..ODS-NFR-PERF-005; ODS-NFR-SEC-001..ODS-NFR-SEC-006; ODS-NFR-MAINT-001..ODS-NFR-MAINT-005; ODS-NFR-PORT-001..ODS-NFR-PORT-005; ODS-NFR-OBS-001..ODS-NFR-OBS-005; ODS-NFR-RES-001..ODS-NFR-RES-005 | Partial | docs/implementation-plan.md; fuzz/README.md; scripts/perf-smoke.sh; scripts/release-evidence-snapshot.sh | Parser fuzz targets now cover DNS datagrams, AXFR/IXFR transfer streams, TSIG message paths, and NOTIFY/EDNS datagrams; `scripts/perf-smoke.sh` adds repeatable startup, AXFR ingestion, metrics, and UDP direct-hit latency smoke evidence; and `scripts/release-evidence-snapshot.sh` captures release-review command logs, tool versions, git state, fuzz compile checks, and cargo-deny output. MVP still needs long-run fuzz evidence, release benchmark artifacts, portability, observability, and resource evidence artifacts. |
| MVP acceptance and traceability | MVP | ODS-VER-001..ODS-VER-009 | Partial | docs/OxideDNS-Secondary-SRS-v0.1.md; docs/verification-ledger.md; docs/appendix-a-traceability-matrix.md | The Appendix A matrix is now a first-pass family-level traceability artifact; it still needs expansion to the full per-requirement matrix required by ODS-VER-009. |

## Maintenance Check

Run:

```sh
python3 scripts/check-verification-ledger.py
```

The check validates that requirement IDs and same-prefix ranges referenced by
this ledger exist in `docs/OxideDNS-Secondary-SRS-v0.1.md`. It also validates the
ledger status values in the table above. This catches typo-level drift without
pretending to prove requirement satisfaction.
