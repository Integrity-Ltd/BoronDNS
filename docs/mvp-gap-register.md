# Engineering MVP and SRS Acceptance Gap Register

This register is the short active queue for remaining implementation decisions,
release blockers, and formal SRS acceptance evidence gaps. It is not the
detailed evidence ledger.

Detailed evidence ownership:

- `docs/verification-ledger.md` records coarse verification state.
- `docs/appendix-a-traceability-matrix.md` records requirement-range evidence
  and remaining acceptance work.
- `docs/srs-review-disposition.md` records the external SRS review findings,
  accepted protocol fixes, and rejected scope-trim suggestions.
- Feature-specific documents such as `docs/catalog-zone-mvp-rfc9432.md`,
  `docs/dnssec-conformance-matrix.tsv`, and
  `docs/rrl-release-thresholds.md` hold focused evidence detail.

Terminology:

- **Engineering MVP** is the first deployable secondary DNS server with the core
  operational path, deterministic tests, short smoke/runtime evidence, and
  checked traceability.
- **Long-running evidence is out of Engineering MVP scope.** Handoff scripts,
  schemas, and runbooks for long fuzzing, Reference Hardware/Profile
  benchmarks, 30-day soak, production-depth logging profiles, external
  operator acceptance, independent reproducible-build comparison, and signed
  release artifacts may exist here for later release/operations use, but they
  are not Engineering MVP deliverables and are not Engineering MVP evidence.
- **SRS acceptance execution** is the later ODS-VER-008 gate run. The current
  Engineering MVP does not depend on those completed results.
- **Current checked-in full SRS** is
  `docs/OxideDNS-Secondary-SRS-v0.9.1.md`.
- **Pending C.5 decisions** in the current SRS remain open even when
  implementation follows the current SRS body defaults. Release notes and
  acceptance review must distinguish implemented defaults from confirmed
  project decisions.

Rows below deliberately name current gaps only. A row being present here does
not mean the feature is absent; it means either an implementation decision, a
release artifact, or a formal acceptance sign-off is still open.

## Open Implementation Decisions

| Gap | Current posture | Needed decision or change |
| --- | --- | --- |
| Catalog member-zone resource cap (`ODS-NFR-SEC-013`) | RFC 9432 catalog support is implemented and tested through explicit/catalog config, mandatory catalog TSIG, internal consumption, live member add/remove, catalog logs, catalog metrics, BIND XoT+TSIG, and PowerDNS/PostgreSQL producer coverage. | Implement `max_member_zones` or equivalent, including cap logging/tests, or revise the SRS requirement if the cap is deferred from the current release target. |
| TSIG secret loading from environment (`ODS-NFR-SEC-008`) | TSIG supports inline `secret` and filesystem `secret_file`; file readability and world-readable mode are validated, and config dumps redact inline secrets. | Implement environment-backed TSIG secret loading with clearing/zeroization evidence, or revise the SRS to make file-backed secrets the supported operational boundary. |
| Runtime timeout defaults from C.5 | TCP idle/read/write/connect timeouts and health probe behavior have local evidence. | Decide whether to implement `query.processing_timeout_ms`, its related per-zone timeout-drop metric, and `health.livez_timeout_ms`, or revise the SRS to rely on existing resource bounds and external orchestrator probe timeouts. |
| Environment override validation evidence | CLI applies supported `ODS_*` overrides before full config validation. | Add explicit regression/traceability evidence for post-override cross-field validation and deployment-specific config snapshots. |
| NSEC3 cap observability (`ODS-FR-DNSSEC-014`) | The server implements configurable `[dnssec].nsec3_max_iterations`, optional EDE 27, proof omission above cap, config warning, and a global counter. | Decide whether the SRS still requires per-zone warning/per-zone metric evidence for acceptance, or whether the current global counter posture is the intended Engineering MVP behavior. |

## Release Acceptance Evidence Still Open

| Area | Current evidence owner | Remaining acceptance work |
| --- | --- | --- |
| Core query, AXFR, unknown RR, negative response, TCP, NOTIFY, ZSM, and TSIG behavior | `docs/appendix-a-traceability-matrix.md`; `docs/verification-ledger.md`; interop scripts | Refresh retained release artifacts, fault-injection cases, primary-version records, and per-requirement traceability where Appendix A marks the row `Partial`. |
| Implemented post-Alpha protocol families: IXFR, XoT, passive DNSSEC serving, RRL, DNS Cookies, catalog zones, broad EDNS behavior, EDE, and CHAOS | `docs/srs-review-disposition.md`; `docs/appendix-a-traceability-matrix.md`; feature-specific docs and scripts | Keep these in Engineering MVP scope; collect broader real-primary, real-client, retained artifact, and release-review evidence before asserting full ODS-VER-008 acceptance. For XoT, current retained evidence covers Knot and BIND paths; release acceptance still needs a current-version capability decision for every ODS-VER-003 primary and NSD XoT evidence when the selected NSD version exposes TLS-protected transfer configuration. |
| Performance and resources | `docs/dns-client-benchmark.md`; `scripts/perf-smoke.sh`; `scripts/benchmark-large-catalog-zones.sh`; `scripts/capture-resource-evidence.sh` | Current smoke and large-catalog runs are exploratory engineering evidence for code tuning. Later release/operations owners run the full Reference Hardware/Profile benchmarks for throughput, latency, memory, transfer performance, published image size, capacity, per-record memory, idle CPU, overload behavior, and regression baseline updates before asserting formal target conformance. |
| Fuzzing, soak, reproducible build, signed release, and external operator acceptance | `docs/test-plan.md`; `docs/operator-deployment-guide.md`; release handoff scripts | Later release/operations owners run the 24-hour parser fuzz campaigns, 30-day soak, independent reproducible-build comparison, signed-artifact workflow, and external operator deployment/sign-off. |
| Portability and deployment matrix | `docs/operator-deployment-guide.md`; `scripts/capture-portability-evidence.sh`; package and Docker scripts | Add per-distribution/per-architecture smoke evidence, Kubernetes/container deployment evidence, and dual-stack operational evidence before full acceptance. |
| Operator documentation and release notes | `docs/operator-deployment-guide.md`; `docs/release-notes-template.md`; `docs/rfc-compliance-assertions.md` | Populate release notes with concrete evidence pointers, RFC compliance assertions, Appendix C.5 dispositions, interface compatibility state, signed-artifact manifest, and role sign-off. |

## Pending SRS C.5 Decision Overlay

SRS v0.9.1 Appendix C.5 is the canonical project-decision table. Rows whose
Decision begins `Pending` remain active release-review risks, even where current
code follows the body default or a document records current implementation
evidence. Rows marked `Resolved` are retained as audit trail, not open risks.
Update release notes from the SRS C.5 table, not from this summary.

## Current Verification Commands

The command inventory is maintained in
`docs/evidence-command-catalog.md`. This gap register records active gaps only;
it is not the command-list source consumed by release snapshot tooling.
