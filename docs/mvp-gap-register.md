# Engineering MVP and SRS Acceptance Gap Register

This register is the short active queue for remaining implementation decisions,
release blockers, and formal SRS acceptance evidence gaps. It is not the
detailed evidence ledger.

Detailed evidence ownership:

- `docs/README.md` records the documentation ownership map used to keep SRS,
  scope, gap, evidence, traceability, architecture, and operator material from
  becoming competing sources of truth.
- `docs/verification-ledger.md` records coarse verification state.
- `docs/appendix-a-traceability-matrix.md` records requirement-range evidence
  and remaining acceptance work.
- `docs/srs-review-disposition.md` records the external SRS review findings,
  accepted protocol fixes, and rejected scope-trim suggestions.
- `docs/implemented-feature-scope.md` records the retained post-Alpha feature
  slices and nearby behavior that is not claimed by those slices.
- `docs/project-decision-register.md` records resolved and pending project
  decisions formerly embedded in SRS Appendix C.5.
- Feature-specific documents such as `docs/catalog-zone-rfc9432.md`,
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
- **Pending project-decision rows** remain open until release review resolves
  or explicitly defers them. Resolved rows are already project decisions;
  release notes and acceptance review must not treat the pending subset as
  confirmed only because implementation evidence exists.

Rows below deliberately name current gaps only. A row being present here does
not mean the feature is absent; it means either an implementation decision, a
release artifact, or a formal acceptance sign-off is still open.

## Open Implementation Decisions

No open Engineering MVP implementation decisions are currently tracked here.

## Release Acceptance Evidence Still Open

| Area | Current evidence owner | Remaining acceptance work |
| --- | --- | --- |
| Core query, AXFR, unknown RR, negative response, TCP, NOTIFY, ZSM, and TSIG behavior | `docs/appendix-a-traceability-matrix.md`; `docs/verification-ledger.md`; interop scripts | Refresh retained release artifacts, fault-injection cases, primary-version records, and per-requirement traceability where Appendix A marks the row `Partial`. |
| Implemented post-Alpha protocol families | `docs/implemented-feature-scope.md`; `docs/srs-review-disposition.md`; `docs/appendix-a-traceability-matrix.md`; feature-specific docs and scripts | Keep these in Engineering MVP scope exactly as bounded in `docs/implemented-feature-scope.md`; collect broader real-primary, real-client, retained artifact, and release-review evidence before asserting full ODS-VER-008 acceptance. For XoT, current retained evidence covers Knot and BIND paths; release acceptance still needs a current-version capability decision for every ODS-VER-003 primary, NSD XoT evidence when the selected NSD version exposes TLS-protected transfer configuration, and a formal-profile decision that either enforces TLS 1.3-or-later for RFC 9103 evidence or explicitly separates TLS 1.2 compatibility evidence from conformance evidence. |
| DNS Cookie shared Server Secret deployment | `docs/OxideDNS-Secondary-SRS-v0.9.1.md`; `docs/implemented-feature-scope.md`; `docs/operator-deployment-guide.md`; `docs/rfc-compliance-assertions.md` | Current Engineering MVP DNS Cookie code uses a process-local random secret generated at startup. Before formal RFC 9018 acceptance for anycast or load-balanced deployments, add configured shared Server Secret support, current-plus-previous secret verification for staged rollover, and retained multi-instance evidence. |
| Catalog member-name semantic validation | `docs/catalog-zone-rfc9432.md`; `crates/oxidedns-core/src/catalog.rs`; `crates/oxidedns-server/src/lib.rs`; `docs/appendix-a-traceability-matrix.md` | Current Engineering MVP evidence covers RFC 9432 structural member PTR parsing, duplicate-member rejection, self-catalog member rejection, and member-count caps. Before formal SRS MVP acceptance, add implementation and retained tests for the remaining `ODS-NFR-SEC-015` semantic exclusions: member names subordinate to the catalog apex, root-zone members, reserved-zone members, and wildcard-label members. |
| Performance and resources | `docs/dns-client-benchmark.md`; `scripts/perf-smoke.sh`; `scripts/benchmark-large-catalog-zones.sh`; `scripts/capture-resource-evidence.sh` | Current smoke and large-catalog runs are exploratory engineering evidence for code tuning. Later release/operations owners run the full Reference Hardware/Profile benchmarks for throughput, latency, memory, transfer performance, published image size, capacity, per-record memory, idle CPU, overload behavior, and regression baseline updates before asserting formal target conformance. |
| Fuzzing, soak, reproducible build, signed release, and external operator acceptance | `docs/test-plan.md`; `docs/operator-deployment-guide.md`; release handoff scripts | Later release/operations owners run the 24-hour parser fuzz campaigns, 30-day soak, independent reproducible-build comparison, signed-artifact workflow, and external operator deployment/sign-off. |
| Portability and deployment matrix | `docs/operator-deployment-guide.md`; `scripts/capture-portability-evidence.sh`; package and Docker scripts | Add per-distribution/per-architecture smoke evidence, Kubernetes/container deployment evidence, and dual-stack operational evidence before full acceptance. |
| Operator documentation and release notes | `docs/operator-deployment-guide.md`; `docs/release-notes-template.md`; `docs/rfc-compliance-assertions.md`; `docs/architecture.md` | Populate release notes with concrete evidence pointers, RFC compliance assertions, Appendix C.5 dispositions, interface compatibility state, signed-artifact manifest, release-time first-party Rust source line count with citation to the Architecture Document's current over-target rationale or a newer refactor plan, and role sign-off. |

## Pending Project Decision Overlay

`docs/project-decision-register.md` is the canonical project-decision table;
SRS Appendix C.5 points to that owner and deliberately does not duplicate the
decision table. This gap register summarizes only the pending subset.
Rows marked `Resolved` are retained as audit trail, not open risks. Rows whose
Decision begins `Pending` need release-review attention, but they are not all
the same kind of blocker: some are non-normative quality candidates, some
require an implementation-or-SRS decision, and some require later formal
release evidence. Update release notes from the project decision register, not
from this summary.

Current pending rows are classified here only to make the active queue
readable:

| Decision item | Current classification | Handling |
| --- | --- | --- |
| Property-based testing in Alpha scope | Non-normative quality candidate | Tracked in the Test Plan; not an Engineering MVP blocker unless promoted to a requirement. |
| Server module decomposition (`server/lib.rs` monolith) | Non-normative maintainability candidate | Tracked in the Architecture Document; not an Engineering MVP blocker unless module growth makes `ODS-NFR-MAINT-002` evidence weak. |
| 1% idle CPU bound for 1000 zones | Formal release evidence target | Covered by the performance/resources row above; requires Reference Hardware/Profile measurement or SRS target revision. |

## Current Verification Commands

The command inventory is maintained in
`docs/evidence-command-catalog.md`. This gap register records active gaps only;
it is not the command-list source consumed by release snapshot tooling.
