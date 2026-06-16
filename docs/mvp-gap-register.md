# SRS Acceptance Gap Register

This register is the short active queue for release-candidate closeout. It
tracks the remaining implementation decisions, release blockers, and formal SRS
acceptance evidence gaps that must be closed before claiming `ODS-VER-008`.
It is not the detailed evidence ledger.

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

- **Release candidate** is the current source and documentation state: the
  server behavior is implemented and locally checked, but formal acceptance
  still depends on retained release artifacts and sign-off.
- **Formal SRS acceptance execution** is the `ODS-VER-008` gate run. It needs
  release-specific evidence, role sign-off, and acceptance decisions rather
  than only local development checks.
- **Retained release evidence** means artifacts that can be cited from release
  notes: command logs, primary versions, configs, benchmark/fuzz summaries,
  signatures, and operator sign-off records.
- **Current checked-in full SRS** is
  `docs/OxideDNS-Secondary-SRS-v0.9.1.md`.
- **Pending project-decision rows** remain open until release review resolves
  or explicitly defers them. Resolved rows are already project decisions;
  release notes and acceptance review must not treat the pending subset as
  confirmed only because implementation evidence exists.

Rows below deliberately name current closeout gaps only. A row being present
here does not mean the feature is absent; it means an implementation decision,
release artifact, formal acceptance decision, or sign-off is still open.

## Open Implementation Decisions

No open product implementation decisions are currently tracked here.

## Acceptance Closeout Still Open

| Area | Already available | Needed to close |
| --- | --- | --- |
| Core protocol traceability | Local and retained script evidence exists for query handling, AXFR, IXFR fallback, unknown RR, negative responses, TCP, NOTIFY, ZSM, EDNS/EDE, TSIG, DNSSEC, RRL, DNS Cookies, catalog zones, and CHAOS; detailed rows live in `docs/appendix-a-traceability-matrix.md`. | Refresh release-candidate artifacts where Appendix A still marks a requirement row `Partial`; attach per-requirement traceability, fault-injection results, primary-version records, and release-note evidence paths. |
| XoT release evidence | TLS 1.3-or-later client profile, ALPN, certificate, mTLS, TSIG-over-XoT, no-cleartext-fallback, and revocation-posture checks exist; `docs/xot-release-evidence-v0.2.0.md` records retained Knot XoT, Knot XoT+TSIG, BIND catalog-over-XoT+TSIG, and local failure-class artifacts under `target/evidence/xot-release-20260614T014700Z` and `target/evidence/xot-failure-20260616T170617Z`. | Add real-primary mTLS evidence, ClientHello/prohibited-suite inspection, default-port evidence where required, and NSD XoT evidence if the selected NSD version exposes TLS-protected transfer configuration before claiming full formal XoT acceptance. |
| DNS Cookie release evidence | Configured shared Server Secret support, current-plus-previous validation, strict/lenient policy behavior, BADCOOKIE handling, metrics, and retained two-instance staged-rollover evidence exist. | Decide whether external load-balanced or anycast deployment sign-off is required for the release; if yes, attach that operator evidence and publish the DNS Cookie acceptance summary in release notes. |
| Performance and resources | Local DNS client benchmarks, tuned UDP/XDP benchmark documentation, `perf-smoke`, large-catalog/resource scripts, coverage/resource evidence, and benchmark handoff schemas exist. | Run the final Reference Hardware/Profile benchmark set or explicitly scope it out of this release: throughput, latency and p99, transfer performance, memory, published image size, capacity, per-record memory, idle CPU, overload behavior, and regression baseline updates. |
| Fuzzing and soak | The parser fuzz targets, two-host campaign tooling, and first ASan-backed two-host 24-hour fuzz evidence are present; soak report schemas and handoff scripts exist. | Decide whether the existing 24-hour fuzz evidence is accepted for the final candidate or rerun it after the release commit; run or explicitly defer the 30-day production-representative soak and attach the completed report/sign-off if claiming full SRS acceptance. |
| Release signing and package/image artifact verification | Static-binary reproducibility is recorded in `docs/reproducible-build-v0.2.0.md`; release installer/Docker packaging, checksum generation, and signing policy/runbooks exist. | Sign accepted release artifacts with the chosen mechanism, attach manifest/checksum/signature verification records, and add package/archive or Docker-image reproducibility evidence if those artifacts are claimed reproducible. |
| Portability and deployment matrix | Current-host portability evidence, operator deployment guide, package/Docker scripts, installer smoke tests, and dual-stack-capable probes exist. | Add release-specific per-distribution/per-architecture smoke evidence, Kubernetes/container deployment evidence if in scope, and dual-stack operational evidence before claiming full portability acceptance. |
| Operator documentation, release notes, and sign-off | Operator guide, release-note template, RFC compliance assertions, architecture, interface compatibility policy, and project decision register exist. | Populate release notes with concrete evidence pointers, final version/tag/date, primary interop versions, RFC assertions, Appendix C.5 dispositions, interface compatibility state, signed-artifact manifest, release-time first-party Rust source line count/rationale, and role/operator sign-off. |

## Closed Release Evidence

| Area | Closed evidence | Remaining related work |
| --- | --- | --- |
| Selected real-primary and current-version interop | `docs/primary-interop-matrix-v0.2.0.md` records a 12 of 12 local matrix pass for BIND 9.20.23, NSD 4.14.2, Knot DNS 3.5.3, and PowerDNS Authoritative 5.0.5, with retained primary-version/config artifacts under `target/evidence/primary-matrix-20260614T010049Z`. | Broader XoT acceptance, DNSSEC breadth, DNS Cookie deployment, production operator acceptance, reference-hardware performance, and long-running soak evidence are intentionally tracked as separate closeout rows. |
| Selected XoT release breadth | `docs/xot-release-evidence-v0.2.0.md` records a 3 of 3 local retained XoT pass for Knot DNS 3.5.3 XoT AXFR, Knot DNS 3.5.3 XoT+TSIG AXFR, and BIND 9.20.23 catalog-zone transfer over XoT+TSIG, plus 10 of 10 local XoT failure-class cases, with redacted retained artifacts under `target/evidence/xot-release-20260614T014700Z` and `target/evidence/xot-failure-20260616T170617Z`. | Formal XoT acceptance still needs real-primary mTLS, default-port, prohibited-suite, and optional NSD XoT evidence. |
| Reproducible static binaries | `docs/reproducible-build-v0.2.0.md` records a clean two-build comparison for `x86_64-unknown-linux-musl` `oxidedns` and `oxide-gun`; both builder digests matched bit-for-bit under `target/evidence/reproducible-build-20260614T013236Z`. | Installer/archive normalization, Docker image archive reproducibility, artifact signing, and external independent-builder sign-off are separate release-governance work. |

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
| Property-based testing in Alpha scope | Non-normative quality candidate | Tracked in the Test Plan; not a release blocker unless promoted to a requirement. |
| Server module decomposition (`server/lib.rs` monolith) | Non-normative maintainability candidate | Tracked in the Architecture Document; not a release blocker unless module growth makes `ODS-NFR-MAINT-002` evidence weak. |
| 1% idle CPU bound for 1000 zones | Formal release evidence target | Covered by the performance/resources row above; requires Reference Hardware/Profile measurement or SRS target revision. |

## Current Verification Commands

The command inventory is maintained in
`docs/evidence-command-catalog.md`. This gap register records active gaps only;
it is not the command-list source consumed by release snapshot tooling.
