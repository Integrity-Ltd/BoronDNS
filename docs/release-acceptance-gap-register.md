# Release Acceptance Gap Register

This register is the short active queue for 1.0 public-beta closeout. It
tracks the remaining implementation decisions, release blockers, and formal SRS
acceptance evidence gaps that must be closed before claiming `BDS-VER-008`.
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

- **Public-beta candidate** is the current source and documentation state: the
  server behavior is implemented and locally checked, but formal acceptance
  still depends on retained release artifacts and sign-off.
- **Formal SRS acceptance execution** is the `BDS-VER-008` gate run. It needs
  release-specific evidence, role sign-off, and acceptance decisions rather
  than only local development checks.
- **Retained release evidence** means artifacts that can be cited from release
  notes: command logs, primary versions, configs, benchmark/fuzz summaries,
  signatures, and operator sign-off records.
- **Current checked-in full SRS** is
  `docs/BoronDNS-Secondary-SRS-v1.0.0.md`.
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
| Fuzzing and extended runtime | The parser fuzz targets and two-host campaign tooling are present. `docs/two-host-fuzz-soak-campaign.md` records the earlier ASan-backed campaign `20260614T003811Z`. `docs/fuzz-soak-v0.9.1-2026-08.md` records the completed and collected v0.9.1 campaign `bdn-v0.9.1-20260822-24h-b`: two 24-hour instances of all nine targets, at least 6,505,132,495 executions, complete resource sampling, and no sanitizer/crash/leak/OOM/timeout finding. | Closed for the 1.0.0 public-beta decision. No fixed 30-day soak or additional pre-release fuzz round is required. Future fuzzing remains routine hardening work. |
| Release signing and package/image artifact verification | Static-binary reproducibility is recorded in `docs/reproducible-build-v0.2.0.md`; release installer/Docker packaging smoke, checksum generation, static-link reports, and read-only Docker image smoke are recorded in `docs/package-docker-smoke-v0.2.0.md`; signing policy/runbooks exist. | Sign accepted release artifacts with the chosen mechanism and attach signature verification records; add installer archive or Docker-image archive reproducibility evidence only if those artifacts are claimed reproducible. |
| Portability and deployment matrix | Current-host portability evidence, operator deployment guide, package/Docker scripts, installer smoke tests, and dual-stack-capable probes exist. | Add release-specific per-distribution/per-architecture smoke evidence, Kubernetes/container deployment evidence if in scope, and dual-stack operational evidence before claiming full portability acceptance. |
| Operator documentation and public release notes | Operator guide, RFC compliance assertions, architecture, interface compatibility policy, project decision register, and retained verification evidence exist. | Closed for the 1.0 public-beta decision. The tagged workflow publishes concise artifact notes and verification instructions; detailed interop, RFC, requirement, and sign-off records remain in their canonical repository evidence rather than being duplicated in the GitHub release body. |

## Closed Release Evidence

| Area | Closed evidence | Remaining related work |
| --- | --- | --- |
| Selected real-primary and current-version interop | `docs/primary-interop-matrix-v0.2.0.md` records a 12 of 12 local matrix pass for BIND 9.20.23, NSD 4.14.2, Knot DNS 3.5.3, and PowerDNS Authoritative 5.0.5, with retained primary-version/config artifacts under `target/evidence/primary-matrix-20260614T010049Z`. | Broader XoT acceptance, DNSSEC breadth, DNS Cookie deployment, reference-hardware performance, and release-selected fuzz/resource evidence are intentionally tracked as separate closeout rows. |
| Selected XoT release breadth | `docs/xot-release-evidence-v0.2.0.md` records a 3 of 3 local retained XoT pass for Knot DNS 3.5.3 XoT AXFR, Knot DNS 3.5.3 XoT+TSIG AXFR, and BIND 9.20.23 catalog-zone transfer over XoT+TSIG, plus 10 of 10 local XoT failure-class cases, with redacted retained artifacts under `target/evidence/xot-release-20260614T014700Z` and `target/evidence/xot-failure-20260616T170617Z`. | Formal XoT acceptance still needs real-primary mTLS, default-port, prohibited-suite, and optional NSD XoT evidence. |
| Reproducible static binaries | `docs/reproducible-build-v0.2.0.md` records a clean two-build comparison for `x86_64-unknown-linux-musl` `borondns` and `boron-gun`; both builder digests matched bit-for-bit under `target/evidence/reproducible-build-20260614T013236Z`. | Installer/archive normalization, Docker image archive reproducibility, artifact signing, and external independent-builder sign-off are separate release-governance work. |
| Package and Docker smoke | `docs/package-docker-smoke-v0.2.0.md` records a 4 of 4 retained package/image pass for installer creation, Ubuntu installer smoke, Docker image archive creation, and read-only Docker runtime smoke under `target/evidence/package-docker-smoke-20260616T173146Z`. | Archive reproducibility, Docker image archive reproducibility, artifact signing, and external independent-builder sign-off are separate release-governance work. |

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
| Server module decomposition (`server/lib.rs` monolith) | Non-normative maintainability candidate | Tracked in the Architecture Document; not a release blocker unless module growth makes `BDS-NFR-MAINT-002` evidence weak. |
| 1% idle CPU bound for 1000 zones | Formal release evidence target | Covered by the performance/resources row above; requires Reference Hardware/Profile measurement or SRS target revision. |

## Current Verification Commands

The command inventory is maintained in
`docs/evidence-command-catalog.md`. This gap register records active gaps only;
it is not the command-list source consumed by release snapshot tooling.
