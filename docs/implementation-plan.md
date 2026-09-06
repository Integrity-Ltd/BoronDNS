# Development Direction

BoronDNS 1.0.0 has been released. Current work improves correctness,
operability, packaging, and measured performance. There is no remaining
pre-1.0 release sequence to execute.

## Product Direction

Keep the secondary-authoritative server focused: acquire zones reliably, publish
validated snapshots without interrupting queries, and answer at predictable
latency and memory cost. The implemented feature list and its limits are in
[Implemented Feature Scope](implemented-feature-scope.md), not in this plan.

The standard UDP backend is the supported default. The official binary also
includes experimental, opt-in AF_XDP. Broader physical-NIC and zero-copy evidence
is needed before promoting that backend. io_uring, a response cache, and further
storage-layout changes remain possible optimizations; each needs measurements
against the existing path, including small-zone QPS and large-zone IXFR cost.
See [Future Optimization Tracks](future-optimization-tracks.md).

## Preparing the Next Release

1. Fix confirmed correctness and security issues with regression coverage.
2. Measure performance-sensitive changes under the relevant workload, including
   query service during transfers when publication or zone layout changes.
3. Keep deployment instructions, configuration examples, and the SRS aligned
   with observable behavior.
4. Run the local quality gate and the clean-container packaging rehearsal on
   the chosen commit. Select additional fuzz and interoperability runs by risk.
5. Review compatibility and open findings, then sign the tag and verify the
   published artifacts.

The [readiness checklist](engineering-mvp-readiness.md) and
[release evidence guide](release-evidence-guide.md) contain the commands and
release process. The original 0.9.1-to-1.0 validation plan used independent
24-hour fuzz rounds; it did not require a 30-day soak or a fixed sequence of
further prereleases. Future release checks should respond to the actual changes.

## Where to Record Changes

| Change | Document |
| --- | --- |
| Required external behavior | [SRS](BoronDNS-Secondary-SRS-v1.0.0.md) |
| Implementation structure and safety boundaries | [Architecture](architecture.md) |
| Operator commands and examples | [Operator guide](operator-deployment-guide.md) |
| Implemented feature or limitation | `docs/implemented-feature-scope.md` |
| Open acceptance issue or release decision | [Acceptance register](release-acceptance-gap-register.md) |
| Requirement evidence | [Verification ledger](verification-ledger.md); [traceability matrix](appendix-a-traceability-matrix.md) |
| Review rationale and project decisions | [Review disposition](srs-review-disposition.md); [decision register](project-decision-register.md) |

Older Alpha and MVP terminology in evidence filenames describes the validation
phase that produced them. It does not narrow the current product to those
historical feature sets.
