# Rust Audit Remediation Evidence — 2026-08-17

This note records historical evidence for the actionable findings in
Tibor's 2026-08-16 Rust/performance audit. The finding-by-finding disposition is
maintained outside the repository with the original review material.
The QPS interpretation below was corrected on 2026-09-08 after inspecting the
retained response-code counts.

## Hot-path evidence

The cookie-prefix metrics and RRL recency structures now use hash lookup plus a
bounded ordered recency index; neither performs a full-table scan or retain on
a touch. The ignored release benchmark produced:

| Cardinality | RRL ns/touch | Cookie ns/touch |
| ---: | ---: | ---: |
| 1,000 | 474 | 201 |
| 10,000 | 330 | 243 |
| 100,000 | 399 | 303 |

The absence of cardinality-proportional growth is the acceptance criterion;
absolute nanoseconds are host- and build-dependent.

Query observation now parses Header/Question once for metrics and CHAOS
handling and classifies DNS Cookies once. An intended direct-link regression
run used the tuned 25 Gbit/s profile: `oxidedns-1` server, `oxidegun-1` requester,
48 dedicated workers, batch 256, metrics off, spin idle, identical socket/fq
tuning, benchmark-scoped NOTRACK, and kxdpgun generic mode. At 4.25M offered
QPS it returned 4,247,533 replies/s (99.961379%), but all 42,484,016 replies
were `REFUSED`, averaging 37 DNS bytes. The requester queried `perf.test.`
instead of the server's configured `alpha.test.` zone because the harness had
not copied the staged query database. The prior 4,247,663 replies/s small-zone
row returned `NOERROR`, averaging 54 bytes: these are different workloads.
The earlier claim that their similarity proved no small-zone QPS regression is
withdrawn. This run does not measure successful authoritative lookup throughput
or the benefit of removing duplicate parsing. The retained artifact is:

`/home/codex/borondns-qps-recovery-20260815/target/qps-recovery-small-stage/evidence/physical-udp-knot-comparison-20260817T054956Z`

A process-perf companion run returned 4,146,410 replies/s while sampling;
all 41,469,930 replies were also `REFUSED`, averaging 37 bytes. Its profiles
describe that refusal workload, not positive-answer lookup cost. Neither these
profiles nor their stripped release symbols support a source-level lookup
optimization claim. Artifact:

`/home/codex/borondns-qps-recovery-20260815/target/qps-recovery-small-stage/evidence/physical-udp-knot-comparison-20260817T055053Z`

The separate cardinality microbenchmark above is unaffected. See the
[loss-matrix evidence](dns-server-loss-matrix-benchmark.md) for the verified
June and August small-zone results and the invalid large-zone comparisons.
Positive-answer regression evidence needs a new matched run with validated
query names, answer content, and response-code counts.

## Transfer and publication memory

`limits.max_transfer_resident_bytes` is a separate global envelope, defaulting
to 64 GiB. Retained transfer wire is charged at 256x to cover maximum name
decompression, owned decoded records and indexes, publication workspace, the
new image, and overlap with the current generation. The RAII reservation now
survives parsing and remains held through catalog validation, last-good
persistence, ZoneImage compilation, publication, and immediate overlay
compaction. The per-session message limit also has a hard 1,048,576 ceiling.
The metrics endpoint exports the configured limit, current and process-lifetime
peak reservations, and the cumulative budget-rejection count.

The factor is intentionally conservative. Existing medium-TLD evidence reports
about 1.49 GiB peak RSS for a 402 MiB final image, far below the reserved ratio.
The envelope remains an admission model, not a promise that unrelated process
or kernel memory can be observed; operators must leave cgroup headroom.

## Verification

- core library: 695 passed;
- server library: 424 passed, 0 failed, 1 manual benchmark ignored;
- workspace/all-target/all-feature clippy with warnings denied: passed;
- workspace/all-target/all-feature test compilation: passed;
- operations harness regressions from a clean candidate commit: passed;
- package publication recovery and Docker daemon-state fixtures: passed;
- declared Rust 1.95 workspace/all-target check: passed;
- root and both excluded eBPF `cargo deny` graphs: passed;
- pinned-nightly BoronDNS and BoronGun eBPF release objects: built;
- invariant, safe-Rust, unsafe-operation, interface, SRS hygiene, workflow, and
  release-signing policy gates: passed.
