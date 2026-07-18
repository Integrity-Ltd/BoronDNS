# ZoneImage Remaining Action-Item Report

Status: implemented and locally measured, 2026-07-18.

This report closes the follow-up items raised after the July ZoneImage proposal
disposition. Exact encoded limits remain normative in
`zone-image-capacity-limits.md`; the snapshot-memory follow-up is scoped in
`zone-snapshot-narrowing-design.md`.

## Disposition

| Item | Result |
| --- | --- |
| F-01 `edge_count` and child-hash edge offsets | Confirmed widened. `NameNode.first_edge` and `edge_count` are checked `u32` values. Child-hash descriptors and arena starts are `u32`; local slots automatically use `u32` offsets when sibling fanout exceeds the narrow representation. |
| F-02 `low_rrtype_bitmap` | Confirmed widened. The node field is a `u32` bitmap-table handle with `u32::MAX` reserved for “none”; it is not a zone-wide 65,535-name ceiling. |
| Denial fallback observability | Added an image-compilation log with indexed/fallback NSEC and NSEC3 counts and the opt-in per-zone `borondns_zone_image_denial_range_groups{proof,mode}` gauge. |
| F-03 removable-authority cast | Removed the release-mode `usize as u16` cast. Query-local scratch indexes now remain `usize`. |
| F-04 TCP framing | `frame_tcp_message` is fallible and rejects messages beyond the DNS-over-TCP `u16` limit with `TcpFrameError::MessageTooLong`; an oversized-frame regression test covers the boundary. |
| F-05 relation sentinel | Documented and asserted that relation offsets are zero-based while `relation_count` is end-exclusive, leaving `u16::MAX` unambiguous as the missing-kind sentinel. |
| Capacity/status documentation | Updated the normative capacity table with the F-01/F-02 cross-check and refreshed the implementation tracker. The SRS has no implementation-layout ceiling to change; its large-zone verification requirement remains shape-neutral. |
| ZoneSnapshot narrowing | Scoped as a separate responsibility/lifetime design with a representative signed-registry replay gate. No memory reduction is claimed in this slice. |
| Counting allocator | Kept as a dedicated profiling-job design task. Adding an unsafe global-allocator wrapper or instrumentation dependency without a stable representative corpus was rejected as a brittle always-on CI gate. Existing per-arena image statistics remain stable inputs. |

## Matched Performance Check

The baseline was detached commit `e4e3d29`; the candidate was the action-item
working tree. Both were built with Rust 1.96.1 using the `profiling` profile on
an AMD Ryzen 9 9950X3D. Nine alternating baseline/candidate pairs were pinned
to logical CPU 4. The alternation is important: an earlier sequential run was
discarded after host warm-up made the unchanged measured path appear 40–50%
faster.

Capacity workload:

```text
zone_image_capacity_bench --names 60000 --lookups 2000000 --signed
```

Denial workload:

```text
zone_image_denial_bench --records 100000 --iterations 100000 --query-cases 257
```

| Metric | Baseline median | Candidate median | Candidate change |
| --- | ---: | ---: | ---: |
| Signed 60k compile | 115.614 ms | 111.869 ms | -3.24% |
| Exact A lookup | 45.199 ns/query | 43.720 ns/query | -3.27% |
| NSEC compile | 108.391 ms | 111.369 ms | +2.75% |
| NSEC denial lookup | 761.974 ns/query | 759.823 ns/query | -0.28% |
| NSEC3 compile | 138.459 ms | 135.582 ms | -2.08% |
| NSEC3 denial lookup | 635.407 ns/query | 595.896 ns/query | -6.22% |
| ZoneImage hot bytes | 17,332,224 | 17,332,224 | 0.00% |
| ZoneImage cold bytes | 14,580,000 | 14,580,000 | 0.00% |

The only median regression was +2.75% in NSEC compilation. Its pairwise median
change was -2.72%, and the paired compile timings varied in both directions,
so this is treated as host noise rather than a candidate regression. The
measured image layout is byte-identical, exact and denial lookup medians did not
regress, and none of the changed robustness/observability code enters the
ZoneImage query hot path.

These are local microbenchmark results, not physical-link promotion evidence.
