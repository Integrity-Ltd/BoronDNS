# ZoneImage status and evidence

Checked against the September 2026 source. `ZoneImage` is the compact serving
representation in BoronDNS, not a prototype awaiting runtime promotion.
Large IXFR updates also have a supported snapshot-overlay path.

This page records what exists, what remains open, and the measurements behind
the design. The [data-plane reference](memory-io-data-plane-design.md) explains
how it works; the [SRS](BoronDNS-Secondary-SRS-v1.0.0.md) owns DNS requirements.

## Current implementation

| Area | Current state | Source or evidence |
| --- | --- | --- |
| Compact lookup | Immutable trie, RRset handles, direct answers, and semantic plans | [zone_image.rs](../crates/borondns-core/src/zone_image.rs) |
| Wire composition | Pre-encoded RRsets, selected record views, bounded synthesis, compression, EDNS, and truncation | [dns.rs](../crates/borondns-core/src/dns.rs) |
| DNSSEC | Compiled NSEC/NSEC3 groups, indexed valid rings, conservative fallback, iteration caps, and proof-selection tests | [July denial measurements](zone-image-proposal-disposition-2026-07.md), [DNSSEC matrix](dnssec-conformance-matrix.tsv) |
| Large image capacity | Global `u64` arenas/ordinals and `u32` RRset membership; adaptive child slots | [Capacity reference](zone-image-capacity-limits.md) |
| IXFR publication | Shared snapshot shards, exact changed dependencies, compact-plan reuse, and background compaction | [IXFR report](ixfr-scaling-2026-08.md) |
| Durable updates | Prepared publication, checksummed checkpoints, bounded RRset journal, stale-journal recovery | [zone_persistence.rs](../crates/borondns-server/src/zone_persistence.rs) |
| Runtime integration | UDP and TCP use the published provider; no snapshot-only rollback switch | [udp.rs](../crates/borondns-server/src/udp.rs), [tcp.rs](../crates/borondns-server/src/tcp.rs) |
| Standard UDP tuning | Batching, reuseport, dedicated workers, affinity, and bounded I/O adapters | [Benchmark guide](dns-client-benchmark.md) |
| AF_XDP | Optional compiled server adapter and separately built project redirect object; physical-link testing exists | [Knot comparison](knot-comparison-benchmark.md) |
| Verification | Unit/differential tests, packet fuzzing, source invariant audits, and dated campaigns | [Verification ledger](verification-ledger.md), [v0.9.1 fuzz evidence](fuzz-soak-v0.9.1-2026-08.md) |

`ZoneSnapshot` remains required for transfer, persistence, catalogs, and dirty
overlay lookup. Its offline oracle remains useful for comparisons. Removing
the live rollback switch did not make every snapshot index test-only.

## Measured decisions

The following decisions remain relevant. Measurements describe their original
fixture and revision, not a promise about today's build.

| Decision | Measurement or reason |
| --- | --- |
| Selectively widen global offsets/ordinals | Removed real capacity ceilings without paying for wide local handles everywhere. Paired physical UDP results showed no material service penalty in the tested profile; [July large-zone report](zone-image-large-zone-design.md). |
| Index valid denial rings | At 100,000 records, the July NSEC/NSEC3 benchmark improved approximately 1,011×/607× over the former linear scan; [full conditions](zone-image-proposal-disposition-2026-07.md). |
| Index RRSIG relation construction | At 60,000 signed names, build time fell from 24.384 s to 0.265 s on one host and 24.822 s to 0.297 s on the other; [two-host evidence](zone-image-large-zone-design.md). |
| Retain open-address child hashes for high fanout | First-byte, last-byte, and length buckets were slower on the retained synthetic fixture; details below. |
| Keep narrow child slots where possible | The 10k fixture's slot arena used 65,536 bytes after `u16` compaction. Adaptive `u32` slots later removed the high-fanout ceiling; [capacity and cost](zone-image-large-zone-design.md). |
| Avoid generic wire compression | The measured wire arena was only 15.8% of total image bytes; even free 2:1 compression would save about 7.9% of that image, before source/reload memory. [Memory analysis](zone-image-proposal-disposition-2026-07.md). |
| Reject the measured owner/RDATA interner | Saved 1,037 cold bytes (0.15%) on the 10k fixture; observed compile time rose from 7.985 to 9.282 ms. [Original result](zone-image-proposal-disposition-2026-07.md). |
| Publish eligible large IXFR as overlays | The 50M-name focused update dropped from the historical full-rebuild total of 980.190 s to 0.288 s in a later isolated sharded row. These are different revisions and a focused update measurement, not universal catch-up bounds. [IXFR report](ixfr-scaling-2026-08.md). |

The IXFR report also records the important cost: under its signed
continuous-churn profile, clean-plan reuse reached 44,814 QPS against 70,639 for
the static compact image. The small-zone control differed by 0.55%, within
that run's variation. These workloads are separate from maximum-QPS tuning;
they should not be compared directly with multi-million-QPS direct-answer
benchmarks.

## What remains open

- Retained snapshot memory can still be reduced, but the next design must
  preserve IXFR, dirty-query, catalog, and recovery responsibilities. See
  [snapshot narrowing](zone-snapshot-narrowing-design.md).
- More representative signed-registry distributions are useful for memory and
  dirty-query tuning. A synthetic projection is not a real registry corpus.
- Full-response caches, custom reclamation, io_uring, huge-page management, and
  NUMA image replication are not implemented. See
  [future optimization tracks](future-optimization-tracks.md).
- Performance evidence must be refreshed when a relevant implementation,
  workload, or host changes. Existing physical-link evidence means “run on a
  real NIC” is no longer an unstarted phase; it does not establish every
  formal reference-profile requirement.

## Evidence map

| Question | Maintained record |
| --- | --- |
| Exact image/transfer/persistence limits | [Capacity limits](zone-image-capacity-limits.md) |
| Why selective `u64` and adaptive child slots? | [July layout decision and paired measurements](zone-image-large-zone-design.md) |
| Why indexed denial and no generic compression? | [July proposal disposition](zone-image-proposal-disposition-2026-07.md) |
| What did the capacity/robustness follow-up change? | [July action-item report](zone-image-action-items-2026-07.md) |
| What fits in hundreds of GiB? | [Two-host large-memory campaign](boron-gen-two-host-campaign-2026-07.md) |
| Does small IXFR keep up as zones grow? | [IXFR scaling and durable-publication measurements](ixfr-scaling-2026-08.md) |
| What is the measured packet-rate ceiling? | [Knot comparison](knot-comparison-benchmark.md) |
| What fuzz evidence belongs to v0.9.1? | [Dated fuzz report](fuzz-soak-v0.9.1-2026-08.md) |

## Historical local baseline

These May–June 2026 measurements explain the original promotion from the
materializing snapshot path. The historical artifact paths identify original
run directories; they are not checked-in downloads and may not exist in a
fresh checkout. The old runtime enable/disable comparison mode is no longer
available. Git history retains its per-change timing logs and commands.

### In-process prototype

The recorded `prototype-latest.tsv` snapshot used an AMD Ryzen 9 9950X3D,
Rust 1.95.0, the `profiling` profile, Linux 7.0.3-1-MANJARO, and dirty revision
`2908b3898609`. It had 10,000 generated records, 200,000 iterations, and 2,000
delegation/DNAME stress candidates. The query sets contained 100 hot cases,
84 weighted trace rows, eight mixed cases, and 200 stress cases; the mixed
set included positive A, CNAME, wildcard, referral/glue, NODATA, NXDOMAIN,
DNAME, and opaque unknown RDATA.

| Work measured (ns/query) | Snapshot comparison | ZoneImage |
| --- | ---: | ---: |
| Exact lookup | 149.171 | 77.420 |
| Hot exact lookup | 133.774 | 53.379 |
| Mixed semantic response/plan | 451.637 | 264.775 |
| Mixed wire emission | — | 281.062 |
| Delegation/DNAME response/plan | 89,382.274 | 634.491 |
| Delegation/DNAME wire emission | — | 701.321 |
| Mixed full packet | 1,405.084 | 753.901 |
| Hot full packet | 567.413 | 211.284 |
| Weighted-trace full packet | 1,636.163 | 505.872 |
| Optioned full packet | 703.985 | 291.758 |

Compile times were 9.643 ms for the main fixture and 7.583 ms for stress.
Semantic and packet mismatch counts were zero. Compared packet-byte totals
matched: mixed 14,750,000; hot 10,054,000; trace 17,219,111; optioned 17,333,324.
Stress record/plan/wire counts each totalled 500,000.

| Historical image shape | Main fixture | Stress fixture |
| --- | ---: | ---: |
| Nodes / edges | 10,013 / 10,012 | 10,002 / 10,001 |
| RRsets / records | 10,013 / 10,033 | 8,003 / 8,003 |
| Hot / cold bytes | 761,144 / 680,154 | 688,184 / 715,614 |
| Bytes per record | 143 | 175 |

These sizes predate selective widening and later RRset changes. The current
capacity reference and live `ZoneImageStats` must be used for new planning.

The later `signed-boundary-packet-coverage.tsv` run on 2026-05-31 added real
signed positive/NODATA DO responses, with four boundary cases, zero mismatches,
packet-byte parity, and a local boundary-packet ratio of 1.004.

### Child-index and composer experiments

The artifact names below are relative to `target/zone-image-bench/`. Ratios
are candidate time divided by the comparison time; lower is better. Each row
is its own experiment, so unrelated rows are not a paired comparison.

| Experiment/artifact | Recorded result | Decision |
| --- | --- | --- |
| `child-byte-bucket-lookup.tsv` | First-byte dispatch 1.543× sorted lookup; open-address hash 0.640×; benchmark HashMap 0.551× | Reject byte buckets |
| `child-length-bucket-lookup.tsv` | 28.868 ns vs sorted 15.740 ns and generated hash 10.226 ns; 40,548 extra index bytes | Reject length buckets |
| `child-last-byte-bucket-lookup.tsv` | 22.049 ns vs sorted 15.559 ns and generated hash 10.005 ns; 42,084 extra index bytes | Reject last-byte buckets |
| `child-compact-generated-hash.tsv` | Half-size slots: 65,536 vs 131,072 bytes; lookup 0.985× sorted vs 0.620× for the larger hash | Retain low-load-factor hash |
| `child-hash-u16-slots-stats.tsv` | Main: 32,768 slots/65,536 bytes; stress: 16,384 slots/32,768 bytes | Retain narrow slots where fanout fits |
| `small-child-linear-lookup.tsv` | Four-child linear lookup 0.541× binary baseline; zero packet mismatches | Retain linear path for 1–4 children |
| `direct-answer-compiled-record-view.tsv` | Hot/mixed packet about 188/549 ns; slower than the then-current copied-body path | Reject that record-view rewrite |
| `rrset-wire-parts-direct-view.tsv` | Hot/mixed packet about 187/559 ns; no packet improvement | Reject that grouping |
| Early synthesized small-buffer experiment | Mixed packet about 870 → 934 ns | Reject that broad variant; later narrowly scoped inline representations were evaluated separately |
| Full direct-response template cache | More retained memory and no local Vec/socket-path packet win | Keep general response caching deferred |
| `combined-plan-wire-summary.tsv`, `packet-combined-wire-summary.tsv` | Correct packets; broader summary made count-only planning heavier and did not beat the direct-count baseline | Reject those combined summaries |

All listed child-index candidates preserved found counts and checksums.
Correctness alone did not justify their memory or timing cost.

### Loopback runtime comparisons

May 2026 runs used the old snapshot-serving toggle. QPS is responses/s; latency
columns are microseconds. All had zero client validation errors. Artifact names
in the old logs used the prefix `target/evidence/zone-image-live-loopback-`.

| Date/profile | Path | QPS | p50 / p99 / p999 | Dropped |
| --- | --- | ---: | --- | ---: |
| May 28, UDP pressure, 8 clients × 64 window | Snapshot | 243,115 | 616.6 / 870.7 / 1,180.5 | 4,111 |
| Same | Image | 248,649 | 544.5 / 1,632.3 / 5,014.8 | 4,110 |
| May 28, UDP latency, 4 × 16 | Snapshot | 295,706 | 194.3 / 290.8 / 410.2 | 0 |
| Same | Image | 296,806 | 191.8 / 283.4 / 350.9 | 0 |
| May 28, pipelined TCP, 4 × 16 | Snapshot | 674,473 | 71.9 / 145.6 / 328.4 | 0 |
| Same | Image | 839,776 | 54.8 / 129.2 / 264.3 | 0 |
| May 28, mixed trace UDP, 4 × 16 | Snapshot | 277,022 | 208.0 / 300.7 / 318.5 | 0 |
| Same | Image | 360,667 | 154.9 / 222.4 / 293.7 | 0 |
| May 28, mixed trace TCP, 4 × 16 | Snapshot | 791,704 | 55.5 / 167.2 / 319.7 | 0 |
| Same | Image | 863,174 | 52.4 / 164.9 / 269.6 | 0 |
| May 29, delegation/DNAME UDP stress, 4 × 16 | Snapshot | 66,042 | 724.8 / 1,939.7 / 81,252.2 | 0 |
| Same | Image | 136,115 | 370.2 / 1,695.8 / 5,203.8 | 0 |

The mixed trace had 1,000 generated A records and 263 query rows. The stress
trace had 128 delegation/DNAME candidates, 1,517 AXFR records, and 392 query
rows. The stress comparison's ratios were 2.061× QPS, 0.511× p50, 0.874× p99,
and 0.064× p999. These were loopback results, not physical-link ceilings.

Follow-up gate artifacts under `target/evidence/` retained these distinct
results:

| Artifact | Result |
| --- | --- |
| `zone-image-evidence-gate-loopback-stress-smoke-final` | 2.395× QPS; p50/p99/p999 ratios 0.411/0.516/0.222 |
| `zone-image-evidence-gate-loopback-stress-metrics-smoke` | 2.153× QPS; latency ratios 0.441/0.441/0.702; 295,243 image serve hits, zero failures |
| `zone-image-evidence-gate-loopback-direct-semantic-smoke` | 1.920× QPS; latency ratios 0.444/0.888/1.977; 776,705 hits (515,175 direct, 261,530 semantic), zero failures |
| `zone-image-live-loopback-count-skip-smoke` | 321,820 QPS; p50/p99/p999 25.5/60.3/110.2 µs |
| `zone-image-live-loopback-opaque-unknown-smoke` | 355,046 QPS; 23.0/50.8/66.6 µs; 1,005 AXFR records and 264 trace queries including type 65280 |
| `zone-image-live-loopback-qname-allocation-smoke` | 188,137 QPS; 38.1/209.7/1,566.8 µs; correctness evidence only because runtime timing was noisy |
| `udp-batch-sweep-current-local` | Batches 1/8/32; batch-8 QPS ratio 1.116 and p50/p99 0.859/0.901; batch-32 QPS 1.101 and p50/p99 0.873/0.897 |

The final four smoke/sweep rows had zero drops and errors; the batch sweep also
reported zero image failures and two rows with measured batching gain.
The direct/semantic gate's worse p999 is retained explicitly: a throughput win
was not a tail-latency win.

The historical local gates passed the tests available at the time. They do not
certify later source revisions. Current release evidence belongs in the dated
reports and verification ledger above.
