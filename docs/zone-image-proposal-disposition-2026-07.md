# ZoneImage Proposal Disposition: Denial Lookup, Memory, And Class Indexes

Decision and measurements: July 18, 2026.

This note preserves the results of the July optimization review. It describes
the tested revision; the [data-plane reference](memory-io-data-plane-design.md)
and [capacity limits](zone-image-capacity-limits.md) describe current code.
The IN-only index representation later changed to counted, sharded maps for
incremental updates, as noted below.

## July decisions

| Proposal | Disposition | Result |
| --- | --- | --- |
| Indexed NSEC/NSEC3 denial lookup | **Accepted and implemented** | Valid closed denial rings use sorted range groups and binary predecessor/exact lookup. Malformed or incomplete groups retain the former linear scan as a correctness fallback. |
| Generic compression of retained names/RDATA/wire | **Rejected** | LZ4/Zstd-style storage would add decode work to query composition without a demonstrated service-level benefit. The measured arenas also do not support the suggested 40-60% process-RSS saving. |
| Owner/RDATA blob interning | **Prototyped and rejected** | It saved 1,037 bytes, or 0.15% of cold image bytes, on the 10k fixture and added build-time hashing. The prototype was removed. |
| Remove DNS class everywhere | **Rejected** | Class remains part of DNS records, keys, proof groups, and pre-encoded wire fixed fields. Removing two bytes does not shrink the measured `RrsetKey`, `Rrset`, or 72-byte `ImageRrset` layouts and would weaken non-IN oracle coverage or add reconstruction work. |
| Compact IN-only name-class indexes | **Alternative implemented** | The July implementation used membership sets instead of a 24-byte `SmallVec` class value per known name, retaining a general map for other classes. This exact representation was later superseded. |
| NSEC proof-path fuzz coverage | **Accepted and implemented** | The ZoneImage differential target now contains valid NSEC and NSEC3 rings in separate zones, while retaining malformed RDATA and offline-oracle comparisons. |

## Denial Lookup Measurement

`zone_image_denial_bench` constructs valid synthetic NSEC and NSEC3 rings and
measures a full NXDOMAIN plan plus DNSSEC augmentation. The profiling build ran
on an AMD Ryzen 9 9950X3D with 200 iterations at 100,000 records:

| Proof type | Former linear scan | Indexed lookup | Speedup |
| --- | ---: | ---: | ---: |
| NSEC | 2,904,594.920 ns/query | 2,872.885 ns/query | 1,011x |
| NSEC3 | 1,057,184.400 ns/query | 1,741.990 ns/query | 607x |

Compilation remained effectively unchanged: NSEC was 141.374 ms before and
139.924 ms after; NSEC3 was 173.001 ms before and 167.102 ms after. Smaller
1k and 10k runs also changed from linear growth to sub-microsecond lookup.

The index is deliberately conditional. A group is binary-searchable only when
owners are unique and sorted and every next-owner/hash points to the following
member, including the wrap. Invalid transfer-derived metadata therefore keeps
the established conservative scan instead of being silently treated as a
valid ring.

Reproduce the focused benchmark with:

```sh
cargo run --profile profiling -p borondns-core \
  --example zone_image_denial_bench -- \
  --records 100000 --iterations 200 --query-cases 64
```

## Memory Measurement

The July 10,000-record prototype fixture reported:

| Arena/layout | Bytes |
| --- | ---: |
| Labels | 78,937 |
| Full owner names and denial keys | 209,190 |
| RDATA | 41,263 |
| Pre-encoded RRset wire | 352,488 |
| Total cold bytes | 682,052 |
| Total hot bytes | 1,548,456 |

Wire is 51.7% of cold bytes but only 15.8% of the 2,230,508-byte image. Even a
free 2:1 reduction of the entire wire arena would therefore save only about
7.9% of this image, before accounting for decode metadata, retained source
snapshots, builder workspace, or old/new generations during reload. Real
registry corpora can differ, which is why the benchmark now emits label, name,
RDATA, and wire bytes separately.

A query-neutral owner/RDATA interner was also measured. It reduced cold bytes
from 682,052 to 681,015: 48 owner bytes and 989 RDATA bytes, just 0.15% total.
The measured compile moved from 7.985 ms to 9.282 ms in those individual runs.
That candidate was removed rather than carrying permanent maps and hashing for
a shape-dependent negligible saving.

Hot-path compression remains rejected. Future memory work may reconsider wire
body representation only with a representative signed registry replay and a
physical-link no-regression gate. Retiring or narrowing the retained
`ZoneSnapshot` after its transfer/catalog/oracle responsibilities are isolated
is more promising than compressing bytes that every response needs.

## IN-Only Class Index Measurement

The production input contract is IN-only, but generic class representation
remains useful in records, wire output, transfer validation, and differential
tests. The July implementation specialized name-existence indexes:

- an all-IN snapshot stored `HashSet<NameKey>` membership;
- a snapshot containing any other class stored the former
  `HashMap<NameKey, SmallVec<[u16; 1]>>`; and
- QCLASS IN/ANY behavior was unchanged, and unusual-class oracle tests retained
  their exact class membership.

At 10,000 records this removed 240,384 bytes of class-value payload from the
retained snapshot indexes. Core layout probes confirm that deleting `class`
from `RrsetKey` or `Rrset` would save zero bytes because of alignment; the
removed per-name `ClassSet` value is 24 bytes. The ZoneImage query path is not
changed. Three 200,000-iteration runs produced mixed-packet timings of 478.034,
464.187, and 455.239 ns/query and hot-packet timings of 206.077, 211.741, and
217.611 ns/query; that spread is treated as benchmark noise, not a query-speed
claim.

The current `NameClassIndex` in
[zone.rs](../crates/borondns-core/src/zone.rs) uses sharded reference counts:
`HashMap<NameKey, u32>` for IN-only data and per-class counts for mixed data.
Counts let incremental deletion distinguish the last RRset at a name from
one of several remaining RRsets. The July 240,384-byte saving therefore
must not be reused as a measurement of the current snapshot layout.

## Validation boundary

The implementation is covered by focused valid-ring, predecessor, wrap,
exact-match, malformed-fallback, class-specialization, and multi-class tests.
The updated `zone_image_datagram` target completed a 2,000-input ASan/libFuzzer
smoke run. Long-running multi-host fuzzing remains release evidence rather than
a prerequisite for this code decision.
