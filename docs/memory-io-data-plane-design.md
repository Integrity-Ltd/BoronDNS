# Query data plane and packet I/O

BoronDNS separates transfer processing from query serving. Transfers build a
validated `ZoneSnapshot`; ordinary queries read a compact, immutable
`ZoneImage`. Large IXFR updates can publish a new snapshot over an existing
image so that a small change does not force an immediate whole-zone rebuild.

This is the current design, checked against the implementation in September
2026. For supported DNS behavior, use the [SRS](BoronDNS-Secondary-SRS-v1.0.0.md).
For measurements and remaining work, use the
[implementation status](zone-image-implementation-status.md).

## From transfer to response

```text
AXFR / IXFR
    │ parse, validate, apply changes
    ▼
ZoneSnapshot ────── full compile ─────► ZoneImage
    │                                     │
    └── current snapshot + compact base ───┘
                         │
             prepare complete zone entry
                         │
             durable commit, then publish
                         ▼
             ArcSwap<ZoneDirectory>
                         │
              select authoritative zone
                         ▼
        direct answer / semantic plan / overlay lookup
                         │
              response composer in dns.rs
                         ▼
             UDP or TCP transport adapter
```

A published entry owns the snapshot, image, lifecycle metadata, and any overlay
dependency state for one generation. A reader keeps that entry alive while
answering; a writer cannot replace part of it underneath the reader.

## Ownership and publication

The implementation lives in
[`zone.rs`](../crates/borondns-core/src/zone.rs).

| Type | Responsibility |
| --- | --- |
| `ZoneSnapshot` | Canonical RRsets, IXFR lineage, name/class indexes, denial-order indexes, and cached shape metadata. Also supplies the semantic lookup used by dirty overlay queries. |
| `ZoneImage` | Immutable lookup arrays, pre-encoded wire, and compiled relationships for a compact generation. |
| `ZoneStoreEntry` | Keeps the current snapshot, compact base, overlay state, and lifecycle metadata together. |
| `ZoneDirectory` | Origin and suffix indexes, each divided into 256 copy-on-write map shards. |
| `PublishedZone` / `PublishedZoneRef` | Owned or borrowed access to one published entry during query work. |
| `TransferZoneSnapshot` / `CatalogZoneView` / `ZoneMetadata` | Restricted views for transfer, catalog, and control work. |

`ZoneStore` publishes directories through `ArcSwap`. Writers serialize the
final replacement with `publish_lock`; readers do not take that lock. A
directory update clones affected map shards rather than every zone entry.

Transfer preparation compiles the replacement outside the publication lock.
The final commit checks that it still replaces the entry seen during
preparation. An obsolete candidate is discarded before its durable commit
callback runs. Catalog reconciliation can publish a coordinated directory
change through the same store.

This design uses safe reference-counted ownership. There is no custom epoch
reclamation layer.

## Compact image layout

The compiler and lookup planner live in
[`zone_image.rs`](../crates/borondns-core/src/zone_image.rs).
The image has separate arrays for name nodes, child edges, RRsets, records,
relationships, and denial indexes. Byte arenas hold labels, full names, RDATA,
and pre-encoded RRset wire.

Arena offsets and `BlobRange` lengths are `u64`. Node and RRset handles remain
`u32`; an RRset's record count is also `u32`. Individual RDATA lengths remain
`u16`. These are distinct limits: a DNS message's 16-bit section counts do not
limit the records stored in a zone or RRset. Checked construction rejects
unrepresentable tables. See the [capacity reference](zone-image-capacity-limits.md)
for exact limits, including the separate persistence ceiling.

The name index is a canonical lowercase label trie. It retains parent and
depth information and nearest IN-class delegation/DNAME metadata. This lets
lookup follow DNS label boundaries for delegation, closest-encloser, wildcard,
and DNAME behavior.

Child selection depends on fanout:

| Children at a node | Current lookup |
| --- | --- |
| 0 | Immediate miss |
| 1–4 | Linear label comparison |
| 5–1,023 | Binary search over sorted edges |
| 1,024 or more | Generated open-address hash, with at most 0.5 load factor |

Hash slots store per-node edge offsets. They use `u16` while fanout fits and a
separate `u32` arena above 65,535 children. Small nodes do not pay for a hash
table. Owner-local low-RRtype bitmaps accelerate missing-type checks at owners
with several RRsets; a zone-level bitmap provides an earlier common-type check.

RRset relationships precompute additional addresses, referral glue, covered
RRSIG records, single-name targets, and delegation DS/NSEC associations.
They are grouped into contiguous spans. Lookup consumes handles and bounded
views rather than rebuilding those relationships for each packet.

## Response composition

[`dns.rs`](../crates/borondns-core/src/dns.rs) owns request parsing and response
assembly. Compact serving has two main paths:

- Eligible direct positive answers copy pre-encoded RRset data, with a guarded
  prebuilt-body fast path where its shape permits.
- Semantic plans carry answer, authority, and additional handles, selected
  records, and any synthesized data needed for CNAME/DNAME, wildcard, referral,
  or negative answers.

The composer accounts for wire size, compression, EDNS, DNSSEC, and truncation.
The query ID and request-dependent fields remain per-response data. Prebuilt
RRset bodies are not a general cache of complete DNS responses.

The common path avoids cloning whole RRsets and RDATA. Small vectors keep
common plans inline, and reusable transport buffers reduce allocation. This is
not a universal zero-allocation guarantee: long indirection chains, large
plans, synthesized data, and dirty overlay responses can allocate.

There is no configurable rollback to the historical snapshot-only server.
`offline_oracle()` still supports differential tests and benchmarks. Separately,
the current incremental overlay deliberately uses snapshot lookup for responses
that cannot safely reuse the compact base.

## DNSSEC denial lookup

The image stores NSEC owner/next keys and decoded NSEC3 owner/next hashes in
ordered groups. Valid closed groups use binary exact/predecessor lookup.
Groups that are not indexable retain a conservative scan; indexability alone
does not establish that every requested denial proof is valid.

NSEC3 parameter selection and broken-chain state are compiled once. The planner
still checks the requested proof and configured iteration cap. Per-query hash
reuse avoids hashing the same name and parameter set repeatedly. Wildcard
denial context follows the effective lookup name, including indirection, rather
than assuming it is always the original QNAME.

Snapshot overlays keep persistent denial-order indexes so a small IXFR can
update the affected order paths. Their query path validates current proof
selection before serving it. See [operator guide](operator-deployment-guide.md) for
operator-facing behavior.

## Large-zone IXFR

The server's `[zone_publication]` defaults are defined in
[`config.rs`](../crates/borondns-core/src/config.rs):

```toml
[zone_publication]
strategy = "auto"
sharded_rrset_threshold = 1000000
overlay_compaction_dirty_owner_threshold = 100000
```

| Strategy | Behavior |
| --- | --- |
| `compact` | Build a new compact image for each publication. |
| `sharded` | Reuse a compact base for eligible descended IXFR snapshots, regardless of the size threshold. |
| `auto` | Use the overlay path for eligible IXFR snapshots at or above the RRset threshold; compile smaller zones. |

AXFR, missing lineage, and other ineligible replacements still need a full
compile. The core library's bare `ZoneStore` default is `compact`; the running
server explicitly supplies the configuration policy above.

IXFR changes become RRset replacements or tombstones. Snapshot maps share
unchanged shards; name counts, shape counters, and denial indexes update
incrementally. Overlay metadata tracks changed owners and RRset dependencies.
An unchanged direct answer or semantic plan can reuse the compact image only
when all relevant dependencies remain valid. Other queries use the current
snapshot.

Background compaction builds a fresh image outside the publication lock, then
rebases IXFR changes that arrived while it compiled. Incarnation and lineage
checks prevent an old build from replacing a removed/re-added or unrelated
zone. One invocation attempts at most two passes. A dirty-owner threshold of
zero disables automatic compaction.

Small updates are therefore much cheaper than whole-zone rebuilds, but not
constant-time. Cost still includes changed shards, changed RRset sizes, retained
journal size, and storage latency. Dirty-query traffic and background compiles
can reduce QPS. The [IXFR measurements](ixfr-scaling-2026-08.md) separate those
costs and include small-zone controls.

## Durable publication

[`zone_persistence.rs`](../crates/borondns-server/src/zone_persistence.rs) stores
a checksummed full checkpoint plus a bounded journal of RRset changes.
Checkpoint and journal staging write and fsync temporary files before the final
publication lock. Promotion renames the staged file and syncs the directory
before the new entry becomes visible. The rename and directory fsync still
occur inside that final commit.

The journal is capped at 1,024 entries and 64 MiB, or the configured cache-file
bound if lower. Exceeding a journal bound, missing compatible lineage, or a
base mismatch falls back to a full checkpoint. Appending a delta rewrites the
bounded journal, not the full zone.

Restore checks file bounds, checksums, structure, serial continuity, and zone
validity. A journal with a valid checksum and format but a different base
checksum is stale and ignored: this covers a crash after checkpoint rename but
before old-journal removal. A corrupt journal is rejected. Checksums detect
corruption; protected filesystem ownership and permissions establish trust.

## Packet I/O

The default UDP backend uses standard sockets. It supports Tokio workers or a
dedicated runtime, `SO_REUSEPORT`, optional CPU pinning, and Linux
`recvmmsg`/`sendmmsg` batching. Default batch size and reuseport worker count
are both 1; benchmark-specific settings are not universal deployment defaults.
TCP retains the kernel stack and bounded connection/pipeline handling.

Official release binaries include the optional AF_XDP adapter. Selecting
`udp_backend = "af_xdp"` requires explicit configuration, a separately built
project redirect object, and a compatible Linux/NIC setup. Aya loads the
validated object; parsing and DNS response decisions stay in userspace.
The AF_XDP path has physical-link evidence, but that does not make it the default
backend or prove a win for every host. See the
[operator guide](operator-deployment-guide.md) and
[benchmark comparison](knot-comparison-benchmark.md).

io_uring, general response caches, custom reclamation, huge-page management,
and NUMA image replication are not implemented runtime backends. Their entry
conditions are in [future optimization tracks](future-optimization-tracks.md).

## Testing and tuning

Correctness checks cover direct and semantic responses, DNSSEC, unknown RDATA,
indirection, EDNS, truncation, publication races, IXFR, and recovery. The
`zone_image_datagram` fuzz target compares generated packet paths against the
offline oracle. `audit-invariants.sh` checks key source boundaries.

Use the `zone_image_bench`, `zone_image_capacity_bench`, and
`zone_image_denial_bench` examples for focused measurements. For service QPS,
use the [benchmark guide](dns-client-benchmark.md) with a separate client and
recorded physical-link settings. Keep host, compiler, affinity, query trace,
offered rate, losses, and latency comparable. A lookup-only speedup does not
establish an end-to-end QPS gain.
