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
| `ZoneDirectory` | Origin and suffix indexes, each divided into 256 copy-on-write map shards by default. |
| `PublishedZone` / `PublishedZoneRef` | Owned or borrowed access to one published entry during query work. |
| `TransferZoneSnapshot` / `CatalogZoneView` / `ZoneMetadata` | Restricted views for transfer, catalog, and control work. |

`ZoneStore` publishes directories through `ArcSwap`. Writers serialize the
final replacement with `publish_lock`; readers do not take that lock. A
directory update clones affected map shards rather than every zone entry.

The off-by-default `experimental-directory-shards` feature uses 4,096 maps per
index, grouped under 64 copy-on-write owners. It reduces unrelated keys copied
on publication, at the cost of an extra pointer lookup for indexed queries.
See the [measured tradeoff](gx10-knot-multi-zone-2026-09.md#smaller-publication-shards);
this is not the released/default layout.

Directories with at most four entries use a small most-specific-first lookup.
Larger directories skip suffix hash probes for key lengths that are absent
from a publication-local bitmap. Removal can leave conservative bits set; that
only permits extra probes and never hides a matching parent or child zone.

Transfer and restoration preparation compile replacements outside the publication lock.
The final commit checks that it still replaces the entry seen during
preparation. An obsolete candidate is discarded before its durable commit
callback runs. Direct restoration re-prepares if its prior entry changes while
compiling, preserving the current lifecycle and visibility. Catalog reconciliation can publish a coordinated directory
change through the same store.

This design uses safe reference-counted ownership. There is no custom epoch
reclamation layer.

## Compact image layout

The compiler and lookup planner live in
[`zone_image.rs`](../crates/borondns-core/src/zone_image.rs).
The image has separate arrays for name nodes, child edges, RRsets, records,
relationships, and denial indexes. Each 16-byte child edge stores labels up to
eight bytes inline; longer labels use a byte arena. Other arenas hold full
names, RDATA and pre-encoded RRset wire. `ZoneImageStats.label_bytes` counts only
the separate label arena; inline labels are already included in edge storage
under `hot_bytes`.

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

### Experimental fused-answer storage

The off-by-default `experimental-fused-serving` feature adds a publication-built
exact-answer index for eligible leaf authorities. Full canonical keys, keyed
hashing and immutable directory ownership protect the lookup; configured
descendants, expired/hidden zones and dirty overlays prevent unsafe shortcuts.
The ordinary resolver handles unsupported answers. This is not a response cache.

`experimental-dense-answers`, also off by default, changes only that index's
answer storage. Bodies up to 64 bytes remain inline; 65–128-byte bodies use
shared immutable storage. Answers beyond 128 bytes retain the existing fallback.
This reduces the key/value size bound from 216 to 160 bytes without narrowing
eligibility. It does not guarantee cache-line alignment or an equivalent drop
in total process memory. Longer bodies gain an extra pointer read and reference
counting when a shard is cloned, so their query and publication costs must be
measured before enabling the feature. Single-record RRsets use the existing
records path rather than these fused templates.

The initial [100k-zone comparison](gx10-knot-multi-zone-2026-09.md) reduced
cycles/query by 1.52%, short of its 5% advancement threshold. It did not establish
longer-answer, publication-cost or capacity acceptance; the feature stays off.

`experimental-direct-buckets` is a separate off-by-default lookup experiment.
Each shard uses a power-of-two, at-most-half-full slot vector with four probes
and an exact overflow map. First-candidate digest reads are staged across the
query batch before full-key resolution. Removal leaves holes, but lookup never
stops at a hole. Keyed hashing, full-key comparison, publication ownership and
answer eligibility are unchanged. More empty slots trade memory for fewer
dependent reads. Its first 100k-zone comparison reduced cycles/query by 2.09%
while increasing anonymous memory by 3.22%, also missing the 5% advancement
threshold. It is not a promoted replacement for the standard map.

`experimental-query-preparation` leaves the index unchanged. An all-hit batch
retains its pinned directory and answer descriptors without building fallback
selection/index vectors. Custom-provider and response-size fallback still use
that pinned directory. The UDP handler can also reuse a completed parse of the
exact packet to prove that an ordinary query has no TSIG: only zero additional
records or one validated OPT record qualify. Partial/error results, other
additional records, signed packets and NOTIFY retain normal processing. This
proof establishes absence of TSIG, never authentication or a policy exemption;
cookies, RRL, metrics and response rules still apply. The feature is off by default.

`experimental-static-redirect` supplies immutable listener settings to the
eBPF loader, allowing the kernel to remove unreachable redirect paths. It is
off by default in both the server and standalone eBPF crate. Old objects and
old loaders keep the mutable configuration-map path. Privileged, wire-free
packet fixtures verify both compatibility directions and frozen-map independence;
the smaller generated code did not pass the 24M service-QPS advancement gate.
The feature remains disabled. See the
[current GX10 investigation](gx10-knot-multi-zone-2026-09.md).

`experimental-xdp-conditional-wakeup` is a separate, off-by-default transport
prototype. It maps only the kernel's TX/FILL header flags through the public
AF_XDP ABI, with bounded/aligned offsets, read-only mappings and ordered
volatile flag reads. The xdp crate retains all descriptor and UMEM ownership.
Fresh TX publication uses the flag to decide whether to wake the driver; FILL
also rechecks after zero admission to avoid stranding already published buffers.
Previous failed wakes still force explicit bounded recovery. Unsupported flag
layouts fail adapter initialization instead of silently omitting wakeups.
The prototype reduces TX syscalls but has not established reliable 24M QPS in
the GX10 comparison; it is not a promoted default or a replacement for stall,
error and shutdown handling.

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
publication lock. Final admission rechecks the exact entry and the transferred
SOA: routine refreshes must advance the current serial under RFC 1982, even if
the earlier SOA probe advertised a different serial. Bootstrap accepts serial
zero; the explicit restoration API is separate from routine refresh admission.

Promotion renames the staged file and cleans up superseded sidecars under the
current-plan, current-secret, and zone-publication guards, then publishes the
already-prepared memory entry. Refresh workers acknowledge the new snapshot's
freshness before awaiting directory synchronization or overlay compaction, so a
slow or cancelled maintenance task cannot leave the old expiry deadline attached
to the new serial. Directory synchronization runs on a blocking worker after
publication guards are released. A rename failure leaves memory unchanged.
After a successful rename, cleanup or sync errors cannot mean "nothing changed":
the new zone remains published and a `zone_cache_published_durability_warning`
reports incomplete cleanup or uncertain crash durability. No destructive rollback
is attempted. After a crash before directory sync, cache recovery can find an old
or new generation, or no usable cache; checksums and journal binding reject torn
or incompatible data. A missing or rejected cache requires a fresh transfer.

DNS readers continue to use immutable state without taking publication locks.
Directory-sync delays no longer hold the global publication guards. Rename and
sidecar unlink calls remain inside them and can still delay other control-plane
operations; this is not a hard publication-latency guarantee. Cleanup cannot move
outside these guards without additional coordination with the next journal.

The journal is capped at 1,024 entries and 64 MiB, or the configured cache-file
bound if lower. Exceeding a journal bound, missing compatible lineage, or a
base mismatch falls back to a full checkpoint. Appending a delta rewrites the
bounded journal, not the full zone.

Restore checks file bounds, checksums, structure, serial continuity, and zone
validity. A journal with a valid checksum and format but a different base
checksum is stale and ignored: this covers a crash after checkpoint rename but
before old-journal removal. A corrupt journal is rejected. Checksums detect
corruption; protected filesystem ownership and permissions establish trust.

Catalog-member caches additionally use persisted lifecycle tokens, bound to the
catalog, member node and effective transfer policy. Revocation rotates the token
before a catalog removal/reset can commit. Old in-flight transfers retain their
old namespace, so a failed unlink or late write cannot restore revoked data into
a new member lifecycle. Failed revocation rejects catalog preparation; a later
aborted catalog update can conservatively require a cold member transfer after
restart. A normal same-lifecycle restart retains its cache eligibility.

Upgrading from caches without this binding requires one cold transfer for catalog
members; static-zone caches keep their existing format and paths. Preserve
`.lifecycle` files when backing up state. Revoked cache files remain recoverable,
but automatic orphan cleanup is not implemented. Older binaries do not enforce
these tokens and can read preserved legacy caches: downgrade only with a reviewed
or clean member-cache state. A remove/re-add performed entirely while BoronDNS
is offline, leaving the same final member identity, cannot be distinguished from
an unchanged catalog snapshot.

### Experimental freshness group commit

The off-by-default `experimental-freshness-batching` feature changes only the
durable freshness evidence for unchanged, authenticated SOA confirmations.
The default still writes a per-zone `.fresh` file. The experiment uses one
writer per cache handle family, a 256-request queue with asynchronous
backpressure, and batches of at most 256 records. The writer waits 2 ms to
collect a batch, checks each zone's cache lineage, then appends and synchronizes
one checksummed batch. It acknowledges successful requests only after sync.
The existing current-plan, secret and snapshot checks still run after that wait.
This does not batch or relax AXFR/IXFR content publication.

[`freshness_batch.rs`](../crates/borondns-server/src/zone_persistence/freshness_batch.rs)
binds each observation to the existing cache namespace, serial and exact active
checkpoint/journal checksum. The observation time is captured before queuing,
not when disk work eventually completes. Recovery ignores an incomplete final
batch; a complete corrupt batch rejects the freshness journal. Either case
can conservatively shorten restart freshness, never synthesize a newer proof.
The legacy `.fresh` files remain readable. Builds without the feature ignore
the new journal and can therefore expire a cached zone earlier on downgrade.

The journal has a 512 MiB byte limit and a two-million-identity limit. Atomic
compaction retains the latest proof per identity, using bounded write buffers.
Retired identities are not garbage-collected in this prototype: hitting the
identity cap rejects new proofs rather than growing without bound. A disk/sync
failure poisons the writer until restart; an exclusive filesystem lock prevents
competing writers, and symlink/non-regular/multiply-linked files are rejected.
Shutdown drains accepted requests and joins the writer; disk stalls can delay
shutdown. These are experimental limits, not a new supported cache format or
a measured QPS improvement. Active-refresh A/B measurements and lifecycle
reclamation are required before considering default enablement.

### Experimental scheduled-refresh admission

By default, the one-second scheduler admits at most the available capacity of
the 1,024-slot external refresh channel on each tick. That can limit admission
to 1,024 zones/second even when transfer workers could finish more work.

The off-by-default `experimental-refresh-pull` feature moves scheduled admission
into the transfer dispatcher. When the external queue is empty and there is no
ready internal request, it pulls up to 64 due zones into available resident-task
and pending-queue slots. Follow-ups blocked on an already-running zone do not
prevent unrelated due zones from using free slots. A
completion can therefore admit more work immediately. A one-second pulse still
discovers newly due work in an otherwise idle dispatcher; expiry and loading
warnings remain in the separate periodic task. This does not increase channel,
resident-task or network-transfer limits, or mark the entire due population
in progress. Queued NOTIFY, catalog and operator requests take precedence.

This prototype removes an admission-rate ceiling, not the cost of doing the
additional transfers. It can raise background CPU/I/O demand, so QPS must be
measured together with achieved refresh cadence. Sustained external-request
traffic can still postpone scheduled work; this is not a hard deadline or
fair-service guarantee under overload. The feature is not enabled by default.

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
