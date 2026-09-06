# Zone and transfer capacity limits

A large image, a large RRset, and a large transfer have different limits.
This reference describes the implementation in September 2026. Encoded
capacity is not a promise that the allocator, persistence format, or host can
hold that much data.

The source owners are [`zone_image.rs`](../crates/borondns-core/src/zone_image.rs),
[`config.rs`](../crates/borondns-core/src/config.rs),
[`transfer.rs`](../crates/borondns-server/src/transfer.rs), and
[`zone_persistence.rs`](../crates/borondns-server/src/zone_persistence.rs).

## Image-wide limits

| Resource | Representation and encoded bound |
| --- | --- |
| Label/name/RDATA/wire arena offset | `u64`; bounded in practice by address space and allocation |
| Stored blob or full RRset wire-range length | `u64`; no 4 GiB range-length ceiling |
| Total record ordinals and relation ordinals | `u64`; vectors and available RAM constrain usable capacity |
| RRset and name-node IDs | `u32`, reserving `u32::MAX`; at most 4,294,967,295 entries |
| Name-trie edge starts/counts | `u32`; at most 4,294,967,295 edges |
| Relation-span, low-RRtype bitmap, and child-hash descriptor IDs | `u32`, reserving `u32::MAX` |
| Narrow/wide child-hash slot arena starts/counts | `u32`; at most 4,294,967,295 slots in each arena |

The builder checks conversions and start-plus-count bounds. IDs never alias
the reserved “none” sentinel: valid compact IDs end at 4,294,967,294.

`NameNode.first_edge`, `edge_count`, and `low_rrtype_bitmap` are `u32`.
They do not impose a zone-wide 65,535-name limit. Child-hash slots are narrow
only when the individual node's fanout fits; larger nodes use `u32` offsets.

The generated child hash uses at least twice the number of children, rounded
to a power of two. With `u32` slot bounds, the largest representable hashed
fanout is therefore `2^30` children, requiring `2^31` slots. This is an
encoding boundary, far beyond a realistic allocation.

## RRset and DNS-format limits

| Resource | Limit |
| --- | ---: |
| RDATA in one record | 65,535 bytes (`u16` RDLENGTH) |
| Records in one RRset | 4,294,967,295 (`u32` record count), subject to memory and ingestion limits |
| RRsets attached to one image node | 65,535 (`u16`) |
| Precomputed relations for one RRset | 65,535; local relation positions end at 65,534 |
| Distinct NSEC3 parameter sets | 65,536 (`u16` IDs 0–65,535) |
| Prebuilt direct-answer body | At most 4,294,967,294 bytes; `u32::MAX` is a fallback sentinel |
| DNS label | 63 bytes |
| Uncompressed wire name | 255 bytes including label lengths and root |
| Records counted by one DNS section header | 65,535 |
| Classic DNS-over-TCP message | 65,535 bytes, excluding the two-byte frame length |

The stored RRset and the DNS response are separate objects. An RRset may have
more than 65,535 records even though one response cannot carry them all.
Response sizing and truncation still apply. The image's `ownerless_wire_len`
is a saturating `u32` sizing hint, not a limit on the stored wire range.

The direct-answer body is only a fast-path representation. Singleton RRsets
and RRsets above the section-count limit use record views instead. It does not
change the `u32` RRset membership limit.

## Transfer admission

| Configuration under `[limits]` | Default | Meaning |
| --- | ---: | --- |
| `max_transfer_ingest_bytes` | 4 GiB | Wire-byte bound for each AXFR/IXFR session |
| `max_transfer_ingest_messages` | 4,096 | Independent DNS-message bound per session; configuration maximum 1,048,576 |
| `max_transfer_resident_bytes` | 64 GiB | Global reservation envelope for concurrent transfer work |

All three are independent. Raising the byte allowance does not raise the
message allowance. The two per-session limits have environment overrides:
`BORONDNS_LIMITS_MAX_TRANSFER_INGEST_BYTES` and
`BORONDNS_LIMITS_MAX_TRANSFER_INGEST_MESSAGES`. Set the resident envelope in
TOML; it has no environment override.

Each retained wire byte reserves 256 bytes of the resident envelope. This is
a conservative admission estimate for compressed-name expansion, decoded
records, indexes, build workspace, and generation overlap. It is not a live
measurement of actual process memory and does not account for every unrelated
allocation.

## Persistence limits

The full last-good checkpoint independently rejects more than
4,294,967,295 records across the entire zone (`MAX_RECORDS = u32::MAX`).
An image with wider global ordinals does not remove this current checkpoint
limit. Durable publication must fit both representations.

The server derives its maximum checkpoint file size as
`max_transfer_ingest_bytes × 128`, with saturating arithmetic, to allow for
uncompressed names. This is a file-size guard, not preallocated disk space.
The incremental journal is limited to 1,024 entries and the lesser of 64 MiB
or that file-size bound. Reaching a journal limit causes a full checkpoint;
it does not permit unbounded journal growth.

## Memory planning

Steady image size understates peak load and reload memory. Include the current
source snapshot, builder maps and sorting workspace, a new image, and old
generations held by readers. IXFR overlays share unchanged snapshot shards but
can retain a compact base snapshot and newer changed shards; compaction again
needs a complete image build.

Rust's global allocator does not generally turn exhaustion into a recoverable
zone-build error. Leave headroom between transfer admission and the service
cgroup limit. Large tests should record cgroup pressure/OOM events as well as
RSS; a process that was contained by the cgroup has not necessarily passed its
capacity target.

The July synthetic projection of 161 million names, 644 million RRsets, and
4.83 billion records estimated about 646.7 GB for the selectively widened
image. It fits the image's compact node/RRset ID space, but exceeds the current
full-checkpoint record limit. It was a measured-shape projection, not a load
test or a claim about the real `.com` corpus. See the
[dated layout measurements](zone-image-large-zone-design.md) and
[two-host capacity campaign](boron-gen-two-host-campaign-2026-07.md).

Use a 64-bit build for large deployments. A 32-bit process cannot exploit
`u64` arena offsets when the backing vectors must fit its address space.
