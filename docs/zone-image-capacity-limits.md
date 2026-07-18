# BoronDNS ZoneImage Capacity Limits

Status: normative implementation limits for the current immutable zone image,
2026-07-18.

This document distinguishes encoded limits from deployment limits. `u64`
removes the former 4 GiB global-arena and 4.29-billion-record ceilings, but it
does not make memory or transfer ingestion unlimited.

## Global Capacity

| Resource | Representation | Encoded limit | Effective limit |
|---|---|---:|---|
| Offset in each label/name/RDATA/wire arena | `u64` | `u64::MAX` | Platform address space, Rust `Vec` capacity, allocator, and available RAM |
| Total records in one zone image | `u64` ordinal | `u64::MAX` | Platform `usize`, `Vec<ImageRecord>` capacity, and RAM |
| Total precomputed RRset relations | `u64` ordinal | `u64::MAX` | Platform `usize`, vector capacity, and RAM |
| RRsets | compact `u32` ID with `u32::MAX` reserved | 4,294,967,295 RRsets | RAM; valid IDs are 0 through 4,294,967,294 |
| Name-trie nodes | compact `u32` ID with `u32::MAX` reserved | 4,294,967,295 nodes | RAM; includes empty non-terminals and the origin node |
| Name-trie edges | `u32` start/count | 4,294,967,295 edges | RAM |
| Relation-span descriptors | compact `u32` ID with sentinel reserved | 4,294,967,295 spans | At most one populated span per RRset |
| Node low-RRtype bitmaps | compact `u32` ID with sentinel reserved | 4,294,967,295 bitmaps | At most one per qualifying node |
| Child-hash descriptors | compact `u32` ID with sentinel reserved | 4,294,967,295 hashes | At most one per indexed node |
| Narrow or wide child-hash slot arena | `u32` start/count | 4,294,967,295 slots per arena | RAM |

The builder uses checked conversions and reserves every `u32::MAX` “none”
sentinel. Crossing one of these compact limits returns `ZoneImageBuildError`
instead of wrapping or aliasing a valid object.

### 16-bit audit cross-check

The July 2026 capacity audit's two shape-dependent findings are covered by the
global table above:

- F-01: `NameNode.first_edge` and `NameNode.edge_count` are `u32`, with a
  checked start-plus-count bound. Child-hash descriptors and slot-arena starts
  are also `u32`. Per-node hash slots retain `u16` edge offsets only while the
  fanout fits; larger sibling sets select the `u32` slot arena.
- F-02: `NameNode.low_rrtype_bitmap` is a `u32` bitmap-table handle with
  `u32::MAX` reserved for “none”. It does not cap multi-RRset owner names at
  65,535 across a zone.

Consequently, the 161-million-name projection is not restricted to
single-RRset shapes by either finding. The remaining 65,535 RRset limit is
local to one owner name, as listed below; it is not a zone-wide count of owners
that carry multiple RRset types.

## Local And DNS-Format Limits

| Resource | Exact limit | Reason |
|---|---:|---|
| RDATA in one record | 65,535 bytes | DNS RDLENGTH is `u16` |
| Records in one RRset | 65,535 | `ImageRrset.record_count` is `u16` |
| RRsets attached to one owner | 65,535 | `NameNode.rrset_count` is `u16` |
| Precomputed relations for one RRset | 65,535 | Relation count and local offsets are `u16`; `u16::MAX` is reserved as a missing-kind offset, so valid relation positions end at 65,534 |
| Distinct NSEC3 parameter sets in one image | 65,536 | Parameter-set IDs use all `u16` values 0 through 65,535 |
| One stored blob or RRset wire range | 4,294,967,295 bytes | Range length is `u32`; its global starting offset is `u64` |
| Prebuilt direct-answer body | 4,294,967,294 bytes | `u32::MAX` is the direct-body fallback sentinel |
| DNS label | 63 bytes | DNS wire format |
| Uncompressed domain name | 255 bytes including length octets and root | DNS wire format |
| Labels in a valid name | 127 maximum | Follows from the 255-byte name and non-empty labels |
| Records represented in one DNS section header | 65,535 | DNS ANCOUNT/NSCOUNT/ARCOUNT fields are `u16`; normal response size limits are reached first |

A child hash maintains at most a 0.5 load factor and rounds its slot count to a
power of two. Consequently, the exact representable fanout for one hashed node
is at most 1,073,741,824 children (`2^30`), requiring `2^31` wide slots. This is
far beyond a physically realistic allocation but is still checked.

## Transfer And Reload Limits

`[limits].max_transfer_ingest_bytes` is a per-AXFR/IXFR-session protocol guard,
not a ZoneImage offset limit. It is a `u64`, defaults to 4,294,967,296 bytes
(4 GiB), and must be raised explicitly for larger transfers. The equivalent
environment override is `BORONDNS_LIMITS_MAX_TRANSFER_INGEST_BYTES`.

The usable zone size is bounded by peak reload memory, not merely the final
image size. Capacity planning must include:

1. the decoded source `ZoneSnapshot`;
2. `ZoneImageBuilder` maps, vectors, sorting, and relation workspace;
3. the newly compiled immutable `ZoneImage`; and
4. any previous published generation still held by in-flight queries.

Allocation failure is not converted into a recoverable zone-build error by the
Rust global allocator. Operators must therefore configure transfer limits and
host memory so an accepted zone cannot drive the process into allocator abort
or system OOM handling.

## Deployment Interpretation

On a 64-bit target, the selective layout supports root, TLD, enterprise,
reverse, DNSSEC-heavy, and unusually dense zones without the former global
`u32` arena/record constraint, provided the zone stays within the compact table
above and the machine can hold the reload working set.

The retained 161-million-name stress projection contains 644 million RRsets and
4.83 billion records. It fits the compact RRset/node limits and requires `u64`
record ordinals and arena offsets. Its measured-shape memory projection is
approximately 646.7 GB after selective widening; that number is a synthetic
capacity bound, not a claim about the real `.com` corpus.

For zones whose image or transfer can exceed 4 GiB, deploy a 64-bit BoronDNS
build. A 32-bit process cannot exploit the `u64` encoded range because all
arenas and record tables are backed by address-space-sized Rust vectors.
