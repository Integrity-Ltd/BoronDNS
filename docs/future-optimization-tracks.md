# Further performance work

This document separates implemented mechanisms from ideas that still need a
workload, measurements, and a design review. A named experiment is not a release
requirement. The [data-plane reference](memory-io-data-plane-design.md) describes
current code; [implementation status](zone-image-implementation-status.md)
links its evidence.

## Implemented foundations

BoronDNS already has a compact immutable `ZoneImage`, pre-encoded RRset wire,
indexed denial lookup, structurally shared IXFR snapshots, dependency-checked
overlays, and background compaction. These are no longer future packed-store
proposals.

Standard UDP supports batching, reuseport workers, and optional dedicated
threads/affinity. An AF_XDP server adapter is implemented and included in
official binaries, but standard sockets remain the default. BoronGun's own
AF_XDP backend is test-tool scope only; its performance does not establish
server-side performance.

## AF_XDP deployment and trust

Selecting AF_XDP requires explicit configuration, a compatible Linux/NIC
environment, and the separately built BoronDNS redirect object. The adapter
uses Aya; the userspace library choice is no longer open. Physical-link
measurements exist in the [Knot comparison](knot-comparison-benchmark.md).

The redirect object is trusted deployment material. The loader rejects
symlinks, unsuitable file types, untrusted ownership, group/world-writable
files, multiple hard links, and objects outside its size bounds. These checks
do not cryptographically prove that the object came from project source.
Release/deployment procedures must supply the intended project artifact;
arbitrary operator-written eBPF extensions remain outside the product contract.

Further AF_XDP work should address a measured bottleneck or an unsupported
deployment requirement. Keep DNS parsing, lookup, and composition in userspace
behind the adapter. Any change must preserve packet bounds, checksums,
fragment/path-MTU handling, UMEM ownership, wakeups, cancellation, overload,
and attach/detach behavior. Test low-rate traffic as well as saturation.

First-party unsafe code and unsafe-prone dependencies must remain confined
to registered adapters. The
[architecture](architecture.md#unsafe-and-dependency-boundaries) and boundary
registries define the source-level review requirements.

## Storage and ownership

Keep the zone store behind a documented lookup/publish boundary. Existing
packed arrays and RRset shards do not authorize mutable edits to a live image
or a change to DNS semantics.

The useful open questions are narrower than “replace the zone store”:

- Can retained source/image duplication be reduced while preserving cheap
  IXFR and recovery?
- Does a representative registry corpus benefit from a different child index,
  wire-body representation, or memory placement?
- Can dirty overlay queries approach compact-path QPS without making small
  compact zones slower?

The [snapshot memory note](zone-snapshot-narrowing-design.md) defines the first
investigation. Canonical-range image sharding, generic hot-path compression,
and several child-bucket layouts were measured and rejected for their tested
profiles; see the [large-zone decision](zone-image-large-zone-design.md) and
[July proposal disposition](zone-image-proposal-disposition-2026-07.md).
Revisit them only with evidence that the workload or tradeoff changed.

## Complete-response caching

The existing direct-answer bodies are immutable RRset data, not a general
cache of complete DNS packets. A full response cache remains unimplemented.

Consider one only if profiles show composition dominates the target workload
and a substantial fraction of requests can reuse a correctly keyed response.
The key and eligibility rules must cover every response-affecting input,
including class, query type, EDNS, DNSSEC, and client-dependent options.
Key cached responses on the DO-bit value so signed and unsigned response shapes
cannot share an entry.

Publication/removal must invalidate old generations. Any time-sensitive cache
must respect its TTL and signature-expiry policy, preserve truncation and
transport behavior, and bypass cases it cannot safely represent. Verify
cached/uncached packet parity and bounded memory under changing queries and
frequent IXFR. Such a cache would still be authoritative-only; it would not add
recursion or an upstream-sourced cache.

## Other experiments

| Idea | Evidence that would justify prototyping |
| --- | --- |
| io_uring packet I/O | Standard socket syscalls or buffer handoffs dominate matched service profiles |
| Software prefetch or another child index | Cache-miss stalls dominate lookup on a representative large shape |
| Huge-page management | TLB pressure accounts for a measurable part of the cost |
| NUMA-local or replicated images | Cross-node memory access limits throughput on a suitable multi-socket host |
| Custom epoch reclamation | `ArcSwap`/reference-count traffic is a demonstrated many-worker bottleneck |

None of these is a current configurable BoronDNS backend or a mandatory next
step. A prototype must include its memory cost and failure behavior, not just a
lookup timing.

## Evidence required for a change

Use the same corpus, compiler, host, affinity, offered load, and query trace for
baseline and candidate. Record image/peak memory, compile/update latency, QPS,
packet loss, tail latency, and correctness. Alternate repeated runs to expose
warm-up and host noise.

An isolated speedup is useful for diagnosis. Promotion needs a service-level
benefit in the target profile, an explicit account of regressions, and a
small-zone control. Retain the decision and dated result; do not append every
intermediate timing run to the current design reference.
