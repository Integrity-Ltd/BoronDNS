# Memory And Packet I/O Data Plane Design

Status: data-plane optimization design with a default-enabled local `ZoneImage`
implementation for supported query shapes. Implementation progress and
remaining retirement work are tracked in
`docs/zone-image-implementation-status.md`.

Owner: this document owns implementation planning for a future cache-local
authoritative query data plane. Normative DNS behavior remains owned by
`docs/OxideDNS-Secondary-SRS-v0.9.1.md`; the current deferred-track boundary
remains owned by `docs/future-optimization-tracks.md`; release evidence remains
owned by the verification ledger and release evidence documents.

## Purpose

The current OxideDNS server favors correctness, readable ownership, and broad
protocol coverage. That is the right shape for transfer ingestion, validation,
configuration, health, metrics, and release evidence. The next performance
track should not rewrite DNS semantics. It should introduce a separate
read-only query data plane that is built from the existing safe model and
published atomically.

The target shape is:

```text
AXFR / IXFR / config / validation / catalog reconciliation
  safe builder model using maps, vectors, owned names, validation state
        |
        v
ZoneImage compiler
  canonicalizes names, builds lookup arrays, encodes immutable wire chunks
        |
        v
Published ZoneImage
  immutable, generation-labelled, read-only, cache-local data plane
        |
        v
Packet I/O adapter
  standard UDP/TCP first; optional UDP acceleration only after evidence
```

The design goal is to move the ordinary UDP query path toward:

- no heap allocation for valid direct positive queries;
- no shared locks after a worker has loaded its published snapshot;
- no per-query clone of owner names, RDATA, RRsets, or response sections;
- bounded stack scratch for parse, lookup, and response planning;
- immutable zone publication with complete-generation replacement;
- packet I/O behind adapters so optimization can be enabled, disabled, or
  replaced without changing DNS semantics.

## Design Discipline

This track uses these guardrails before any implementation is promoted:

- Packed storage, response templates, software prefetch, io_uring, and AF_XDP
  are independent experiments with separate entry conditions and rollback
  paths. They are not one mandatory sequence.
- The current safe model remains the correctness oracle until the optimized
  model has passed differential tests across the full query corpus.
- Data structures are chosen by measurement. A structure proposal must define
  its benchmark corpus, expected win, promotion gate, and rollback condition.
- Low-level crates and unsafe code are introduced only through the existing
  unsafe-boundary and unsafe-prone dependency registries.
- Packet bypass is considered only after the standard UDP batch baseline shows
  whether the kernel socket path is the limiting factor.

## Scope

In scope:

- an immutable per-zone `ZoneImage` representation;
- a `ZoneDirectory` that maps a QNAME suffix to a published zone slot;
- a `LookupPlan` or equivalent handle-based result that avoids owned response
  records on the hot path;
- pre-encoded immutable RRset wire chunks;
- standard UDP batching as the first packet I/O optimization;
- optional response-template, prefetch, huge-page, NUMA, io_uring, and AF_XDP
  experiments after baseline evidence exists;
- benchmark, differential-test, and packet-capture evidence for each phase.

Out of scope for the first implementation:

- authoritative DNS semantics in eBPF;
- a custom TCP stack;
- operator-supplied eBPF programs;
- mutable in-place edits to live zone data;
- replacing the safe DNS parser with an unsafe parser;
- making AF_XDP or io_uring mandatory;
- enabling full response templates by default;
- changing DNS behavior to fit a data structure.

## Core Boundaries

### Builder Model

The existing safe zone model remains the ingestion and correctness model. It may
continue to use maps, owned names, vectors, and validation-specific metadata.
Build-time comfort is acceptable because AXFR/IXFR and publication are not the
ordinary per-packet hot path.

Responsibilities:

- parse and validate zone transfer input;
- enforce structural DNS rules;
- preserve unknown RR data according to the current SRS policy;
- build complete replacement snapshots;
- provide an oracle for old-model versus new-model differential tests.

### ZoneImage

`ZoneImage` is an immutable read-side representation compiled from one complete
zone snapshot.

The initial design should prefer simple packed arrays over clever compression:

```text
ZoneImage
  header and generation
  name nodes
  child edges
  rrset entries
  rrset-type slices
  labels arena
  names arena
  rdata arena
  wire arena
  additional-data index
  optional DNSSEC denial indexes
  build statistics
```

Use integer IDs and arena references in hot structures. Avoid `String`,
`HashMap`, `Arc<Vec<_>>`, and per-record heap objects on the query path.

### ZoneDirectory

`ZoneDirectory` owns the suffix-to-zone-slot index and a stable vector of zone
slots.

```text
ZoneDirectory
  suffix index over reversed canonical labels
  slots: [ZoneSlot]

ZoneSlot
  zone name
  class
  generation
  current ZoneImage publication cell
  state
```

Catalog-zone add/remove operations may rebuild the directory. Ordinary zone
refreshes should update the affected slot only.

Start with `arc-swap` or an equivalent safe publication primitive. Load a guard
once per batch where practical. A custom epoch/RCU layer is a later experiment
only if measurements show publication-cell overhead is limiting throughput.

### LookupPlan

The lookup layer should return handles into immutable data, not owned DNS
records.

```text
LookupPlan
  rcode
  authoritative-answer flag
  answer rrset IDs
  authority rrset IDs
  additional rrset IDs
  synthesized records for wildcard, CNAME, DNAME, or dynamic metadata
  negative proof plan
  response flags
```

The response composer consumes this plan and copies immutable wire chunks or
emits small synthesized records into the worker-owned response buffer.

## ZoneImage Layout Rules

### Arenas

Use segmented arenas. A single 32-bit offset into one large blob is too small
for generated and large operator zones.

Recommended baseline:

```text
BlobRange
  segment: u16
  offset: u32
  length: u32
```

Use narrower compact references only after build statistics prove they cover the
common case without special-case complexity.

### Hot And Cold Split

Hot structures should include only fields touched by ordinary lookup:

- child edge ranges;
- RRset ranges;
- delegation, wildcard, CNAME, and DNAME markers;
- compact flags;
- refs to pre-encoded wire chunks.

Cold structures should carry:

- full owner-name bytes;
- debug and provenance data;
- large RDATA;
- large TXT/SVCB/HTTPS material;
- DNSSEC proof payloads;
- optional cache metadata.

If a hot struct grows beyond one or two cache lines, split it into hot and cold
arrays before adding prefetch or more exotic indexes.

### Name Graph

Start with a label-level trie using canonical lowercase labels. DNS wildcard,
delegation, closest-encloser, and empty-non-terminal behavior is label-oriented,
so a label-level first implementation is easier to verify.

Initial child-edge layout:

- inline or small sorted slice for low fan-out nodes;
- sorted slice with linear or binary search for medium fan-out nodes;
- no adaptive radix tree until fan-out histograms show it is worth testing.

ART, byte-compressed radix, generated perfect hash, SIMD child matching, and
other high-fan-out structures are experiments. They must be compared against the
baseline on the same corpus and hardware before promotion.
The in-process ZoneImage prototype benchmark now retains a high-fanout
first/middle/last/absent-child lookup mix and the matching fan-out histogram
rows so this decision can be made from evidence instead of shape guesses.
It also retains a benchmark-only first-byte child-label bucket comparison; on
the current high-fanout fixture that ART-like first dispatch is slower than the
sorted baseline and the retained generated open-address child hash, so it is
not a production layout candidate. A benchmark-only label-length bucket with
per-bucket sorted labels was also rejected: it preserved found counts and
checksums but measured slower than both sorted lookup and generated hash while
adding about 40 KiB of side-index storage on the 10k-record fixture. A compact
generated hash table with half the slot bytes was also measured; it preserved
correctness but largely gave back the high-fanout lookup win, so the production
table keeps the retained 2x next-power-of-two slot policy. The production child
hash still reduces memory by storing slot values as `u16` per-node edge
offsets, using `u16::MAX` as the empty sentinel; the edge-count bound is
already enforced in each `NameNode`.
A benchmark-only last-byte child-label bucket was also measured and rejected on
the same fixture: it preserved found counts and checksums, but measured slower
than sorted lookup and generated hash while adding about 41 KiB of side-index
storage.
The retained checker now emits explicit production slot-footprint rows so the
layout is audited directly: `child-hash-u16-slots-stats.tsv` reports one main
fixture child hash with `32768` slots and `65536` slot bytes, plus one
delegation/DNAME stress child hash with `16384` slots and `32768` slot bytes.
Child-hash probe comparisons now use a stored-lowercase label equality helper
for compiled lowercase labels rather than the generic two-sided
ASCII-insensitive slice comparison. The probe path also checks direct byte
equality first for already-lowercase query labels, then falls back to
case-insensitive comparison for mixed-case queries. Retained evidence treats
this as isolated lookup-path discipline because packet timings remain noisy.
Low-fanout trie lookup now has a matching retained fast path:
`target/zone-image-bench/single-child-trie-fast-path.tsv` handles one-child
nodes with one stored-lowercase equality check before falling back to the
generated-hash and binary-search paths. Focused tests cover mixed-case
single-child lookup and retained high-fanout hash lookup; the checker passed
with zero validation and packet mismatches, byte parity, exact lookup ratio
`0.222`, hot exact lookup ratio `0.226`, high-fanout exact lookup ratio
`0.111`, mixed packet ratio `0.964`, hot packet ratio `0.915`, and UDP-ceiling
packet ratio `1.015`.
Leaf trie nodes now also return a child miss before entering the hash or binary
search paths: `target/zone-image-bench/leaf-child-trie-fast-path.tsv` covers a
missing child below a leaf owner while preserving closest-encloser state. The
checker passed with zero validation and packet mismatches, byte parity, exact
lookup ratio `0.264`, hot exact lookup ratio `0.263`, mixed planning ratio
`0.143`, mixed packet ratio `1.013`, hot packet ratio `0.917`, and UDP-ceiling
packet ratio `0.994`.
Fanout 2-4 trie nodes now use the same small-node policy instead of immediately
entering binary search: `target/zone-image-bench/small-child-linear-lookup.tsv`
adds a retained four-child lookup fixture and compares sorted binary search
against linear stored-lowercase equality checks. The checker passed at
`target/zone-image-bench/small-child-linear-lookup-check.tsv` with matching
found counts/checksums, small-child linear ratio `0.541`, zero packet
mismatches, byte parity, mixed packet ratio `0.959`, hot packet ratio `0.969`,
trace packet ratio `0.975`, and UDP-ceiling packet ratio `1.010`. This is the
retained low-fanout half of the child-layout policy; the high-fanout path stays
on the generated child hash.
Owners with a single RRset now get the same kind of low-fanout shortcut:
`target/zone-image-bench/single-rrset-owner-fast-path.tsv` checks QTYPE/QCLASS
directly before falling back to the compiled-order RRset scan used for
multi-RRset owners. Focused tests cover ordinary IN, QCLASS=ANY, and NODATA
semantics; the checker passed with zero validation and packet mismatches, byte
parity, exact lookup ratio `0.217`, hot exact lookup ratio `0.227`, mixed
planning ratio `0.144`, mixed packet ratio `1.000`, and UDP-ceiling packet
ratio `1.011`.
Multi-RRset owners now get a sparse node-local low-RRtype bitmap side table:
only nodes with more than one RRset receive an entry, preserving the single-RRset
fast path. `NameNode` carries a compact side-table handle so
`find_rrset_at_node` reaches the bitmap with one indexed load instead of a
side-table binary search. Common absent-present types such as a CNAME query at
an A/AAAA owner can then return without walking the owner RRsets. QCLASS=ANY
exact lookup uses the same owner-local gate before its retained multi-class
collection scan. The retained
`target/zone-image-bench/node-low-rrtype-bitmap-handle.tsv` checker passed at
`target/zone-image-bench/node-low-rrtype-bitmap-handle-check.tsv` with hot
bytes/record `106.364`, total bytes/record `174`, stress bytes/record at the
configured cap `256`, absent-present low direct-preflight ratio `0.948`,
absent-present low QCLASS=ANY exact ratio `0.802`, mixed packet ratio `1.029`,
trace packet ratio `1.023`, and UDP-ceiling packet ratio `1.011`.
Concrete-class exact lookups now reuse that compiled RRset handle path instead
of scanning all same-owner RRsets:
`target/zone-image-bench/exact-lookup-compiled-handle.tsv` keeps QCLASS=ANY on
the retained multi-class scan, but ordinary concrete QCLASS lookups route
through the early-exit compiled class/type lookup. Focused tests cover a mixed
class/type owner plus QCLASS=ANY multi-class collection; the checker passed with
zero validation and packet mismatches, byte parity, exact lookup ratio `0.225`,
hot exact lookup ratio `0.244`, mixed planning ratio `0.141`, mixed packet
ratio `1.052`, hot packet ratio `0.967`, and UDP-ceiling packet ratio `1.002`.
The retained `target/zone-image-bench/single-rrset-any-fast-path.tsv` applies
that same low-fanout shape to QTYPE=ANY. Minimal and full ANY planning check
QCLASS and DNSSEC-proof eligibility once for single-RRset owners, then keep the
compiled-order scan for multi-RRset owners. Focused tests cover single-MX
minimal/full ANY, DNSSEC-proof-only NODATA, wildcard ANY, concrete-class ANY,
and QCLASS=ANY behavior; the checker passed with zero validation and packet
mismatches, byte parity, mixed planning ratio `0.141`, mixed packet ratio
`1.016`, hot packet ratio `0.960`, boundary packet ratio `0.978`, and
UDP-ceiling packet ratio `0.987`.

### RRsets And WireArena

Store ordinary RRsets in sorted slices per owner. Linear scan is acceptable for
the common one-to-four RRset case; binary search is a measurement candidate for
larger names.

Pre-encode immutable RRsets into uncompressed wire chunks first. That gives a
simple response-composition win without immediately coupling correctness to a
full-packet template cache. For wildcard owner-substitution upper-bound
accounting, the composer derives the non-owner byte total from already-compiled
RRset wire length, owner-wire length, and record count, so it avoids walking
every record without adding another hot `ImageRrset` metadata field. The same
private accounting helper returns RRset record count and wire upper bound from
one compiled-RRset read for ordinary RRset lists and owner-override answer
items.

Special cases remain dynamic:

- wildcard owner substitution, with common owner-override wire stored inline in
  the lookup plan;
- DNAME-generated CNAME records;
- CNAME chain planning;
- EDNS OPT, DNS Cookie, NSID, EDE, TSIG, and other response metadata;
- truncation decisions;
- compression dictionary choices.

RRSIG records need a covered-type index rather than being treated as ordinary
RRsets in all cases. Selected RRSIG records now stay as direct immutable answer
items or section handles; only truly synthesized records use dynamic record
buckets, and those remaining synthesized-record helpers append and account from
the synthesized record fields directly. DNAME-generated CNAME owner/target wire
uses inline buffers for the common short generated names while longer names can
still spill safely.
The retained `target/zone-image-bench/synthesized-inline-wire.tsv` run keeps
that field-level inline storage after narrowing the earlier rejected experiment:
the synthesized-record bucket itself still has one inline entry, and the common
DNAME-generated CNAME owner/RDATA wire buffers now avoid heap allocation. The
checker passed with zero validation and packet mismatches, byte parity, mixed
planning ratio `0.148`, mixed wire ratio `0.169`, mixed packet ratio `1.006`,
hot packet ratio `0.965`, trace packet ratio `0.988`, optioned packet ratio
`0.977`, boundary packet ratio `1.007`, UDP-ceiling packet ratio `0.969`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.002`. Treat this
as generated-record allocation/layout cleanup, not a broad packet-path win.
The later retained `target/zone-image-bench/single-name-target-wire-range.tsv`
run narrows DNAME synthesis without adding hot image metadata: precomputed
CNAME/DNAME targets still carry a `DomainName` for chain semantics, while the
synthesized CNAME RDATA appends the already-compiled single-name RDATA wire
from the target RRset's first record. Its checker passed with zero validation
mismatches and unchanged response bytes.
The follow-up `target/zone-image-bench/single-name-target-rdata-range.tsv`
carries that validated target `RdataRange` directly in `ImageSingleNameTarget`,
so target-wire access slices the RDATA arena from the precomputed target view
instead of re-indexing the owner RRset's first record during CNAME/DNAME
resolution. Its retained checker
`target/zone-image-bench/single-name-target-rdata-range-check.tsv` passed with
zero validation mismatches and unchanged response bytes: mixed planning ratio
`0.140`, mixed wire ratio `0.164`, mixed packet ratio `1.000`, hot packet ratio
`0.945`, trace packet ratio `0.975`, optioned packet ratio `0.987`, boundary
packet ratio `1.002`, UDP-ceiling packet ratio `0.992`, and delegation/DNAME
stress planning and wire ratios of `0.001`. Image bytes stayed under the hot
gates (`106.359` hot bytes per record and `144.140` stress hot bytes per
record, both below `160.000`), while stress total bytes per record sits exactly
on the retained `256.000` ceiling. This is a narrow precomputed-target view
cleanup.
`target/zone-image-bench/dname-target-node-hint.tsv` also retains the next
DNAME planning cleanup: generated CNAME target classification reuses the
literal DNAME target's precomputed node hint where that is provably safe. An
existing in-zone target walks only the prepended query-label prefix from the
compiled target node, a known-missing in-zone target stays missing without a
target lookup, and out-of-zone literal targets are split by shape. Parent-suffix
targets keep the conservative synthesized-target lookup because prefixing can
produce an in-zone target, while unrelated out-of-zone targets stay out-of-zone
without that trie walk. The retained
`target/zone-image-bench/dname-out-of-zone-parent-suffix-hint-check.tsv`
checker passed with zero validation and packet mismatches, byte parity, mixed
planning ratio `0.166`, mixed wire ratio `0.191`, mixed packet ratio `1.035`,
hot packet ratio `1.130`, trace packet ratio `1.040`, boundary packet ratio
`1.024`, UDP-ceiling packet ratio `1.037`, delegation/DNAME stress planning
ratio `0.002`, and unchanged image bytes per record (`174.000` base,
`256.000` stress). This is narrow DNAME planner no-scan cleanup, not a
packet-throughput claim.
The follow-up `target/zone-image-bench/dname-out-of-zone-wire-only.tsv`
narrows that unrelated out-of-zone branch further: after the compiled DNAME
target hint proves the generated CNAME target is terminal outside the zone,
suffix replacement builds only the generated target wire and does not
materialize a synthesized `DomainName` for a lookup that cannot happen. The
checker artifact
`target/zone-image-bench/dname-out-of-zone-wire-only-check.tsv` passed with
zero validation and packet mismatches, byte parity, mixed planning ratio
`0.168`, mixed wire ratio `0.190`, mixed packet ratio `1.045`, hot packet ratio
`0.979`, trace packet ratio `1.063`, optioned packet ratio `1.050`, boundary
packet ratio `1.000`, UDP-ceiling packet ratio `1.014`, and delegation/DNAME
stress planning and wire ratios of `0.002`. This is DNAME
allocation/planning cleanup inside the current synthesized-record path, not
template/WireArena completion.
The retained `target/zone-image-bench/dname-target-wire-inline-serialize.tsv`
then removes the remaining prefix-label sizing walk from generated DNAME target
wire construction. The counted suffix-replacement helper now writes the query
prefix labels directly into the inline target-wire buffer, appends the
precomputed DNAME target wire, and accounts from the completed buffer instead
of summing prefix label lengths before serializing the same labels. The checker
artifact
`target/zone-image-bench/dname-target-wire-inline-serialize-check.tsv` passed
with zero validation and packet mismatches, byte parity, mixed planning ratio
`0.152`, mixed wire ratio `0.166`, mixed packet ratio `1.005`, hot packet ratio
`0.964`, trace packet ratio `1.000`, optioned packet ratio `0.990`, boundary
packet ratio `1.007`, UDP-ceiling packet ratio `1.013`, and
delegation/DNAME-stress plan and wire ratios of `0.002`. This is generated
DNAME target bookkeeping cleanup inside the current synthesized-record path,
not template/WireArena completion.
The retained `target/zone-image-bench/dname-owner-label-count.tsv` then uses
existing `ImageRrset` padding to carry the owner label count compiled from the
RRset owner. DNAME synthesis passes that count into the stored-wire suffix
replacement helper, avoiding a query-time parse of the stored DNAME owner wire
whose only purpose was to find the query-prefix boundary. Focused DNAME tests,
filtered ZoneImage tests, and the invariant audit cover the invariant, and the
checker passed at `target/zone-image-bench/dname-owner-label-count-check.tsv`
with zero validation and packet mismatches, byte parity, mixed packet ratio
`0.996`, delegation/DNAME stress planning ratio `0.001`, and unchanged hot
bytes per record.
The retained `target/zone-image-bench/ds-delegation-owner-label-count.tsv`
applies the same compiled owner-label metadata to the DS-at-delegation
exception. The planner still compares borrowed stored owner wire for the
case-insensitive DS-at-cut rule, but it now rejects below-cut label-count
mismatches before scanning that wire. Focused DS-at-delegation tests, filtered
ZoneImage tests, and the invariant audit cover the invariant, and the checker
passed at `target/zone-image-bench/ds-delegation-owner-label-count-check.tsv`
with zero validation and packet mismatches, byte parity, mixed packet ratio
`0.995`, delegation/DNAME stress planning ratio `0.001`, and hot bytes per
record still `102.491`.
The follow-up `target/zone-image-bench/semantic-ds-delegation-node-owner.tsv`
removes that remaining semantic stored-owner scan. The referral guard now treats
DS as at-cut only when the query resolved to the exact trie node and that node
owns the compiled delegation policy RRset; below-cut DS queries remain
referrals, including safe QCLASS=ANY images. Focused DS-at-delegation and
node-policy tests cover the invariant, the audit rejects a stored-owner scan in
`lookup_response_plan`, and the checker passed at
`target/zone-image-bench/semantic-ds-delegation-node-owner-check.tsv` with zero
validation and packet mismatches, byte parity, mixed packet ratio `1.016`, hot
packet ratio `1.038`, boundary packet ratio `1.008`, UDP-ceiling packet ratio
`1.002`, delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
`0.002`.

### Negative DNSSEC Indexes

DNSSEC denial-of-existence should be implemented after exact positive lookup,
delegation, wildcard, CNAME, and DNAME equivalence is proven.

NSEC baseline:

- canonical owner order;
- owner-to-order position;
- RRset ID by owner;
- predecessor lookup for nonexistent names.

Current `ZoneImage` NSEC proof metadata stores canonical owner/next range keys
and the precomputed range-order bit. Query-time proof lookup compares borrowed
query label views against those keys and does not recompute whether each
immutable NSEC range wraps while scanning candidates.
Those canonical range keys are now compact lowercase length-prefixed byte
ranges in the image arena rather than per-label heap vectors. The retained
`target/zone-image-bench/nsec-range-arena-keys.tsv` run passed
`target/zone-image-bench/nsec-range-arena-keys-check.tsv` with zero validation
mismatches and unchanged response bytes, while keeping denial lookup on
borrowed query-label views.
NSEC range compilation now also builds those keys directly from stored owner
wire and NSEC RDATA next-owner wire instead of materializing `DomainName`
values just to reverse/lowercase labels. The retained
`target/zone-image-bench/nsec-range-wire-key-no-parse.tsv` run passed
`target/zone-image-bench/nsec-range-wire-key-no-parse-check.tsv` with zero
semantic and packet mismatches, byte parity, image bytes per record `174.000`,
stress bytes per record `256.000`, mixed planning ratio `0.137`, mixed wire
ratio `0.158`, and mixed packet ratio `1.024`. This is builder-side metadata
hygiene, not a claimed query-path speedup.

NSEC3 baseline:

- sorted hashed owners;
- parameter record for hash, flags, iterations, and salt;
- capped dynamic hash work for candidate closest-encloser names;
- per-worker cache only if negative responses are hot in perf data.

Current `ZoneImage` NSEC3 range metadata stores decoded owner/next hashes as
inline SHA-1 arrays, stores shared algorithm/iteration/salt tuples in a compact
image-wide parameter-set table, and stores only a `u16` parameter-set handle in
each range. Query hash-cache entries are keyed by that handle instead of
rechecking salt bytes while scanning candidates, and the full parameter view is
materialized only on cache misses from the already-loaded range-loop descriptor.
The retained `target/zone-image-bench/nsec3-param-set-descriptor-reuse.tsv` run
passed `target/zone-image-bench/nsec3-param-set-descriptor-reuse-check.tsv`
with zero trace and boundary packet mismatches, hot bytes/record `106.364`,
bytes/record `174`, stress bytes/record `256`, mixed planning ratio `0.144`,
mixed packet ratio `0.987`, hot packet ratio `0.985`, trace packet ratio
`0.999`, boundary packet ratio `0.999`, and UDP-ceiling packet ratio `1.005`.
This is retained as signed-denial data-path discipline, not as a broad
packet-speed claim.
NSEC3 range compilation also extracts owner hashes directly from stored
uncompressed owner wire and decodes base32hex straight into fixed SHA-1 bytes.
The retained `target/zone-image-bench/nsec3-owner-wire-no-parse.tsv` run passed
`target/zone-image-bench/nsec3-owner-wire-no-parse-check.tsv` with zero
semantic and packet mismatches, byte parity across retained packet mixes, image
bytes per record `174.000`, stress bytes per record `256.000`, mixed planning
ratio `0.142`, mixed wire ratio `0.164`, and mixed packet ratio `1.026`. This
is builder-side metadata hygiene, not a claimed query-path speedup.

NSEC3 acceleration must not be a prerequisite for ordinary positive-path
performance.

## Response Composition

Each worker owns reusable buffers and scratch state:

```text
WorkerBuffers
  UDP response buffers sized to configured payload policy
  TCP stream buffer
  lookup scratch
  compression scratch
  per-worker metrics
```

The first optimized composer should:

- copy the original question section exactly where DNS rules allow;
- copy selected immutable RRset wire chunks;
- emit synthesized records through safe bounded writers;
- maintain existing EDNS, Cookie, RRL, DNSSEC, truncation, and TSIG behavior;
- expose per-stage timing for parse, lookup, compose, and send.

Response templates are optional. They should not be enabled by default until the
hit rate and CPU data justify the memory and invalidation complexity.

Template eligibility must be explicit. Initial eligible candidates can be
direct positive unsigned `A` and `AAAA` responses without TSIG, EDNS padding,
dynamic EDE, DNAME, wildcard owner substitution, or truncation boundary risk.

Template keys must include the zone generation and every query or response
feature that can change the wire result, including QNAME identity or hash,
QTYPE, QCLASS, transport class, EDNS payload bucket, DO bit, Cookie state, NSID
state, and template feature flags.

## Packet I/O Plan

Packet I/O remains an adapter. DNS parser, lookup, response composition, TSIG,
DNSSEC proof logic, RRL, and catalog behavior must not depend on the backend.

### Standard UDP Batch Backend

Implement and measure standard UDP batching before AF_XDP:

- one socket per worker where `SO_REUSEPORT` is available;
- `recvmmsg` and `sendmmsg` or a narrowly isolated equivalent;
- fixed-size packet batches;
- worker-owned buffers and scratch;
- optional CPU affinity after baseline evidence;
- ordinary Tokio/control paths preserved for transfer, TCP, health, metrics,
  and background work.

This path is the practical production baseline because it improves syscall and
runtime overhead while preserving ordinary Linux socket behavior.

The standard UDP backend now has the first `SO_REUSEPORT` worker scaffold:
`[limits].udp_reuseport_workers` creates multiple same-address UDP sockets for
each configured UDP listener when the standard backend is selected, and
`[limits].udp_runtime = "dedicated"` selects one OS thread per UDP worker
instead of the stable Tokio socket path. On Linux, dedicated workers use a
tightly scoped unsafe `recvmmsg`/`sendmmsg` module with reusable mmsghdr/iovec/
sockaddr slabs, `MSG_DONTWAIT`, bounded partial-send retry, and a 1024-message
batch cap matching the Linux mmsg limit. Off Linux, the same worker falls back
to the safe `recv_from`/`send_to` loop. Dedicated workers own their socket,
bounded packet buffers, parser/lookup/compose loop, and optional per-thread CPU
affinity. `[limits].udp_worker_cpu_affinity` can request a Linux CPU id per
dedicated worker. Defaults preserve one socket, Tokio runtime ownership, and no
affinity. The benchmark harness records the runtime, worker count, and affinity
settings so Tokio and dedicated profiles can be compared without changing the
release default. Dedicated Linux runs also expose mmsg syscall counters,
partial-send counters, WouldBlock retry counters, and per-worker labelled
datagram counters so local tuning can distinguish syscall batch depth from
reuseport worker imbalance.

On 2026-06-02, the local loopback profile with reduced hot-path metrics,
`udp_batch_size=32`, four server threads, four client threads, and client
window 16 measured about 482k responses/s with one UDP worker. Two
four-worker Tokio no-affinity runs measured about 951k and 845k responses/s,
and a four-worker Tokio `0,1,2,3` affinity run measured about 782k
responses/s. A later same-profile runtime comparison measured four-worker
Tokio at about 936k responses/s, four-worker dedicated pre-mmsg standard UDP at
about 879k responses/s, and four-worker dedicated with CPU affinity `0,1,2,3`
at about 641k responses/s, all with zero drops/errors. After adding Linux mmsg,
small batches were still slower, but larger batches improved the local profile:
batch 128 measured about 1.21M responses/s, batch 256 about 1.24M responses/s,
batch 512 about 1.47M responses/s, and batch 1024 fell back to about 1.19M
responses/s. A batch-512 affinity run measured about 898k responses/s, so
affinity remains host/runtime specific and evidence-gated. This is not physical
NIC evidence.

The local runtime sweep harness can now compare runtimes, worker counts, batch
sizes, and affinity modes under one retained query trace. It records both
`summary.tsv` and a sorted `best.tsv` so follow-up optimization work can start
from retained evidence rather than hand-run profiles.

For hosts that block direct `perf -p` attach under the default
`perf_event_paranoid` policy, the benchmark can optionally use the installed
`/usr/local/libexec/oxidedns-perf-capture` helper through non-interactive
`sudo -n`. The helper is root-owned, installed by one `pkexec` setup step, and
checks target PID ownership before running `perf stat` or `perf record`.

### io_uring Evaluation

io_uring belongs behind `PacketIo` as an evaluation path. It may be useful for
standard-stack batching and future zero-copy receive experiments, but the
zero-copy receive path has NIC and queue steering requirements and must not be
assumed portable.

TCP ordering remains a hard constraint. Do not overlap multiple sends or
receives on the same TCP stream unless the implementation explicitly proves
ordering.

### Reduced Hot-Path Metrics

The DNS data path is designed around immutable `ZoneImage` snapshots and
per-listener packet processing, but detailed observability can still introduce
shared synchronization when every query records per-zone maps, RCODE maps,
latency histograms, DNS Cookie prefix maps, or pipeline/cache-planning
histograms. The default `[metrics].hot_path_detail = "full"` keeps that
operator detail.

High-rate packet-path experiments may use
`[metrics].hot_path_detail = "reduced"`. Reduced mode keeps coarse fixed
counters on the query path, including received queries, truncation, DNS Cookie
case totals, UDP batch/datagram totals, and ZoneImage serve counters. It skips
mutex-backed detailed series on the hot path and disables pipeline timing
collection internally even if `pipeline_timing_enabled` is set. Reduced mode is
an observability/performance tradeoff for benchmarking and does not change DNS
answer behavior.

Saturation-only packet-path experiments may use
`[metrics].hot_path_detail = "off"` to suppress per-query hot-path counters as
well. This profile is intended for isolating transport, response composition,
and kernel/socket overhead from shared counter cost. It keeps worker and batch
metrics available after the run, but query, RCODE, DNS Cookie, RRL, and per-zone
hot-path metrics are not representative while the profile is active.

Physical UDP loss experiments should record worker affinity and socket buffer
settings with the result. On the current 48-CPU 25G host, pinning 16 dedicated
UDP workers to sibling-free even CPUs improved the 3M offered-QPS counters-off
profile from about 2.33M replies/s and 77.6% reply rate to about 2.69M replies/s
and 89.7% reply rate. A first 4 MiB `SO_RCVBUF`/`SO_SNDBUF` run was worse than
the default on the same host, so socket-buffer sizing remains evidence-gated
rather than a default recommendation.

### AF_XDP Evaluation

AF_XDP is an advanced UDP backend, not a default server dependency.

Allowed XDP program scope:

- parse enough Ethernet/IP/UDP headers to classify packets;
- redirect eligible UDP DNS packets to the matching AF_XDP socket;
- pass or drop non-matching traffic according to a documented policy;
- keep coarse counters.

Forbidden XDP program scope:

- DNS name decompression;
- RR lookup;
- DNSSEC proof selection;
- TSIG or Cookie validation;
- response generation;
- catalog-zone behavior;
- full RRL semantics.

The userspace AF_XDP worker owns UMEM frame lifetime, RX/TX descriptor handling,
safe DNS parsing, lookup, composition, and fallback behavior. Physical-NIC
zero-copy evidence is required before claiming a production benefit; veth or
generic-mode tests are useful only for smoke and fault coverage.

The first server-side AF_XDP scaffold keeps that boundary explicit. The
configuration model now has `limits.udp_backend = "std" | "af_xdp"`,
`limits.udp_runtime = "tokio" | "dedicated"` for the standard backend, and an
optional `[xdp]` section for interface, queue, UMEM frame count, RX/TX/fill/
completion ring sizes, batch size, zero-copy policy, XDP attach mode, and the
project-built redirect object. Selecting `af_xdp` requires `xdp.interface` and
`xdp.redirect_object`, and ring sizes are validated as non-zero powers of two
before runtime setup reaches the lower-level AF_XDP crate. The default backend
remains `std`, and AF_XDP keeps its own packet worker model rather than sharing
the standard UDP runtime toggle.

The standard UDP path is routed through a private mutable `PacketIo` boundary
so the common DNS batch loop can later consume either ordinary socket batches
or AF_XDP RX/TX ring batches while allowing the AF_XDP backend to own and
release UMEM frames after each batch. Selecting `af_xdp` currently fails with
an explicit `UdpBackendUnavailable` runtime error; without the
`oxidedns-server/af-xdp` feature the error reports that the binary lacks AF_XDP
support. With the feature, the server binds an AF_XDP socket, loads the
project-built `oxidedns_xdp_redirect` object, configures its destination-port
selector and XSK map, and attaches the program in the configured mode. The
feature-gated `af_xdp` helper module has safe local coverage for parsing
Ethernet/IPv4/UDP DNS frames, extracting source/destination socket metadata,
rejecting fragmented IPv4 UDP packets, constructing AF_XDP frame targets, and
rewriting Ethernet, IPv4, and UDP response headers with a valid IPv4 header
checksum. The same module also has a tested send-side primitive that writes
larger or smaller DNS responses into an owned AF_XDP packet, resizes the packet
tail, and avoids transmitting stale bytes.

`crates/oxidedns-server-ebpf` owns the excluded Rust eBPF redirect object, and
`scripts/oxidedns-server-build-ebpf.sh` builds it with `bpf-linker`. The local
root-only smoke path is `scripts/oxidedns-af-xdp-veth-smoke.sh`, which creates
a veth pair and verifies generic-mode AF_XDP bind/attach startup. On
2026-06-01 that smoke passed locally with evidence under
`target/oxidedns-af-xdp-veth-smoke/`. This is intentional local scaffolding,
not a packet-bypass performance result.

## Unsafe And Dependency Policy

The safe default remains: no unsafe in DNS semantics.

Unsafe may be considered only in adapter modules such as:

- standard UDP batch syscall wrappers;
- AF_XDP UMEM and ring handling;
- io_uring registration and buffer adapters if required by the chosen API;
- architecture-specific prefetch intrinsics;
- optional aligned or huge-page allocation adapters.

Unsafe is not allowed in:

- DNS name decompression semantics;
- DNS parser state machines;
- zone lookup rules;
- DNSSEC proof selection;
- TSIG verification;
- response policy decisions.

Any implementation change that adds first-party unsafe or unsafe-prone
dependencies must update `docs/unsafe-boundaries.tsv`,
`docs/unsafe-prone-dependencies.tsv`, `docs/architecture.md`, and the relevant
audit allowlist in the same change. Unsafe APIs need `/// # Safety` docs, and
unsafe blocks need local `// SAFETY:` rationale plus targeted fault tests.

## Test Plan

### Phase-Level Tests

| Phase | Required tests before merge |
| --- | --- |
| Baseline instrumentation | Existing workspace tests; benchmark harness emits parse, lookup, compose, send, allocation, and memory metrics for current model. |
| `LookupPlan` on current store | Old public query behavior unchanged; direct positive query allocation test; semantic comparison with existing response tests. |
| Exact `ZoneImage` lookup | Old-model versus packed-model differential tests for direct A, AAAA, NS, MX, TXT, SOA, CAA, SVCB, HTTPS, and unknown RR queries. |
| Name-graph semantics | Wildcard, empty non-terminal, delegation cut, glue, CNAME, DNAME, NXDOMAIN, and NODATA differential tests. |
| DNSSEC denial indexes | NSEC and NSEC3 positive and negative proof tests; DO=0 and DO=1 comparisons; cap behavior for expensive NSEC3 cases. |
| WireArena composer | Packet capture comparison; truncation and EDNS payload tests; compression legality tests; no out-of-bounds writes under fuzz. |
| Standard UDP batch backend | Loopback and network-namespace smoke; loss/error accounting; fallback to existing socket path; packet-capture equality for sampled responses. |
| Response templates | Eligibility matrix tests; generation invalidation tests; disabled-by-default tests; hot-query and random-query benchmark comparison. |
| io_uring backend | Feature-gated smoke; fallback when unsupported; TCP ordering tests if TCP path is attempted. |
| AF_XDP backend | veth/generic smoke; attach/detach cleanup; queue mismatch fault test; physical NIC zero-copy benchmark before production claim. |
| Prefetch, huge pages, NUMA | Feature-disabled default tests; target-host benchmark evidence; portability fallback tests. |

### Differential Corpus

The old and new models must be compared on these query classes:

- direct positive: `A`, `AAAA`, `NS`, `MX`, `TXT`, `SOA`, `CAA`, `SVCB`,
  `HTTPS`, unknown RR type;
- negative: NXDOMAIN, NODATA, empty non-terminal;
- wildcard: positive wildcard and wildcard NODATA;
- delegation: referral with glue and referral without glue;
- CNAME/DNAME: direct, chained, maximum depth, and loop failure;
- DNSSEC: DO=0, DO=1, NSEC, NSEC3, unsigned delegation DS absence;
- EDNS: absent, common 1232-byte payload, larger payload, BADVERS;
- Cookies: absent, client-only, valid server cookie, invalid server cookie;
- RRL: below threshold, over threshold, slip behavior;
- malformed: bad label length, bad compression, truncated question,
  unsupported opcode, multi-question packet.

Compare semantic results first. Byte-for-byte comparison is required only for
paths where current behavior already promises stable bytes or where a packet
capture test owns the exact wire result.

### Fuzz Targets

Add fuzz targets when each implementation surface exists:

- DNS query parse to packed lookup to response composition;
- generated legal zone to builder model to `ZoneImage` to differential lookup;
- legal RRset to WireArena encode and response write;
- malformed names and compression pointers through the parser;
- EDNS, Cookie, EDE, DNSSEC, and truncation combinations through the composer;
- packet I/O adapters with short packets, oversized packets, partial batches,
  send errors, and cancellation.

The first ZoneImage composer fuzz surface is `zone_image_datagram`. It feeds raw
and shaped query packets through the public datagram API with a static
`ZoneImage` provider. The static zone includes direct, CNAME, DNAME, wildcard,
referral/glue, answer-additional, QTYPE=ANY, basic DNSSEC, EDNS,
opaque-unknown, compression-eligible owner/RDATA, and malformed known-name
RDATA shapes, so the composer is continuously checked for safe opaque fallback
and no panics before transport work starts.
The local campaign runner can invoke cargo-fuzz through a selected rustup
toolchain with `--toolchain nightly`, including prepending that toolchain's
cargo directory so cargo-fuzz's inner build uses the same filesystem view. A
retained 60-second run at
`target/fuzz-evidence/zone-image-local-20260531-nightly-60s/campaign-summary.tsv`
passed `zone_image_datagram` for 1,396,283 executions in 61 seconds. Shorter
direct-nightly and `--toolchain nightly` smoke runs are retained as tooling
validation. Overnight or release-window ASan campaigns remain release evidence,
not a default local gate.

Compile-time wire bounds are part of the same hardening line. `ZoneImage`
preencoding now rejects RDATA that cannot fit the DNS RR rdlength field instead
of truncating the length during immutable wire construction. The retained
`target/zone-image-bench/compile-rdata-rdlength-bound.tsv` run passed
`target/zone-image-bench/compile-rdata-rdlength-bound-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.131`,
mixed wire ratio `0.164`, mixed packet ratio `1.004`, boundary packet ratio
`1.000`, UDP-ceiling packet ratio `0.998`, and delegation/DNAME stress planning
and wire ratios of `0.001`. This is retained as a correctness guard for more
aggressive immutable wire/template composition before io_uring or AF_XDP work.

## Metrics

Every benchmark report for this track must include:

- git commit;
- build profile and feature set;
- kernel version;
- CPU model, core count, SMT state, and governor;
- memory size and NUMA topology where relevant;
- NIC model, driver, queue count, offload state, and XDP mode for network tests;
- zone shape and query mix;
- exact command line;
- packet-loss and error counters.

Required server metrics:

```text
queries/second/core
cycles/query
instructions/query
branch-miss rate
L1 data miss rate
LLC miss rate
dTLB miss rate
allocations/query
bytes allocated/query
parse ns/query
lookup ns/query
compose ns/query
send/receive ns/query
p50/p90/p99/p999 latency
RSS
hot bytes/record
cold bytes/record
publish memory spike
zone build duration
publish duration
packet loss
send errors
receive errors
fallback count
fallback count by fixed reason
```

Required build statistics per `ZoneImage`:

```text
zone name
record count
rrset count
name count
node count
edge count
max depth
average depth
child-count histogram
rrsets-per-name histogram
rdata bytes
wire bytes
hot bytes
cold bytes
bytes/record
nsec entries
nsec3 entries
largest rrset wire length
build duration
self-check duration
```

The runtime exposes the child fan-out, RRsets-per-owner, RDATA-per-RRset, and
RDATA-bytes-per-RRset distributions as opt-in Prometheus gauges under
`oxidedns_zone_shape_*` when `[metrics].zone_shape_enabled = true`. These are
scrape-time diagnostics for retained layout evidence and must stay disabled for
plain throughput runs unless the run is explicitly collecting memory-layout
data.

## Structure Comparison And Tuning

Do not pick a structure because it looks faster in isolation. Compare it under
the same workload, corpus, compiler, hardware, and packet path.

### Name Edge Layouts

Baseline:

- inline small edge list;
- sorted edge slice;
- linear scan below a measured fan-out threshold;
- binary search above that threshold.

Candidates:

- adaptive radix tree for high fan-out nodes;
- byte-compressed radix for labels;
- generated perfect hash for extreme static fan-out;
- SIMD label comparison where supported.

Promotion gate:

- at least 15 percent lower lookup ns/query or a material memory reduction on a
  documented high-fan-out zone shape;
- no regression above the configured threshold on ordinary mixed zones;
- equal old/new semantic results for the full differential corpus.

Retain `zone_image_max_child_fanout`,
`current_high_fanout_lookup_ns_per_query`,
`zone_image_high_fanout_exact_lookup_ns_per_query`, and
`zone_shape_child_name_fanout_names_bucket_*` before adding a candidate layout.
If the sorted-edge baseline is already comfortably below the current snapshot
path and CPU profiles do not show lookup-memory stalls, keep the simpler
layout.

### RRset Lookup

Baseline:

- sorted per-owner RRset slice;
- linear scan for small slices;
- binary search candidate for larger slices.

Tune by measuring `rrsets_per_name_histogram`. A hash table at each name is not
allowed unless real data shows large per-owner RRset counts make slice search a
bottleneck.

### Arena References

Baseline:

- explicit segment, offset, and length fields.

Candidates:

- compact packed `u64` references;
- separate small/large range tables;
- type-specific arenas for labels, RDATA, and wire chunks.

Promotion gate:

- lower hot bytes/record or lower cache/TLB miss rate;
- no overflow edge cases on generated multi-GiB zones;
- simpler bounds checks are not traded away for ambiguous bit packing.

### Response Composition

Baseline:

- uncompressed immutable RRset wire chunks plus dynamic compression dictionary.

Candidates:

- compressed RRset chunks for safe names;
- response body templates;
- full packet templates with patch points.

Promotion gate:

- at least 20 percent lower compose ns/query in the target query mix;
- template hit rate above 70 percent for the profile that enables templates;
- strict generation invalidation and feature-key coverage;
- no packet-capture mismatch in eligible paths.

### Publication

Baseline:

- safe publication cell such as `ArcSwap`;
- load once per batch when possible.

Candidates:

- cached guards;
- custom epoch reclamation;
- per-worker directory snapshot pointer.

Promotion gate:

- publication load/refcount or cache-line contention is visible in profiles;
- improvement is measurable under many-worker load;
- writer-side retirement remains obviously safe and tested.

### Packet I/O

Baseline:

- current socket path;
- then standard UDP batching.

Candidates:

- io_uring standard-stack backend;
- AF_XDP UDP backend.

Promotion gate:

- standard UDP batch path beats the current path before deeper backends are
  attempted;
- io_uring or AF_XDP beats the standard UDP batch baseline on target hardware;
- snapshot comparison evidence remains continuously tested offline;
- attach/detach and unsupported-hardware behavior are clean.

## Implementation Phases

### Phase 0: Baseline Instrumentation

Tasks:

- add per-query allocation counters for representative query classes;
- separate parse, lookup, compose, and send timing;
- add build-stat output for current zone shapes;
- add benchmark artifact schema under the release evidence process;
- record current qps/core and latency for loopback and reference profile runs.

Exit:

- baseline report exists;
- top allocation and clone sites are known;
- old-model behavior corpus is reproducible.

### Phase 1: Handle-Based Lookup

Tasks:

- introduce `LookupPlan` or equivalent;
- make current `ZoneSnapshot` return handles or borrowed refs;
- update composer to consume handles;
- remove ordinary direct-positive response clones.

Exit:

- direct positive UDP query path is zero or near-zero allocation;
- existing tests and packet comparisons still pass;
- lookup/compose timing improves or the next bottleneck is clearly identified.

### Phase 2: Exact ZoneImage Prototype

Tasks:

- compile a simple `ZoneImage` from the current snapshot;
- build canonical label nodes, sorted edges, and RRset slices;
- implement exact positive lookup without DNSSEC denial proofs;
- add old/new differential tests.

Exit:

- exact positive corpus passes;
- no unsafe in packed lookup;
- build statistics and lookup metrics are emitted;
- old/new comparisons are retained in offline tests and benchmarks rather than
  live runtime shadow validation.

### Phase 3: Full Name Semantics

Tasks:

- add wildcard, empty non-terminal, delegation, glue, CNAME, and DNAME support;
- add additional-data index;
- extend differential corpus;
- add a default-enabled serving gate that composes supported response sections
  directly from immutable `ZoneImage` wire chunks and falls back to the current
  snapshot response path for unsupported or oversized responses.

Exit:

- current name-semantics tests pass under both models;
- packet-level sampled responses match expected behavior for the gated serving
  path;
- offline old/new comparison evidence stays at zero mismatches/errors for the
  retained sampled query set;
- no regression in current interop smoke.

### Phase 4: DNSSEC Denial

Tasks:

- add RRSIG covered-type index;
- add NSEC and NSEC3 indexes;
- implement bounded dynamic NSEC3 work;
- add DNSSEC-specific differential and packet-capture tests.

Exit:

- passive DNSSEC serving remains correct;
- negative proof selection is bounded and tested;
- NSEC/NSEC3 metrics show cost by query class.

### Phase 5: WireArena Composer

Tasks:

- pre-encode ordinary RRset wire chunks;
- precompute negative SOA variant;
- write dynamic synthesized records safely;
- preserve truncation, EDNS, Cookie, DNSSEC, EDE, and TSIG behavior.

Exit:

- response composition improves materially on target query mixes;
- packet captures remain acceptable;
- fuzz and bounds tests cover writer edge cases.

### Phase 6: Standard UDP Batch Backend

Tasks:

- implement `PacketIo` and `StdUdpBatchIo`;
- keep the initial `StdUdpBatchIo` baseline in safe Rust using ordinary Tokio
  socket readiness and `try_recv_from`; isolate Linux `recvmmsg`/`sendmmsg`
  syscall unsafe in the dedicated standard UDP mmsg adapter;
- add batch parse/lookup/compose/send pipeline;
- retain existing socket path as fallback.

Exit:

- qps/core improves over the current UDP path;
- sampled response behavior is unchanged;
- loss and error accounting is visible;
- unsupported-platform fallback is tested.

Initial safe-Rust loopback evidence from 2026-05-29 used
`scripts/benchmark-dns-clients.sh` with 1,000 generated records, UDP, four
server threads, four client threads, and client window 16. The retained
`target/evidence/udp-batch-loopback-baseline-1` artifact recorded 303,943
responses/s at `udp_batch_size=1`; `target/evidence/udp-batch-loopback-batch-32`
recorded 350,738 responses/s at `udp_batch_size=32`, with zero drops/errors and
receive/send batch counters showing 352,049 datagrams over 11,013 batches. This
is local loopback evidence only; physical NIC evidence remains required before
promotion.

The current-layout trace replay from 2026-05-31 refreshed that local evidence
after the always-on `ZoneImage` data-plane work. With 1,000 records, 128
delegation/DNAME stress candidates, four server threads, four client threads,
client window 16, and zero drops/errors, `target/evidence/udp-batch-loopback-current-1`
recorded 350,726 responses/s at `udp_batch_size=1`, while
`target/evidence/udp-batch-loopback-current-32` recorded 367,297 responses/s at
`udp_batch_size=32`. The batch-32 run processed 1,104,781 datagrams over 34,530
receive/send batches and retained `zone_image_serve_failures=0` with rollback
count `0`. This keeps standard UDP batching as the local no-XDP baseline, but
it is still loopback evidence and cannot promote a physical NIC claim.
The same harness now has opt-in bounded UDP DNS packet capture through
`OXIDEDNS_BENCH_PACKET_CAPTURE_ENABLED=true`. The retained
`target/evidence/udp-batch-loopback-current-32-pcap-sampled` artifact captured
128 DNS packets on loopback with 64 queries and 64 responses, zero drops/errors,
and `zone_image_serve_failures=0`. This closes the local sampled-response
capture gap for the standard UDP path while keeping physical NIC promotion out
of scope.

### Phase 7: Optional Experiments

Run only after earlier phases produce stable evidence:

- response-template cache;
- prefetch;
- huge pages;
- NUMA-local or replicated images;
- io_uring backend;
- AF_XDP backend.

Exit:

- each experiment has a written hypothesis, benchmark result, and rollback
  decision;
- no experiment becomes default without broad evidence.

## Validation Commands

Before implementation starts:

```sh
python3 scripts/check-doc-hygiene.py
python3 scripts/check-unsafe-boundaries.py
python3 scripts/check-unsafe-prone-dependencies.py
git diff --check
```

For every code phase:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-functional-requirement-references.py
python3 scripts/check-unsafe-boundaries.py
python3 scripts/check-unsafe-prone-dependencies.py
git diff --check
```

For packet or unsafe adapter work, add:

```sh
scripts/audit-safe-rust.sh
scripts/check-shell-scripts.sh
```

For performance evidence, retain the benchmark command, generated metric files,
packet-loss counters, and environment metadata with the release evidence
handoff process. A benchmark without hardware, kernel, NIC, build hash, query
mix, and zone-shape metadata is not useful for promotion decisions.

The initial in-tree prototype benchmark is:

```sh
OXIDEDNS_ZONE_IMAGE_BENCH_RECORDS=10000 \
OXIDEDNS_ZONE_IMAGE_BENCH_STRESS_CANDIDATES=2000 \
OXIDEDNS_ZONE_IMAGE_BENCH_ITERATIONS=200000 \
scripts/benchmark-zone-image-prototype.sh
```

It compares the explicit `ZoneSnapshot::offline_oracle()` direct-positive
offline oracle against the `ZoneImage::lookup_exact_plan` handle path for a
generated flat authoritative zone. It also validates a mixed semantic query set
covering direct positive, CNAME, wildcard, referral/glue, NODATA, NXDOMAIN,
DNAME behavior, and an opaque unknown RR type before timing both the current
oracle path and the `ZoneImage` semantic path. The packet validator also checks
positive EDNS
option handling for NSID, DNS Cookie, and padding, signed DO handling for the
covered corpus, plus boundary coverage for full QTYPE ANY, signed positive DO,
signed NODATA DO, UDP truncation, EDE not-ready responses, and varied
no-EDNS/EDNS UDP payload ceilings before timing the gated packet path. A
deterministic hot-query shape
also exercises 90 percent repeated `host0` A queries and 10 percent spread
queries across the generated zone at both lookup and packet layers. A weighted
reference trace fixture in
`crates/oxidedns-core/examples/zone_image_reference_trace.tsv` covers repeated
positive A queries, spread positives, CNAME, wildcard, referral, NODATA,
NXDOMAIN, DNAME, opaque unknown RDATA, large EDNS TXT, and signed DO packets.
The output is tab-separated metrics for schema version, build and host
metadata, query-mix labels, trace path, compile time, ns/query, mismatch count,
record/item counts, node/edge/RRset counts, and hot/cold byte estimates. By
default the script also writes the retained TSV to
`target/zone-image-bench/prototype-latest.tsv`.
The benchmark also builds a separate stress zone with many delegation and DNAME
candidate RRsets, then alternates referral-with-glue and DNAME-synthesis
queries to prove that the packed parent-chain path avoids the current
snapshot's global candidate-list scans.
Validate the retained TSV with:

```sh
scripts/check-zone-image-prototype-benchmark.py \
  --output target/zone-image-bench/prototype-check-latest.tsv
```

The checker verifies zero semantic/packet/fallback mismatches, byte and count
parity for comparable packet and record totals, required boundary packet
coverage including signed positive and signed NODATA DO responses, and
configured performance ratios for exact lookup, mixed planning/wire emission,
packet response, EDNS optioned response, and delegation/DNAME stress paths.

Current retained prototype sample from 2026-05-29 on this development machine,
after the exact lookup allocation removal, compact delegation/DNAME indexes,
direct RR-section wire emission, the gated packet response path, arena-wire
owner/RDATA name compression, signed-zone RRSIG/NSEC/NSEC3 indexes, and
publication-time `ZoneImage` compilation, and the `ArcSwap`-published
`ZoneStore` directory with an exact-origin map plus QNAME suffix index. Runtime
serving reads a `PublishedZone` handle and answers from the compiled
`ZoneImage`; the retained `ZoneSnapshot` behind that handle is for safe
ingestion, transfer/catalog state, and offline comparison rather than a live
query-serving rollback. The query path no longer compiles through a query-time
shadow cache, scans all zones, or performs a second store lookup. The gated
packet path uses a
lightweight lookup-metrics observer so normal responses do not materialize
`ResourceRecord` values only to record termination counters, and semantic
planning skips answer materialization when the answer RR type cannot produce
additional address records. Public `ZoneImage` materialization helpers have
also been removed; tests and benchmarks compare plan summaries or immutable
wire output instead of rebuilding temporary `LookupResult` values from the
image. Publication-time `ZoneImage` compilation also avoids
`ZoneSnapshot::records()` now: the compiler iterates snapshot RRsets and RDATA
directly through crate-private builder APIs, so it does not build a full
temporary `Vec<ResourceRecord>` before regrouping into immutable image RRsets.
The retained `target/zone-image-bench/compile-from-rrset-iter.tsv` run passed
with zero semantic and packet mismatches, byte parity, compile time `15.952 ms`,
and stress compile time `16.488 ms`. Catalog-zone reconciliation now follows
the same boundary discipline for management work: RFC 9432 version TXT and
member PTR parsing scans borrowed snapshot RRsets/RDATA instead of
materializing the full snapshot through `ZoneSnapshot::records()`. This is
guarded by the invariant audit and focused catalog tests rather than packet
benchmark evidence. Whole-snapshot `ResourceRecord` materialization is also
crate-internal and transfer-named now: `ZoneSnapshot::transfer_records()` is
reserved for IXFR state rebuilds instead of exposed as a generic serving-style
API. The follow-up
`target/zone-image-bench/compile-borrowed-rrset-rdata.tsv` run keeps that
boundary and removes the temporary `BTreeMap<RrsetGroupKey, Vec<Vec<u8>>>`:
the compiler sorts borrowed RRset references for deterministic image order,
sorts borrowed RDATA slices per RRset, and only copies payload bytes into the
final immutable arenas. It passed with zero semantic and packet mismatches,
byte parity, compile time `5.802 ms`, and stress compile time `7.086 ms`. The
current retained `target/zone-image-bench/compile-owner-key-reuse.tsv` run then
reuses each sorted canonical owner key for the builder's RRset index insertion
instead of rebuilding the same canonical string per compiled RRset; it passed
the checker with zero semantic and packet mismatches, byte parity, compile time
`5.444 ms`, and packet ratios within the local gates. The follow-up
`target/zone-image-bench/attach-inline-label-key.tsv` run removes the owned
reversed label vector previously built for every RRset attachment and
single-name target node-hint walk. The builder now borrows relative labels,
walks them in reverse, and uses inline lowercase lookup keys for existing trie
edges, allocating a `Vec<u8>` only when inserting a new edge. It passed the
checker with zero semantic and packet mismatches, byte parity, compile time
`5.337 ms`, and stress compile time `7.998 ms`. A follow-up owner-bucket RRset
index experiment was measured and rejected at
`target/zone-image-bench/owner-bucket-rrset-index-rejected.tsv`: it avoided
owned tuple lookup keys during relation precompute, but regressed compile time
to `8.291 ms`, so the tuple-key index was kept. A narrower relation owner-key
clone-unroll experiment was also rejected at
`target/zone-image-bench/relation-owner-key-clone-unroll-rejected.tsv`: the
checker passed with zero mismatches and byte parity, but delegation/DNAME
stress compile time regressed to `9.654 ms` versus the recent retained
`minimal-any-single-additional-span` run's `6.105 ms`. The
direct answer emitter is attempted before the generic
section-counting pass, and the common single-RRset hot path now writes final DNS
header counts before copying validated RRset body chunks. The direct-copy eligibility now follows the current
composer: it rejects RR types whose RDATA is rewritten for DNS name
compression, but admits opaque and unknown RR types after byte-for-byte
validation. The response composer also writes question names directly from
parsed labels and registers the already-written question slice with the wire
compressor, avoiding an extra QNAME wire allocation in both the direct emitter
and generic ZoneImage composer. Packet question parsing stores the consumed
question wire length instead of copying the original question wire into a
per-query buffer; compressed-QNAME tests keep section offsets tied to the
compressed length while responses are re-encoded from parsed labels. ZoneImage
response capacity sizing and the shared response-prefix helper reuse that
stored parsed length rather than walking the question labels again; the
retained `target/zone-image-bench/question-wire-len-reuse.tsv` run passed its
checker with zero packet mismatches and unchanged response bytes. Canonical
lowercase wire-name compression suffix probes now borrow the already validated
wire suffix, while mixed-case names and new compression entries still
canonicalize into owned suffix keys. Parsed question-label compressor seeding
uses the same shape: already-lowercase QNAME suffixes copy parsed label bytes
directly into the inline suffix-key table, while mixed-case QNAMEs keep the
canonicalizing path. The retained
`target/zone-image-bench/question-compression-lowercase-label-key-fast-path.tsv`
checker passed with zero packet mismatches and byte parity. The follow-up
`target/zone-image-bench/question-compression-carried-lowercase-qname.tsv`
carries the parsed QNAME's lowercase state on `Question`, so each registered
question suffix can reuse that fact instead of rescanning the suffix to prove
the same lowercase property. The follow-up
`target/zone-image-bench/question-parse-carried-lowercase-qname.tsv` moves that
proof into the DNS name parser walk used by `Question::parse`, avoiding a
separate post-parse scan of parsed labels before composer seeding. The retained
`target/zone-image-bench/question-parse-inline-pointer-tracking.tsv` run then
keeps compressed-name pointer loop tracking inline with
`SmallVec<[usize; 4]>`, so ordinary compressed QNAME parsing and malformed
pointer checks do not need a heap-backed pointer scratch vector while carrying
the same lowercase-name proof forward. This is narrow parser/composer
bookkeeping cleanup, not response-template completion.
Answer order tracking is lazy: direct positive plans record only their RRset
list, while synthesized-answer paths populate a small ordering list with
indexes into the stored synthesized answers only when interleaving is required.
Delegation and DNAME discovery now walk the packed name graph's closest
existing node and parent chain instead of scanning global candidate RRset
lists. Ordinary IN-class queries also carry compiled nearest-delegation and
nearest-DNAME policy handles inside each `NameNode`; inherited DNAME is derived
from the parent node when exact-owner DNAME must be skipped. The response
planner and direct-answer guard can avoid repeated ancestor walks on the common
class. QCLASS=ANY can use those IN handles only when the compiled image proves
all delegation and DNAME policy RRsets are IN-class; images containing non-IN
policy data keep the conservative scan fallback.
High-fanout nodes also carry their generated child-hash side-index handle, so
label lookup can probe hash slots without first searching the side-index table.
The hash slot arena stores `u16` edge offsets, preserving the retained 2x slot
policy while avoiding a wider `u32` value for per-node offsets. Retained
benchmark checks assert the reported child-hash slot bytes equal slot count
times two for both the main and delegation/DNAME stress fixtures. Child-hash
label equality also checks lowercase query labels directly before falling back
to case-insensitive comparison, with
`target/zone-image-bench/child-hash-direct-label-eq.tsv` retained as isolated
high-fanout lookup evidence.
The runtime serving path first tries a guarded exact direct-answer candidate
before full semantic planning; the candidate is allowed only when the packed
ancestor policy proves no referral, ancestor DNAME, or additional-address processing can
change the answer. The direct emitter then compares the RRset owner to the
question once and uses the stored owner-wire length while copying each RR,
avoiding repeated owner-name parsing for multi-RDATA direct answers.
Additional-data planning for ordinary
NS/MX/SRV/NAPTR/SVCB/HTTPS answers and delegation-glue discovery now parses
targets directly from immutable RDATA arenas. Wildcard owner substitution keeps
RRset handles plus stored owner-wire overrides, while DNAME CNAME synthesis
stores only owner wire and RDATA instead of a full `ResourceRecord`:
CNAME/DNAME indirection endpoint planning also avoids the generic
additional-data planner when the endpoint cannot introduce address targets. A
chain that ends out of zone, at an in-zone missing name, at a malformed CNAME
target, or at a final non-target RR type now returns the plan directly; a final
target-bearing RRset such as SRV appends its precomputed relation span directly.
The retained `target/zone-image-bench/indirection-additional-gate.tsv` run keeps
zero semantic and packet mismatches and is treated as planner-pass cleanup
rather than packet-path speed evidence.
Exact, wildcard, and CNAME/DNAME endpoint plans with one target-bearing answer
RRset now append that RRset's compiled additional-address relation span directly
instead of rebuilding a per-query dedupe set. The relation compiler deduplicates
repeated target-address RRsets inside the span; the retained
`target/zone-image-bench/single-answer-additional-span.tsv` run keeps zero
semantic and packet mismatches for this bookkeeping cleanup.
Those single-answer paths now also use the compiled additional-address relation
bitmap as the entry gate, so target-bearing RRsets with no retained address
relations return without touching relation spans. The retained
`target/zone-image-bench/single-answer-relation-bitmap.tsv` run passed
`target/zone-image-bench/single-answer-relation-bitmap-check.tsv` with zero
semantic and packet mismatches for this follow-up.
The follow-up `target/zone-image-bench/single-answer-additional-type-gate.tsv`
narrows the same single-answer helper further: RR types that cannot legally have
address additionals, such as A/AAAA/TXT, now return before the relation bitmap
or relation-span lookup, while target-bearing NS/MX/SRV/NAPTR/SVCB/HTTPS answers
keep the compiled relation path. The checker passed at
`target/zone-image-bench/single-answer-additional-type-gate-check.tsv` with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.162`,
mixed wire ratio `0.184`, mixed packet ratio `1.004`, hot packet ratio `1.006`,
trace packet ratio `1.003`, optioned packet ratio `1.017`, boundary packet ratio
`1.013`, and UDP-ceiling packet ratio `1.004`.
RRsets now reference compact relation-span descriptors instead of carrying only
a mixed relation start/count. Those descriptors store same-kind offsets for
single-name targets, RRSIGs, referral glue, delegation DNSSEC proof relations,
and additional-address relations, letting query-time consumers jump directly to
the precomputed slice. The retained
`target/zone-image-bench/relation-span-offset-table-final.tsv` run keeps zero
semantic and packet mismatches; mixed planning and wire ratios improved to
`0.121` and `0.147`, while packet ratios remain mixed, so this is planner and
composer metadata discipline rather than broad packet-path speed evidence.
Signed-referral DNSSEC proof selection now reads the descriptor's delegation
proof offset directly instead of requesting separate DS and NSEC same-kind
subspans. The retained
`target/zone-image-bench/relation-span-direct-delegation-proof.tsv` run keeps
zero semantic and packet mismatches and is retained as narrow referral planner
cleanup inside the local gates.
CNAME/DNAME first-hop target lookup now also reads the descriptor's
single-name target offset directly instead of asking the generic subspan helper
for the one expected relation. The retained
`target/zone-image-bench/relation-span-direct-single-name-target.tsv` run keeps
zero semantic and packet mismatches, unchanged image memory, mixed packet ratio
`0.988`, hot packet ratio `0.987`, and UDP-ceiling packet ratio `0.994`; it is
retained as narrow CNAME/DNAME planner metadata cleanup inside the local gates.
Live CNAME continuation is now handle-only as well:
`target/zone-image-bench/cname-handle-only-resolution.tsv` removes the
name-based fallback lookup from `resolve_cname_at`, since exact, wildcard, and
chained CNAME callers already have the CNAME RRset handle. The broader
name-based RRset lookup helper is kept only for tests.
Additional-address, referral-glue, and RRSIG consumers now also read their
explicit relation-span offsets directly; the generic relation-kind helper is
test-only inspection surface. The retained
`target/zone-image-bench/relation-span-direct-relation-consumers.tsv` run keeps
zero semantic and packet mismatches, unchanged image memory, mixed planning and
wire ratios of `0.125` and `0.147`, and a UDP-ceiling packet ratio of `0.993`.
It is retained as relation-consumer discipline and warning cleanup inside the
local gates, not as broad packet-path speed evidence.
DNSSEC augmentation now also has a compile-time image capability bit. If an
image has no NSEC/NSEC3 ranges and no RRSIG or delegation-DNSSEC relation spans,
a DO-bit request returns the semantic plan without constructing augmentation
state or walking denial/signature hooks. The retained
`target/zone-image-bench/dnssec-unsigned-augmentation-skip.tsv` run keeps zero
semantic and packet mismatches; it is no-regression evidence for the mixed
fixture plus direct focused coverage for unsigned images.
That coarse bit is now split into denial, referral, and RRSIG capability gates,
also computed at compile time. DO-bit augmentation skips denial proof work when
no NSEC/NSEC3 ranges exist, referral proof work when no delegation proof or
NSEC3 fallback can add records, and selected-RRSIG walks when no RRSIG relation
span exists. The retained
`target/zone-image-bench/dnssec-capability-gates.tsv` run keeps zero semantic
and packet mismatches for this branch-pruning cleanup.
The same capability split now controls augmentation dedupe-state seeding:
RRSIG-only images skip the authority RRset clone used by denial/referral proof
insertion, and denial/referral-only images skip selected-record identity scans.
The retained `target/zone-image-bench/dnssec-state-seeding-gates.tsv` run keeps
zero semantic and packet mismatches for this narrower per-query bookkeeping
cleanup.
The per-query NSEC3 hash cache now keeps one parameter set inline, matching the
common single-parameter signed-zone path while allowing unusual multi-parameter
images to spill. The retained
`target/zone-image-bench/nsec3-hash-cache-inline-one.tsv` run passed
`target/zone-image-bench/nsec3-hash-cache-inline-one-check.tsv` with zero
semantic and packet mismatches and unchanged response bytes.
Authority proof dedupe is also now lazy within enabled denial/referral paths:
the authority RRset set is cloned only when the first DNSSEC proof RRset is
actually inserted. The retained
`target/zone-image-bench/dnssec-lazy-authority-dedupe-seed.tsv` run keeps zero
semantic and packet mismatches, and focused tests keep the existing SOA dedupe
case covered.
The remaining authority RRset dedupe clone has since been removed: proof
insertion checks the existing authority section directly and tracks only proof
RRsets appended during augmentation. The retained
`target/zone-image-bench/dnssec-authority-dedupe-clone-free.tsv` run keeps zero
semantic and packet mismatches, unchanged image memory, mixed planning and wire
ratios of `0.122` and `0.152`, and a UDP-ceiling packet ratio of `0.999`.
The denial-candidate gate now also uses a short-circuit answer-presence check
instead of summing answer RRset record counts. Positive DO-bit responses in
DNSSEC-capable zones can prove that NODATA/NXDOMAIN denial work is irrelevant
after the first answer record is observed, while exact section counting remains
in the composer accounting path. The retained
`target/zone-image-bench/dnssec-answer-presence-denial-gate.tsv` run keeps zero
semantic and packet mismatches for this branch cleanup.
The same classifier now derives answer presence from the response plan shape
instead of reading compiled RRset record counts. This relies on the compile
invariant that image RRsets are built from grouped snapshot records and are
non-empty; the builder debug-asserts that invariant, and the count helpers are
test-only. The retained
`target/zone-image-bench/dnssec-answer-presence-plan-shape.tsv` run keeps zero
semantic and packet mismatches, byte parity, mixed planning and wire ratios of
`0.122` and `0.149`, and a UDP-ceiling packet ratio of `0.991`.
That answer-presence classifier is now explicit plan state. Answer insertion
paths set the bit for direct RRsets, wildcard owner overrides, synthesized DNAME
CNAMEs, and selected DNSSEC answer records, so denial/wildcard DNSSEC
augmentation reads the bit instead of re-deriving the shape. The retained
`target/zone-image-bench/plan-answer-presence-bit.tsv` run passed
`target/zone-image-bench/plan-answer-presence-bit-check.tsv` with zero semantic
and packet mismatches, byte parity, mixed planning ratio `0.131`, mixed wire
ratio `0.150`, and packet ratios inside the local gates.
Those per-query plan booleans now share one compact flag byte: answer presence,
authority SOA presence, wildcard synthesis, DNSSEC augmentation, and NSEC3 cap
state stay explicit while avoiding separate boolean fields on every
`ZoneImageLookupPlan`. The retained
`target/zone-image-bench/plan-state-flags.tsv` run passed
`target/zone-image-bench/plan-state-flags-check.tsv` with zero semantic and
packet mismatches, byte parity, mixed planning ratio `0.113`, mixed wire ratio
`0.138`, and packet ratios inside the local gates.
The direct-answer composer shape is now cached in the same plan flag byte for
simple exact-answer plans. The direct response builder still validates
direct-copy RRset eligibility and owner matching, but no longer re-derives the
section shape before those checks. The retained
`target/zone-image-bench/direct-answer-plan-flag.tsv` run passed
`target/zone-image-bench/direct-answer-plan-flag-check.tsv` with zero semantic
and packet mismatches, byte parity, mixed planning ratio `0.116`, mixed wire
ratio `0.137`, and packet ratios inside the local gates.
The plan's authoritative/referral state is now also stored in that flag byte
instead of a separate boolean field. The retained
`target/zone-image-bench/authoritative-plan-flag.tsv` run passed
`target/zone-image-bench/authoritative-plan-flag-check.tsv` with zero semantic
and packet mismatches, byte parity, mixed planning ratio `0.117`, mixed wire
ratio `0.143`, and packet ratios inside the local gates.
The plan's inline answer-RRset handle storage is also narrowed to one handle,
matching the common concrete-answer shape while allowing QTYPE=ANY plans to
spill only when they need multiple handles. The retained
`target/zone-image-bench/answer-rrsets-inline-one.tsv` run passed
`target/zone-image-bench/answer-rrsets-inline-one-check.tsv` with zero semantic
and packet mismatches, byte parity, mixed planning ratio `0.119`, mixed wire
ratio `0.146`, and packet ratios inside the local gates.
The plan's inline authority-RRset storage is narrowed to two handles, covering
the common SOA plus one proof/referral shape and spilling only for larger DNSSEC
proof sections. The retained
`target/zone-image-bench/authority-rrsets-inline-two.tsv` run passed
`target/zone-image-bench/authority-rrsets-inline-two-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.129`,
mixed wire ratio `0.150`, and packet ratios inside the local gates.
The plan's inline additional-RRset storage is narrowed to four handles, keeping
room for common multi-target additional sections while reducing the previous
eight-handle inline storage. The retained
`target/zone-image-bench/additional-rrsets-inline-four.tsv` run passed
`target/zone-image-bench/additional-rrsets-inline-four-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.125`,
mixed wire ratio `0.151`, and packet ratios inside the local gates.
Selected authority/additional RRSIG handles now keep one inline slot per
section, matching the common direct section-signature case while spilling only
for larger signed sections. The retained
`target/zone-image-bench/selected-section-inline-one.tsv` run passed
`target/zone-image-bench/selected-section-inline-one-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.129`,
mixed wire ratio `0.157`, and packet ratios inside the local gates.
Dynamic synthesized-answer records now also keep one inline slot in the lookup
plan, matching the common DNAME-synthesized CNAME response while spilling only
for uncommon larger synthesized sections. The retained
`target/zone-image-bench/dynamic-answer-inline-one.tsv` run passed
`target/zone-image-bench/dynamic-answer-inline-one-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.124`,
mixed wire ratio `0.145`, and packet ratios inside the local gates.
The later `target/zone-image-bench/synthesized-inline-wire.tsv` run narrows the
same generated-record path by storing common synthesized owner and RDATA wire
buffers inline in each dynamic record entry. Its checker artifact
`target/zone-image-bench/synthesized-inline-wire-check.tsv` passed with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.148`,
mixed wire ratio `0.169`, mixed packet ratio `1.006`, and delegation/DNAME
stress plan/wire ratios of `0.001` and `0.002`.
DNSSEC selected-record dedupe scratch now keeps four inline records, matching
the common small RRSIG augmentation shape while spilling for larger signed
sections. The retained
`target/zone-image-bench/selected-record-dedupe-inline-four.tsv` run passed
`target/zone-image-bench/selected-record-dedupe-inline-four-check.tsv` with
zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.119`, mixed wire ratio `0.145`, and packet ratios inside the local gates.
NSEC and NSEC3 proof helper entry is also gated by compiled proof-family
presence. NSEC-only images skip NSEC3 helper state setup, NSEC3-only images skip
empty NSEC range scans, exact NODATA skips the exact-name NSEC probe when the
image has no NSEC proof family, and NXDOMAIN/wildcard callsites only enter each
proof family when that family is present in the compiled image. The retained
`target/zone-image-bench/dnssec-denial-proof-family-callsite-gates.tsv` run
passed
`target/zone-image-bench/dnssec-denial-proof-family-callsite-gates-check.tsv`
with zero trace and boundary packet mismatches, hot bytes/record `106.364`,
bytes/record `174`, stress bytes/record `256`, mixed planning ratio `0.150`,
mixed packet ratio `0.998`, hot packet ratio `1.026`, trace packet ratio
`1.017`, boundary packet ratio `1.006`, and UDP-ceiling packet ratio `1.017`.
This is retained as partial-DNSSEC branch pruning, not as a broad packet-speed
claim.

CNAME/DNAME loop tracking now keeps both the borrowed original query name and,
when exact lookup found one, the original compiled node. Existing in-zone
targets compare node IDs for loop detection; generated missing and out-of-zone
targets compare compiled or synthesized target wire directly to the original
query labels without constructing canonical-key strings or using a second
`DomainName` label-vector comparison helper.
The visited-node scratch for that loop tracking now keeps four inline node IDs,
matching common short CNAME/DNAME chains while spilling only for longer chains.
The retained `target/zone-image-bench/chain-visited-node-inline-four.tsv` run
passed `target/zone-image-bench/chain-visited-node-inline-four-check.tsv` with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.130`,
mixed wire ratio `0.156`, and packet ratios inside the local gates.

| Metric | Value |
| --- | ---: |
| `benchmark_schema_version` | 1 |
| `benchmark_kind` | `in_process_zone_image_prototype` |
| `benchmark_build_profile` | `profiling` |
| `benchmark_git_revision` | `2908b3898609` |
| `benchmark_git_dirty` | `true` |
| `benchmark_kernel` | `Linux 7.0.3-1-MANJARO x86_64 GNU/Linux` |
| `benchmark_rustc` | `rustc 1.95.0 (59807616e 2026-04-14)` |
| `benchmark_rust_target` | `x86_64-unknown-linux-gnu` |
| `benchmark_cpu_model` | `AMD Ryzen 9 9950X3D 16-Core Processor` |
| `benchmark_network_device` | `not-applicable-in-process-benchmark` |
| `benchmark_artifact` | `target/zone-image-bench/prototype-latest.tsv` |
| `benchmark_trace` | `crates/oxidedns-core/examples/zone_image_reference_trace.tsv` |
| `query_mix_direct` | `flat_positive_a` |
| `query_mix_hot_direct` | `repeated_host0_90_percent_spread_10_percent` |
| `query_mix_trace` | `weighted_reference_trace_tsv` |
| `query_mix_mixed` | `positive_a,cname,wildcard,referral_glue,nodata,nxdomain,dname,opaque_unknown` |
| `query_mix_optioned` | `edns_nsid,dns_cookie,edns_padding` |
| `query_mix_boundary` | `qtype_any_full,dnssec_do,response_build_truncation` |
| `query_mix_udp_ceiling` | `no_edns_512,edns_payload_512,edns_payload_1232,edns_payload_4096` |
| `query_mix_delegation_dname_stress` | `referral_glue,dname_synthesis` |
| `serving_gate` | `zone_image_without_snapshot_rollback` |
| Records | 10,000 |
| Delegation/DNAME stress candidates | 2,000 |
| Iterations | 200,000 |
| Hot direct query cases | 100 |
| Hot packet query cases | 100 |
| Trace packet query cases | 84 |
| Mixed query cases | 8 |
| Delegation/DNAME stress query cases | 200 |
| `mixed_validation_mismatches` | 0 |
| `delegation_dname_stress_validation_mismatches` | 0 |
| `mixed_packet_validation_mismatches` | 0 |
| `hot_packet_validation_mismatches` | 0 |
| `trace_packet_validation_mismatches` | 0 |
| `optioned_packet_cases` | 3 |
| `optioned_packet_validation_mismatches` | 0 |
| `boundary_packet_cases` | 3 |
| `boundary_packet_validation_mismatches` | 0 |
| `udp_ceiling_packet_cases` | 5 |
| `udp_ceiling_packet_validation_mismatches` | 0 |
| `ede_fallback_packet_cases` | 2 |
| `ede_fallback_packet_validation_mismatches` | 0 |
| `zone_image_compile_ms` | 9.643 |
| `zone_image_delegation_dname_stress_compile_ms` | 7.583 |
| `current_lookup_ns_per_query` | 149.171 |
| `zone_image_exact_lookup_ns_per_query` | 77.420 |
| `current_hot_lookup_ns_per_query` | 133.774 |
| `zone_image_hot_exact_lookup_ns_per_query` | 53.379 |
| `current_mixed_response_ns_per_query` | 451.637 |
| `zone_image_mixed_plan_ns_per_query` | 264.775 |
| `zone_image_mixed_wire_ns_per_query` | 281.062 |
| `current_delegation_dname_stress_response_ns_per_query` | 89,382.274 |
| `zone_image_delegation_dname_stress_plan_ns_per_query` | 634.491 |
| `zone_image_delegation_dname_stress_wire_ns_per_query` | 701.321 |
| `current_mixed_packet_ns_per_query` | 1,405.084 |
| `zone_image_mixed_packet_ns_per_query` | 753.901 |
| `current_hot_packet_ns_per_query` | 567.413 |
| `zone_image_hot_packet_ns_per_query` | 211.284 |
| `current_trace_packet_ns_per_query` | 1,636.163 |
| `zone_image_trace_packet_ns_per_query` | 505.872 |
| `current_optioned_packet_ns_per_query` | 703.985 |
| `zone_image_optioned_packet_ns_per_query` | 291.758 |
| `current_mixed_packet_bytes` | 14,750,000 |
| `zone_image_mixed_packet_bytes` | 14,750,000 |
| `current_hot_packet_bytes` | 10,054,000 |
| `zone_image_hot_packet_bytes` | 10,054,000 |
| `current_trace_packet_bytes` | 17,219,111 |
| `zone_image_trace_packet_bytes` | 17,219,111 |
| `current_optioned_packet_bytes` | 17,333,324 |
| `zone_image_optioned_packet_bytes` | 17,333,324 |
| `zone_image_mixed_wire_bytes` | 14,925,000 |
| `current_delegation_dname_stress_record_count` | 500,000 |
| `zone_image_delegation_dname_stress_plan_item_count` | 500,000 |
| `zone_image_delegation_dname_stress_wire_record_count` | 500,000 |
| `zone_image_nodes` | 10,013 |
| `zone_image_edges` | 10,012 |
| `zone_image_rrsets` | 10,013 |
| `zone_image_records` | 10,033 |
| `zone_image_hot_bytes` | 761,144 |
| `zone_image_cold_bytes` | 680,154 |
| `zone_image_bytes_per_record` | 143 |
| `zone_image_delegation_dname_stress_nodes` | 10,002 |
| `zone_image_delegation_dname_stress_edges` | 10,001 |
| `zone_image_delegation_dname_stress_rrsets` | 8,003 |
| `zone_image_delegation_dname_stress_records` | 8,003 |
| `zone_image_delegation_dname_stress_hot_bytes` | 688,184 |
| `zone_image_delegation_dname_stress_cold_bytes` | 715,614 |
| `zone_image_delegation_dname_stress_bytes_per_record` | 175 |

The retained prototype check artifact
`target/zone-image-bench/prototype-check-latest.tsv` passed with:

| Check Metric | Value |
| --- | ---: |
| `exact_lookup_ratio` | 0.486 |
| `hot_exact_lookup_ratio` | 0.380 |
| `mixed_plan_ratio` | 0.595 |
| `mixed_wire_ratio` | 0.644 |
| `mixed_packet_ratio` | 0.569 |
| `hot_packet_ratio` | 0.348 |
| `trace_packet_ratio` | 0.388 |
| `optioned_packet_ratio` | 0.414 |
| `delegation_dname_stress_plan_ratio` | 0.007 |
| `delegation_dname_stress_wire_ratio` | 0.008 |

Additional retained signed-boundary packet coverage from 2026-05-31 is stored
at `target/zone-image-bench/signed-boundary-packet-coverage.tsv` and passed
`scripts/check-zone-image-prototype-benchmark.py --input
target/zone-image-bench/signed-boundary-packet-coverage.tsv`. This run requires
`query_mix_boundary` coverage for
`qtype_any_full,dnssec_positive_do,dnssec_nodata_do,response_build_truncation`,
uses 4 boundary packet cases, records zero boundary validation mismatches, and
keeps boundary packet byte parity while measuring a local boundary packet ratio
of `1.004` against the offline snapshot oracle. It is retained as evidence that
the local benchmark boundary set now contains real signed positive and signed
NODATA DO packet responses, not only an unsigned response with the DO bit set.

Interpretation: direct exact handle lookup is faster than the current snapshot
path on this flat-zone sample. The mixed semantic plan path is also faster than
the current materialized lookup because the packed name graph avoids global
delegation and DNAME candidate scans. The former temporary
`ResourceRecord` materialization adapter is no longer part of `ZoneImage`'s
public comparison surface; retained parity checks now compare plan summaries,
immutable wire sections, and packet bytes. Direct RR-section emission from
handles and wire arenas keeps most of the plan-path gain, while the served
negative authority path now uses precomputed SOA negative TTL instead of
reparsing SOA RDATA for each packet. Generic ZoneImage responses also pre-size
their response buffers from plan wire bounds instead of relying on a small
fixed starting capacity. The current accounting path also reads immutable
`BlobRange` lengths directly when computing RRset and selected-record wire
upper bounds, avoiding arena slicing whose only purpose was a length lookup.
Relation lookups use the existing contiguous relation-kind order to scan only
same-kind subspans for additional-address, referral-glue, RRSIG, single-name
target, and signed-referral DS/NSEC proof relations, without adding per-kind
offsets to the hot image structs. The subspan finder uses one direct index scan
over the per-RRset relation slice, which keeps the query-time helper small while
preserving the compact single-span relation layout. The retained
`target/zone-image-bench/relation-kind-subspan-consumers.tsv` run keeps byte
parity and zero validation/packet mismatches for that consumer cleanup. The
signed-referral DNSSEC proof selector now uses one scan of the referral RRset's
relation span to find either precomputed DS or NSEC proof relation, rather than
asking for both same-kind subspans separately. The retained
`target/zone-image-bench/signed-referral-dnssec-single-relation-scan.tsv` run
keeps byte parity and zero validation/packet mismatches, and is retained as
narrow signed-referral planner cleanup. Signed-referral relation compilation
also builds the DS/NSEC owner lookup key directly from stored uncompressed NS
owner wire and compares apex NS owners directly from wire. The retained
`target/zone-image-bench/signed-referral-owner-wire-no-parse.tsv` run passed
`target/zone-image-bench/signed-referral-owner-wire-no-parse-check.tsv` with
zero semantic and packet mismatches, byte parity, image bytes per record
`174.000`, stress bytes per record `256.000`, mixed planning ratio `0.128`,
mixed wire ratio `0.147`, and mixed packet ratio `1.011`. This is builder-side
relation metadata hygiene, not a claimed query-path speedup. Referral-glue
relation compilation applies the same no-parse rule to delegation-owner suffix
checks: it compares glue targets against stored uncompressed delegation owner
wire and rejects malformed owner wire instead of rebuilding a `DomainName`.
The retained `target/zone-image-bench/referral-glue-owner-wire-no-parse.tsv`
run passed
`target/zone-image-bench/referral-glue-owner-wire-no-parse-check.tsv` with
zero semantic and packet mismatches, byte parity, image bytes per record
`174.000`, stress bytes per record `256.000`, mixed planning ratio `0.134`,
mixed wire ratio `0.156`, and mixed packet ratio `1.010`. This is builder-side
relation metadata hygiene, not a claimed query-path speedup. The follow-up
`target/zone-image-bench/relation-target-wire-no-parse.tsv` extends that
discipline to all additional-address target-bearing relation compilation:
NS/MX/SRV/NAPTR/SVCB/HTTPS target names are borrowed as validated wire slices,
suffix checks run directly on wire, and A/AAAA relation lookup uses direct
canonical owner-wire keys instead of target `DomainName` values. Its checker
artifact `target/zone-image-bench/relation-target-wire-no-parse-check.tsv`
passed with zero semantic and packet mismatches, byte parity, image bytes per
record `174.000`, stress bytes per record `256.000`, mixed planning ratio
`0.146`, mixed wire ratio `0.171`, mixed packet ratio `1.072`, hot packet ratio
`1.168`, trace packet ratio `1.086`, optioned packet ratio `1.049`, boundary
packet ratio `1.008`, and UDP-ceiling packet ratio `1.006`. This is
builder-side relation metadata hygiene, not a claimed query-path speedup.
The subsequent
`target/zone-image-bench/single-name-target-uncompressed-wire.tsv` run keeps
CNAME/DNAME single-name target precompute on whole uncompressed RDATA wire
instead of invoking the generic DNS message-name parser. Its checker artifact
`target/zone-image-bench/single-name-target-uncompressed-wire-check.tsv`
passed with zero semantic and packet mismatches, byte parity, image bytes per
record `174.000`, stress bytes per record `256.000`, mixed planning ratio
`0.142`, mixed wire ratio `0.160`, mixed packet ratio `1.000`, hot packet ratio
`0.923`, trace packet ratio `1.010`, optioned packet ratio `0.945`, boundary
packet ratio `0.985`, and UDP-ceiling packet ratio `0.995`. This is
compile-time target precompute hygiene, not a packet-throughput claim.
Referral-only
DNSSEC proof augmentation
also now returns immediately for authoritative response plans, avoiding an
authority-section NS scan for ordinary positive and negative DNSSEC responses.
The retained `target/zone-image-bench/referral-dnssec-authoritative-skip.tsv`
run keeps byte parity and zero validation/packet mismatches, and is retained as
narrow DNSSEC planner-scan cleanup.
Actual referral plans now carry the delegation NS RRset handle as plan state,
so referral DNSSEC augmentation can jump straight to the precomputed DS/NSEC
relation or NSEC3 fallback for that RRset instead of walking the authority
section to rediscover it. The retained
`target/zone-image-bench/referral-ns-plan-handle.tsv` run passed
`target/zone-image-bench/referral-ns-plan-handle-check.tsv` with zero semantic
and packet mismatches, byte parity, mixed planning ratio `0.114`, mixed wire
ratio `0.139`, and packet ratios inside the local gates.
The follow-up `target/zone-image-bench/referral-dnssec-strict-plan-handle.tsv`
removes the old compatibility scan over authority RRsets when a
non-authoritative plan lacks that referral handle. Actual referral plans now
must carry `referral_ns_rrset`; a focused regression covers the legacy-shaped
plan and the invariant audit guards the no-scan property. The retained checker
`target/zone-image-bench/referral-dnssec-strict-plan-handle-check.tsv` passed
with zero validation/packet mismatches and byte parity: mixed planning ratio
`0.143`, mixed wire ratio `0.166`, mixed packet ratio `1.047`, hot packet ratio
`1.098`, trace packet ratio `1.025`, optioned packet ratio `1.024`, boundary
packet ratio `1.000`, UDP-ceiling packet ratio `0.994`, and delegation/DNAME
stress planning and wire ratios of `0.001` and `0.002`.
The packet composer also keeps the common wire-name compression suffix table inline
and now scans that small table with direct loops for suffix lookup and
registration. It emits exact full-name suffix hits as pointers before label
parsing or temporary offset collection, discovers reusable compression pointers
while validating wire-name label offsets, avoids a second pass over those
offsets before registering newly written suffixes, and does not retain label
offsets after the chosen pointer because those labels cannot be emitted or
registered by the current response. The retained
`target/zone-image-bench/wire-name-exact-suffix-fast-path.tsv` run passed with
zero validation/packet mismatches and byte parity.
A smaller four-entry inline suffix-table experiment was measured and rejected at
`target/zone-image-bench/wire-compressor-inline-four.tsv`. The checker passed
with zero semantic and packet mismatches, but mixed, trace, optioned, boundary,
and UDP-ceiling packet ratios all moved above the current path while no image
bytes or composer work were removed. The compressor therefore keeps the
eight-entry inline suffix table until profiles justify a different fixed-buffer
or template-oriented design.
The delegation/DNAME stress shape validates the main scaling reason for the
packed name graph: the current snapshot path pays about 86 us/query while it
scans 2,000 delegation and 2,000 DNAME candidates, while ZoneImage semantic
planning stays below 1 us/query with byte-equivalent record counts. The gated
packet path is faster than the current packet path in this sample
after replacing its full-lookup observer with a lightweight termination/NSEC3
metrics observer, skipping additional-record materialization for answer types
that cannot reference address targets, skipping the generic additional planner
for exact positive answer RRsets that cannot have address-target additionals,
and adding a direct answer emitter for single opaque-RDATA RRsets whose owner
is the query name. That emitter writes
the answer owner as a normal pointer to the question, copies the pre-encoded
RRset body, and appends the regular OPT encoder for EDNS responses, avoiding
per-record compressor and RDATA materialization work on direct answers whose
RDATA is already copied opaquely by the normal composer. Runtime tests verify
published images are reused for the active snapshot, stale snapshot handles do
not resolve to a new image, a new snapshot for the same zone publishes a new
image, and read-side lookup runs through the published directory handle.

Retained node-policy and child-index evidence in
`target/zone-image-bench/question-wire-len-no-copy.tsv` keeps the same
zero-mismatch stress shape while precomputing ordinary IN-class delegation and
nearest-DNAME policy directly in each `NameNode`. The node stores nearest
delegation and nearest DNAME, then derives inherited DNAME from the parent node
when exact-owner DNAME must be skipped. The final node-emission pass computes
those handles directly, avoiding the previous temporary builder-side policy
vector. High-fanout nodes also store their generated child-hash side-index
handle directly in `NameNode`, avoiding a per-label binary search through the
`child_hashes` table before probing hash slots, and the side-index metadata no
longer carries the stale indexed node id. A later retained cleanup stores child
hash slot values as `u16` edge offsets instead of `u32`, dropping main-zone hot
bytes on the retained 10k-record fixture to `988,468` and bytes per record to
`166` without changing the lookup algorithm. The explicit stats rerun reports
the production child-hash footprint as `32768` main slots / `65536` bytes and
`16384` stress slots / `32768` bytes, with checker assertions for `u16` slot
storage. Child-hash probe equality now checks already-lowercase query labels
directly before falling back to case-insensitive matching; the retained
`target/zone-image-bench/child-hash-direct-label-eq.tsv` run keeps zero
mismatches and measures high-fanout exact lookup ratio `0.101`. The retained
`target/zone-image-bench/child-length-bucket-lookup.tsv` run rejects a
label-length bucket side index (`28.868` ns/query versus sorted `15.740` and
generated hash `10.226`) before it reaches the production layout. The
`target/zone-image-bench/child-last-byte-bucket-lookup.tsv` run similarly
rejects a last-byte bucket side index (`22.049` ns/query versus sorted `15.559`
and generated hash `10.005`) before it reaches the production layout. The
question-wire run also removes the
per-packet question-wire copy from `Question::parse`. The checker artifact
`target/zone-image-bench/question-wire-len-no-copy-check.tsv` reports stress
plan and wire ratios of `0.002`, main-zone hot bytes at `1,052,564`,
stress-zone hot bytes at `1,041,776`, and main/stress hot-byte-per-record
checks of `104.910` and `130.173`. This is retained as allocation and
build/layout cleanup with a measured hot-byte tradeoff, not a packet-path win
claim.

The follow-up `target/zone-image-bench/qclass-any-policy-handles.tsv` keeps that
policy-handle shape conservative for QCLASS=ANY. Builder-derived image flags
allow ANY-class delegation and DNAME checks to reuse the stored IN handles only
when the image has no non-IN NS or DNAME policy RRsets; mixed-class images keep
the scan fallback. The focused node-policy test covers both paths, the invariant
audit checks the flags and planner/direct-answer guards, and the checker
artifact `target/zone-image-bench/qclass-any-policy-handles-check.tsv` reports
zero validation and packet mismatches, byte parity, mixed packet ratio `0.994`,
hot packet ratio `0.997`, trace packet ratio `0.996`, optioned packet ratio
`0.991`, boundary packet ratio `1.035`, UDP-ceiling packet ratio `1.021`, and
delegation/DNAME-stress plan and wire ratios of `0.001`. This is retained as
policy fallback cleanup; the broad packet mix is expected to remain near parity.

The direct-answer delegation guard now uses the same compiled ownership metadata
for the DS-at-delegation exception. The retained
`target/zone-image-bench/direct-delegation-policy-owner.tsv` run compares the
compiled policy RRset owner label count against node depth for IN and safe
QCLASS=ANY images instead of rescanning the current node to decide whether the
delegation handle belongs to the query owner; mixed-class images keep the
fallback scan. The checker artifact
`target/zone-image-bench/direct-delegation-policy-owner-check.tsv` reports zero
validation and packet mismatches, byte parity, hot bytes per record `106.359`,
total bytes per record `174.000`, stress bytes per record `256.000`, mixed
packet ratio `1.050`, hot packet ratio `1.117`, boundary packet ratio `1.215`,
UDP-ceiling packet ratio `1.007`, delegation/DNAME-stress plan ratio `0.001`,
and stress wire ratio `0.002`. This is retained as direct-path policy branch
discipline, not as a packet-speed promotion.

The direct exact-owner packet composer now gates earlier as well:
`target/zone-image-bench/direct-owner-precheck.tsv` compares immutable RRset
owner wire against parsed question labels before allocating or encoding the
direct response, and it reserves EDNS slack only for EDNS responses. The focused
mixed-case direct-answer test verifies that this precheck is still
case-insensitive. The checker artifact
`target/zone-image-bench/direct-owner-precheck-check.tsv` passed with zero
packet mismatches, unchanged image bytes, mixed/hot/trace/optioned/boundary and
UDP-ceiling packet ratios inside the retained gates, and main/stress hot bytes
per record still at `104.910` and `130.173`. This is allocation discipline for
the direct composer, not proof of a broad packet-path win.

The later `target/zone-image-bench/direct-answer-plan-owner-invariant.tsv`
supersedes that redundant owner-wire check for the exact direct path. Direct
plans are private products of exact trie-node lookup with no custom answer,
authority, or additional sections, so the direct view no longer carries owner
wire solely to reparse and compare it against the already parsed question name
before allocation. The focused direct-answer tests, full filtered ZoneImage
test set, invariant audit, and check build passed. The checker artifact
`target/zone-image-bench/direct-answer-plan-owner-invariant-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.129`, mixed wire ratio `0.157`, mixed packet ratio `1.010`, hot packet ratio
`0.976`, trace packet ratio `0.970`, optioned packet ratio `0.934`, boundary
packet ratio `1.025`, UDP-ceiling packet ratio `1.001`,
delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio `0.001`.
This is retained as direct hot-path invariant tightening, not as a broad timing
claim.

The same direct emitter now reserves the compressed answer body it actually
emits instead of the stored full-owner RRset wire. It subtracts repeated stored
owner-wire bytes from the immutable RRset body and adds the two-byte question
pointer emitted for each answer. The retained
`target/zone-image-bench/direct-answer-compressed-capacity.tsv` run keeps byte
parity and zero validation/packet mismatches, with focused helper coverage for
the checked capacity math. This is direct-composer allocation sizing cleanup,
not a replacement for response-template work.

The follow-up `target/zone-image-bench/direct-answer-edns-capacity-hint.tsv`
run reuses the shared `ZoneImage` response-capacity helper for direct
exact-owner answers. EDNS direct responses now reserve for the actual OPT option
shape instead of a fixed 64-byte slack block, while padding-capacity behavior
stays centralized with the generic composer. The focused direct EDNS test keeps
byte parity with the reference response and asserts exact capacity for the NSID
case. The checker artifact
`target/zone-image-bench/direct-answer-edns-capacity-hint-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.144`,
mixed wire ratio `0.169`, mixed packet ratio `0.993`, hot packet ratio `0.960`,
trace packet ratio `0.973`, optioned packet ratio `0.994`, boundary packet
ratio `1.014`, UDP-ceiling packet ratio `1.005`, total image bytes per record
`174.000`, and stress bytes per record `254.000`. This is direct-composer
allocation discipline before transport work.

The next direct cleanup shares the known-count response-prefix helper as well:
`target/zone-image-bench/direct-answer-shared-prefix.tsv` has the direct
exact-owner composer write the DNS header and section counts through the same
`ZoneImage` prefix path as the generic composer. The invariant audit checks for
that shared helper and rejects a separate hand-assembled direct header path. The
checker artifact
`target/zone-image-bench/direct-answer-shared-prefix-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.145`, mixed
wire ratio `0.163`, mixed packet ratio `0.976`, hot packet ratio `0.942`, trace
packet ratio `1.022`, optioned packet ratio `1.030`, boundary packet ratio
`0.996`, UDP-ceiling packet ratio `0.972`, total image bytes per record
`174.000`, and stress bytes per record `254.000`. This is direct-composer header
discipline before transport work, not a throughput claim.

The same direct exact-owner composer now writes the answer count from immutable
RRset metadata instead of incrementing an emitted-record counter and patching
the DNS header after the copy loop. The retained run at
`target/zone-image-bench/direct-answer-compiled-count-header.tsv` passed
`target/zone-image-bench/direct-answer-compiled-count-header-check.tsv`, kept
zero validation mismatches and byte parity, and stayed inside the local packet
ratio gates. This is retained as direct-composer accounting cleanup; it is not
claimed as a broad packet-path win.

The direct composer also fetches copied-answer owner wire, RRset wire, and
record count through one immutable RRset view instead of separate image
metadata lookups. The retained run at
`target/zone-image-bench/direct-answer-single-rrset-view.tsv` passed
`target/zone-image-bench/direct-answer-single-rrset-view-check.tsv`, kept zero
validation mismatches and byte parity, and left image byte counts unchanged.
This is retained as direct metadata-access cleanup inside the local gates, not
as a broad packet-path win.

Direct exact-owner response bodies now append from compiled record/RDATA
metadata instead of parsing immutable RRset wire to skip each stored owner name.
The retained `target/zone-image-bench/direct-answer-compiled-record-body.tsv`
run passed
`target/zone-image-bench/direct-answer-compiled-record-body-check.tsv` with zero
validation mismatches, unchanged response bytes, mixed planning ratio `0.125`,
mixed wire ratio `0.153`, mixed packet ratio `1.000`, hot packet ratio `1.009`,
boundary packet ratio `1.042`, UDP-ceiling packet ratio `1.009`, main bytes per
record `166.000`, and stress bytes per record `246.000`. A full direct-body
materialization experiment was measured but not retained because the duplicate
body storage exceeded the stress fixture's retained total bytes-per-record
ceiling; this kept the cleanup as parse avoidance rather than a premature
template cache.

The follow-up `target/zone-image-bench/direct-answer-view-body-len.tsv` run
carries the emitted direct-answer body length in the selected direct RRset view,
avoiding a second RRset lookup and eligibility check before response allocation.
It passed
`target/zone-image-bench/direct-answer-view-body-len-check.tsv` with zero
validation mismatches, unchanged response bytes, mixed planning ratio `0.123`,
mixed wire ratio `0.148`, mixed packet ratio `1.021`, hot packet ratio `0.991`,
boundary packet ratio `1.009`, UDP-ceiling packet ratio `1.015`, main bytes per
record `166.000`, and stress bytes per record `246.000`. This is retained as a
narrow direct metadata-access cleanup.

The later `target/zone-image-bench/direct-answer-compiled-body-len.tsv` run
moves that emitted body length into compact compiled `ImageRrset` metadata. That
removes the remaining per-query length arithmetic without duplicating full
direct-answer bodies. It passed
`target/zone-image-bench/direct-answer-compiled-body-len-check.tsv` with zero
validation mismatches, unchanged response bytes, mixed planning ratio `0.117`,
mixed wire ratio `0.148`, mixed packet ratio `0.981`, hot packet ratio `1.022`,
boundary packet ratio `1.026`, UDP-ceiling packet ratio `1.022`, main bytes per
record `170.000`, and stress bytes per record `250.000`; this is retained as
historical compact precomputation from a smaller image layout. The current tree
does not keep the emitted-length field because the later
`target/zone-image-bench/direct-answer-emitted-body-len-check.tsv` retest fails
the current `256.000` delegation/DNAME-stress bytes-per-record ceiling.
The retained `target/zone-image-bench/owner-override-direct-body-metrics.tsv`
run then reuses the compiled ownerless direct-copy length in owner-override plan
accounting for direct-copy wildcard answers. This avoids recomputing non-owner
RR bytes from stored full-owner RRset wire on the query path while preserving
the generic fallback for non-direct RDATA shapes. The checker passed at
`target/zone-image-bench/owner-override-direct-body-metrics-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.147`, mixed
wire ratio `0.170`, mixed packet ratio `0.973`, hot packet ratio `0.978`, trace
packet ratio `0.994`, optioned packet ratio `0.979`, boundary packet ratio
`1.015`, and UDP-ceiling packet ratio `1.012`.

The next retained `target/zone-image-bench/direct-answer-view-append-metadata.tsv`
run carries the immutable RRset append metadata in the selected direct RRset
view, so direct answer emission no longer re-indexes the RRset by ID after
preflight. Its checker passed with zero validation mismatches, unchanged
response bytes, mixed planning ratio `0.116`, mixed wire ratio `0.146`, mixed
packet ratio `1.005`, hot packet ratio `1.029`, boundary packet ratio `1.038`,
UDP-ceiling packet ratio `1.035`, main bytes per record `170.000`, and stress
bytes per record `250.000`. This remains a narrow direct-view cleanup, not the
future immutable template/WireArena composer.

The retained `target/zone-image-bench/direct-answer-record-slice-view.tsv` run
then carries the pre-bounds-checked compiled record slice in the selected direct
RRset view. Direct answer emission walks that slice rather than recomputing
record indexes after preflight. It passed
`target/zone-image-bench/direct-answer-record-slice-view-check.tsv` with zero
validation mismatches, unchanged response bytes, mixed planning ratio `0.115`,
mixed wire ratio `0.140`, mixed packet ratio `1.000`, hot packet ratio `1.061`,
boundary packet ratio `1.022`, UDP-ceiling packet ratio `1.007`, main bytes per
record `170.000`, and stress bytes per record `250.000`. This keeps the direct
path cleanup in transient views with no image memory increase.

The retained `target/zone-image-bench/direct-answer-record-prefix-view.tsv` run
then moves the constant compressed-owner/type/class/TTL record prefix into the
selected direct RRset view. Direct answer emission writes that prepared prefix
for each record instead of converting those fields on every append. It passed
`target/zone-image-bench/direct-answer-record-prefix-view-check.tsv` with zero
validation mismatches, unchanged response bytes, mixed planning ratio `0.112`,
mixed wire ratio `0.135`, mixed packet ratio `1.014`, hot packet ratio `0.958`,
trace packet ratio `0.987`, optioned packet ratio `0.999`, boundary packet
ratio `1.047`, UDP-ceiling packet ratio `0.981`, main bytes per record
`170.000`, and stress bytes per record `250.000`. This remains direct-answer
transient-view cleanup with no image memory increase; it does not make the
generic composer a template path.

The retained `target/zone-image-bench/direct-prefix-fixed-fields.tsv` follow-up
keeps that selected-view prefix but builds it from the immutable RRset wire's
already-preencoded TYPE/CLASS/TTL bytes rather than rebuilding those bytes from
scalar RRset metadata when the direct view is selected. Its checker artifact
`target/zone-image-bench/direct-prefix-fixed-fields-check.tsv` passed with zero
validation and packet mismatches, byte parity, main image bytes/record `170`,
stress image bytes/record `250`, mixed planning ratio `0.139`, mixed wire ratio
`0.168`, mixed packet ratio `1.053`, hot packet ratio `1.084`, trace packet
ratio `1.023`, optioned packet ratio `1.037`, boundary packet ratio `1.040`,
UDP-ceiling packet ratio `0.993`, and delegation/DNAME-stress plan and wire
ratios of `0.001` and `0.002`. This is retained as no-growth direct-view
scalar-rebuild cleanup.

A later `target/zone-image-bench/direct-answer-prefix-precompute.tsv`
experiment moved that same 10-byte prefix into every compiled `ImageRrset`.
It kept zero semantic and packet mismatches but failed the retained checker
because the larger hot rrset metadata raised the delegation/DNAME stress image
to `258.000` bytes per record, above the `256.000` ceiling. The code was
reverted; the prefix remains a selected direct-view field rather than
per-RRset image metadata.

A broader transient wire-record view flag was measured and rejected. The
`target/zone-image-bench/wire-record-direct-copy-rdata-view.tsv` experiment
carried the compiled direct-copy RDATA decision through every generic
`ZoneImage` wire-record view so the generic composer could bypass the RDATA
compression match and rdlength patch for opaque records. It preserved zero
validation mismatches and unchanged response bytes, but packet evidence was
weaker than the retained direct-view cleanup: mixed wire ratio `0.158`, mixed
packet ratio `1.026`, hot packet ratio `1.077`, boundary packet ratio `1.016`,
and UDP-ceiling packet ratio `1.016`. The code change was not retained because
it added transient view surface without a measured packet-path win.

Per-record checked RDATA length storage was also measured and rejected. The
`target/zone-image-bench/record-rdata-len-field-candidate.tsv` experiment stored
the already-validated DNS `rdlength` as a `u16` in each compiled `ImageRecord`.
It passed correctness and byte-parity checks, but pushed main bytes per record
to `174.000` and stress bytes per record to `254.000` while mixed packet ratio
was `1.033`, trace packet ratio `1.065`, optioned packet ratio `1.076`, and
only UDP-ceiling improved to `0.966`. The code change was not retained because
that per-record hot metadata nearly consumed the stress memory gate without a
broad packet-path win.

A no-memory `target/zone-image-bench/direct-answer-blob-rdlength-candidate.tsv`
variant was also rejected. It used the compiled RDATA `BlobRange` length for
direct-answer `rdlength` instead of measuring the sliced RDATA bytes. The
checker passed with zero validation mismatches and unchanged response bytes,
but packet evidence was weaker than the retained prefix/slice view: mixed wire
ratio `0.153`, mixed packet ratio `1.009`, hot packet ratio `1.107`, trace
packet ratio `1.038`, optioned packet ratio `1.112`, boundary packet ratio
`1.044`, and UDP-ceiling packet ratio `1.039`.

A compact no-growth variant was then retained. The
`target/zone-image-bench/stored-record-ttl-override-split.tsv` run replaces
stored record RDATA `BlobRange` metadata with a compact `RdataRange` whose
length is the already-validated DNS `u16` rdlength. `ImageRecord` stays the same
size as the old `BlobRange` metadata, so main hot bytes per record remain
`102.491`, total bytes per record remain `170.000`, and stress bytes per record
remain `250.000`. Direct-copy answer emission, selected stored-record emission,
and stored-record TTL-override emission now write the compiled rdlength bytes
instead of performing a per-record fallible length conversion. The common
stored-RRset, selected-record, and owner-override append/visit helpers also no
longer carry an optional TTL override per emitted record; the rare negative-SOA
case uses a separate explicit-TTL helper, and only dynamic synthesized records
stay on the fallible append path. The retained run passed with zero semantic
and packet mismatches, byte parity, mixed planning ratio `0.118`, mixed wire
ratio `0.144`, mixed packet ratio `1.018`, hot packet ratio `0.991`, trace
packet ratio `1.031`, optioned packet ratio `1.019`, boundary packet ratio
`0.999`, and UDP-ceiling packet ratio `1.009`. This is retained as
representation/precomputation cleanup, not as a broad packet-speed claim.

The later
`target/zone-image-bench/authority-soa-ttl-override-gate.tsv` run keeps that
split but also gates authority-section TTL override checks behind the compiled
plan's authority-SOA bit. The common authority append and record-visitor paths
copy or visit immutable RRset wire directly; only plans that already carry an
authority SOA enter the explicit negative-TTL override helper. The retained run
passed
`target/zone-image-bench/authority-soa-ttl-override-gate-check.tsv` with zero
semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
total bytes per record `170.000`, stress bytes per record `250.000`, mixed
planning ratio `0.123`, mixed wire ratio `0.148`, mixed packet ratio `0.997`,
hot packet ratio `1.009`, trace packet ratio `1.013`, optioned packet ratio
`0.992`, boundary packet ratio `1.034`, and UDP-ceiling packet ratio `0.988`.
This is retained as branch isolation and immutable-composer cleanup; it is not
a transport or broad packet-throughput claim.
The retained `target/zone-image-bench/authority-first-soa-fast-path.tsv` run
then narrows the negative-SOA override gate further: `ZoneImageLookupPlan`
carries a compact first-authority-SOA flag, so ordinary negative responses
apply the precomputed SOA TTL override to the first authority RRset and then
copy or visit the remaining authority RRsets without scanning each one for SOA.
Its checker artifact passed with zero validation and packet mismatches, byte
parity, mixed planning ratio `0.142`, mixed wire ratio `0.166`, mixed packet
ratio `0.984`, hot packet ratio `0.994`, trace packet ratio `1.011`, optioned
packet ratio `1.003`, boundary packet ratio `1.027`, UDP-ceiling packet ratio
`1.002`, and delegation/DNAME stress plan and wire ratios of `0.001` and
`0.002`. This is authority-section composer cleanup, not template/WireArena
completion.
The retained `target/zone-image-bench/authority-soa-indexed-emission.tsv` run
then removes the older scanned-SOA fallback by carrying the authority SOA
position in the transient plan. Uncommon authority sections where the SOA is not
first now split around that known index and apply the negative-TTL override
without a per-RRset SOA type check. Its checker artifact
`target/zone-image-bench/authority-soa-indexed-emission-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.148`,
mixed wire ratio `0.168`, mixed packet ratio `0.994`, hot packet ratio `0.997`,
trace packet ratio `0.979`, optioned packet ratio `0.968`, boundary packet
ratio `1.019`, UDP-ceiling packet ratio `0.996`, total image bytes per record
`174.000`, and stress bytes per record `254.000`.

The follow-up `target/zone-image-bench/packed-rdata-direct-enum.tsv` run
collapses the compact RDATA shape tag and the decoded composer enum into one
two-byte `PackedRdataEncoding` value. The runtime wire-record encoder now
matches the precomputed shape directly, keeps the copy-RDATA fast path, and
preserves the existing `ImageRecord`/`RdataRange` size guards. Its checker
artifact `target/zone-image-bench/packed-rdata-direct-enum-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.138`, mixed wire ratio `0.161`, mixed packet ratio `1.007`, hot packet ratio
`1.131`, trace packet ratio `1.051`, optioned packet ratio `1.077`, boundary
packet ratio `1.018`, UDP-ceiling packet ratio `1.011`, total image bytes per
record `174.000`, and stress bytes per record `254.000`. Treat this as
representation cleanup and duplicate-branch removal before transport work, not
as a broad packet-throughput claim.

The follow-up `target/zone-image-bench/soa-rdata-validated-span.tsv` run
removes the remaining defensive second-name span recomputation from the SOA
RDATA compression branch. The compiler still validates the SOA RDATA shape
before storing the packed SOA encoding; packet emission derives the RNAME span
directly from the carried MNAME length and RDATA length with debug assertions
for that invariant. Its checker artifact
`target/zone-image-bench/soa-rdata-validated-span-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.156`,
mixed wire ratio `0.180`, mixed packet ratio `1.043`, hot packet ratio
`1.053`, trace packet ratio `1.000`, optioned packet ratio `1.005`, boundary
packet ratio `1.023`, UDP-ceiling packet ratio `1.022`, total image bytes per
record `174.000`, and stress bytes per record `254.000`. Treat this as SOA
compressed-RDATA invariant cleanup before transport work, not as a broad
packet-throughput claim.

The retained `target/zone-image-bench/soa-rdata-packed-spans.tsv` follow-up
packs both validated SOA wire-name spans into the same two-byte
`PackedRdataEncoding` value. The runtime SOA branch now slices MNAME, RNAME,
and timers from carried spans instead of recomputing the second-name span from
RDATA length while still preserving `ImageRecord` and `RdataRange` size guards.
Its checker artifact `target/zone-image-bench/soa-rdata-packed-spans-check.tsv`
passed with zero semantic and packet mismatches, byte parity, mixed planning
ratio `0.149`, mixed wire ratio `0.172`, mixed packet ratio `1.015`, hot packet
ratio `1.119`, trace packet ratio `1.003`, optioned packet ratio `1.000`,
boundary packet ratio `1.006`, UDP-ceiling packet ratio `1.003`, total image
bytes per record `174.000`, and stress bytes per record `256.000`. Treat this
as compact SOA precompute cleanup, not as a throughput claim.

The retained `target/zone-image-bench/metadata-wire-no-parse.tsv` follow-up
keeps the same direct-wire discipline in validation and compile metadata. Plan
summary validation now builds canonical owner keys through the uncompressed
owner-wire scanner instead of allocating a `DomainName`, and SOA minimum TTL
precompute reads the two leading SOA wire names with `wire_name_len_at()` before
reading the timer fields. Its checker artifact
`target/zone-image-bench/metadata-wire-no-parse-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.143`,
mixed wire ratio `0.165`, mixed packet ratio `1.041`, hot packet ratio
`0.854`, trace packet ratio `1.000`, optioned packet ratio `1.051`, boundary
packet ratio `1.040`, UDP-ceiling packet ratio `0.990`, total image bytes per
record `174.000`, and stress bytes per record `256.000`. Treat this as
metadata and validation-path hygiene, not as a packet-throughput claim.

The later `target/zone-image-bench/dynamic-record-rdlength-infallible.tsv` run
closes the remaining synthesized-record append edge. DNAME-generated CNAME
records still use per-query dynamic plan storage because their owner and target
depend on the query name, but the plan now validates and stores the DNS
`rdlength` bytes when the synthesized record is created. The benchmark append
hook and synthesized-record helper then copy those bytes directly and return a
record count without fallible length conversion. The checker artifact
`target/zone-image-bench/dynamic-record-rdlength-infallible-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.130`, mixed wire ratio `0.152`, mixed packet ratio `0.988`, hot packet ratio
`1.005`, trace packet ratio `0.997`, optioned packet ratio `0.990`, boundary
packet ratio `1.016`, UDP-ceiling packet ratio `1.005`, total image bytes per
record `170.000`, and stress bytes per record `250.000`. Treat this as
append-path discipline before transport work; it is intentionally not a
transport or broad throughput claim.

The follow-up `target/zone-image-bench/synthesized-inline-wire.tsv` keeps the
same dynamic DNAME CNAME semantics but stores common generated owner and target
wire buffers inline in the synthesized record. The focused CNAME/DNAME test
asserts the retained case does not spill either buffer, and the invariant audit
guards the inline field types. The checker artifact
`target/zone-image-bench/synthesized-inline-wire-check.tsv` passed with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.148`,
mixed wire ratio `0.169`, mixed packet ratio `1.006`, hot packet ratio `0.965`,
trace packet ratio `0.988`, optioned packet ratio `0.977`, boundary packet
ratio `1.007`, UDP-ceiling packet ratio `0.969`, stress planning ratio `0.001`,
and stress wire ratio `0.002`. This is generated-record allocation/layout
cleanup before transport-buffer work.

The follow-up
`target/zone-image-bench/indirection-target-wire-loop-check.tsv` carries that
same generated target wire into CNAME/DNAME loop detection. Compiled
single-name targets pass their stored RDATA wire, DNAME-generated targets borrow
the synthesized-answer RDATA wire from the plan, and existing in-zone targets
continue to use node-handle equality. The checker artifact
`target/zone-image-bench/indirection-target-wire-loop-check-check.tsv` passed
with zero validation and packet mismatches, byte parity, mixed planning ratio
`0.147`, mixed wire ratio `0.169`, mixed packet ratio `1.018`, hot packet ratio
`1.024`, trace packet ratio `0.974`, optioned packet ratio `0.938`, boundary
packet ratio `1.010`, UDP-ceiling packet ratio `1.020`, and
delegation/DNAME-stress plan and wire ratios of `0.001`.

The follow-up `target/zone-image-bench/selected-record-wire-len-handle.tsv`
keeps selected DNSSEC records as immutable plan handles, but carries each
selected record's wire length in that handle when the RRSIG is selected.
Generic plan accounting can then use the carried length instead of indexing the
selected RRset and record again before the append/visit pass. The checker
artifact `target/zone-image-bench/selected-record-wire-len-handle-check.tsv`
passed with zero semantic and packet mismatches, byte parity, mixed planning
ratio `0.123`, mixed wire ratio `0.147`, mixed packet ratio `1.018`, hot packet
ratio `0.990`, trace packet ratio `1.009`, optioned packet ratio `1.014`,
boundary packet ratio `0.990`, UDP-ceiling packet ratio `0.995`, total image
bytes per record `170.000`, and stress bytes per record `250.000`. This is
retained as per-plan selected-DNSSEC accounting cleanup with no `ZoneImage`
memory growth.

The follow-up `target/zone-image-bench/rrsig-relation-rdata-len.tsv` moves the
selected RRSIG RDATA length one step earlier into the immutable RRSIG relation.
Selected DNSSEC handles now compute their carried wire length from that relation
RDATA length and the immutable RRset owner length, so the query path no longer
indexes the selected record table just to measure RDATA. The broader
full-wire-length relation candidate was superseded because it raised the
delegation/DNAME stress fixture to `253.000` bytes per record. The retained
checker artifact `target/zone-image-bench/rrsig-relation-rdata-len-check.tsv`
passed with zero semantic and packet mismatches, byte parity, mixed planning
ratio `0.116`, mixed wire ratio `0.139`, mixed packet ratio `0.973`, hot packet
ratio `0.901`, trace packet ratio `0.943`, optioned packet ratio `0.939`,
boundary packet ratio `0.985`, UDP-ceiling packet ratio `0.996`, total image
bytes per record `170.000`, and stress bytes per record `250.000`. This keeps
the selected-DNSSEC precompute in `ZoneImage` proper without measured image
memory growth.

The follow-up `target/zone-image-bench/rrsig-relation-owner-wire-len.tsv` also
stores the selected RRSIG owner wire length in the immutable relation as a
checked `u8`. Selected-record handle creation still computes the final carried
wire length, but it no longer reads the RRset owner arena just to measure that
owner. A broader relation-carried `u32` full-wire-length candidate was measured
and rejected because it raised the current stress fixture to `259.000` bytes per
record. The retained checker artifact
`target/zone-image-bench/rrsig-relation-owner-wire-len-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.141`,
mixed wire ratio `0.164`, mixed packet ratio `0.990`, hot packet ratio `1.005`,
trace packet ratio `0.974`, optioned packet ratio `0.971`, boundary packet ratio
`0.991`, UDP-ceiling packet ratio `0.993`, total image bytes per record
`174.000`, and stress bytes per record `256.000`.

The attempted `target/zone-image-bench/rrsig-relation-wire-len.tsv` full
selected-wire-length variant remains rejected in the current layout. Replacing
the compact owner/RDATA length pair with a single `u32` final wire length raised
the delegation/DNAME stress fixture to `259.000` bytes per record, above the
retained `256.000` gate, and the checker artifact records that failure at
`target/zone-image-bench/rrsig-relation-wire-len-check.tsv`. The implementation
therefore keeps the 12-byte relation layout, guarded by a focused layout test,
and accepts the tiny per-selected-record addition needed to derive final wire
length from relation-carried owner/RDATA lengths.

The follow-up `target/zone-image-bench/rrsig-runtime-empty-relation-trust.tsv`
removes the runtime covered-RRSIG type check from selected-signature
augmentation. The relation compiler already skips RRSIG RRsets, so an RRSIG
query observes an empty selected-RRSIG relation slice instead of paying a runtime
RRset metadata read just to reject RRSIG-over-RRSIG augmentation. Focused tests
cover a synthetic RRSIG-over-RRSIG record to keep that contract explicit. The
checker artifact
`target/zone-image-bench/rrsig-runtime-empty-relation-trust-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.137`, mixed wire ratio `0.160`, mixed packet ratio `0.996`, hot packet ratio
`1.012`, trace packet ratio `1.006`, optioned packet ratio `1.017`, boundary
packet ratio `0.988`, UDP-ceiling packet ratio `0.996`, total image bytes per
record `174.000`, and stress bytes per record `256.000`.

The follow-up `target/zone-image-bench/rrsig-relation-bitmap-gate.tsv` adds a
compact per-RRset bitmap for RRsets that actually have selected RRSIG
relations. Runtime RRSIG augmentation now returns before relation-span lookup
when compiled metadata proves the covered RRset has no RRSIG relation, while
RRSIG RRsets still rely on the empty-relation contract instead of a runtime
covered-type guard. The checker artifact
`target/zone-image-bench/rrsig-relation-bitmap-gate-check.tsv` passed with zero
trace and boundary packet mismatches, hot bytes per record `106.365`, total
bytes per record `174.000`, stress bytes per record `256.000`, mixed planning
ratio `0.149`, mixed packet ratio `0.962`, trace packet ratio `0.982`, boundary
packet ratio `1.005`, and UDP-ceiling packet ratio `1.002`. This is retained as
per-query DNSSEC relation-span gating with a small hot-byte increase inside the
existing memory gates.

The follow-up `target/zone-image-bench/rrsig-direct-relation-slice.tsv` removes
the runtime selected-RRSIG iterator wrapper from `push_rrsig_for_rrset`.
Runtime augmentation now consumes the compiled relation slice directly, while
the RRset iterator wrapper remains test-only. The checker artifact
`target/zone-image-bench/rrsig-direct-relation-slice-check.tsv` passed with
zero trace and boundary packet mismatches, hot bytes per record `106.365`,
total bytes per record `174.000`, stress bytes per record `256.000`, mixed
planning ratio `0.149`, mixed packet ratio `0.994`, trace packet ratio
`0.998`, boundary packet ratio `0.955`, and UDP-ceiling packet ratio `0.952`.
This is retained as relation-slice discipline and a small query-path cleanup,
not as broad throughput evidence.

The follow-up `target/zone-image-bench/selected-record-fixed-fields.tsv` keeps
that selected DNSSEC record shape as a transient plan handle and carries the
selected RRset's immutable TYPE/CLASS/TTL fixed fields with the precomputed wire
length. Selected-record append and visit paths now write those carried fields
directly instead of re-indexing the selected RRset during the later emission
pass. The checker artifact
`target/zone-image-bench/selected-record-fixed-fields-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.143`,
mixed wire ratio `0.161`, mixed packet ratio `1.032`, hot packet ratio `1.094`,
trace packet ratio `1.062`, optioned packet ratio `1.036`, boundary packet
ratio `1.018`, UDP-ceiling packet ratio `1.021`, total image bytes per record
`174.000`, and stress bytes per record `254.000`. This does not add compiled
image memory; it is retained as selected-record emission discipline before
transport-buffer work.

The follow-up
`target/zone-image-bench/selected-record-rdata-range-handle.tsv` carries the
selected RRSIG record's immutable `RdataRange` in the transient selected DNSSEC
handle as well. Selected-record append and visit paths now use the carried RDATA
range, prevalidated rdlength bytes, and compact RDATA encoding instead of
re-indexing the selected record table during emission. The checker artifact
`target/zone-image-bench/selected-record-rdata-range-handle-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.139`, mixed wire ratio `0.158`, mixed packet ratio `0.999`, hot packet ratio
`0.954`, trace packet ratio `0.962`, optioned packet ratio `0.943`, boundary
packet ratio `0.995`, UDP-ceiling packet ratio `0.992`, total image bytes per
record `174.000`, and stress bytes per record `256.000`. This does not add
compiled image memory; it is retained as the last selected-record emission
metadata cleanup before transport-buffer work.

The follow-up `target/zone-image-bench/selected-record-no-record-index.tsv`
then removes the stale selected record table index from that transient handle.
Handle construction still uses the relation's `record_index` once to copy the
immutable `RdataRange`, but the selected DNSSEC handle carried through the plan
now contains only the RRset handle, precomputed wire length, fixed fields, and
RDATA range. A size guard keeps `ZoneImageSelectedRecord` at `24` bytes. The
checker artifact
`target/zone-image-bench/selected-record-no-record-index-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.144`,
mixed wire ratio `0.165`, mixed packet ratio `0.997`, hot packet ratio `1.086`,
trace packet ratio `0.988`, optioned packet ratio `1.018`, boundary packet ratio
`0.996`, UDP-ceiling packet ratio `0.990`, total image bytes per record
`174.000`, and stress bytes per record `256.000`. This is retained as transient
plan-shape cleanup, not as packet-speed evidence.

An attempted follow-up,
`target/zone-image-bench/selected-record-owner-wire-range.tsv`, replaced the
selected RRset handle with the selected owner-wire `BlobRange` so append and
visit would not re-index the RRset for owner wire. That candidate passed the
checker artifact
`target/zone-image-bench/selected-record-owner-wire-range-check.tsv` with zero
semantic and packet mismatches, but it grew the transient selected handle from
`24` to `28` bytes and measured worse than the retained no-index shape on this
local run: mixed planning ratio `0.162`, mixed wire ratio `0.184`, mixed packet
ratio `1.026`, hot packet ratio `1.021`, trace packet ratio `1.007`, optioned
packet ratio `1.016`, boundary packet ratio `1.021`, and UDP-ceiling packet
ratio `1.015`. The code change was removed; selected DNSSEC handles retain the
compact RRset handle for owner-wire access and drop only the stale selected
record table index.

Direct-copy RRset eligibility is now also a compiled image decision rather than
a packet-time RR-type comparison chain. The retained bitmap run at
`target/zone-image-bench/direct-copy-eligibility-bitmap.tsv` passed
`target/zone-image-bench/direct-copy-eligibility-bitmap-check.tsv`, kept zero
validation mismatches and byte parity, and kept the generated 10k-record
fixture at 172 total image bytes per record while adding only a compact RRset
bitmap to hot metadata.

That bitmap is now superseded by the retained
`target/zone-image-bench/direct-copy-eligibility-body-len.tsv` run. Direct-copy
eligibility is derived from compiled `ImageRrset::direct_answer_body_len`: the
field is zero for ineligible RRsets and non-zero for any non-empty direct-copy
body, so the direct RRset view no longer performs a second side-bitset lookup.
The invariant audit rejects reintroducing `direct_copy_rrset_flags`. The checker
artifact `target/zone-image-bench/direct-copy-eligibility-body-len-check.tsv`
passed with zero semantic and packet mismatches, byte parity, mixed packet ratio
`1.011`, hot packet ratio `1.073`, trace packet ratio `1.049`, optioned packet
ratio `1.058`, UDP-ceiling packet ratio `1.001`, hot bytes per record `106.358`,
and stress hot bytes per record `142.141`. This is a small layout cleanup before
transport work, not a packet-throughput claim.

The later retained
`target/zone-image-bench/direct-answer-body-template.tsv` run uses the same
compiled direct-body field as a bounded body-template hook: multi-record
direct-copy RRsets store a prebuilt `c00c + TYPE/CLASS/TTL + RDLENGTH + RDATA`
answer body immediately after the RRset's immutable owner-full wire, while
single-record direct RRsets keep the old record-slice emission path to avoid
duplicating cold wire across ordinary A/AAAA-heavy zones. The checker passed at
`target/zone-image-bench/direct-answer-body-template-check.tsv` with zero
semantic/packet mismatches, byte parity, total bytes per record `174.000`,
delegation/DNAME stress bytes per record exactly at the retained ceiling
`256.000`, mixed packet ratio `0.997`, hot packet ratio `0.955`, trace packet
ratio `0.998`, and UDP-ceiling packet ratio `0.998`. This keeps the template
discipline for shapes where it can remove a per-record append loop without
letting direct-answer templates bloat the generated image. The current-tree
`target/zone-image-bench/single-record-direct-body-template-check.tsv` retest
still rejects templating every single-record direct RRset because the
delegation/DNAME stress image rises to `272.000` bytes per record. The
`target/zone-image-bench/direct-answer-prefix-metadata-check.tsv` retest also
rejects storing the 10-byte direct-answer prefix in every `ImageRrset`: stress
total bytes rise to `268.000` bytes per record and stress hot bytes rise to
`156.144` bytes per record.

The retained
`target/zone-image-bench/direct-template-branch-no-record-slice.tsv` run keeps
that same bounded template policy but narrows the direct-template query branch:
multi-record template responses now select the compiled body slice without
first fetching the fallback record slice, and the direct RRset view computes the
emitted body length in the same body-selection branch. Single-record direct
RRsets continue to use the record-slice fallback to avoid image growth. The
checker artifact
`target/zone-image-bench/direct-template-branch-no-record-slice-check.tsv`
passed with zero validation and packet mismatches, byte parity, mixed planning
ratio `0.146`, mixed wire ratio `0.170`, mixed packet ratio `0.975`, hot packet
ratio `0.930`, trace packet ratio `0.946`, optioned packet ratio `0.941`,
boundary packet ratio `0.988`, UDP-ceiling packet ratio `0.988`, and
delegation/DNAME-stress plan and wire ratios of `0.002` and `0.002`.

The measured
`target/zone-image-bench/direct-answer-emitted-body-len.tsv` variant tried
precomputing the emitted compressed direct-answer body length in every
`ImageRrset`, eliminating the single-record fallback branch's per-query
`ownerless_wire_len + 2 * record_count` arithmetic. Its checker artifact
`target/zone-image-bench/direct-answer-emitted-body-len-check.tsv` kept zero
validation and packet mismatches plus byte parity, with mixed packet ratio
`0.959`, hot packet ratio `0.998`, trace packet ratio `1.063`, and UDP-ceiling
packet ratio `1.012`, but failed the retained memory ceiling because
delegation/DNAME-stress bytes per record rose to `260.000` over the `256.000`
limit. That precompute is rejected; the current branch-local length derivation
is the better tradeoff before transport work.

The retained
`target/zone-image-bench/synthesized-rdata-encoding-prevalidated.tsv` run keeps
the same shape discipline on the one remaining synthesized dynamic record
family: DNAME-generated CNAME answers now pass the already-known single-name
RDATA encoding into `ZoneImageSynthesizedRecord` instead of asking
`zone_image_rdata_encoding()` to parse the generated target wire again. The
checker passed at
`target/zone-image-bench/synthesized-rdata-encoding-prevalidated-check.tsv` with
zero semantic/packet mismatches, byte parity, total bytes per record `174.000`,
delegation/DNAME stress bytes per record `256.000`, mixed packet ratio `1.015`,
hot packet ratio `0.927`, trace packet ratio `1.039`, optioned packet ratio
`1.052`, and UDP-ceiling packet ratio `1.006`. This is retained as a narrow
generated-record metadata cleanup before transport work.

The next retained `target/zone-image-bench/direct-eligible-view.tsv` run removes
the remaining post-view direct-copy branch from the direct packet composer:
ineligible RRsets now return `None` from the direct RRset view constructor, so
only eligible views reach response emission. The checker artifact
`target/zone-image-bench/direct-eligible-view-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.144`, mixed
wire ratio `0.160`, mixed packet ratio `0.992`, hot packet ratio `0.991`, trace
packet ratio `1.029`, optioned packet ratio `1.046`, UDP-ceiling packet ratio
`1.008`, hot bytes per record `106.358`, and stress hot bytes per record
`142.141`. This keeps the direct path's branch shape tighter without changing
image footprint.

The retained `target/zone-image-bench/direct-nonempty-view.tsv` run then removes
the redundant zero-answer guard after the eligible view is loaded. The view
constructor already returns `None` for zero direct body length and carries a
debug assertion that eligible direct RRsets contain at least one record. The
checker artifact `target/zone-image-bench/direct-nonempty-view-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.141`, mixed wire ratio `0.163`, mixed packet ratio `0.977`, hot packet ratio
`1.020`, trace packet ratio `1.011`, optioned packet ratio `1.044`, boundary
packet ratio `0.988`, UDP-ceiling packet ratio `1.004`, hot bytes per record
`106.358`, and stress hot bytes per record `142.141`. This is another
direct-composer invariant cleanup rather than a throughput claim.

The retained `target/zone-image-bench/direct-known-flags.tsv` run then applies
the same direct-plan invariant to DNS header flags: after the debug assertions
check that the plan is `NoError` and authoritative, direct response assembly
writes those constants instead of calling the plan flag accessors again. The
invariant audit rejects reintroducing those dynamic direct-header flag reads. The
checker artifact `target/zone-image-bench/direct-known-flags-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.149`, mixed wire ratio `0.169`, mixed packet ratio `1.011`, hot packet ratio
`0.996`, trace packet ratio `1.020`, optioned packet ratio `1.034`, boundary
packet ratio `0.982`, UDP-ceiling packet ratio `1.017`, hot bytes per record
`106.358`, and stress hot bytes per record `142.141`. This is direct-composer
invariant cleanup, not a throughput claim.

The follow-up `target/zone-image-bench/direct-shared-edns-append.tsv` removes
the remaining direct-only OPT append branch. Direct exact-owner responses now
call the same `append_zone_image_response_edns` helper used by generic and
truncated `ZoneImage` composers after copying the compiled direct answer body.
The invariant audit requires this shared helper in the direct response builder
and rejects inline direct `encode_opt_record` use. The checker artifact
`target/zone-image-bench/direct-shared-edns-append-check.tsv` passed with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.137`,
mixed wire ratio `0.162`, mixed packet ratio `0.963`, hot packet ratio `0.953`,
trace packet ratio `0.946`, optioned packet ratio `0.957`, boundary packet
ratio `0.989`, UDP-ceiling packet ratio `0.995`, hot bytes per record
`106.358`, and stress hot bytes per record `142.141`. This is EDNS
composer-shape cleanup before transport work, not a throughput claim.

The retained `target/zone-image-bench/direct-preflight-rrtype-bitmap.tsv` run
adds a conservative 256-bit low-RRtype presence bitmap to `ZoneImage`. Direct
answer planning now returns before trie lookup when a queried low RR type is
known absent from the compiled image, while RR types above 255 keep the old
conservative path for private and future RR types. The checker artifact
`target/zone-image-bench/direct-preflight-rrtype-bitmap-check.tsv` passed with
zero validation and packet mismatches, byte parity, absent low direct-preflight
ratio `0.099`, exact lookup ratio `0.226`, mixed planning ratio `0.135`, mixed
wire ratio `0.158`, mixed packet ratio `0.989`, hot packet ratio `0.923`, trace
packet ratio `1.007`, UDP-ceiling packet ratio `0.991`, hot bytes per record
`106.362`, and stress hot bytes per record `144.144`. The artifact's isolated
timing rows measured the skipped low-type direct preflight at `2.382 ns/query`
versus `24.054 ns/query` for the conservative absent high-type path.

The retained `target/zone-image-bench/semantic-absent-rrtype-bitmap.tsv` run
reuses that bitmap in generic semantic planning. The exact-qtype RRset probe is
skipped when a queried low RR type is absent from the compiled image, while
CNAME, DNAME, and denial processing still run. The focused test covers an
absent-low query at a CNAME owner and compares the plan against the old snapshot
oracle. The checker artifact
`target/zone-image-bench/semantic-absent-rrtype-bitmap-check.tsv` passed with
zero validation and packet mismatches, byte parity, absent low direct-preflight
ratio `0.093`, absent low response-plan ratio `0.964`, exact lookup ratio
`0.222`, mixed planning ratio `0.149`, mixed wire ratio `0.177`, mixed packet
ratio `1.010`, hot packet ratio `1.027`, UDP-ceiling packet ratio `0.999`, hot
bytes per record `106.362`, and stress hot bytes per record `144.144`. This is
a small semantic-planning cleanup with a no-regression gate, not a broad
throughput claim.

The retained `target/zone-image-bench/indirection-free-absent-rrtype-bitmap.tsv`
run uses the same bitmap to skip generic CNAME and DNAME fallback lookups when
the compiled image contains no matching indirection RRsets. The direct-answer
DNAME guard also returns immediately for DNAME-free images. The indirection-free
fixture keeps the same `bench.test.` owner shape as the baseline so the
comparison is about compiled indirection presence, not deeper names. The checker
artifact
`target/zone-image-bench/indirection-free-absent-rrtype-bitmap-check.tsv`
passed with zero validation and packet mismatches, byte parity, absent low
direct-preflight ratio `0.098`, absent low response-plan ratio `0.981`,
indirection-free absent low response-plan ratio `0.976`, exact lookup ratio
`0.280`, mixed planning ratio `0.141`, mixed wire ratio `0.172`, mixed packet
ratio `1.037`, hot packet ratio `1.031`, UDP-ceiling packet ratio `0.984`, hot
bytes per record `106.362`, and stress hot bytes per record `144.144`. This is
a narrow fallback-probe cleanup before transport work, not evidence of broader
packet throughput improvement.

The retained `target/zone-image-bench/wildcard-low-rrtype-gates.tsv` run applies
that same absent-low-type gate to wildcard planning. Wildcard exact RRset
lookups are skipped when the requested low RR type is absent from the compiled
image, and wildcard CNAME fallback lookup is skipped when the image has no
CNAME RRsets. High/private RR types remain conservative. The checker artifact
`target/zone-image-bench/wildcard-low-rrtype-gates-check.tsv` passed with zero
validation and packet mismatches, byte parity, base image bytes per record
`174.000`, delegation/DNAME stress bytes per record `256.000`, absent low
direct-preflight ratio `0.098`, absent low response-plan ratio `0.971`,
indirection-free absent low response-plan ratio `0.963`, mixed planning ratio
`0.148`, mixed wire ratio `0.165`, mixed packet ratio `0.978`, hot packet ratio
`0.973`, trace packet ratio `0.932`, boundary packet ratio `1.003`, and
UDP-ceiling packet ratio `0.998`. This is retained as local planner symmetry
cleanup; it does not change response bytes or transport behavior.

The retained `target/zone-image-bench/indirection-target-low-rrtype-gates.tsv`
run carries that same low-type discipline into CNAME/DNAME target resolution
after a target has been classified as an existing in-zone node. Requested-type
target-node probes are skipped when the low RR type is absent from the compiled
image, target CNAME fallback probes are skipped when the image has no CNAME
RRsets, and QTYPE=CNAME avoids repeating the same CNAME lookup after the
requested-type probe. The checker artifact
`target/zone-image-bench/indirection-target-low-rrtype-gates-check.tsv` passed
with zero validation and packet mismatches, byte parity, base image bytes per
record `174.000`, delegation/DNAME stress bytes per record `256.000`, absent
low direct-preflight ratio `0.103`, absent low response-plan ratio `0.986`,
indirection-free absent low response-plan ratio `1.000`, mixed planning ratio
`0.144`, mixed wire ratio `0.156`, mixed packet ratio `0.985`, hot packet ratio
`1.057`, trace packet ratio `0.974`, boundary packet ratio `0.958`, and
UDP-ceiling packet ratio `0.987`. This is retained as local target-resolution
planner cleanup; it does not change response bytes or transport behavior.

The retained `target/zone-image-bench/exact-lookup-low-rrtype-gate.tsv` run
applies that same bitmap to the older public `lookup_exact_plan` helper after
the name has already been classified. Existing names with globally absent low
RR types now return `NoData` before owner RRset scanning; missing and
out-of-zone names still report `NameError` or `OutOfZone`, and high/private RR
types keep the conservative scan. The checker artifact
`target/zone-image-bench/exact-lookup-low-rrtype-gate-check.tsv` passed with
zero validation and packet mismatches, byte parity, absent low exact lookup
ratio `0.951`, absent low direct-preflight ratio `0.104`, absent low
response-plan ratio `0.979`, mixed planning ratio `0.142`, mixed wire ratio
`0.162`, mixed packet ratio `0.993`, hot packet ratio `0.896`, UDP-ceiling
packet ratio `0.988`, total image bytes per record `174.000`, and stress bytes
per record `256.000`. This is compatibility-helper no-scan cleanup before
transport work, not evidence of broader packet throughput improvement.

The retained `target/zone-image-bench/rejected-direct-plan-reuse.tsv` run keeps
the direct semantic plan when direct-copy emission rejects it, then composes the
generic response from that same plan instead of repeating semantic response
planning. This preserves the earlier decision not to move direct-copy
eligibility into `lookup_direct_answer_plan`: compressible CNAME/PTR/SOA-style
answers can still build a direct semantic plan, fail direct-copy emission, and
fall through to the generic composer without replanning. Focused tests cover the
CNAME case and direct-answer metrics stay false for the generic response. The
checker passed with zero validation and packet mismatches, byte parity, exact
lookup ratio `0.189`, hot exact lookup ratio `0.226`, mixed planning ratio
`0.141`, mixed packet ratio `0.978`, hot packet ratio `0.901`, optioned packet
ratio `0.936`, and UDP-ceiling packet ratio `0.996`.

The public wire-helper surface is intentionally narrow: the prototype benchmark
keeps `append_plan_wire` for uncompressed immutable wire-emission timing, while
raw RRset wire access is test-only and the per-section append helpers are
private implementation details. Section-count accounting helpers are also kept
out of the public runtime API. `scripts/audit-invariants.sh` rejects widening
that helper surface again, and it now requires the raw RRset wire helpers plus
the direct wire-bound helper to remain under `#[cfg(test)]`. The retained
`target/zone-image-bench/zone-image-test-only-wire-helper-audit.tsv` run keeps
zero validation and packet mismatches through the checker as API-surface
hardening evidence.

Generic packet composition now avoids the older runtime pre-accounting walk.
`target/zone-image-bench/one-pass-plan-record-composer.tsv` uses a
section-aware `ZoneImage` record visitor: the composer emits a zero-count DNS
header, encodes immutable records once while counting answer, authority, and
additional sections, patches the header counts before EDNS, and reuses those
counts if UDP truncation needs a retry. The checker artifact
`target/zone-image-bench/one-pass-plan-record-composer-check.tsv` passed with
zero semantic and packet mismatches, byte parity, generated child-hash evidence
from the 10k-record fixture, mixed packet ratio `0.995`, hot packet ratio
`1.001`, trace packet ratio `1.004`, optioned packet ratio `0.977`, boundary
packet ratio `1.019`, UDP-ceiling packet ratio `0.995`, total image bytes per
record `170.000`, and stress bytes per record `250.000`. The old direct plan
accounting and wire-bound helpers are now test-only invariants for the
uncompressed benchmark hook rather than normal response-builder work.

The retained `target/zone-image-bench/packet-known-counts-no-patch.tsv` follow-up
removes even that count-while-encoding patch path from normal generic responses.
The response builder asks `ZoneImage` for answer, authority, and additional
counts from compiled RRset metadata, writes final DNS header counts before
encoding records, and leaves the section-aware immutable-record visit as
encode-only work. The checker artifact
`target/zone-image-bench/packet-known-counts-no-patch-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.128`, mixed
wire ratio `0.175`, mixed packet ratio `1.025`, hot packet ratio `1.008`, trace
packet ratio `0.985`, optioned packet ratio `0.982`, boundary packet ratio
`1.035`, UDP-ceiling packet ratio `0.997`, total image bytes per record
`170.000`, and stress bytes per record `250.000`. This is retained as current
Vec-backed composer cleanup; it still does not close the future immutable
template or AF_XDP transport-buffer work.

The follow-up `target/zone-image-bench/packet-encode-only-record-visitor.tsv`
removes the discarded section enum from the normal generic packet composer.
Normal responses now visit immutable plan records through an encode-only
callback, while truncation scratch collection keeps a split-section visitor for
the buffers that genuinely need section routing. The checker artifact
`target/zone-image-bench/packet-encode-only-record-visitor-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.127`,
mixed wire ratio `0.159`, mixed packet ratio `1.006`, hot packet ratio `1.008`,
trace packet ratio `1.030`, optioned packet ratio `1.024`, boundary packet ratio
`1.041`, UDP-ceiling packet ratio `1.001`, total image bytes per record
`170.000`, and stress bytes per record `250.000`. This is another current
Vec-backed composer cleanup rather than template or transport-buffer completion.

The retained `target/zone-image-bench/plan-carried-section-counts.tsv` run moves
generic packet section counts into `ZoneImageLookupPlan` itself. Answer,
authority, and additional record counts are updated as the semantic planner
appends RRsets, synthesized records, and selected DNSSEC records, so the normal
packet composer reads `plan.section_record_counts()` instead of asking
`ZoneImage` to walk selected plan handles after planning. The checker artifact
`target/zone-image-bench/plan-carried-section-counts-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.130`, mixed
wire ratio `0.158`, mixed packet ratio `1.016`, hot packet ratio `1.001`, trace
packet ratio `0.982`, optioned packet ratio `0.988`, boundary packet ratio
`1.008`, UDP-ceiling packet ratio `0.998`, total image bytes per record
`170.000`, and stress bytes per record `250.000`. This closes the last normal
composer section-count recomputation pass; template and AF_XDP transport-buffer
work remain separate.

The retained `target/zone-image-bench/generic-response-capacity-hint.tsv` run
uses those carried section counts for ordinary generic response buffer sizing.
The normal composer now combines question length, total carried record count,
and fixed EDNS option shape, instead of reserving the full UDP ceiling for every
unpadded generic UDP response. Truncation retries and EDNS-padding-sensitive
responses still reserve the ceiling to avoid retry growth. A focused unit test
asserts an unpadded EDNS-4096 generic response does not keep a 4096-byte
capacity, and the invariant audit checks the known-count composer uses the
capacity hint rather than returning to full-ceiling allocation. The checker
artifact `target/zone-image-bench/generic-response-capacity-hint-check.tsv`
passed with zero validation and packet mismatches, byte parity, mixed planning
ratio `0.139`, mixed wire ratio `0.161`, mixed packet ratio `0.983`, hot packet
ratio `0.981`, trace packet ratio `0.949`, optioned packet ratio `0.947`,
boundary packet ratio `0.969`, UDP-ceiling packet ratio `0.965`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.002`.

The retained `target/zone-image-bench/zone-image-edns-capacity-single-read.tsv`
run keeps EDNS response-capacity sizing as a caller-carried response-path
input. The generic capacity helper now consumes a precomputed
`edns_capacity_hint` instead of recalculating the OPT shape, ordinary
direct/generic paths reuse that hint, and only metadata-changing NSEC3 EDE or
EDE-stripped truncation retries recompute it. Focused tests cover the unpadded
generic capacity case, rejected direct-plan generic fallback, and the
DNSSEC/NSEC3 EDE cap. The checker artifact
`target/zone-image-bench/zone-image-edns-capacity-single-read-check.tsv` passed
with zero validation and packet mismatches, byte parity, mixed planning ratio
`0.143`, mixed wire ratio `0.168`, mixed packet ratio `1.023`, hot packet ratio
`1.044`, trace packet ratio `1.034`, optioned packet ratio `1.039`, boundary
packet ratio `1.004`, UDP-ceiling packet ratio `1.011`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.002`.

The retained `target/zone-image-bench/plan-carried-wire-bounds.tsv` run moves
ordinary generic response sizing from a per-record byte hint to compact
wire-byte upper bounds carried by `ZoneImageLookupPlan`. The original run
carried answer, authority, and additional section wire counters, including
wildcard owner overrides, synthesized DNAME CNAMEs, and selected DNSSEC
records. That per-section shape is now superseded by
`target/zone-image-bench/zone-image-derived-section-wire-bounds.tsv`: runtime
composition only keeps the total body bound for response sizing and the answer
bound needed by SERVFAIL conversion, while benchmark-only direct accounting can
derive authority/additional wire lengths from immutable handles. Truncation
retries and EDNS-padding-sensitive responses still use the UDP ceiling. The
original checker artifact
`target/zone-image-bench/plan-carried-wire-bounds-check.tsv` passed with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.138`,
mixed wire ratio `0.174`, mixed packet ratio `0.959`, hot packet ratio `0.901`,
trace packet ratio `0.957`, optioned packet ratio `0.951`, boundary packet
ratio `1.046`, UDP-ceiling packet ratio `1.006`, and delegation/DNAME-stress
plan and wire ratios of `0.001` and `0.001`.

The retained `target/zone-image-bench/truncation-plan-accounting.tsv` run
extends the same compact plan-accounting model to truncation metadata:
`ZoneImageLookupPlan` then carried a total DNSSEC-record count alongside
section counts and body wire bounds. The later
`zone-image-dead-dnssec-count-retired` slice supersedes the DNSSEC-counter side
after final response bytes became the DNSSEC latency-classification source of
truth. The retained body-bound side remains current: truncation scratch setup
starts from compact plan response bounds instead of summing every kept wire
record during scratch collection. The checker artifact
`target/zone-image-bench/truncation-plan-accounting-check.tsv` passed with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.153`,
mixed wire ratio `0.180`, mixed packet ratio `0.996`, hot packet ratio `1.019`,
trace packet ratio `1.006`, optioned packet ratio `1.026`, boundary packet
ratio `1.041`, UDP-ceiling packet ratio `1.020`, and delegation/DNAME stress
plan and wire ratios of `0.001` and `0.002`. This is local truncation composer
accounting cleanup, not physical NIC or transport evidence.

The retained `target/zone-image-bench/plan-response-shape-view.tsv` run bundles
that compact response accounting behind one `ZoneImageLookupPlan` response-shape
view. Generic and truncated packet composition now read section counts, total
body wire bound, and EDNS sizing from the single view before composing or
collecting truncation scratch, rather than calling separate plan accessors at
each stage. The original run also carried a DNSSEC record count in the view,
but the current implementation removed it as dead bookkeeping. The checker artifact
`target/zone-image-bench/plan-response-shape-view-check.tsv` passed with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.135`,
mixed wire ratio `0.157`, mixed packet ratio `1.045`, hot packet ratio `1.050`,
trace packet ratio `1.041`, optioned packet ratio `1.035`, boundary packet
ratio `0.993`, UDP-ceiling packet ratio `1.005`, delegation/DNAME-stress
planning ratio `0.001`, stress wire ratio `0.002`, hot bytes per record
`106.358`, and stress hot bytes per record `142.141`. This is interface
tightening for immutable-plan accounting before template or transport-buffer
work.

The retained `target/zone-image-bench/carried-plan-body-wire-bound.tsv` run
moves the total response-body wire bound itself into compact
`ZoneImageLookupPlan` state. Plan push sites update that total beside the
section counters, so `response_shape()` and the test-only
`response_body_wire_upper_bound()` expose the carried total body bound without
walking planned records on each read. SERVFAIL conversion preserves carried
partial-answer bounds when it clears authority/additional state. The checker
artifact `target/zone-image-bench/carried-plan-body-wire-bound-check.tsv`
passed with zero validation and packet mismatches, byte parity, mixed planning
ratio `0.150`, mixed wire ratio `0.180`, mixed packet ratio `1.026`, hot packet
ratio `1.096`, trace packet ratio `1.009`, optioned packet ratio `1.001`,
boundary packet ratio `0.980`, UDP-ceiling packet ratio `1.010`, and
delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`. This
is retained as response-shape accounting cleanup inside the local gates, not as
a packet-throughput claim.

The follow-up `target/zone-image-bench/plan-section-counts-u32.tsv` keeps those
carried plan counts compact: `ZoneImageLookupPlan` stores answer, authority, and
additional counts as `u32` fields with saturating updates, then exposes `usize`
counts to the packet composer so the existing `u16` DNS header checks still fail
closed for oversized responses. The checker artifact
`target/zone-image-bench/plan-section-counts-u32-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.141`, mixed
wire ratio `0.167`, mixed packet ratio `0.999`, hot packet ratio `1.010`, trace
packet ratio `0.990`, optioned packet ratio `0.994`, boundary packet ratio
`1.035`, UDP-ceiling packet ratio `0.974`, total image bytes per record
`170.000`, and stress bytes per record `250.000`. This is retained as
per-query plan-layout compaction, not as a transport-buffer result.

The retained `target/zone-image-bench/plan-answer-compact-indexes.tsv` run
continues that plan-layout work for custom answer items. `PlanAnswer` now stores
owner-override and dynamic synthesized-record indexes as DNS-answer-count-bound
`u16` values instead of pointer-sized `usize` values, while push sites keep
explicit bounds and focused tests keep the enum at 28 bytes with 4-byte
alignment. Its checker artifact
`target/zone-image-bench/plan-answer-compact-indexes-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.139`, mixed
wire ratio `0.161`, mixed packet ratio `0.999`, hot packet ratio `0.896`,
trace packet ratio `1.000`, optioned packet ratio `0.997`, boundary packet
ratio `1.002`, UDP-ceiling packet ratio `0.991`, total image bytes per record
`174.000`, and stress bytes per record `256.000`. Treat this as transient plan
item compaction, not as a broad throughput claim.

The retained `target/zone-image-bench/authority-soa-index-u16.tsv` run applies
the same section-bound discipline to the negative-SOA authority position.
`ZoneImageLookupPlan` now stores the authority SOA index as a `u16` section
index with an explicit sentinel and widens it only at the accessor boundary.
The checker artifact
`target/zone-image-bench/authority-soa-index-u16-check.tsv` passed with zero
semantic and packet mismatches, byte parity, unchanged image bytes per record
(`174` main, `256` stress), mixed planning ratio `0.146`, mixed wire ratio
`0.166`, mixed packet ratio `1.008`, hot packet ratio `1.019`, trace packet
ratio `0.995`, optioned packet ratio `0.994`, boundary packet ratio `1.005`,
UDP-ceiling packet ratio `0.997`, and delegation/DNAME-stress plan and wire
ratios of `0.001` and `0.002`. This is per-query plan metadata compaction, not
a transport result.

The retained `target/zone-image-bench/authority-metrics-rrtype.tsv` run removes
the duplicate authority RR-type scalar from authority RRset planning. The
transient `ZoneImageRrsetPlanMetrics` loaded from immutable `ImageRrset`
metadata now carries the compiled RR type alongside record counts and wire
bounds; authority-SOA state is derived from those metrics instead of trusting
caller-supplied `RecordType` arguments. Historical DNSSEC-counter metrics from
that path are superseded by the later dead-counter removal. The checker artifact
`target/zone-image-bench/authority-metrics-rrtype-check.tsv` passed with zero
validation and packet mismatches, hot bytes per record `106.365`, total bytes
per record `174.000`, stress bytes per record `256.000`, mixed planning ratio
`0.140`, mixed packet ratio `0.960`, trace packet ratio `0.983`, boundary
packet ratio `1.018`, and UDP-ceiling packet ratio `1.026`. This is retained
as authority-plan metadata discipline before transport work, not as standalone
throughput evidence.

The retained `target/zone-image-bench/dname-indirection-dynamic-index-u16.tsv`
run extends the same bounded-index rule to DNAME synthesized-CNAME target
resolution. The transient `IndirectionTargetWire` handle now stores dynamic
answer references as the DNS-answer-count-bounded `u16` index already used by
`PlanAnswer::DynamicRecord`, widening only at the slice lookup boundary. The
checker artifact
`target/zone-image-bench/dname-indirection-dynamic-index-u16-check.tsv` passed
with zero semantic and packet mismatches, byte parity, unchanged image bytes per
record (`174` main, `256` stress), mixed planning ratio `0.142`, mixed wire
ratio `0.166`, mixed packet ratio `0.996`, hot packet ratio `0.985`, trace
packet ratio `0.998`, optioned packet ratio `1.037`, boundary packet ratio
`1.019`, UDP-ceiling packet ratio `1.022`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`. This is DNAME transient-plan layout
compaction, not a transport result.

The retained `target/zone-image-bench/dnssec-original-authority-count-u16.tsv`
run applies the same section-bound rule to DNSSEC augmentation scratch state.
The original-authority-prefix count used by duplicate-proof checks is now stored
as a `u16` DNS section count and widened only when slicing the plan's authority
RRset prefix. The checker artifact
`target/zone-image-bench/dnssec-original-authority-count-u16-check.tsv` passed
with zero semantic and packet mismatches, byte parity, unchanged image bytes per
record (`174` main, `256` stress), mixed planning ratio `0.145`, mixed wire
ratio `0.165`, mixed packet ratio `1.024`, hot packet ratio `1.075`, trace
packet ratio `1.047`, optioned packet ratio `1.064`, boundary packet ratio
`1.008`, UDP-ceiling packet ratio `1.034`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`. This is DNSSEC transient-state layout
compaction, not a transport result.

The retained
`target/zone-image-bench/truncation-authority-removability.tsv` run narrows the
truncated response scratch collector. `ZoneImage` now exposes a split-section
visitor variant that carries whether each authority record is removable based on
the plan's protected negative-SOA position, so the truncation setup no longer
checks every retained authority wire record's RR type to rebuild the same fact.
The checker artifact
`target/zone-image-bench/truncation-authority-removability-check.tsv` passed
with zero semantic and packet mismatches, byte parity, unchanged image bytes per
record (`174` main, `256` stress), mixed planning ratio `0.149`, mixed wire
ratio `0.174`, mixed packet ratio `1.000`, hot packet ratio `0.969`, trace
packet ratio `1.006`, optioned packet ratio `0.991`, boundary packet ratio
`1.015`, UDP-ceiling packet ratio `1.032`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`. This is truncation-composer bookkeeping
cleanup before transport work.

The retained `target/zone-image-bench/response-shape-dns-counts-u16.tsv` run
applies the same DNS-width discipline to final response section counts.
`ZoneImageLookupPlan::response_shape()` now validates answer, authority, and
additional counts into `u16` fields once, and the known-count packet builder
writes those carried counts directly instead of reconverting from `usize` on
each response. The checker artifact
`target/zone-image-bench/response-shape-dns-counts-u16-check.tsv` passed with
zero semantic and packet mismatches, byte parity, unchanged image bytes per
record (`174` main, `256` stress), mixed planning ratio `0.148`, mixed wire
ratio `0.174`, mixed packet ratio `0.991`, hot packet ratio `0.922`, trace
packet ratio `0.952`, optioned packet ratio `0.945`, boundary packet ratio
`1.001`, UDP-ceiling packet ratio `0.986`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`. This is response-header bookkeeping cleanup
before transport work.

The retained `target/zone-image-bench/truncation-carried-retry-counts.tsv`
follow-up keeps those DNS-width counts live through UDP truncation retry.
Answer, authority, and additional counts are initialized from the response
shape and decremented as records are removed, so the wire-record retry composer
receives carried counts directly instead of converting scratch-vector lengths
back into DNS section counts on every retry. The checker artifact
`target/zone-image-bench/truncation-carried-retry-counts-check.tsv` passed with
zero semantic and packet mismatches, byte parity, unchanged image bytes per
record (`174` main, `256` stress), mixed planning ratio `0.144`, mixed wire
ratio `0.167`, mixed packet ratio `1.010`, hot packet ratio `1.020`, trace
packet ratio `1.027`, optioned packet ratio `0.999`, boundary packet ratio
`0.963`, UDP-ceiling packet ratio `0.981`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`. This is truncation retry bookkeeping
cleanup before transport work.

The retained
`target/zone-image-bench/truncation-section-local-retry-encode.tsv` follow-up
keeps the carried retry counts and encodes retained answer, authority, and
additional scratch sections through explicit section-local loops instead of one
chained iterator over all sections. The checker artifact
`target/zone-image-bench/truncation-section-local-retry-encode-check.tsv`
passed with zero semantic and packet mismatches, byte parity, unchanged image
bytes per record (`174` main, `256` stress), mixed planning ratio `0.146`,
mixed wire ratio `0.173`, mixed packet ratio `0.933`, hot packet ratio `0.989`,
trace packet ratio `0.957`, optioned packet ratio `0.945`, boundary packet
ratio `0.978`, UDP-ceiling packet ratio `0.984`, and delegation/DNAME-stress
plan and wire ratios of `0.001` and `0.002`. This is truncation retry composer
cleanup before transport work.

The retained `target/zone-image-bench/truncation-retry-count-bytes.tsv`
follow-up carries retry section counts as one response-shape-derived value that
starts from the plan's preencoded section-count bytes. As records are removed,
the retry loop patches only the changed section's two count bytes, and the
wire-record retry composer consumes those carried bytes plus the carried EDNS
additional count instead of rebuilding answer, authority, and additional count
bytes from separate counters on every retry. The checker artifact
`target/zone-image-bench/truncation-retry-count-bytes-check.tsv` passed with
two EDE fallback packet cases, zero semantic and packet mismatches, byte
parity, unchanged image bytes per record (`174` main, `256` stress), mixed
planning ratio `0.144`, mixed wire ratio `0.163`, mixed packet ratio `1.011`,
hot packet ratio `1.024`, trace packet ratio `0.996`, optioned packet ratio
`1.002`, boundary packet ratio `1.020`, UDP-ceiling packet ratio `0.996`,
NOTIFY SOA mixed-case validation ratio `0.998`, CHAOS mixed-case
classification ratio `0.957`, and delegation/DNAME-stress plan and wire ratios
of `0.002` and `0.002`. This is retry response-header bookkeeping cleanup, not
packet-speed evidence.

The retained `target/zone-image-bench/response-shape-plan-flag-bits.tsv`
follow-up keeps response-header semantics in the same bundled response-shape
object as DNS-width counts and body bounds. `ZoneImageLookupPlan::response_shape()`
now carries the plan-derived AA/Rcode flag bits, and both known-count and
truncation retry packet builders pass those bits directly into the shared
ZoneImage DNS-header prefix helper instead of rereading `rcode` and
authoritative state from the plan during composition. The checker artifact
`target/zone-image-bench/response-shape-plan-flag-bits-check.tsv` passed with
zero semantic and packet mismatches, byte parity, unchanged image bytes per
record (`174` main, `256` stress), mixed planning ratio `0.152`, mixed wire
ratio `0.174`, mixed packet ratio `1.012`, hot packet ratio `1.035`, trace
packet ratio `1.024`, optioned packet ratio `0.995`, boundary packet ratio
`0.996`, UDP-ceiling packet ratio `1.019`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`. This is response-header bookkeeping
cleanup before transport work, not a standalone packet-throughput claim.

The retained `target/zone-image-bench/response-shape-section-count-bytes.tsv`
follow-up keeps the DNS section-count header bytes beside the response-shape
counts. `ZoneImageLookupPlan::response_shape()` preencodes the no-EDNS answer,
authority, and additional count bytes after the DNS-width count check. The
ordinary known-count packet composer copies those bytes through the shared
header-prefix helper; when EDNS is present, the response-shape helper performs
the only additional-count adjustment and returns rebuilt count bytes. Truncation
retry composition was later tightened by `truncation-retry-count-bytes`, which
keeps mutable retry count bytes in a response-shape-derived carrier. The checker
artifact `target/zone-image-bench/response-shape-section-count-bytes-check.tsv`
passed with zero semantic and packet mismatches, byte parity, unchanged image
bytes per record (`174` main, `256` stress), mixed planning ratio `0.149`,
mixed wire ratio `0.173`, mixed packet ratio `1.013`, hot packet ratio `0.978`,
trace packet ratio `0.995`, optioned packet ratio `1.018`, boundary packet
ratio `0.979`, UDP-ceiling packet ratio `0.994`, and delegation/DNAME-stress
plan and wire ratios of `0.001` and `0.002`. This is response-header byte
bookkeeping cleanup before transport work, not a standalone packet-throughput
claim.

The follow-up
`target/zone-image-bench/direct-rrset-section-count-bytes.tsv` applies the same
header-byte discipline to the direct exact-owner response view.
`ZoneImageDirectRrset` now carries no-EDNS and EDNS-adjusted section-count
header bytes, so the direct composer consumes the direct view instead of
reencoding answer/additional counts in `dns.rs`. Focused direct-plan and
direct-body tests passed, and the checker artifact
`target/zone-image-bench/direct-rrset-section-count-bytes-check.tsv` passed with
zero semantic and packet mismatches, byte parity, unchanged image bytes per
record (`174` main, `256` stress), mixed planning ratio `0.149`, mixed wire
ratio `0.172`, mixed packet ratio `0.974`, hot packet ratio `1.000`, trace
packet ratio `1.034`, optioned packet ratio `1.006`, boundary packet ratio
`0.965`, UDP-ceiling packet ratio `0.991`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`. This is direct-composer response-header
bookkeeping cleanup before transport work, not a standalone packet-throughput
claim.

The later `target/zone-image-bench/carried-plan-count-append.tsv` extends that
discipline to the low-level uncompressed `append_plan_wire` helper used by
wire-emission benchmarking and test surfaces. Section appenders now write the
planned immutable handles without accumulating a second record counter; the
public helper now derives its return count from carried section counters after
the append. The checker
artifact `target/zone-image-bench/carried-plan-count-append-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.151`, mixed wire ratio `0.169`, mixed packet ratio `0.982`, hot packet ratio
`0.902`, trace packet ratio `1.017`, optioned packet ratio `1.019`, boundary
packet ratio `1.003`, UDP-ceiling packet ratio `1.000`, and delegation/DNAME
stress planning and wire ratios of `0.001` and `0.002`. This is composer
accounting cleanup; it does not change response bytes or transport behavior.
The retained `target/zone-image-bench/carried-plan-total-record-count.tsv`
follow-up makes that total explicit compact plan state instead of deriving it by
summing section counters when the helper returns. All plan push sites update
the total beside section counts, and SERVFAIL conversion resets it to the
carried answer count after authority/additional state is cleared. That
aggregate field is now superseded by
`target/zone-image-bench/zone-image-derived-total-record-count.tsv`, which
removes the redundant total and derives the benchmark-only `append_plan_wire`
count from carried section counters at the boundary. The original checker
artifact `target/zone-image-bench/carried-plan-total-record-count-check.tsv`
passed with zero semantic and packet mismatches, byte parity, mixed planning
ratio `0.150`, mixed wire ratio `0.171`, mixed packet ratio `0.971`, hot packet
ratio `1.035`, trace packet ratio `0.974`, optioned packet ratio `1.001`,
boundary packet ratio `0.971`, UDP-ceiling packet ratio `1.006`, and
delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
The superseding checker artifact
`target/zone-image-bench/zone-image-derived-total-record-count-check.tsv`
passed with two EDE fallback cases, zero validation/packet mismatches, byte
parity, mixed planning ratio `0.148`, mixed packet ratio `1.038`, hot packet
ratio `1.061`, trace packet ratio `1.030`, optioned packet ratio `1.029`,
boundary packet ratio `0.980`, UDP-ceiling packet ratio `0.991`,
delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`, and
NOTIFY SOA mixed-case validation ratio `1.031`. The invariant audit now
rejects restoring the aggregate plan field or per-push aggregate updates.

The retained
`target/zone-image-bench/zone-image-derived-section-wire-bounds.tsv` follow-up
removes the redundant authority/additional section wire-bound fields and their
per-push updates from `ZoneImageLookupPlan`. Runtime response composition still
carries the total body wire bound for buffer sizing and truncation, and it
still carries the answer wire bound because SERVFAIL conversion preserves
partial answers while clearing authority/additional state. Benchmark-only
direct accounting derives exact authority/additional wire lengths by walking
immutable plan handles. The checker artifact
`target/zone-image-bench/zone-image-derived-section-wire-bounds-check.tsv`
passed with two EDE fallback cases, zero validation/packet mismatches, byte
parity, mixed planning ratio `0.139`, mixed packet ratio `0.989`, hot packet
ratio `1.011`, trace packet ratio `1.008`, optioned packet ratio `1.048`,
boundary packet ratio `1.006`, UDP-ceiling packet ratio `1.029`,
delegation/DNAME stress plan and wire ratios of `0.001` and `0.002`, and
NOTIFY SOA mixed-case validation ratio `1.015`. The invariant audit rejects
restoring the redundant fields or authority/additional push-site updates.

The retained `target/zone-image-bench/dnssec-direct-retry-gate.tsv` follow-up
keeps DO-bit response composition on the generic DNSSEC path without entering
the later direct-answer retry helper that would immediately reject on
`dnssec_requested()`. The request path now caches the DO-bit state before
planning and passes an explicit `allow_direct_answer_retry` flag to the
response builder. The checker artifact
`target/zone-image-bench/dnssec-direct-retry-gate-check.tsv` passed with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.141`,
mixed wire ratio `0.160`, mixed packet ratio `1.051`, hot packet ratio
`1.074`, trace packet ratio `0.978`, optioned packet ratio `0.939`, boundary
packet ratio `1.000`, UDP-ceiling packet ratio `1.001`, and delegation/DNAME
stress planning and wire ratios of `0.002` and `0.002`. Treat this as narrow
DNSSEC branch cleanup before transport work, not as a throughput claim.

The retained `target/zone-image-bench/direct-answer-caller-do-contract.tsv`
run removes the remaining duplicate DO-bit rejection from the direct-answer
builder. Request handling already skips direct preflight and direct retry for
DO-bit requests, so the helper now keeps the non-DNSSEC caller contract as a
debug assertion and branches only on the cached direct-answer plan flag. The
checker artifact
`target/zone-image-bench/direct-answer-caller-do-contract-check.tsv` passed with
zero semantic and packet mismatches, hot bytes per record `106.365`, total
bytes per record `174.000`, stress bytes per record `256.000`, mixed planning
ratio `0.143`, mixed packet ratio `1.046`, hot packet ratio `1.087`, trace
packet ratio `1.005`, boundary packet ratio `0.999`, and UDP-ceiling packet
ratio `0.992`. Treat this as direct-answer contract cleanup before transport
work.

The retained `target/zone-image-bench/zone-image-udp-ceiling-single-read.tsv`
follow-up extends the same request-state discipline to UDP payload sizing:
ZoneImage request handling computes the effective UDP ceiling once before
direct/generic response composition and passes it through direct-answer retry
and generic response building. That avoids re-reading EDNS/options state after
a direct candidate falls through to the generic composer. The checker artifact
`target/zone-image-bench/zone-image-udp-ceiling-single-read-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.144`, mixed wire ratio `0.170`, mixed packet ratio `1.018`, hot packet ratio
`1.059`, trace packet ratio `1.018`, optioned packet ratio `1.052`, boundary
packet ratio `0.966`, UDP-ceiling packet ratio `0.989`, and delegation/DNAME
stress planning and wire ratios of `0.002` and `0.002`. Treat this as
request-metadata plumbing cleanup before transport work, not as a broad
throughput result.

The retained `target/zone-image-bench/zone-image-capacity-reserve-flag.tsv`
follow-up carries the EDNS-padding/full-UDP-capacity reserve decision from the
request path into the ZoneImage direct, generic, and truncation response
builders. The response capacity helper now consumes only caller-carried sizing
state, so it no longer accepts `RequestMetadata`/`AnswerOptions` or rechecks
EDNS padding internally. The checker artifact
`target/zone-image-bench/zone-image-capacity-reserve-flag-check.tsv` passed with
zero semantic and packet mismatches, hot bytes per record `106.365`, total
bytes per record `174.000`, stress bytes per record `256.000`, mixed planning
ratio `0.150`, mixed packet ratio `0.978`, hot packet ratio `1.035`, trace
packet ratio `1.047`, boundary packet ratio `0.983`, and UDP-ceiling packet
ratio `1.017`. Treat this as request-capacity plumbing cleanup before transport
work.

The retained `target/zone-image-bench/zone-image-response-sizing-bundle.tsv`
follow-up carries the fixed header-plus-question minimum response capacity
beside the cached UDP ceiling and EDNS response sizing in one
`ZoneImageResponseSizing` value. Direct, generic, failure, CHAOS TXT,
EDE-stripped, and truncation retry response builders now consume that bundle
instead of recomputing the fixed parsed-query capacity base or threading the UDP
ceiling and EDNS sizing as separate hot-path arguments. The checker artifact
`target/zone-image-bench/zone-image-response-sizing-bundle-check.tsv` passed
with two EDE fallback packet cases, zero semantic and packet mismatches, byte
parity, unchanged image bytes per record (`174` main, `256` stress), mixed
planning ratio `0.146`, mixed wire ratio `0.163`, mixed packet ratio `1.051`,
hot packet ratio `1.056`, trace packet ratio `1.025`, optioned packet ratio
`0.952`, boundary packet ratio `0.996`, UDP-ceiling packet ratio `0.991`,
NOTIFY SOA mixed-case validation ratio `0.997`, CHAOS mixed-case
classification ratio `0.965`, and delegation/DNAME stress planning and wire
ratios of `0.002` and `0.002`. Treat this as response-sizing plumbing cleanup
before transport work, not as broad throughput evidence.

The retained `target/zone-image-bench/borrowed-zone-image-provider.tsv`
follow-up removes a hot-path ownership cost from the serving boundary: the
provider now returns a borrowed `&ZoneImage` from the active `PublishedZone`
instead of cloning the zone image `Arc` for each query. The checker artifact
`target/zone-image-bench/borrowed-zone-image-provider-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.146`,
mixed wire ratio `0.168`, mixed packet ratio `1.033`, hot packet ratio `1.006`,
trace packet ratio `1.039`, optioned packet ratio `1.039`, boundary packet
ratio `1.033`, UDP-ceiling packet ratio `1.038`, and delegation/DNAME stress
planning and wire ratios of `0.002` and `0.002`. Treat this as ownership and
cache-discipline cleanup before transport work, not as physical NIC throughput
evidence.
The follow-up
`target/zone-image-bench/borrowed-active-zone-image-surface-rerun.tsv` removes
the stale active `ZoneImage` Arc-clone accessor from `PublishedZone`, leaving
active query serving on the borrowed `active_zone_image_ref()` API. The later
API cleanup also removes the broad optional `Arc<ZoneImage>` clone accessor
after tests were converted to borrowed identity checks, so publication checks no
longer need to preserve a clone-returning query-surface helper. The retained
follow-up `target/zone-image-bench/published-zone-image-ref-surface.tsv` passed
its checker at
`target/zone-image-bench/published-zone-image-ref-surface-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.152`,
mixed packet ratio `1.021`, hot packet ratio `0.998`, trace packet ratio
`1.010`, optioned packet ratio `1.002`, boundary packet ratio `1.033`, and
UDP-ceiling packet ratio `1.012`. Treat this as query-surface API discipline,
not as a throughput claim.

The follow-up `target/zone-image-bench/truncated-ede-known-counts.tsv` carries
that count discipline into the EDE-stripped truncation retry. If a response is
too large only because of EDE, the retry rebuilds the same immutable plan
without the EDE option and writes the known section counts directly instead of
running the counting composer again. The checker artifact
`target/zone-image-bench/truncated-ede-known-counts-check.tsv` passed with zero
semantic, packet, UDP-ceiling, and EDE fallback mismatches, byte parity,
generated child-hash evidence from the 10k-record fixture, mixed packet ratio
`1.013`, hot packet ratio `0.970`, trace packet ratio `1.014`, optioned packet
ratio `1.006`, boundary packet ratio `1.040`, UDP-ceiling packet ratio
`1.005`, total image bytes per record `170.000`, and stress bytes per record
`250.000`. This is retained as narrow retry-composer work reduction, not as a
new transport throughput claim.

Generic packet composition also now avoids reparsing its own question output:
`target/zone-image-bench/question-compression-label-seed.tsv` seeds the
wire-name compressor from parsed question labels after writing the question
section instead of scanning the serialized question wire to rediscover label
offsets. The checker artifact
`target/zone-image-bench/question-compression-label-seed-check.tsv` passed with
zero packet mismatches, unchanged image bytes, mixed packet ratio `0.994`, hot
packet ratio `1.034`, optioned packet ratio `1.045`, boundary packet ratio
`0.993`, and main/stress hot-byte-per-record checks still at `104.910` and
`130.173`. This is retained as a small composer work reduction that keeps the
same compression semantics.

The follow-up `target/zone-image-bench/question-compression-single-pass-labels.tsv`
keeps that parsed-label registration path and tracks the remaining suffix wire
length in one pass, rather than recomputing each label suffix length while
registering question compression pointers. Its checker artifact
`target/zone-image-bench/question-compression-single-pass-labels-check.tsv`
passed with zero packet mismatches, unchanged image bytes, mixed packet ratio
`1.014`, hot packet ratio `1.115`, boundary packet ratio `0.989`, UDP-ceiling
packet ratio `0.999`, and main/stress hot-byte-per-record checks still at
`104.910` and `130.173`. This is kept as a small bounded work cleanup, not as a
standalone packet-path timing claim.

The retained
`target/zone-image-bench/question-compression-carried-suffix-key-len.tsv` run
then threads that already-carried suffix wire length into canonical suffix-key
construction, removing the remaining per-suffix `name_wire_len` recomputation
from parsed-question compressor seeding. Its checker artifact
`target/zone-image-bench/question-compression-carried-suffix-key-len-check.tsv`
passed with zero validation and packet mismatches, byte parity, mixed planning
ratio `0.141`, mixed wire ratio `0.162`, mixed packet ratio `0.994`, hot packet
ratio `0.973`, trace packet ratio `0.941`, optioned packet ratio `0.920`,
boundary packet ratio `0.966`, and UDP-ceiling packet ratio `0.952`. This is
current-composer bookkeeping cleanup, not template/WireArena completion.

The next retained
`target/zone-image-bench/question-compression-parsed-qname-wire-len.tsv` run
starts that same compressor seeding from the QNAME wire length stored by
`Question::parse`, removing the full-label length walk that previously ran
before suffix registration. The compressed-QNAME regression keeps the response
behavior honest: compressed query names are re-encoded normally in responses,
while only the parsed length feeds this bookkeeping path. Its checker artifact
`target/zone-image-bench/question-compression-parsed-qname-wire-len-check.tsv`
passed with zero validation and packet mismatches, byte parity, mixed planning
ratio `0.163`, mixed wire ratio `0.172`, mixed packet ratio `0.990`, hot packet
ratio `0.913`, trace packet ratio `1.020`, optioned packet ratio `1.049`,
boundary packet ratio `1.023`, and UDP-ceiling packet ratio `1.013`. This is
current-composer bookkeeping cleanup, not template/WireArena completion.

The retained `target/zone-image-bench/question-qtype-qclass-wire-bytes.tsv` run
keeps the no-question-wire-copy model but stores the parsed question's four
QTYPE/QCLASS bytes on `Question`. Response question echo still re-encodes the
parsed QNAME labels, including compressed query names, but now copies those
four tail bytes directly instead of converting scalar `qtype` and `qclass`
values back to network byte order for each response. The checker artifact
`target/zone-image-bench/question-qtype-qclass-wire-bytes-check.tsv` passed
with zero validation and packet mismatches, byte parity, mixed planning ratio
`0.141`, mixed wire ratio `0.163`, mixed packet ratio `0.980`, hot packet ratio
`0.966`, trace packet ratio `0.999`, optioned packet ratio `1.030`, boundary
packet ratio `0.994`, UDP-ceiling packet ratio `1.012`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.002`. This is
parser/composer response-echo bookkeeping cleanup, not template/WireArena
completion.

The retained `target/zone-image-bench/question-qname-wire-len-stored.tsv` run
keeps that parsed-question no-copy shape but stores the parsed QNAME wire
length directly on `Question`, deriving total question length only for section
offset and capacity callers. That removes the subtract-four step from the
response compressor seed path while preserving parsed-label response echo and
parsed QTYPE/QCLASS byte copies. The checker artifact
`target/zone-image-bench/question-qname-wire-len-stored-check.tsv` passed with
zero validation and packet mismatches, byte parity, mixed planning ratio
`0.145`, mixed wire ratio `0.170`, mixed packet ratio `1.038`, hot packet ratio
`0.980`, trace packet ratio `1.015`, optioned packet ratio `1.011`, boundary
packet ratio `0.970`, UDP-ceiling packet ratio `0.953`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.002`. This is
parser/composer length-state cleanup, not template/WireArena completion.

Wire-name response compression also now avoids rescanning suffixes that were
already checked while looking for a compression pointer. The retained
`target/zone-image-bench/wire-compressor-prechecked-suffix-register.tsv` run
passed
`target/zone-image-bench/wire-compressor-prechecked-suffix-register-check.tsv`
with zero packet mismatches and unchanged response bytes. The check recorded
mixed packet ratio `1.030`, hot packet ratio `1.028`, trace packet ratio
`1.011`, optioned packet ratio `1.054`, boundary packet ratio `1.002`, and
UDP-ceiling packet ratio `1.024`. This is retained as local compressor
bookkeeping cleanup inside the current generic composer, not as evidence that
the remaining template/WireArena gap is closed.

The retained
`target/zone-image-bench/wire-compressor-lowercase-suffix-key-fast-path.tsv`
run adds a narrower stored-wire suffix-key fast path: validated suffixes that
are already all lowercase are copied directly into the suffix-key table instead
of lowercasing every label byte during key construction. Mixed-case suffixes
keep the canonicalizing path. The checker artifact
`target/zone-image-bench/wire-compressor-lowercase-suffix-key-fast-path-check.tsv`
passed with zero validation and packet mismatches, byte parity, mixed planning
ratio `0.153`, mixed wire ratio `0.171`, mixed packet ratio `0.998`, hot packet
ratio `1.100`, trace packet ratio `0.994`, optioned packet ratio `1.017`,
boundary packet ratio `0.997`, and UDP-ceiling packet ratio `0.990`. This is a
current-composer suffix-key fast path, not template/WireArena completion.

The follow-up
`target/zone-image-bench/stored-wire-suffix-key-single-pass.tsv` run keeps that
stored-wire direct-copy discipline but removes the separate full-suffix
lowercase pre-scan. Stored-wire suffix keys are now built in one pass: lowercase
labels copy directly, while only labels containing uppercase bytes are
canonicalized. The checker artifact
`target/zone-image-bench/stored-wire-suffix-key-single-pass-check.tsv` passed
with zero validation and packet mismatches, byte parity, mixed planning ratio
`0.145`, mixed wire ratio `0.170`, mixed packet ratio `1.017`, hot packet ratio
`0.981`, trace packet ratio `0.996`, optioned packet ratio `1.020`, boundary
packet ratio `0.983`, UDP-ceiling packet ratio `1.009`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.002`.

The generic compressor keeps the exact full-name suffix fast path for same-name
answers, but now treats a miss on that fast path as authoritative for the
subsequent label parser. That avoids immediately probing the same full suffix a
second time while still allowing later suffix labels to find compression
pointers. The retained
`target/zone-image-bench/wire-compressor-skip-full-miss-recheck.tsv` run passed
`target/zone-image-bench/wire-compressor-skip-full-miss-recheck-check.tsv` with
zero validation mismatches and unchanged response bytes. The check recorded
mixed packet ratio `1.038`, hot packet ratio `1.008`, trace packet ratio
`1.047`, optioned packet ratio `1.043`, boundary packet ratio `0.988`, and
UDP-ceiling packet ratio `0.981`. This remains a bounded local composer cleanup;
it does not close the future template or transport-buffer work.

The follow-up `target/zone-image-bench/wire-compressor-no-offset-scratch.tsv`
run removes the temporary label-offset `SmallVec` from the same generic
wire-name path. Stored wire-name parsing now returns only the write boundary
and selected compression pointer, and the composer registers pre-pointer
suffixes with a direct pass over the already validated wire labels. The retained
check at `target/zone-image-bench/wire-compressor-no-offset-scratch-check.tsv`
passed with zero validation mismatches and unchanged response bytes, recording
mixed packet ratio `1.005`, hot packet ratio `1.018`, trace packet ratio
`1.011`, optioned packet ratio `0.967`, boundary packet ratio `0.987`, and
UDP-ceiling packet ratio `0.995`. This removes local composer scratch state; it
does not replace the future immutable template composer.

The parsed-question compressor seed path is now direct as well. Every
`ZoneImage` response composer starts with a fresh suffix table, so the question
suffixes are inserted without probing for duplicates first, guarded by a debug
assertion that the table is empty. The retained
`target/zone-image-bench/wire-compressor-direct-question-seed.tsv` run passed
`target/zone-image-bench/wire-compressor-direct-question-seed-check.tsv` with
zero validation mismatches and unchanged response bytes. The check recorded
mixed packet ratio `1.008`, hot packet ratio `1.017`, trace packet ratio
`1.011`, optioned packet ratio `1.013`, boundary packet ratio `1.007`, and
UDP-ceiling packet ratio `1.008`. This keeps the current mutable composer
leaner while leaving template/WireArena work separate.
The retained `target/zone-image-bench/wire-compressor-direct-label-eq.tsv` and
rerun `target/zone-image-bench/wire-compressor-direct-label-eq-rerun.tsv`
extend that same compressor discipline to suffix comparison: stored canonical
suffix labels are first checked with direct byte equality, and only mixed-case
candidate labels fall back to the checked case-insensitive comparison. The rerun
checker passed with zero semantic and packet mismatches and unchanged response
bytes; this is kept as a narrow comparison fast path within the current mutable
composer gates, not as a broad packet-speed claim.
The follow-up `target/zone-image-bench/wire-compressor-direct-suffix-eq.tsv`
adds the same idea one level earlier: if an emitted stored suffix already
matches the canonical suffix-key bytes exactly, the compressor returns before
the label-by-label parser. Mixed-case suffixes still take the checked
case-insensitive path. Its checker passed with zero validation and packet
mismatches plus unchanged response bytes; packet ratios were noisy, so this is
retained as current-composer comparison work reduction, not as a broad
throughput claim.

The generic `ZoneImage` response builder also now computes the request UDP
ceiling once and passes that value through EDNS OPT emission, the UDP truncation
gate, and truncated/EDE retry helpers. The retained
`target/zone-image-bench/zone-image-single-udp-ceiling.tsv` run passed
`target/zone-image-bench/zone-image-single-udp-ceiling-check.tsv` with zero
validation mismatches and unchanged response bytes. The check recorded mixed
packet ratio `1.007`, hot packet ratio `1.028`, trace packet ratio `1.010`,
optioned packet ratio `0.987`, boundary packet ratio `0.987`, and UDP-ceiling
packet ratio `0.998`. This is local composer bookkeeping cleanup; the old
snapshot composer remains separate offline-oracle code.

EDNS OPT emission now appends response options directly into the final response
buffer instead of building a temporary option-RDATA `Vec` first. The composer
reserves the OPT rdlength field, writes NSID, DNS Cookie, EDE, TCP keepalive,
and padding options in place, then patches rdlength after padding decisions are
known. The retained `target/zone-image-bench/direct-edns-opt-append.tsv` run
passed `target/zone-image-bench/direct-edns-opt-append-check.tsv` with zero
validation mismatches and unchanged response bytes. The check recorded mixed
packet ratio `0.976`, hot packet ratio `1.051`, trace packet ratio `1.033`,
optioned packet ratio `1.018`, boundary packet ratio `0.986`, and UDP-ceiling
packet ratio `0.998`. This removes one response-composer allocation for EDNS
traffic while keeping the broader immutable template/WireArena composer work
separate.

Request-side EDNS parsing follows the same allocation discipline now:
additional-record parsing keeps RDATA as a borrowed packet slice for EDNS OPT
and NOTIFY SOA validation instead of copying every parsed additional record into
a `Vec`. Answer and authority record-header scans also skip compressed owner
names without materializing `DomainName` labels when checking for misplaced OPT
records. The invariant audit rejects restoring either the RDATA copy or the
owner-name allocation in that header-scan path, so the request/response EDNS
path stays allocation-light before io_uring or AF_XDP transport work. The retained
`target/zone-image-bench/edns-additional-borrowed-rdata.tsv` run passed
`target/zone-image-bench/edns-additional-borrowed-rdata-check.tsv` with zero
optioned, boundary, UDP-ceiling, and NOTIFY SOA validation mismatches, NOTIFY
SOA exact/mixed-case byte parity, mixed-case NOTIFY SOA validation ratio
`0.984`, optioned packet ratio `0.962`, boundary packet ratio `1.020`, and
UDP-ceiling packet ratio `1.007`. The follow-up
`target/zone-image-bench/edns-record-header-skip-name.tsv` run passed
`target/zone-image-bench/edns-record-header-skip-name-check.tsv` with zero
mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
mismatches, NOTIFY SOA exact/mixed-case byte parity, mixed packet ratio `0.995`,
optioned packet ratio `0.999`, boundary packet ratio `1.013`, and UDP-ceiling
packet ratio `1.014`. The follow-up
`target/zone-image-bench/edns-notify-record-view-no-owner-alloc.tsv` run makes
the full parsed-record view owner-allocation-free too: EDNS OPT root checks use
scanned owner metadata, NOTIFY SOA owner validation compares compressed packet
owner wire directly against the question labels, and SOA serial parsing skips
MNAME/RNAME directly to the serial field. Its checker passed at
`target/zone-image-bench/edns-notify-record-view-no-owner-alloc-check.tsv` with
zero mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA
validation mismatches, NOTIFY SOA exact/mixed-case byte parity, mixed packet
ratio `1.008`, optioned packet ratio `1.007`, boundary packet ratio `1.022`,
UDP-ceiling packet ratio `1.025`, and NOTIFY SOA mixed-case validation ratio
`0.999`. The follow-up
`target/zone-image-bench/notify-soa-single-owner-scan.tsv` run folds NOTIFY SOA
owner matching into the borrowed record-view scan, so the compressed answer
owner is no longer walked once for parsing and again for question comparison.
Its checker passed at
`target/zone-image-bench/notify-soa-single-owner-scan-check.tsv` with zero
mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
mismatches, NOTIFY SOA exact/mixed-case byte parity, mixed packet ratio `1.001`,
optioned packet ratio `0.980`, boundary packet ratio `1.018`, UDP-ceiling
packet ratio `1.006`, and NOTIFY SOA mixed-case validation ratio `1.002`.
The follow-up
`target/zone-image-bench/edns-fixed-option-prefixes-rerun.tsv` run removes
repeated fixed network-order encoding from EDNS response option emission: the
OPT owner/type bytes plus TCP keepalive, DNS Cookie, and EDE fixed option
prefixes are copied from preencoded constants, while dynamic payload bytes and
dynamic payload lengths stay on the runtime path. Its checker passed at
`target/zone-image-bench/edns-fixed-option-prefixes-rerun-check.tsv` with zero
mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
mismatches, packet byte parity for those corpora, mixed packet ratio `1.000`,
hot packet ratio `1.044`, trace packet ratio `0.960`, optioned packet ratio
`0.991`, boundary packet ratio `1.011`, UDP-ceiling packet ratio `0.997`, and
NOTIFY SOA mixed-case validation ratio `0.999`.
The follow-up `target/zone-image-bench/edns-padding-current-len.tsv` run removes
redundant OPT-offset bookkeeping from EDNS padding sizing: padding length is
computed from the current response buffer length plus the padding option header
instead of carrying OPT-start and RDATA-start offsets into the padding helper.
Its checker passed at
`target/zone-image-bench/edns-padding-current-len-check.tsv` with zero mixed,
hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
mismatches, packet byte parity for those corpora, mixed packet ratio `0.967`,
hot packet ratio `0.928`, trace packet ratio `0.978`, optioned packet ratio
`0.982`, boundary packet ratio `1.018`, UDP-ceiling packet ratio `1.012`, and
NOTIFY SOA mixed-case validation ratio `1.004`.
The follow-up `target/zone-image-bench/edns-response-option-shape.tsv` run
computes one carried EDNS response option shape before OPT emission, writes OPT
RDLENGTH from the carried RDATA length, and has option emission consume carried
TCP keepalive, NSID, Cookie, EDE, and padding decisions instead of rechecking
response-option presence while writing. Its checker passed at
`target/zone-image-bench/edns-response-option-shape-check.tsv` with zero mixed,
hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
mismatches, packet byte parity for those corpora, mixed packet ratio `1.003`,
hot packet ratio `1.015`, trace packet ratio `0.995`, optioned packet ratio
`1.002`, boundary packet ratio `1.005`, UDP-ceiling packet ratio `0.993`, and
NOTIFY SOA mixed-case validation ratio `0.997`.
The follow-up `target/zone-image-bench/zone-image-edns-sizing-bundle.tsv` run
bundles the ZoneImage EDNS capacity hint and full-UDP-capacity reserve decision
into one carried response sizing value, removes the old separate runtime helper
split, and threads the bundled sizing through direct, generic, failure, and
truncation response builders. Its checker passed at
`target/zone-image-bench/zone-image-edns-sizing-bundle-check.tsv` with zero
mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
mismatches, packet byte parity for those corpora, mixed packet ratio `0.984`,
hot packet ratio `0.990`, trace packet ratio `1.015`, optioned packet ratio
`0.978`, boundary packet ratio `0.980`, UDP-ceiling packet ratio `0.990`, and
NOTIFY SOA mixed-case validation ratio `0.995`.
The follow-up `target/zone-image-bench/zone-image-edns-base-shape.tsv` run
carries the fixed EDNS response option base shape inside the bundled ZoneImage
EDNS sizing value. ZoneImage capacity sizing and OPT emission now share that
base shape; only padding length remains computed from the final response length
at emission time. Its checker passed at
`target/zone-image-bench/zone-image-edns-base-shape-check.tsv` with zero mixed,
hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
mismatches, packet byte parity for those corpora, mixed packet ratio `1.021`,
hot packet ratio `1.035`, trace packet ratio `1.005`, optioned packet ratio
`1.008`, boundary packet ratio `1.017`, UDP-ceiling packet ratio `1.020`, and
NOTIFY SOA mixed-case validation ratio `0.996`.
The follow-up `target/zone-image-bench/zone-image-edns-additional-count.tsv`
run also carries the EDNS additional-record count inside the same bundled
ZoneImage EDNS sizing value. Failure, direct, generic, and truncation-retry
response builders now consume that carried 0/1 count instead of converting
`metadata.edns` into an additional count again while assembling DNS section
counts. Its checker passed at
`target/zone-image-bench/zone-image-edns-additional-count-check.tsv` with zero
mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
mismatches, packet byte parity for those corpora, mixed packet ratio `1.010`,
hot packet ratio `0.900`, trace packet ratio `1.029`, optioned packet ratio
`0.947`, boundary packet ratio `1.000`, UDP-ceiling packet ratio `1.001`, and
NOTIFY SOA mixed-case validation ratio `0.990`.
The follow-up
`target/zone-image-bench/zone-image-dead-dnssec-count-retired.tsv` removes the
now-dead DNSSEC response-metadata and record-count bookkeeping from the
ZoneImage and legacy truncation composers plus `ZoneImageLookupPlan`. DNSSEC
latency classification remains driven by final response bytes, so no wire
behavior depends on the removed counters. Its checker passed at
`target/zone-image-bench/zone-image-dead-dnssec-count-retired-check.tsv` with
zero mixed, hot, trace, optioned, boundary, UDP-ceiling, and EDE fallback
validation mismatches, packet byte parity for those corpora, mixed packet ratio
`1.001`, hot packet ratio `1.014`, trace packet ratio `0.982`, optioned packet
ratio `1.021`, boundary packet ratio `1.006`, UDP-ceiling packet ratio
`1.001`, and NOTIFY SOA mixed-case validation ratio `1.006`.
The follow-up `target/zone-image-bench/zone-image-ede-stripped-sizing.tsv`
carries the recomputed stripped EDNS sizing into the truncation record-removal
retry after an oversized EDE response remains too large even without the EDE
option. The EDE fallback benchmark bucket now covers both loading-zone EDE and
low-ceiling NSEC3-cap EDE truncation, and the invariant audit rejects keeping
stripped metadata with stale OPT sizing. Its checker passed at
`target/zone-image-bench/zone-image-ede-stripped-sizing-check.tsv` with two EDE
fallback packet cases, zero mixed, hot, trace, optioned, boundary, UDP-ceiling,
and EDE fallback validation mismatches, packet byte parity for those corpora,
mixed packet ratio `0.974`, hot packet ratio `0.949`, trace packet ratio
`0.977`, optioned packet ratio `0.964`, boundary packet ratio `0.997`,
UDP-ceiling packet ratio `0.999`, and NOTIFY SOA mixed-case validation ratio
`1.028`.

Minimal QTYPE=ANY planning now has the same shape: the default minimal policy
selects the lowest class/type same-owner RRset from the compiled per-owner
order instead of collecting all candidates, sorting them, and truncating to
one. Full ANY also uses that compiled owner/class/type order directly rather
than sorting the same-owner list per query. The retained
`target/zone-image-bench/minimal-any-single-pass-selection.tsv` run passed
`target/zone-image-bench/minimal-any-single-pass-selection-check.tsv` with zero
packet mismatches, unchanged image bytes, mixed packet ratio `0.981`, hot
packet ratio `0.953`, optioned packet ratio `0.977`, boundary packet ratio
`1.012`, and main/stress hot-byte-per-record checks still at `104.910` and
`130.173`.
The later retained
`target/zone-image-bench/any-compile-order-no-sort.tsv` run removes the
remaining full-ANY query-time sort after the surrounding planner/composer
cleanups made the earlier rejected compile-order attempt viable. It passed
`target/zone-image-bench/any-compile-order-no-sort-check.tsv` with zero
validation mismatches, unchanged response bytes, and packet ratios inside the
local gates.
`target/zone-image-bench/any-precomputed-additional-spans.tsv` then routes
exact and wildcard full-ANY additional-data planning through the answer RRset
list's precomputed additional-address relation spans. That removes the generic
plan-item rewalk and the unused dynamic-record additional fallback from the
live planner while keeping target-bearing exact and wildcard full-ANY coverage.
Its checker passed with zero validation mismatches and unchanged response
bytes.
`target/zone-image-bench/minimal-any-single-additional-span.tsv` extends the
single-answer relation-span shortcut to default minimal QTYPE=ANY when the
selected RRset can reference address targets. Minimal ANY now skips the
multi-RRset additional dedupe helper for the common one-answer case; full ANY
and multi-answer plans keep the deduping path.
`target/zone-image-bench/minimal-any-scalar-selection.tsv` then keeps the same
compiled-order minimal ANY semantics but returns the selected exact or wildcard
RRset through a scalar helper instead of building the one-entry RRset list used
by full ANY. Its checker artifact
`target/zone-image-bench/minimal-any-scalar-selection-check.tsv` passed with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.126`,
mixed wire ratio `0.152`, mixed packet ratio `1.011`, hot packet ratio `0.970`,
trace packet ratio `1.001`, optioned packet ratio `0.975`, boundary packet ratio
`1.014`, UDP-ceiling packet ratio `1.002`, delegation/DNAME-stress planning
ratio `0.001`, stress wire ratio `0.001`, total image bytes per record
`170.000`, and stress bytes per record `250.000`.
`target/zone-image-bench/full-any-streamed-planning.tsv` then removes the
remaining temporary full-ANY RRset list. Exact and wildcard full-ANY planning
walk the compiled owner RRset order once, push matching answers directly into
the plan, and run additional-address relation dedupe during the same pass. Its
checker artifact `target/zone-image-bench/full-any-streamed-planning-check.tsv`
passed with zero semantic and packet mismatches, byte parity, mixed planning
ratio `0.138`, mixed wire ratio `0.159`, mixed packet ratio `0.965`, hot packet
ratio `0.916`, trace packet ratio `0.981`, optioned packet ratio `0.977`,
boundary packet ratio `1.020`, UDP-ceiling packet ratio `0.995`, total image
bytes per record `174.000`, and stress bytes per record `254.000`. This keeps
QTYPE=ANY response ordering from compiled layout while avoiding the extra
per-query collection and rewalk before transport work.
`target/zone-image-bench/concrete-class-rrset-scan-early-exit.tsv` then uses
the same compiled per-owner class/type order for concrete-class response-plan
helper scans: exact-type helper and ANY scans stop once the requested class or
type has been passed, while QCLASS=ANY keeps scanning every class. The checker
passed with zero mismatches, byte parity, exact lookup ratio `0.211`, mixed
planning ratio `0.124`, and packet ratios inside the local gates. Extending
that branch to the older public `lookup_exact_plan` helper was measured and
rejected at
`target/zone-image-bench/lookup-exact-plan-class-early-exit-rejected.tsv`: the
checker still passed, but the retained fixture's `ZoneImage` exact lookup time
regressed to `40.805 ns` from the previous retained `34.465 ns`, so the helper
keeps the simpler class/type scan. The later retained absent-low gate is a
different branch: it only skips scanning after name classification when the
global low-RRtype bitmap proves the requested low type is absent from the image.
Storing per-node minimal-QTYPE=ANY RRset hints was also measured and rejected at
`target/zone-image-bench/minimal-any-node-hints.tsv`. The focused ANY tests and
packet differential checks stayed clean, but the checker failed at
`target/zone-image-bench/minimal-any-node-hints-check.tsv` because the
delegation/DNAME stress fixture reached `260.000` bytes per record against the
`256.000` cap. That keeps minimal-ANY selection on the existing node RRset scan
until a narrower representation can prove both packet-path and memory-density
value.

The non-ANY wildcard branch now shares the exact-positive additional-data gate:
wildcard answers whose RR type cannot reference address targets skip the
generic additional planner entirely, while target-bearing wildcard MX and
full-ANY wildcard answers use their compiled additional-address relation spans.
The retained
`target/zone-image-bench/wildcard-additional-gate.tsv` run passed
`target/zone-image-bench/wildcard-additional-gate-check.tsv` with zero semantic
and packet mismatches, byte parity, mixed planning ratio `0.122`, mixed wire
ratio `0.148`, mixed packet ratio `0.998`, optioned packet ratio `0.981`,
boundary packet ratio `0.986`, UDP-ceiling packet ratio `0.994`, and
delegation/DNAME stress planning and wire ratios of `0.001`.

The first directory index is intentionally simple: query lookup tests canonical
length-delimited reversed-label QNAME prefixes from most-specific to root
against the published suffix map, skipping hidden catalog zones and falling back
to the next visible parent zone. Lookup builds one canonical byte key per query
and probes borrowed prefix slices, avoiding the earlier per-suffix canonical
string construction.
The in-process benchmark records `zone_directory_linear_lookup_ns_per_query`,
`zone_directory_suffix_lookup_ns_per_query`, matching found counts, and matching
origin-label checksums so future directory structures can be compared against
both old linear semantics and the current suffix-index baseline.
The current retained `target/zone-image-bench/published-zone-key-suffix-baseline.tsv`
run kept that vector prefix-list builder after an inline temporary-key
experiment measured slower. The checker passed with zero semantic and packet
mismatches, matching directory found counts and label checksums, and
`zone_directory_suffix_lookup_ratio` of `0.013`.
The follow-up
`target/zone-image-bench/query-inline-parser-and-zone-suffix-scratch.tsv` keeps
that measured-faster single-key suffix lookup, but moves the per-query prefix
length list into inline `SmallVec<[usize; 8]>` storage for ordinary QNAME depths.
Its checker again passed with matching directory found counts and label
checksums, and `zone_directory_suffix_lookup_ratio` of `0.014`.
The retained `target/zone-image-bench/query-lowercase-zone-suffix-key.tsv` run
threads the parser-carried lowercase-QNAME fact into published-zone suffix
lookup. Lowercase query labels are copied directly into the canonical reversed
suffix key, while mixed-case queries keep the canonicalizing path. Its checker
passed with byte parity, zero packet mismatches, matching directory found
counts/checksums, and `zone_directory_suffix_lookup_ratio` of `0.014`; this is
retained as duplicate lowercase-work removal, not as a broad packet-speed claim.
The retained
`target/zone-image-bench/query-observation-lowercase-suffix-hint.tsv` run keeps
that hinted suffix lookup as an explicit cross-crate `ZoneStore` API and uses it
from runtime query observation after `Question` parsing has proved the QNAME
labels are lowercase ASCII. Its checker artifact
`target/zone-image-bench/query-observation-lowercase-suffix-hint-check.tsv`
passed with byte parity, zero packet mismatches, matching directory found
counts/checksums, `zone_directory_suffix_lookup_ratio` of `0.017`,
`mixed_plan_ratio` of `0.148`, `mixed_packet_ratio` of `1.013`,
`hot_packet_ratio` of `0.978`, and `udp_ceiling_packet_ratio` of `1.018`. Treat
this as API-boundary and duplicate lowercase-work evidence for the packet
metrics path, not as a broad throughput claim.
The follow-up `target/zone-image-bench/published-zone-directory-hidden-filter.tsv`
keeps hidden-zone filtering inside `ZoneDirectory::find_best_match`, where the
suffix walk already checks visibility before returning a match, and removes the
redundant post-match hidden filter from `ZoneStore`'s published-zone wrapper.
The checker artifact
`target/zone-image-bench/published-zone-directory-hidden-filter-check.tsv`
passed with matching directory found counts/checksums, suffix lookup ratio
`0.019`, byte parity, zero packet mismatches, `mixed_plan_ratio` of `0.154`,
`mixed_packet_ratio` of `1.016`, `hot_packet_ratio` of `0.973`, and
`udp_ceiling_packet_ratio` of `1.006`. Treat this as query-boundary branch
cleanup, not as broad packet-throughput evidence.
The retained `target/zone-image-bench/zone-directory-cached-active-count.tsv`
run also moves active-zone counting into the immutable published directory.
`ZoneDirectory` updates the cached active-zone count as zones are published,
replaced, expired, or removed, so status and zone-count metrics no longer scan
published snapshot states to derive that scalar. The checker artifact
`target/zone-image-bench/zone-directory-cached-active-count-check.tsv` passed
with matching cached and linear active-count checksums, cached active-count
ratio `0.025`, suffix lookup ratio `0.016`, byte parity, zero packet
mismatches, `mixed_packet_ratio` of `0.977`, and `udp_ceiling_packet_ratio` of
`1.005`. Treat this as status/metrics old-layout cleanup, not as packet-path
throughput evidence.
The retained `target/zone-image-bench/query-lowercase-zone-image-trie.tsv` run
threads the same parser-carried lowercase-QNAME fact into `ZoneImage` direct and
semantic trie lookup. Child hash probes, single-child equality checks, and
binary-search comparisons can skip per-byte lowercasing when the query parser
proved the QNAME labels were already lowercase; public lookup wrappers keep the
conservative canonicalizing path for other callers. The checker passed with byte
parity, zero packet mismatches, `mixed_plan_ratio` of `0.148`,
`mixed_packet_ratio` of `1.008`, and `zone_directory_suffix_lookup_ratio` of
`0.015`.
The retained
`target/zone-image-bench/query-lowercase-dnssec-augmentation.tsv` run extends
that same lowercase-QNAME fact into DNSSEC denial augmentation's query-node
lookup. The public DNSSEC augmentation wrapper remains conservative for generic
callers; only the packet path that already parsed the QNAME as ASCII lowercase
uses the hinted helper. The checker passed with byte parity, zero packet
mismatches, `mixed_plan_ratio` of `0.150`, `mixed_packet_ratio` of `0.972`,
`boundary_packet_ratio` of `0.988`, `udp_ceiling_packet_ratio` of `1.026`, and
`zone_directory_suffix_lookup_ratio` of `0.015`. Treat this as duplicate
lowercase-work removal for the DO denial path, not as a broad packet-throughput
claim.
The retained `target/zone-image-bench/query-lowercase-denial-label-view.tsv`
run carries the same parser-proven lowercase-QNAME fact into NSEC/NSEC3 proof
label views. NSEC range comparison and NSEC3 SHA-1 input skip per-byte
lowercasing for lowercase packet labels; mixed-case packets and public wrappers
keep the conservative canonicalizing path. Its checker passed with byte parity,
zero packet mismatches, `mixed_plan_ratio` of `0.144`, `mixed_packet_ratio` of
`0.948`, `boundary_packet_ratio` of `0.994`, `udp_ceiling_packet_ratio` of
`1.015`, and `zone_directory_suffix_lookup_ratio` of `0.014`. Treat this as
further duplicate lowercase-work removal in DNSSEC denial proof selection, not
as a broad packet-throughput claim.
Arena-wire compression for
owner names plus known-name RDATA keeps packet bytes equal to the current
composer for the retained query mix without rehydrating `DomainName` owners.
The compressor now avoids per-probe suffix-key allocation for canonical
lowercase wire names, which is the normal compiled `ZoneImage` owner/RDATA
shape.
ZoneImage packet response code no longer references the compatibility
`LookupResult` materialization APIs: those APIs have been removed from
`ZoneImage`. The runtime and fuzzed ZoneImage serving surface use the
lookup-metrics observer, which reads termination and NSEC3-cap state directly
from the plan, then the response composer visits immutable wire records. Old/new
differential checks and in-process benchmarks compare `ZoneImage` plan
summaries, immutable wire sections, or final packet bytes rather than
materializing image `LookupResult` values.
The stale `observer_unsupported` fallback reason was removed after ZoneImage
serving moved fully onto the lookup-metrics observer. The `unavailable` bucket
was then removed by making rollback skip the image attempt entirely and making
enabled serving use the compiled image already attached to the active
`PublishedZone`. DNSSEC augmentation now returns a plan directly after NSEC and
NSEC3 proof selection moved onto compiled metadata and optional proof handles,
so the dead DNSSEC plan-error metric bucket was removed. DNSSEC denial planning
also computes the negative authority-SOA precondition once before NODATA and
NXDOMAIN proof selection, using authority RRset handles only. The earlier
SOA-first authority check has now been superseded by explicit plan state:
`ZoneImageLookupPlan` tracks whether an authority SOA was inserted, and
SERVFAIL conversion clears the bit with the authority section. The retained
`target/zone-image-bench/authority-soa-plan-bit.tsv` run passed
`target/zone-image-bench/authority-soa-plan-bit-check.tsv` with zero semantic
and packet mismatches, byte parity, mixed planning ratio `0.119`, mixed wire
ratio `0.148`, and packet ratios inside the local gates. This removes the
remaining authority RRset scan from DNSSEC denial precondition checks without
adding bytes to `ZoneImage`. Semantic response planning also returns a plan
directly after CNAME, DNAME, wildcard, and additional-data planning stopped
surfacing build errors, so the dead plan-error metric bucket was removed. The
remaining internal failure bucket is response build failure; it returns a
ZoneImage SERVFAIL response instead of re-entering the snapshot lookup path.
That SERVFAIL fallback now also stays on the ZoneImage composer helpers:
`target/zone-image-bench/zone-image-failure-prefix-path.tsv` uses the shared
ZoneImage DNS-header prefix and EDNS append path rather than the old
`ResourceRecord` response composer. The retained checker
`target/zone-image-bench/zone-image-failure-prefix-path-check.tsv` passed with
zero validation/packet mismatches and byte parity: mixed planning ratio `0.136`,
mixed wire ratio `0.160`, mixed packet ratio `0.998`, hot packet ratio `1.004`,
trace packet ratio `1.011`, optioned packet ratio `1.025`, boundary packet ratio
`1.003`, UDP-ceiling packet ratio `1.012`, and delegation/DNAME stress planning
and wire ratios of `0.001` and `0.002`. Treat this as rare-path
composer-boundary cleanup, not a broad packet-path speed claim.
The follow-up `target/zone-image-bench/empty-response-zone-image-prefix.tsv`
extends that boundary to empty protocol shell responses before any record
section exists. FORMERR, REFUSED, NOTIMP, NOTIFY acknowledgements, and similar
no-record responses now reuse the shared ZoneImage-style DNS header prefix,
section-count byte helper, and EDNS append path instead of instantiating the old
`ResourceRecord`/`NameCompressor` composer. A focused EDNS NSID empty-response
test covers the fast path, and the invariant audit rejects sending empty record
sections through the old composer. The checker artifact
`target/zone-image-bench/empty-response-zone-image-prefix-check.tsv` passed
with two EDE fallback cases, zero validation/packet mismatches, byte parity,
mixed planning ratio `0.134`, mixed packet ratio `0.997`, hot packet ratio
`0.944`, trace packet ratio `0.985`, optioned packet ratio `1.008`, boundary
packet ratio `1.065`, UDP-ceiling packet ratio `1.025`, delegation/DNAME stress
plan and wire ratios of `0.001` and `0.002`, and NOTIFY SOA mixed-case
validation ratio `0.998`. Treat this as protocol-shell composer-boundary
cleanup before transport work, not a physical throughput claim.
The request path still attempts the exact-owner direct-answer emitter before
full semantic planning, but the generic `ZoneImage` response builder no longer
retries that same direct plan after the first attempt rejected it. The retained
`target/zone-image-bench/direct-preflight-retry-skip.tsv` run keeps byte parity
and zero validation/packet mismatches; this is narrow duplicate preflight
cleanup for known-name RDATA and oversized direct UDP fallthroughs, not proof
that the remaining immutable template composer gap is closed.
The retained `target/zone-image-bench/direct-preflight-target-type-gate.tsv`
run moves the target-bearing RR-type rejection ahead of direct-preflight trie,
delegation, DNAME, and RRset lookup work. Target-bearing answers need the
semantic/generic path for additional records, so the direct path can reject
them from the query type alone.
Additional-data planning also now uses one pass over answer handles for target
detection and target emission, while keeping the common target-dedupe set
inline. The retained `target/zone-image-bench/additional-planning-single-pass.tsv`
run keeps zero validation and packet mismatches and passes the benchmark
checker; it is retained as planner-pass cleanup rather than a broad packet-path
speed claim.
Answer additional-data planning also now asserts that it starts with an empty
additional section and relies on the inline target-dedupe set as the only
duplicate check while populating precomputed and dynamic target RRsets. The
retained `target/zone-image-bench/additional-empty-section-dedupe.tsv` run keeps
zero validation and packet mismatches and passes the benchmark checker; it is
retained as narrow duplicate-check cleanup.
The retained
`target/zone-image-bench/additional-relations-direct-slice-rerun.tsv` run keeps
that shape and removes the remaining runtime RRset-iterator wrapper from
additional-address planning: non-target RRsets still leave through the compiled
bitmap fast gate, while target-bearing single and multi-answer paths consume
the immutable relation slice directly. The checker passes with zero validation
and packet mismatches, so this is retained as narrow relation-slice cleanup
inside the local gates rather than a broad packet-path speed claim.
The retained `target/zone-image-bench/indirection-additional-gate.tsv` run
extends that discipline to CNAME/DNAME endpoint planning: non-target endpoints
return without invoking the generic answer-additional pass, while
target-bearing final RRsets append the same precomputed target discovery span
directly. Future target-bearing dynamic records keep the guarded dynamic target
parser.
The retained `target/zone-image-bench/single-answer-additional-span.tsv` run
narrows the single target-bearing answer path further: exact, wildcard, and
CNAME/DNAME endpoint plans append the deduplicated compiled relation span
directly, leaving the generic answer-additional scan for multi-answer and
dynamic target-bearing shapes.
The retained `target/zone-image-bench/minimal-any-single-additional-span.tsv`
run applies that same shape to minimal QTYPE=ANY with one target-bearing
answer, avoiding the per-query `seen` set used by multi-answer additional
planning while retaining full-ANY dedupe semantics.
The retained `target/zone-image-bench/minimal-any-scalar-selection.tsv` run
narrows default minimal ANY one step further: exact and wildcard minimal ANY use
scalar compiled-order selection and only full ANY builds the ordered RRset list.
The retained
`target/zone-image-bench/semantic-additional-qtype-predicate.tsv` run then
removes redundant compiled-RRset type reads from the semantic planner: exact
positive, wildcard, and CNAME/DNAME endpoint additional-target predicates use
the concrete query type after exact RRset lookup has already matched that type.
The checker passed with zero validation mismatches, unchanged response bytes,
mixed planning ratio `0.114`, mixed wire ratio `0.149`, and packet ratios inside
the local gates.
The retained `target/zone-image-bench/additional-relation-flag.tsv` run then
makes that relation-driven planner model explicit for multi-answer and
QTYPE=ANY additional planning, and
`target/zone-image-bench/single-answer-relation-bitmap.tsv` extends the same
bitmap gate to single-answer exact, wildcard, and CNAME/DNAME endpoint plans:
compiled RRsets carry a compact bitmap bit when they actually have an
additional-address relation span, so query-time code tests relation availability
rather than reclassifying RR types. The additional-relation-flag checker passed
with zero validation mismatches, unchanged response bytes, mixed planning ratio
`0.132`, mixed wire ratio `0.158`, mixed packet ratio `1.046`, hot packet ratio
`1.079`, optioned packet ratio `1.040`, boundary packet ratio `0.963`,
UDP-ceiling packet ratio `1.002`, main hot bytes per record `98.499`, and stress
hot bytes per record `134.267`; this is retained as data-model cleanup with
bounded memory cost, not as a broad packet-path speed claim.
Single-answer planning then regained the cheaper RR-type precondition in front of
that bitmap: `target/zone-image-bench/single-answer-additional-type-gate.tsv`
skips relation lookup entirely for non-target RR types and returns whether
additionals were appended so exact A/AAAA/TXT-style plans can keep direct-answer
eligibility without inspecting the additional section. The checker retained zero
validation/packet mismatches and byte parity, with mixed planning ratio `0.162`,
mixed wire ratio `0.184`, mixed packet ratio `1.004`, and UDP-ceiling packet
ratio `1.004`.
The retained `target/zone-image-bench/dnssec-unsigned-augmentation-skip.tsv` run
adds the same kind of coarse compile-time capability gate for DO-bit DNSSEC
augmentation. Unsigned images with no proof/signature relation material skip the
augmentation state machine entirely; signed images keep the existing path.
The retained `target/zone-image-bench/dnssec-capability-gates.tsv` run narrows
that further with compile-time denial/referral/RRSIG sub-gates, so partial
DNSSEC images do not enter augmentation branches that cannot emit records.
The retained `target/zone-image-bench/dnssec-state-seeding-gates.tsv` run uses
those same sub-gates to avoid seeding dedupe state for augmentation branches
that are disabled by the compiled image.
The retained
`target/zone-image-bench/dnssec-lazy-authority-dedupe-seed.tsv` run then moves
authority-proof dedupe seeding to first insertion, avoiding the per-query
authority RRset clone when enabled denial/referral capability does not emit a
proof RRset for that response.
The retained
`target/zone-image-bench/dnssec-authority-dedupe-clone-free.tsv` run removes
that clone entirely by checking the existing authority section before inserting
and tracking only authority proof RRsets appended during augmentation.
The retained
`target/zone-image-bench/dnssec-authority-dedupe-fast-path.tsv` run keeps the
same clone-free model but checks the small appended-proof set before scanning
the full authority section, so repeated proof candidates appended during the
same augmentation return from the narrow dedupe set first. It passed
`target/zone-image-bench/dnssec-authority-dedupe-fast-path-check.tsv` with zero
validation mismatches and unchanged response bytes.
The retained
`target/zone-image-bench/dnssec-authority-dedupe-single-scan.tsv` run then
removed the second appended-set scan for newly appended authority proof RRsets:
existing authority records still use the full section duplicate check before
the appended set is created, while new proof records are pushed directly after
the checks pass. It passed
`target/zone-image-bench/dnssec-authority-dedupe-single-scan-check.tsv` with
zero validation mismatches and unchanged response bytes.
The retained
`target/zone-image-bench/dnssec-appended-authority-inline-two.tsv` run narrows
the appended-proof scratch set itself to two inline RRset handles. Larger proof
sets still spill, while common denial/referral proof bookkeeping carries less
inline state. It passed
`target/zone-image-bench/dnssec-appended-authority-inline-two-check.tsv` with
zero semantic and packet mismatches and unchanged response bytes.
The retained
`target/zone-image-bench/dnssec-authority-appended-inline-set-rerun.tsv` run
then removes the optional state wrapper around that appended-proof scratch set:
DNSSEC augmentation state always carries the two-entry inline set, and proof
insertion checks it directly before the original authority prefix. It passed
the checker with zero validation and packet mismatches and is retained as
narrow authority-proof bookkeeping cleanup inside the local gates.
The retained
`target/zone-image-bench/dnssec-authority-original-prefix.tsv` run narrows that
existing-authority check to the original authority-section prefix captured
before DNSSEC augmentation. Proof RRsets appended during augmentation are
deduped by the appended-proof set only, so repeated proof candidates no longer
rescan the growing authority suffix. It passed
`target/zone-image-bench/dnssec-authority-original-prefix-check.tsv` with zero
validation mismatches and unchanged response bytes.
The retained `target/zone-image-bench/dnssec-answer-presence-denial-gate.tsv`
run narrows the denial branch again: positive-answer plans use a short-circuit
presence predicate instead of exact answer-record summation before deciding that
denial proof planning is not applicable.
The retained `target/zone-image-bench/dnssec-answer-presence-plan-shape.tsv`
run narrows that branch further: denial/wildcard candidate classification now
uses the response plan's answer shape rather than compiled RRset count reads,
with the non-empty compiled-RRset invariant checked at build time in debug
builds.
The retained `target/zone-image-bench/plan-answer-presence-bit.tsv` run then
makes that classifier explicit plan state: answer insertion paths set a cached
answer-presence bit, and DNSSEC denial/wildcard augmentation reads it directly.
The checker passed at `target/zone-image-bench/plan-answer-presence-bit-check.tsv`
with zero semantic and packet mismatches and unchanged response bytes.
The retained `target/zone-image-bench/plan-state-flags.tsv` run then compacts
the plan's explicit boolean state into one flag byte. The checker passed at
`target/zone-image-bench/plan-state-flags-check.tsv` with zero semantic and
packet mismatches and unchanged response bytes.
The retained `target/zone-image-bench/direct-plan-state-access.tsv` run then
makes ownership of that state explicit in code: answer-presence, authority-SOA,
and first-authority-SOA checks are `ZoneImageLookupPlan` accessors rather than
`ZoneImage` helper calls. DNSSEC denial/wildcard classification and
authority-section emission read the compact flags directly from the plan. The
checker passed at `target/zone-image-bench/direct-plan-state-access-check.tsv`
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.153`, mixed wire ratio `0.183`, mixed packet ratio `1.002`, hot packet ratio
`0.905`, trace packet ratio `0.952`, optioned packet ratio `0.888`, boundary
packet ratio `0.989`, UDP-ceiling packet ratio `0.984`, total image bytes per
record `174.000`, and stress bytes per record `254.000`.
The retained
`target/zone-image-bench/dnssec-denial-candidate-single-eval.tsv` run removes
the remaining duplicate denial query-node classifier helper. DNSSEC denial
augmentation now computes the NODATA and NXDOMAIN predicates once and reuses the
combined `denial_candidate` for both authority-SOA and query-node-handle
decisions while leaving wildcard proof classification separate. The checker
passed at
`target/zone-image-bench/dnssec-denial-candidate-single-eval-check.tsv` with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.139`,
mixed wire ratio `0.159`, mixed packet ratio `1.028`, hot packet ratio `1.074`,
trace packet ratio `1.066`, boundary packet ratio `0.981`, and UDP-ceiling
packet ratio `1.007`.

The retained
`target/zone-image-bench/dnssec-denial-callsite-candidate-gates.tsv` run moves
the NODATA, NXDOMAIN, and wildcard proof helper candidate gates to the DNSSEC
augmentation callsite. The helpers no longer carry duplicate candidate boolean
arguments; they run only after the already-computed plan predicate has passed,
while still receiving the parser-carried lowercase-QNAME hint and the relevant
query-node handle where needed. The checker artifact
`target/zone-image-bench/dnssec-denial-callsite-candidate-gates-check.tsv`
passed with zero validation and packet mismatches, hot bytes per record
`106.365`, total bytes per record `174.000`, stress bytes per record `256.000`,
mixed planning ratio `0.157`, mixed packet ratio `1.007`, trace packet ratio
`1.050`, boundary packet ratio `0.986`, and UDP-ceiling packet ratio `1.017`.
This is branch-shape cleanup for DNSSEC denial proof selection, not transport
evidence.

The retained
`target/zone-image-bench/dnssec-denial-soa-gated-query-node.tsv` run narrows the
same branch again: the exact/closest query-node trie lookup now sits behind the
already-computed authority-SOA precondition, so NODATA and NXDOMAIN plans that
cannot emit SOA-backed denial proofs do not compute query-node handles they will
discard. The checker artifact
`target/zone-image-bench/dnssec-denial-soa-gated-query-node-check.tsv` passed
with zero validation and packet mismatches, hot bytes per record `106.365`,
total bytes per record `174.000`, stress bytes per record `256.000`, mixed
planning ratio `0.146`, mixed packet ratio `1.018`, hot packet ratio `1.087`,
trace packet ratio `1.063`, boundary packet ratio `1.010`, and UDP-ceiling
packet ratio `1.016`.

The retained
`target/zone-image-bench/dnssec-prestate-no-candidate-gate.tsv` run then moves
the same candidate classification before `ZoneImageDnssecState` construction.
Referral, NODATA, NXDOMAIN, and wildcard candidacy are computed first, and
proof-family-only images return the semantic plan unchanged for positive
non-wildcard responses that cannot consume NSEC/NSEC3 proof helpers. The checker
artifact `target/zone-image-bench/dnssec-prestate-no-candidate-gate-check.tsv`
passed with zero validation and packet mismatches, hot bytes per record
`106.365`, total bytes per record `174.000`, stress bytes per record `256.000`,
mixed planning ratio `0.142`, mixed packet ratio `0.992`, hot packet ratio
`0.949`, trace packet ratio `0.984`, boundary packet ratio `0.997`, and
UDP-ceiling packet ratio `0.995`.

The retained
`target/zone-image-bench/dnssec-nodata-plan-precondition.tsv` run keeps that
ownership boundary in the signed NODATA branch: DNSSEC augmentation no longer
accepts `qtype` or repeats exact-qtype lookup after response planning has
classified the plan as no-answer. The exact qname node is used only for
exact-name NSEC proof selection. The checker passed at
`target/zone-image-bench/dnssec-nodata-plan-precondition-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.138`,
mixed wire ratio `0.157`, mixed packet ratio `0.972`, hot packet ratio `0.943`,
trace packet ratio `0.993`, optioned packet ratio `0.980`, boundary packet
ratio `1.009`, and UDP-ceiling packet ratio `1.013`. This is narrow
signed-denial planning/API cleanup before transport work.
The retained `target/zone-image-bench/owner-override-direct-body-metrics.tsv`
run applies the same "use compiled metrics first" rule to wildcard
owner-override direct-copy answers: carried wire bounds reuse the compiled
direct-answer body length rather than deriving non-owner bytes from stored
full-owner RRset wire per query. The checker passed at
`target/zone-image-bench/owner-override-direct-body-metrics-check.tsv` with zero
semantic and packet mismatches, byte parity, mixed planning ratio `0.147`, mixed
wire ratio `0.170`, mixed packet ratio `0.973`, hot packet ratio `0.978`, trace
packet ratio `0.994`, optioned packet ratio `0.979`, boundary packet ratio
`1.015`, and UDP-ceiling packet ratio `1.012`.
A broader per-RRset `ownerless_wire_len` metadata experiment was first measured
and rejected. `target/zone-image-bench/ownerless-wire-len-precompute.tsv`
avoided the remaining owner-override non-owner byte derivation for every RRset,
but grew `ImageRrset` from 48 to 52 bytes. The checker artifact
`target/zone-image-bench/ownerless-wire-len-precompute-check.tsv` failed because
delegation/DNAME stress bytes per record rose to `260.000` against the retained
maximum `256.000`. The retained
`target/zone-image-bench/fixed-field-rrset-ownerless-len.tsv` follow-up keeps
the same per-RRset ownerless wire length but removes duplicate scalar
`rr_type`/`class` fields and reads TYPE/CLASS from immutable fixed fields. That
keeps `ImageRrset` at 48 bytes while turning owner-override non-owner byte
accounting into a metadata read. The checker passed at
`target/zone-image-bench/fixed-field-rrset-ownerless-len-check.tsv` with zero
semantic and packet mismatches, base image bytes per record `174.000`,
delegation/DNAME stress bytes per record `256.000`, mixed planning ratio
`0.137`, mixed wire ratio `0.152`, mixed packet ratio `1.004`, hot packet ratio
`1.004`, trace packet ratio `0.987`, optioned packet ratio `0.998`, boundary
packet ratio `0.979`, and UDP-ceiling packet ratio `0.989`.
The retained `target/zone-image-bench/direct-answer-plan-flag.tsv` run then
uses that plan flag byte to carry simple direct-answer composer eligibility.
The checker passed at
`target/zone-image-bench/direct-answer-plan-flag-check.tsv` with zero semantic
and packet mismatches and unchanged response bytes.
The retained `target/zone-image-bench/authoritative-plan-flag.tsv` run folds
authoritative/referral state into that same compact plan flag byte. The checker
passed at `target/zone-image-bench/authoritative-plan-flag-check.tsv` with zero
semantic and packet mismatches and unchanged response bytes.
The retained `target/zone-image-bench/answer-rrsets-inline-one.tsv` run then
narrows inline answer-RRset storage for the common one-handle concrete-answer
shape. The checker passed at
`target/zone-image-bench/answer-rrsets-inline-one-check.tsv` with zero semantic
and packet mismatches and unchanged response bytes.
The retained `target/zone-image-bench/authority-rrsets-inline-two.tsv` run then
narrows inline authority-RRset storage for the common small authority section.
The checker passed at
`target/zone-image-bench/authority-rrsets-inline-two-check.tsv` with zero
semantic and packet mismatches and unchanged response bytes.
The retained `target/zone-image-bench/additional-rrsets-inline-four.tsv` run
then narrows inline additional-RRset storage while keeping headroom for common
multi-target additional sections. The checker passed at
`target/zone-image-bench/additional-rrsets-inline-four-check.tsv` with zero
semantic and packet mismatches and unchanged response bytes.
The retained `target/zone-image-bench/selected-section-inline-one.tsv` run then
narrows selected authority/additional RRSIG storage for the common one-handle
section-signature shape. The checker passed at
`target/zone-image-bench/selected-section-inline-one-check.tsv` with zero
semantic and packet mismatches and unchanged response bytes.
The retained `target/zone-image-bench/dynamic-answer-inline-one.tsv` run then
narrows dynamic synthesized-answer storage for the common one-record DNAME
synthesized CNAME shape. The checker passed at
`target/zone-image-bench/dynamic-answer-inline-one-check.tsv` with zero
semantic and packet mismatches and unchanged response bytes.
The retained
`target/zone-image-bench/dnssec-denial-proof-family-callsite-gates.tsv` run
keeps NSEC and NSEC3 helper entry tied to compiled proof-family presence at the
NODATA, NXDOMAIN, and wildcard denial callsites, so partial DNSSEC images do
not pay empty-family helper setup costs.
The retained `target/zone-image-bench/selected-record-dedupe-inline-four.tsv`
run narrows the DNSSEC selected-record dedupe scratch to four inline records
for the common small RRSIG augmentation shape. The checker passed at
`target/zone-image-bench/selected-record-dedupe-inline-four-check.tsv` with
zero semantic and packet mismatches and unchanged response bytes; packet ratios
stayed inside the local gates.
Referral glue uses compile-time deduplicated relation spans and appends them
directly to fresh referral plans without a per-response duplicate scan. The
retained `target/zone-image-bench/referral-glue-no-runtime-dedupe.tsv` run keeps
zero validation and packet mismatches and passes the benchmark checker; this is
also retained as narrow planner cleanup.

The follow-up
`target/zone-image-bench/referral-glue-direct-relation-append.tsv` run keeps
that compile-time dedupe policy and removes the runtime referral-glue RRset
iterator adapter from the planner. Referral plans now append directly from the
immutable referral-glue relation slice, with the RRset iterator wrapper retained
only for tests. The checker artifact
`target/zone-image-bench/referral-glue-direct-relation-append-check.tsv` passed
with zero validation and packet mismatches, byte parity, mixed planning ratio
`0.148`, mixed wire ratio `0.172`, mixed packet ratio `1.032`, hot packet ratio
`1.022`, trace packet ratio `1.008`, optioned packet ratio `0.970`, boundary
packet ratio `0.993`, UDP-ceiling packet ratio `1.004`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.002`.
DNSSEC authority proof insertion also avoids copying existing authority RRset
handles before adding NSEC/NSEC3/DS proof RRsets. The retained
`target/zone-image-bench/dnssec-authority-dedupe-clone-free.tsv` run keeps zero
validation and packet mismatches and passes the benchmark checker; this is
retained as narrow DNSSEC planner cleanup.
The default-enabled query branch now also checks `PublishedZone` state directly
before attempting `ZoneImage`, so it does not clone the old `ZoneSnapshot` on
the hot path. Runtime query metric observation now reads origin state and a
cached canonical origin key through the same published-zone handle instead of
cloning the snapshot or rebuilding the key from the snapshot origin just to
label metrics. The live runtime shadow-validation oracle has been retired, so
the runtime metric path no longer clones snapshots or runs old snapshot lookups
for comparison. The hidden snapshot-rollback serving entry points were then
removed, along with the runtime path selector and the materializing
`LookupResult` observer bridge. The core `answer_datagram` and `answer_message`
convenience APIs now use the same required-provider ZoneImage serving path by
default, and packet-answering code has no snapshot clone or
offline-oracle call. Query-suffix zone lookup now exposes
`PublishedZone` handles rather than `Arc<ZoneSnapshot>` or a snapshot-to-image
bridge; exact-origin snapshot access is retained for transfer, catalog, builder,
and offline benchmark comparison responsibilities. The broad string-key
`ZoneStore::get` accessor has been removed, and presence-only NOTIFY/catalog
membership decisions use `contains_exact_zone_for_control` so they do not clone
`Arc<ZoneSnapshot>` just to test membership. Runtime status and metrics now use
`ZoneStore::zone_metadata()`, with active-zone shape summaries cached on the
published entry at publication time, instead of cloning full snapshots and
rescanning the old layout for each scrape. `zone_metadata()` also sorts from the
cached published entry origin key before materializing `ZoneMetadata`, avoiding
canonical-origin key rebuilds while producing stable status order. The cached
published origin key is now carried inside `ZoneMetadata` as well, so scheduler
metric lookup, per-zone query counts, and per-zone RCODE counters do not
rebuild `metadata.origin.canonical_key()` for every metric family. The retained
`target/zone-image-bench/zone-metadata-cached-origin-key.tsv` run records
matching cached/rebuilt origin-key checksums and cached/rebuilt key ratio
`0.284`, with mixed packet ratio `1.031` and UDP-ceiling packet ratio `1.018`.
`ZoneMetadata` also carries the cached display origin name used by status,
shape, scheduler, and query metric labels, so those scrape loops no longer
rebuild `metadata.origin.to_string()` for each metric line. The retained
`target/zone-image-bench/zone-metadata-cached-origin-name.tsv` run records
matching cached/rebuilt origin-name checksums and cached/rebuilt name ratio
`0.232`, with mixed packet ratio `0.984` and UDP-ceiling packet ratio `0.997`.
Transfer
control paths that only need state, serial, or SOA timers now use
`ZoneStore::exact_zone_control_metadata()` for NOTIFY current-serial checks,
refresh-failure scheduling, loading warnings, serial-hint decisions, and SOA
poll decisions. That accessor intentionally omits status-only shape summaries
and histograms while full `ZoneStore::exact_zone_metadata()` remains available
for status/metrics. The retained
`target/zone-image-bench/zone-control-metadata-no-shape-clone.tsv` run records
matching full/control found counts and serial checksums, full shape count
`200000`, control shape count `0`, and control/full metadata ratio `0.726`.
Current refresh outcomes return `ZoneMetadata` instead of carrying an
`Arc<ZoneSnapshot>` through success handling. Current serial-hint and SOA-poll
outcomes consume the already-loaded control metadata when returning, and
success handling consumes the outcome into one metadata value plus an
updated-only snapshot handle. The snapshot is still borrowed only when IXFR
needs the current builder model, and IXFR-current outcomes return the cached
control metadata carried by that transfer snapshot view. IXFR current-zone
setup is now serial-gated before exposing that transfer snapshot view; the
retained `target/zone-image-bench/ixfr-serial-gated-transfer-view.tsv` checker
passed with `100000` serial-bearing transfer views, `100000` no-serial skips,
serial checksum `50000000`, zero validation/packet mismatches,
control-metadata ratio `0.775`, and serial-gated transfer view ratio `1.527`.
Newly transferred
AXFR/IXFR builder snapshots are
wrapped once in an `Arc`, published through
`ZoneStore::insert_snapshot_arc_for_transfer`, which returns the newly
published entry's cached control metadata. The updated success outcome carries
that metadata with the same shared snapshot handle. This avoids cloning the
full old layout or hand-rebuilding metadata between transfer completion,
publication, scheduler recording, serial logging, and catalog follow-up.
Catalog follow-up detection also uses the carried metadata origin before
borrowing the updated snapshot for catalog parsing, and catalog snapshot
application looks up the catalog runtime configuration by the carried
`origin_key` instead of rebuilding a key from `snapshot.origin`. Refresh success handling
records scheduler state from narrow `ZoneMetadata`; full snapshot catalog
reconciliation runs only for updated catalog snapshots, not for current or
unchanged refresh outcomes.
The test refresh helper follows the same boundary: it returns carried
`ZoneMetadata` for successful refreshes instead of cloning current or updated
success outcomes back into owned `ZoneSnapshot` values. The invariant audit
rejects restoring that hidden test-only `into_owned` conversion.
The older retained
`target/zone-image-bench/refresh-success-consumed-metadata.tsv` follow-up
captures the consume-path cleanup, but it predates the current checker's
required NOTIFY SOA validation metric. Current-schema retained evidence for the
transfer cached-metadata boundary is
`target/zone-image-bench/transfer-snapshot-cached-metadata-view.tsv`.
NOTIFY SOA answer-owner validation now uses a direct parsed-label
case-insensitive comparison instead of rebuilding canonical owner strings for
the SOA answer owner and question name. The retained
`target/zone-image-bench/notify-soa-owner-no-canonical-key.tsv` run covers
exact and mixed-case SOA owner validation with `200000` NoError responses for
each case, zero RCODE checksums, matching response bytes, and
mixed-case/exact validation ratio `0.978`; the same checker run keeps the
packet gates green with mixed packet ratio `1.010` and UDP-ceiling packet
ratio `0.970`.
CHAOS TXT classification now follows the same no-canonical-string discipline:
`version.bind`, `version.server`, `hostname.bind`, and `id.server` are matched
through parsed-label comparisons, so the class-specific control path does not
allocate a canonical QNAME just to dispatch the response. The retained
`target/zone-image-bench/chaos-classification-no-canonical-key.tsv` run covers
exact and mixed-case CHAOS version names with `200000` NoError responses for
each case, zero RCODE checksums, matching response bytes, and
mixed-case/exact classification ratio `1.017`; the checker also kept mixed
packet ratio `0.991` and UDP-ceiling packet ratio `1.006`.
The follow-up `target/zone-image-bench/chaos-txt-direct-response.tsv` removes
the remaining answered CHAOS TXT `ResourceRecord` materialization. The response
path now writes the single TXT answer directly from the parsed question name and
configured value, uses a question-owner compression pointer, and still shares
the common prefix/capacity/EDNS helpers. A focused EDNS NSID test covers the
direct owner pointer, and the invariant audit rejects routing answered CHAOS
TXT back through `ResourceRecord` or a temporary TXT RDATA buffer. Its checker
passed at `target/zone-image-bench/chaos-txt-direct-response-check.tsv` with
zero validation/packet mismatches, byte parity, mixed-case/exact CHAOS
classification ratio `0.945`, mixed planning ratio `0.146`, mixed packet ratio
`1.057`, hot packet ratio `1.191`, trace packet ratio `1.101`, optioned packet
ratio `1.149`, boundary packet ratio `1.034`, UDP-ceiling packet ratio `1.012`,
and delegation/DNAME stress plan and wire ratios of `0.001` and `0.002`. Treat
this as narrow control-response composer cleanup, not a broad packet-throughput
claim.
The retained `target/zone-image-bench/transfer-snapshot-arc-publication.tsv`
run keeps that control-plane cleanup inside the packet benchmark gates; its
checker passed at
`target/zone-image-bench/transfer-snapshot-arc-publication-check.tsv` with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.141`,
mixed packet ratio `0.982`, hot packet ratio `0.954`, trace packet ratio
`0.969`, boundary packet ratio `1.008`, and UDP-ceiling packet ratio `1.021`.
IXFR-current transfer access now uses a transfer-specific exact snapshot view
that carries cached control metadata from the same directory entry. IXFR still
borrows the current snapshot where RFC 1995 delta comparison needs the old
builder/oracle layout, but unchanged IXFR outcomes no longer rebuild
`ZoneMetadata` from that snapshot before returning, and the current serial is
read from the cached transfer-view metadata rather than from the old snapshot
layout. Updated refresh outcomes now carry the `ZoneMetadata` returned by
`ZoneStore::insert_snapshot_arc_for_transfer` beside their shared
`Arc<ZoneSnapshot>`, so success handling consumes published-entry metadata
instead of rebuilding it from the old layout; transfer completion logging and
updated-catalog detection read the carried metadata rather than scalar fields
from the updated snapshot, and catalog application uses the carried metadata
origin key for its configuration lookup before parsing snapshot RRsets. The retained
`target/zone-image-bench/transfer-snapshot-cached-metadata-view.tsv` run passed
`target/zone-image-bench/transfer-snapshot-cached-metadata-view-check.tsv` with
zero trace and boundary packet mismatches, control/full metadata ratio `0.767`,
mixed planning ratio `0.153`, mixed packet ratio `1.002`, trace packet ratio
`0.980`, and UDP-ceiling packet ratio `0.988`. This remains
transfer-boundary cleanup, not packet hot-path evidence.
Catalog-zone reconciliation now takes a narrow `CatalogZoneView` over borrowed
RRsets/RDATA instead of depending on a full `&ZoneSnapshot` parser parameter or
the old materialized snapshot record surface.
The remaining whole-store snapshot iterator is named
`ZoneStore::offline_snapshots()` and is reserved for benchmark/test oracle
collection. That iterator now sorts by the directory entry's cached origin key
before cloning `Arc<ZoneSnapshot>` handles, avoiding a
`snapshot.origin.canonical_key()` rebuild in the offline-oracle collection
path. The retained
`target/zone-image-bench/offline-snapshots-cached-origin-sort.tsv` run records
matching cached/rebuilt snapshot counts and serial checksums, cached-sort ratio
`0.379`, mixed packet ratio `1.036`, and UDP-ceiling packet ratio `0.986`.
Zone publication state now lives on `ZoneStoreEntry` instead of requiring the
old `ZoneSnapshot` itself to be cloned for state-only publication changes.
`ZoneStore::expire_zone()` updates the entry state, clears active-only cached
views, and leaves exact snapshot access behind a lazy control/offline adapter
that still returns state-compatible snapshots to transfer and oracle callers.
The retained `target/zone-image-bench/zone-entry-state-expire.tsv` checker
passed at `target/zone-image-bench/zone-entry-state-expire-check.tsv` with
matching entry-expire/snapshot-clone counts `1000`, matching serial checksums
`500500`, zero semantic and packet mismatches, byte parity,
`zone_directory_entry_state_expire_ratio` `337.370`, mixed packet ratio
`1.004`, hot packet ratio `1.124`, trace packet ratio `0.963`, boundary packet
ratio `1.008`, and UDP-ceiling packet ratio `1.006`. This is old-layout
publication-boundary cleanup rather than packet hot-path speed evidence; the
high ratio reflects ArcSwap directory publication work while avoiding full
snapshot cloning on expiration.
The follow-up
`target/zone-image-bench/zone-entry-cached-origin-scalars.tsv` keeps origin,
origin label count, serial, and SOA timer scalars on `ZoneStoreEntry` as well.
`PublishedZone`, suffix-index removal, and status/control metadata views now
read cached entry fields instead of `ZoneSnapshot` fields, leaving exact
snapshot access behind the explicit control/offline adapter. The checker artifact
`target/zone-image-bench/zone-entry-cached-origin-scalars-check.tsv` passed with
zero semantic and packet mismatches, byte parity, suffix lookup ratio `0.017`,
control metadata ratio `0.773`, cached origin-key ratio `0.284`, cached
origin-name ratio `0.227`, mixed packet ratio `0.972`, hot packet ratio
`0.898`, trace packet ratio `1.001`, boundary packet ratio `0.934`, and
UDP-ceiling packet ratio `0.965`. This is old-layout scalar-boundary cleanup
for query/status APIs rather than packet hot-path speed evidence.
`PublishedZone` no longer exposes generic or rollback/oracle snapshot accessors
to query-serving callers.
The broad exact-origin snapshot accessor has been removed. The remaining
old-layout exact snapshot view is `ZoneStore::exact_snapshot_for_transfer()`,
which carries cached control metadata beside the snapshot for IXFR transfer
work, and the invariant audit rejects restoring the old generic
`find_exact_zone` or `find_exact_snapshot_for_control` surfaces. The retained
`target/zone-image-bench/exact-snapshot-control-accessor.tsv` run keeps zero
validation and packet mismatches through the benchmark checker; it is retained
as old-layout API-boundary evidence rather than packet-path performance work.
The transfer snapshot view also no longer implements `Deref<Target =
ZoneSnapshot>`, and its old-layout fields are private. Callers must choose
`TransferZoneSnapshot::metadata()` or `TransferZoneSnapshot::into_metadata()`
for control scalars, or `TransferZoneSnapshot::snapshot_for_transfer()` for the
narrow transfer/oracle work that still requires the old builder layout, and the
invariant audit rejects restoring the implicit deref or public snapshot fields.
The retained
`target/zone-image-bench/transfer-snapshot-explicit-accessors.tsv` artifact
passed its checker at
`target/zone-image-bench/transfer-snapshot-explicit-accessors-check.tsv` with
`100000` serial-bearing transfer views, `100000` no-serial skips, serial
checksum `50000000`, control-metadata ratio `0.748`, explicit transfer-view
ratio `1.351`, zero validation/packet mismatches, mixed plan ratio `0.133`,
mixed packet ratio `0.993`, hot packet ratio `1.062`, trace packet ratio
`1.022`, boundary packet ratio `0.990`, and UDP-ceiling packet ratio `0.996`.
This is transfer-view API-boundary evidence, not packet hot-path throughput
evidence.
IXFR current-zone lookup now uses the serial-gated
`ZoneStore::exact_snapshot_with_serial_for_transfer()` view. The cached entry
serial is checked before exposing the old snapshot handle, so no-serial zones
do not take the broader transfer snapshot path just to discover that IXFR
cannot be seeded. The retained
`target/zone-image-bench/ixfr-serial-gated-transfer-view.tsv` artifact passed
its checker at
`target/zone-image-bench/ixfr-serial-gated-transfer-view-check.tsv` with
`100000` serial-bearing transfer views, `100000` no-serial skips, serial
checksum `50000000`, control-metadata ratio `0.775`, serial-gated transfer view
ratio `1.527`, zero validation/packet mismatches, two EDE fallback cases, mixed
plan ratio `0.146`, mixed packet ratio `1.002`, hot packet ratio `0.976`, trace
packet ratio `0.981`, boundary packet ratio `1.008`, and UDP-ceiling packet
ratio `0.988`. This is old-layout transfer-control API-boundary evidence, not
packet hot-path throughput evidence.
The query-time suffix lookup key now also stays inline for common names:
`target/zone-image-bench/zone-directory-inline-reverse-key.tsv` keeps the
reversed canonical QNAME key in `SmallVec<[u8; 128]>` before probing the
published suffix index, while stored directory keys remain `Vec<u8>`. The
checker passed with zero validation and packet mismatches, byte parity, matching
directory found counts/checksums, and a suffix/linear lookup ratio of `0.017`.
This is allocation-discipline evidence at the runtime zone-selection boundary,
not an isolated suffix-lookup speed claim.
The exact-origin presence probe follows the same naming boundary:
`ZoneStore::contains_exact_zone_for_control()` is the only non-cloning exact
membership helper, and the invariant audit rejects the old generic
`contains_exact_zone` name in runtime source. The retained
`target/zone-image-bench/exact-presence-control-accessor.tsv` run keeps zero
validation and packet mismatches through the benchmark checker; it is retained
as old-layout API-boundary evidence rather than packet-path performance work.
Refresh scheduler success state is now fed from cached `ZoneMetadata`, including
test helpers and metrics fixtures. The invariant audit rejects restoring
`ZoneRefreshRegistry` success helpers that accept `&ZoneSnapshot`, and rejects
metrics fixtures that seed refresh success through `exact_snapshot_for_transfer()`.
This keeps scheduler/control bookkeeping on cached metadata instead of masking
old-layout field reads behind convenience helpers.
The architectural invariant audit also requires the remaining old snapshot
query helper to stay behind the explicit `#[doc(hidden)]`
`ZoneSnapshot::offline_oracle()` handle, and rejects restoring direct public
`ZoneSnapshot::oracle_lookup` methods, so the offline oracle cannot silently
become a normal serving API again.
SOA access follows the same boundary: the server IXFR query path uses a
borrowed `ZoneSnapshot::soa_record_view()`, while owned SOA materialization is a
crate-internal transfer-validation helper instead of public snapshot API.
RRset-to-`ResourceRecord` materialization helpers are also crate-internal, so
the remaining public builder model no longer exposes serving-style record
materialization convenience methods.
After removing the live `[query].zone_image_serve_enabled` rollback switch, the
current in-process profiling benchmark retained
`target/zone-image-bench/default-serve-promotion-profiling.tsv` and passed
`target/zone-image-bench/default-serve-promotion-profiling-check.tsv` with zero
semantic, packet, fallback, UDP-ceiling, and EDE fallback mismatches. The packet
ratios remained inside the promotion gates: mixed `0.583`, hot `0.390`, trace
`0.435`, and optioned `0.428`.
After adding fixed fallback-reason counters for the rollback path, the retained
in-process profiling benchmark
`target/zone-image-bench/fallback-reasons-profiling.tsv` passed
`target/zone-image-bench/fallback-reasons-profiling-check.tsv` with zero
semantic, packet, fallback, UDP-ceiling, and EDE fallback mismatches. The
served packet ratios stayed inside the gates: mixed `0.567`, hot `0.397`,
trace `0.406`, and optioned `0.423`.
Full-ANY mode first stopped forcing non-ANY traffic down the old path, then
QTYPE ANY itself moved onto the immutable `ZoneImage` path for supported exact
and wildcard RRsets. Minimal mode keeps one real RRset from compiled class/type
order; full mode emits all matching real owner RRsets from the same compiled
order while omitting DNSSEC proof and signature RRsets, matching the snapshot
path. The retained profiling benchmark
`target/zone-image-bench/full-any-scope-profiling.tsv` passed
`target/zone-image-bench/full-any-scope-profiling-check.tsv`; packet ratios
remained inside the gates for the scoped non-ANY slice: mixed `0.538`, hot
`0.411`, trace `0.414`, and optioned `0.447`.
UDP truncation for supported responses is now handled by the ZoneImage composer:
it emits TC=1 directly from immutable wire records, preserving the same record
removal order as the snapshot composer and avoiding the old path for the
oversized UDP boundary. The retained profiling benchmark
`target/zone-image-bench/zone-image-udp-truncation-profiling.tsv` passed
`target/zone-image-bench/zone-image-udp-truncation-profiling-check.tsv`; packet
ratios remained inside the gates: mixed `0.584`, hot `0.393`, trace `0.295`,
and optioned `0.446`.
The later retained
`target/zone-image-bench/truncated-ceiling-capacity.tsv` run also pre-sizes
each truncated ZoneImage retry buffer to the UDP ceiling. Its checker artifact
`target/zone-image-bench/truncated-ceiling-capacity-check.tsv` passed with zero
packet mismatches and unchanged response bytes, recording boundary packet ratio
`1.009` and UDP-ceiling packet ratio `1.007`. This is a bounded allocation
cleanup for the retry composer, not a replacement for the remaining immutable
template/WireArena work.
The retained
`target/zone-image-bench/truncation-kept-records-inline-half.tsv` run then
narrows truncated-response kept-record scratch sections to four inline answer
records, four inline authority records, and eight inline additional records.
The checker artifact
`target/zone-image-bench/truncation-kept-records-inline-half-check.tsv` passed
with zero semantic and packet mismatches, unchanged response bytes, boundary
packet ratio `0.994`, and UDP-ceiling packet ratio `0.992`. This is retained as
retry-composer scratch-layout compaction; larger truncated sections still spill.
The retry composer also keeps a retained count of DNSSEC wire records and
decrements it as records are removed, instead of rescanning all kept records
before every retry to decide whether the response still carries DNSSEC
augmentation. The retained
`target/zone-image-bench/truncated-dnssec-count-retained.tsv` run keeps byte
parity and zero validation/packet mismatches, and is retained as
retry-composer bookkeeping cleanup rather than proof that the full template
path is complete. The later retained
`target/zone-image-bench/truncation-dnssec-count-while-collecting.tsv` run also
accumulates that DNSSEC count while the truncated scratch sections are first
collected, removing the separate setup scan before the retry loop while keeping
zero packet mismatches and unchanged response bytes. The retained
`target/zone-image-bench/truncation-section-aware-collect.tsv` run then moves
that scratch collection onto the section-aware immutable-plan visitor and keeps
one retained DNSSEC counter instead of three per-section counters plus a final
sum. Its checker artifact
`target/zone-image-bench/truncation-section-aware-collect-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed packet ratio
`1.022`, hot packet ratio `1.022`, trace packet ratio `1.000`, optioned packet
ratio `0.931`, boundary packet ratio `1.022`, UDP-ceiling packet ratio
`0.989`, total image bytes per record `170.000`, and stress bytes per record
`250.000`. The retained
`target/zone-image-bench/truncated-authority-index-while-collecting.tsv` run
also records the next removable non-SOA authority index while authority scratch
records are collected, removing the initial post-collection reverse scan. The
retry loop still moves that retained index backward after authority removal.
Its checker artifact
`target/zone-image-bench/truncated-authority-index-while-collecting-check.tsv`
passed with zero semantic and packet mismatches, byte parity, mixed packet
ratio `1.002`, hot packet ratio `1.011`, trace packet ratio `0.990`, optioned
packet ratio `0.970`, boundary packet ratio `1.010`, UDP-ceiling packet ratio
`0.990`, total image bytes per record `170.000`, and stress bytes per record
`250.000`. The retained
`target/zone-image-bench/truncated-authority-index-stack.tsv` run extends that
cleanup by collecting all removable non-SOA authority indices into a small
stack. The retry loop pops indices in the same last-non-SOA removal order and
no longer rescans authority scratch records after each authority removal. Its
checker artifact
`target/zone-image-bench/truncated-authority-index-stack-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed packet ratio `1.048`,
hot packet ratio `1.130`, trace packet ratio `1.046`, optioned packet ratio
`1.031`, boundary packet ratio `1.081`, UDP-ceiling packet ratio `1.006`,
total image bytes per record `170.000`, and stress bytes per record `250.000`.
This is retained as retry-loop rescan removal inside the current mutable
composer, not as a broad packet-path speed claim. The follow-up
`target/zone-image-bench/truncated-authority-index-u16-stack.tsv` narrows that
stack from `usize` to `u16`, matching the DNS section-count bound already
checked before truncation retry can run. Its checker artifact
`target/zone-image-bench/truncated-authority-index-u16-stack-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed packet ratio
`1.016`, hot packet ratio `0.969`, trace packet ratio `0.990`, optioned packet
ratio `0.971`, boundary packet ratio `1.006`, UDP-ceiling packet ratio
`0.982`, total image bytes per record `170.000`, and stress bytes per record
`250.000`. The invariant audit also requires the debug assertion that makes the
DNS section-count bound explicit before the compact `u16` index cast. The retained
`target/zone-image-bench/truncation-dnssec-count-gated.tsv` run then gates that
classification on `metadata.dnssec_augmented`, so unsigned oversized responses
do not classify kept records only to compute a DNSSEC retry flag that must stay
false. The follow-up
`target/zone-image-bench/truncation-dnssec-removal-gated.tsv` run extends the
same gate to the removal loop, so unsigned oversized retry passes do not
classify removed records while shrinking the response. The retained
`target/zone-image-bench/truncation-dnssec-zero-count-gate.tsv` run then stops
that classification after the retained DNSSEC count reaches zero, even for a
response that originally carried DNSSEC records. These retained cleanup runs
are now historical stepping stones: the later
`zone-image-dead-dnssec-count-retired` run removes the dead DNSSEC
metadata/count bookkeeping entirely because final response bytes classify
DNSSEC latency.
The earlier retained
`target/zone-image-bench/truncated-authority-index-retained.tsv` run kept only
the next removable non-SOA authority index across retries. That step is now
superseded by the collection-time index and retained index-stack runs above,
which remove both the initial authority scan and the per-removal authority
rescans while preserving the same truncation removal order.
The retained `target/zone-image-bench/truncation-kept-wire-bounds.tsv` run
also carries the uncompressed wire-byte bound for kept answer, authority, and
additional records while truncation scratch records are collected, then
decrements that bound as records are removed. The wire-record rebuild helper
now consumes that retained bound instead of falling back to a rough per-record
capacity heuristic. Truncated UDP retries still reserve the UDP ceiling, so
this is retained as accounting discipline and future template-readiness work,
not as a packet throughput claim. The checker artifact
`target/zone-image-bench/truncation-kept-wire-bounds-check.tsv` passed with
zero validation and packet mismatches, byte parity, mixed planning ratio
`0.148`, mixed wire ratio `0.169`, mixed packet ratio `0.994`, hot packet
ratio `0.999`, trace packet ratio `1.002`, optioned packet ratio `1.004`,
boundary packet ratio `1.038`, UDP-ceiling packet ratio `1.005`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.001`.
The later retained `target/zone-image-bench/truncation-plan-accounting.tsv` run
supersedes the setup-side DNSSEC and body-byte accumulation: truncation now
starts from compact body-wire counters carried by `ZoneImageLookupPlan`; the
intermediate DNSSEC-record counters from that run are superseded by
`zone-image-dead-dnssec-count-retired`.
For oversized EDE responses, the retry composer now tries the EDE-stripped
response directly from the immutable plan before collecting mutable kept-record
scratch vectors for record removal. The retained
`target/zone-image-bench/truncated-ede-direct-retry.tsv` run keeps byte parity
and zero validation/packet mismatches, and is retained as a narrow EDE
truncation scratch-deferral cleanup rather than proof that the full template
path is complete. The later `zone-image-ede-stripped-sizing` run tightens the
fallback side by carrying the stripped OPT sizing into the record-removal retry
when the direct stripped rebuild is still oversized.
The retained `target/zone-image-bench/truncation-tail-authority-pop.tsv` run
then narrows the authority-removal retry loop: after additionals are exhausted,
the retry composer still uses the retained removable-authority index stack, but
it pops tail non-SOA authority records directly instead of paying
`SmallVec::remove` shifting. Non-tail authority removals still use ordered
removal to preserve DNS section order. The checker artifact
`target/zone-image-bench/truncation-tail-authority-pop-check.tsv` passed with
zero semantic and packet mismatches, byte parity, mixed planning ratio `0.143`,
mixed wire ratio `0.165`, mixed packet ratio `1.033`, boundary packet ratio
`1.003`, UDP-ceiling packet ratio `1.001`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`. This is retry-loop bookkeeping cleanup, not
packet-speed evidence.
The retained
`target/zone-image-bench/wire-record-uncompressed-len-rdlength.tsv` run moves
removed-record body-bound decrement accounting to the carried
`ZoneImageWireRecord::rdlength_bytes` field instead of reading the runtime RDATA
slice length. That rdlength is already checked and carried for emission, so the
truncation retry loop now consumes the same prevalidated metadata as the encoder.
The checker artifact
`target/zone-image-bench/wire-record-uncompressed-len-rdlength-check.tsv` passed
with zero semantic and packet mismatches, byte parity, mixed planning ratio
`0.140`, mixed wire ratio `0.157`, mixed packet ratio `0.965`, boundary packet
ratio `0.998`, UDP-ceiling packet ratio `0.990`, and delegation/DNAME-stress plan
and wire ratios of `0.001` and `0.002`. This is accounting discipline and future
template-readiness work, not transport evidence.
Stored and synthesized `ZoneImage` records now carry a compact precomputed RDATA
compression shape for copy, single-name, SOA, and MX RDATA. The runtime
wire-record composer matches that shape instead of reparsing wire-name lengths
for every emitted `ZoneImage` record. Copy-RDATA records also write the validated
rdlength and bytes directly, bypassing the compressed-RDATA placeholder/patch
path. The tag is packed into the existing `RdataRange` padding, keeping
`ImageRecord` at 8 bytes and preserving the hot layout budget. The retained
`target/zone-image-bench/rdata-encoding-precomputed.tsv` checker artifact passed
with zero validation and packet mismatches, hot packet ratio `1.000`, and
UDP-ceiling packet ratio `1.000`. The follow-up
`target/zone-image-bench/rdata-copy-fast-path.tsv` checker artifact passed with
zero validation and packet mismatches, mixed packet ratio `0.991`, boundary
packet ratio `0.981`, and UDP-ceiling packet ratio `0.945`; this is per-record
composer precompute evidence, not completion of the full immutable template
path.
The follow-up `target/zone-image-bench/wire-record-rdlength-bytes.tsv` carries
the prevalidated RDATA length bytes through the generic `ZoneImageWireRecord`
view, so the copy-RDATA packet encoder writes those compiled bytes instead of
deriving them from the runtime RDATA slice length. Its checker artifact passed
with zero validation and packet mismatches, byte parity, mixed packet ratio
`0.980`, hot packet ratio `0.968`, boundary packet ratio `0.981`, and
UDP-ceiling packet ratio `0.950`; this remains generic-composer cleanup, not
completion of the immutable template path.
The retained `target/zone-image-bench/wire-record-fixed-fields.tsv` run carries
prepared TYPE/CLASS/TTL bytes through `ZoneImageWireRecord`, so the generic
packet encoder writes those bytes directly instead of rebuilding scalar
network-order fields. Stored RRsets reuse the already-existing immutable RRset
wire arena for those bytes, keeping `ImageRrset` at 44 bytes and preserving the
hot-layout budget; synthesized records store their fixed bytes when they are
pushed into the plan. The checker artifact
`target/zone-image-bench/wire-record-fixed-fields-check.tsv` passed with zero
validation and packet mismatches, byte parity, mixed planning ratio `0.147`,
mixed wire ratio `0.167`, mixed packet ratio `1.024`, hot packet ratio
`0.919`, trace packet ratio `0.965`, optioned packet ratio `0.951`, boundary
packet ratio `1.014`, UDP-ceiling packet ratio `0.993`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.001`. This is
retained as bounded generic composer byte-assembly cleanup, not as broad
packet-speed evidence.
The follow-up
`target/zone-image-bench/wire-record-fixed-fields-no-rrtype.tsv` removes the
separate scalar RR type from the transient `ZoneImageWireRecord` view. DNSSEC
classification and truncation's non-SOA authority decision decode the type from
the carried fixed TYPE/CLASS/TTL bytes, avoiding two RR-type sources while
keeping the persistent image layout unchanged. Its checker artifact
`target/zone-image-bench/wire-record-fixed-fields-no-rrtype-check.tsv` passed
with zero validation and packet mismatches, byte parity, mixed planning ratio
`0.140`, mixed wire ratio `0.161`, mixed packet ratio `0.980`, hot packet ratio
`0.940`, trace packet ratio `0.967`, optioned packet ratio `0.952`, boundary
packet ratio `1.018`, UDP-ceiling packet ratio `0.992`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.001`.
The next retained cleanup
`target/zone-image-bench/wire-record-packed-rdata.tsv` keeps the same compact
`PackedRdataEncoding` shape in transient wire records and synthesized records
that immutable records already use. Stored RRset visits therefore pass the
two-byte packed shape through unchanged; the composer checks the copy fast path
with `is_copy()` and only expands the SOA/name details on the compressed-RDATA
branch. Its checker artifact
`target/zone-image-bench/wire-record-packed-rdata-check.tsv` passed with zero
validation and packet mismatches, byte parity, `ZoneImageWireRecord` size 48
bytes, main image bytes/record `170`, stress image bytes/record `250`, mixed
planning ratio `0.131`, mixed wire ratio `0.159`, mixed packet ratio `0.983`,
hot packet ratio `1.033`, trace packet ratio `1.004`, optioned packet ratio
`0.978`, boundary packet ratio `1.010`, UDP-ceiling packet ratio `0.992`, and
delegation/DNAME-stress plan and wire ratios of `0.001` and `0.002`.
The follow-up
`target/zone-image-bench/synthesized-fixed-fields-no-rrtype.tsv` removes the
scalar RR type from `ZoneImageSynthesizedRecord`. Dynamic DNAME/CNAME records
already carry precomputed TYPE/CLASS/TTL bytes, so tests and the composer now
derive the synthesized type from those bytes instead of maintaining a second
field. Its checker artifact
`target/zone-image-bench/synthesized-fixed-fields-no-rrtype-check.tsv` passed
with zero validation and packet mismatches, byte parity, main image bytes/record
`170`, stress image bytes/record `250`, mixed planning ratio `0.140`, mixed wire
ratio `0.172`, mixed packet ratio `1.031`, hot packet ratio `1.062`, trace
packet ratio `1.038`, optioned packet ratio `1.052`, boundary packet ratio
`1.014`, UDP-ceiling packet ratio `1.008`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`.
The next retained cleanup
`target/zone-image-bench/compiled-rrset-fixed-fields.tsv` moves normal
TYPE/CLASS/TTL bytes into compiled `ImageRrset` metadata and stores
negative-response SOA TTL bytes beside them. Direct-answer prefix construction,
selected DNSSEC record emission, stored-record visits, and negative SOA
authority emission now consume carried bytes instead of recovering fixed fields
from immutable RRset wire or rebuilding negative TTL bytes from scalar fields.
A full negative-fixed-field variant was measured first and rejected because it
pushed the stress fixture over the retained 256 bytes/record gate; the retained
layout keeps `ImageRrset` at 48 bytes by storing only the negative TTL bytes.
The checker artifact
`target/zone-image-bench/compiled-rrset-fixed-fields-check.tsv` passed with zero
validation and packet mismatches, byte parity, main image bytes/record `174`,
stress image bytes/record `254`, mixed planning ratio `0.130`, mixed wire ratio
`0.157`, mixed packet ratio `0.962`, hot packet ratio `0.920`, trace packet
ratio `0.992`, optioned packet ratio `1.086`, boundary packet ratio `1.032`,
UDP-ceiling packet ratio `1.007`, and delegation/DNAME-stress plan and wire
ratios of `0.001` and `0.001`.
The next retained DNAME-specific cleanup
`target/zone-image-bench/dname-synthesized-cname-fixed-fields.tsv` reuses the
compiled DNAME RRset fixed TYPE/CLASS/TTL bytes for generated CNAME answers,
changing only the TYPE bytes to CNAME. This removes the remaining generated
CNAME fixed-field rebuild from scalar class/TTL metadata without growing the
image. A broader variant stored generated CNAME fixed fields in every
single-name target and was narrowed because it hit the stress bytes/record
ceiling exactly. The retained checker artifact
`target/zone-image-bench/dname-synthesized-cname-fixed-fields-check.tsv` passed
with zero validation and packet mismatches, byte parity, main image
bytes/record `174`, stress image bytes/record `254`, mixed planning ratio
`0.162`, mixed wire ratio `0.177`, mixed packet ratio `0.996`, hot packet ratio
`1.135`, trace packet ratio `0.977`, optioned packet ratio `1.005`, boundary
packet ratio `1.027`, UDP-ceiling packet ratio `1.010`, and
delegation/DNAME-stress plan and wire ratios of `0.002` and `0.002`.
The refreshed `target/zone-image-bench/rrset-accounting-single-read-refresh.tsv`
run keeps runtime RRset accounting on private single-read plan metrics helpers.
Ordinary answer, authority, additional, referral, DNSSEC proof, CNAME/DNAME, and
wildcard owner-override plan construction now push RRsets through helpers that
read compiled record count and wire upper bound together; standalone count and
wire-bound helpers remain test-only. The checker artifact
`target/zone-image-bench/rrset-accounting-single-read-refresh-check.tsv` passed
with zero validation and packet mismatches, byte parity, main image bytes/record
`170`, stress image bytes/record `250`, mixed planning ratio `0.140`, mixed wire
ratio `0.163`, mixed packet ratio `1.048`, hot packet ratio `1.077`, trace
packet ratio `1.049`, optioned packet ratio `1.043`, boundary packet ratio
`1.016`, UDP-ceiling packet ratio `1.002`, and delegation/DNAME-stress plan and
wire ratios of `0.001` and `0.002`.
The retained
`target/zone-image-bench/wildcard-owner-override-inline-serialize.tsv` then
narrows wildcard owner-substitution bookkeeping: the single-RRset wildcard path
serializes the query-owner override directly into the inline owner buffer and
accounts from that built wire length instead of walking the parsed owner labels
separately for length and serialization. The checker artifact
`target/zone-image-bench/wildcard-owner-override-inline-serialize-check.tsv`
passed with zero validation and packet mismatches, byte parity, mixed planning
ratio `0.156`, mixed wire ratio `0.179`, mixed packet ratio `1.014`, hot packet
ratio `0.978`, trace packet ratio `1.015`, optioned packet ratio `0.977`,
boundary packet ratio `0.983`, UDP-ceiling packet ratio `0.988`, and
delegation/DNAME-stress plan and wire ratios of `0.002`. This is local
wildcard-owner bookkeeping cleanup and does not change the remaining
template/WireArena transport boundary.
QTYPE ANY now uses the `ZoneImage` planner for supported exact and wildcard
owner RRsets. The retained profiling benchmark
`target/zone-image-bench/zone-image-qtype-any-profiling.tsv` passed
`target/zone-image-bench/zone-image-qtype-any-profiling-check.tsv` with zero
semantic, packet, boundary, UDP-ceiling, and EDE fallback mismatches. Packet
ratios remained inside the gates: mixed `0.549`, hot `0.368`, trace `0.318`,
and optioned `0.481`.
Public `ZoneImage` materialization helpers were then removed and the retained
benchmark stopped timing temporary image-to-`LookupResult` reconstruction. The
replacement parity path compares plan summaries, immutable wire section output,
and final packets. The retained profiling benchmark
`target/zone-image-bench/zone-image-no-materialization-profiling.tsv` passed
`target/zone-image-bench/zone-image-no-materialization-profiling-check.tsv`
with zero semantic, packet, boundary, UDP-ceiling, and EDE fallback mismatches.
Packet ratios remained inside the gates: mixed `0.537`, hot `0.372`, trace
`0.309`, and optioned `0.414`.
After isolating the default-enabled ZoneImage branch from `ZoneSnapshot` clones,
the retained profiling benchmark
`target/zone-image-bench/zone-image-snapshot-isolation-profiling.tsv` passed
`target/zone-image-bench/zone-image-snapshot-isolation-profiling-check.tsv`
with zero semantic, packet, boundary, UDP-ceiling, and EDE fallback mismatches.
Packet ratios remained inside the gates: mixed `0.569`, hot `0.424`, trace
`0.298`, and optioned `0.465`.
After splitting the core serving API into required-provider ZoneImage serving
and an explicitly named snapshot-rollback entry point, the retained profiling
benchmark `target/zone-image-bench/zone-image-explicit-serving-api-profiling.tsv`
passed
`target/zone-image-bench/zone-image-explicit-serving-api-profiling-check.tsv`
with zero semantic, packet, boundary, UDP-ceiling, and EDE fallback mismatches.
Packet ratios remained inside the gates: mixed `0.597`, hot `0.352`, trace
`0.321`, and optioned `0.493`.
After removing the hidden snapshot-rollback serving entry points and
`PublishedZone` rollback snapshot accessor, the retained profiling benchmark
`target/zone-image-bench/no-rollback-serving-profiling.tsv` passed
`target/zone-image-bench/no-rollback-serving-profiling-check.tsv` with zero
semantic, packet, boundary, UDP-ceiling, and EDE fallback mismatches. The
snapshot-layout plan/wire ratios remain strict win gates: mixed plan `0.561`,
mixed wire `0.612`, delegation/DNAME stress plan `0.007`, and stress wire
`0.007`. Packet ratios are now parity guardrails because both benchmark packet
paths use ZoneImage packet serving after live rollback retirement: mixed
`1.105`, hot `1.137`, trace `1.072`, and optioned `1.116`, all below the
`1.25` regression ceiling.
The separately timed optioned EDNS packet corpus now also uses the direct
answer emitter for direct positive answers. The hot-query shape shows a strong
exact-lookup win and a positive gated packet-path win once packet parsing and
response framing dominate the repeated-name workload. The benchmark now
verifies zero byte-level packet mismatches across the retained mixed, hot, and
weighted trace packet corpora before timing, and it also verifies that the
gated path preserves positive EDNS option behavior for NSID, DNS Cookie, and
padding while preserving served DO positive signing, served full QTYPE ANY,
direct UDP truncation, EDE not-ready, and varied no-EDNS/EDNS UDP payload
ceiling cases. The focused unit suite also verifies that DO positive
signing, NODATA/NSEC proof selection, NXDOMAIN/NSEC proof selection, wildcard
proofs, referral proofs, and NSEC3 iteration-cap EDE responses serve through
ZoneImage while preserving byte-for-byte responses and the existing DNSSEC cap
metric. Promotion still needs real operator trace coverage and physical network
evidence, not only retained in-process ns/query evidence.

A direct-answer response-template cache experiment was tried and rejected in
this slice. The prototype stored a prebuilt question-pointer RR body per RRset,
then patched only the normal dynamic response fields. The existing direct
packet differential tests stayed byte-identical, but the retained local
benchmark moved the wrong way: hot packet response was 205.672 ns/query versus
the retained 190.808 ns/query baseline, trace packet response was 673.813
ns/query versus 625.646 ns/query, and `zone_image_bytes_per_record` increased
from 143 to 167. The cache is therefore not retained for the current
Vec-backed socket composer; the direct emitter remains smaller and faster on
this machine. This result does not rule out template-backed transmission after
the packet I/O layer changes: io_uring fixed buffers, send-zc style paths, or
AF_XDP UMEM may make reusable response templates valuable if the transport can
reference prebuilt immutable regions and only patch the query ID, flags, counts,
and optional OPT/EDE bytes in a per-packet scratch header.

An earlier generic-composer count-patching experiment was measured and rejected
for the then-current Vec-backed composer. The prototype removed the normal
pre-encode plan accounting pass, emitted immutable plan records first, counted
records as they were encoded, then patched ANCOUNT/NSCOUNT/ARCOUNT before EDNS
emission. The focused ZoneImage serving tests and benchmark checker stayed
byte-identical, but the retained
`target/zone-image-bench/generic-composer-count-patch.tsv` run regressed mixed,
hot, trace, and optioned packet ratios to `1.032`, `1.129`, `1.039`, and
`1.052`. That rejected experiment has since been superseded by the narrower
retained `target/zone-image-bench/one-pass-plan-record-composer.tsv` path,
which carries section counts into truncation retry and stays inside the current
checker gates. Template-backed transmission still remains separate future work.

### Live Loopback Serving Sample

`scripts/benchmark-dns-clients.sh` can compare the current snapshot serving path
and the default-enabled ZoneImage serving path through the actual OxideDNS runtime,
loopback UDP/TCP sockets, AXFR load from a synthetic primary, and the checked-in
`tools/dns-load-client.rs` load client. It can also pass an explicit query
trace into the client with `OXIDEDNS_BENCH_TRACE_ENABLED=true` or
`OXIDEDNS_BENCH_TRACE_FILE=/path/to/query-trace.tsv`; retained artifacts record
`query_mode`, `trace_queries`, and the exact `query-trace.tsv` input when trace
mode is used. Trace rows may specify `rcode=` and `answers=` expectations so
positive, NODATA, and NXDOMAIN rows can be validated through the same live
client. For physical NIC evidence, the same harness can bind OxideDNS to a
chosen address with `OXIDEDNS_BENCH_LISTEN_ADDRESS`, drive a concrete client
destination with `OXIDEDNS_BENCH_CLIENT_SERVER`, and retain the selected or
auto-detected `network_device` in `run.env` and `benchmark-results.tsv`. Each
run also retains a `network/` artifact directory with before/after route, link,
`/proc/net/dev`, softirq, interrupt, optional `ethtool` snapshots, and
precomputed counter deltas so a NIC run can be audited against the actual
interface and queue state. The physical promotion comparator requires those
artifacts to record the same non-loopback network device,
`require_non_loopback_device=true`, matching listen/client provenance, and a
concrete non-loopback `client_server`. It also requires counter deltas to show
positive RX/TX packet and byte movement, with zero RX/TX drop and error deltas,
for both the current-path and ZoneImage artifacts. RX and TX packet deltas must
also scale with the measured response count; the default threshold is `0.25`
packets per measured response.
Use
`OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true` for physical-NIC evidence so
loopback or unresolved device selection fails before a run is recorded:

```sh
OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR=target/evidence/zone-image-live-loopback \
OXIDEDNS_BENCH_DURATION_SECONDS=3 \
OXIDEDNS_BENCH_RECORDS=10000 \
OXIDEDNS_BENCH_TRANSPORT=udp \
OXIDEDNS_BENCH_SERVER_THREADS=4 \
OXIDEDNS_BENCH_CLIENT_THREADS=8 \
OXIDEDNS_BENCH_CLIENT_WINDOW=64 \
scripts/benchmark-dns-clients.sh
```

Retained loopback UDP samples from 2026-05-28 before the live rollback switch was
removed:

| Profile | ZoneImage serving | Responses/s | p50 us | p99 us | p999 us | Dropped | Errors | Artifact |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Throughput pressure, 8 clients x window 64 | false | 243,115 | 616.6 | 870.7 | 1,180.5 | 4,111 | 0 | `target/evidence/zone-image-live-loopback-disabled` |
| Throughput pressure, 8 clients x window 64 | true | 248,649 | 544.5 | 1,632.3 | 5,014.8 | 4,110 | 0 | `target/evidence/zone-image-live-loopback-enabled` |
| Latency smoke, 4 clients x window 16 | false | 295,706 | 194.3 | 290.8 | 410.2 | 0 | 0 | `target/evidence/zone-image-live-loopback-latency-disabled` |
| Latency smoke, 4 clients x window 16 | true | 296,806 | 191.8 | 283.4 | 350.9 | 0 | 0 | `target/evidence/zone-image-live-loopback-latency-enabled` |

Retained loopback TCP samples from 2026-05-28:

| Profile | ZoneImage serving | Responses/s | p50 us | p99 us | p999 us | Dropped | Errors | Artifact |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| TCP pipelined, 4 clients x window 16 | false | 674,473 | 71.9 | 145.6 | 328.4 | 0 | 0 | `target/evidence/zone-image-live-loopback-tcp-disabled` |
| TCP pipelined, 4 clients x window 16 | true | 839,776 | 54.8 | 129.2 | 264.3 | 0 | 0 | `target/evidence/zone-image-live-loopback-tcp-enabled` |

Retained mixed-trace loopback samples from 2026-05-28, using
`OXIDEDNS_BENCH_TRACE_ENABLED=true`, 1,000 generated A records, 263 retained
trace rows, four clients, and window 16:

| Transport | ZoneImage serving | Responses/s | p50 us | p99 us | p999 us | Dropped | Errors | Artifact |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| UDP | false | 277,022 | 208.0 | 300.7 | 318.5 | 0 | 0 | `target/evidence/zone-image-live-loopback-edns-fastpath-mixed-disabled` |
| UDP | true | 360,667 | 154.9 | 222.4 | 293.7 | 0 | 0 | `target/evidence/zone-image-live-loopback-edns-fastpath-mixed-enabled` |
| TCP | false | 791,704 | 55.5 | 167.2 | 319.7 | 0 | 0 | `target/evidence/zone-image-live-loopback-edns-fastpath-mixed-tcp-disabled` |
| TCP | true | 863,174 | 52.4 | 164.9 | 269.6 | 0 | 0 | `target/evidence/zone-image-live-loopback-edns-fastpath-mixed-tcp-enabled` |

Interpretation: loopback runtime evidence now confirms that enabling ZoneImage
serving does not regress direct-hit UDP or TCP serving in these bounded local
profiles.
The saturated profile shows a small throughput and p50 improvement but noisier
tail latency under queue pressure, while the lower-window latency profile shows
slightly higher throughput and improved p50/p99/p999 with zero drops or errors.
The TCP pipelined profile shows a larger throughput and latency improvement
through the same runtime answer path, with zero drops or errors.
The mixed-trace loopback profile exercises live replay of a retained query mix
with hot names, spread names, EDNS, apex NS/SOA, glue-positive rows, opaque
unknown RDATA, NODATA, and NXDOMAIN. The live client validates each row's
expected RCODE and minimum answer count, and the retained samples show zero
errors or drops. This is useful runtime-path evidence, but it is still not
physical NIC, multi-queue, or production-operator trace evidence.

Retained delegation/DNAME stress loopback samples from 2026-05-29, using the
same retained trace for both runs, `OXIDEDNS_BENCH_STRESS_CANDIDATES=128`,
1,000 generated A records, 1,517 AXFR records, 392 trace rows, four clients,
and window 16:

| Transport | ZoneImage serving | Responses/s | p50 us | p99 us | p999 us | Dropped | Errors | Artifact |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| UDP | false | 66,042 | 724.8 | 1,939.7 | 81,252.2 | 0 | 0 | `target/evidence/current-live-loopback-delegation-dname-stress-smoke` |
| UDP | true | 136,115 | 370.2 | 1,695.8 | 5,203.8 | 0 | 0 | `target/evidence/zone-image-live-loopback-delegation-dname-stress-smoke` |

The historical retained comparison
`target/evidence/zone-image-live-loopback-delegation-dname-stress-comparison.tsv`
passed with matching trace SHA-256, `2.061x` responses/s, `0.511x` p50,
`0.874x` p99, and `0.064x` p999 latency ratios. New comparisons should use the
served-path metric artifacts below so the comparator can also prove that the
ZoneImage path, not fallback, served the measured queries.

The end-to-end gate wrapper
`target/evidence/zone-image-evidence-gate-loopback-stress-smoke-final`
was produced with:

```sh
OXIDEDNS_ZONE_IMAGE_GATE_DIR=target/evidence/zone-image-evidence-gate-loopback-stress-smoke-final \
OXIDEDNS_ZONE_IMAGE_GATE_MIN_QPS_RATIO=1.25 \
OXIDEDNS_ZONE_IMAGE_GATE_MAX_P50_RATIO=0.75 \
OXIDEDNS_BENCH_DURATION_SECONDS=1 \
OXIDEDNS_BENCH_RECORDS=1000 \
OXIDEDNS_BENCH_STRESS_CANDIDATES=128 \
OXIDEDNS_BENCH_TRANSPORT=udp \
OXIDEDNS_BENCH_SERVER_THREADS=4 \
OXIDEDNS_BENCH_CLIENT_THREADS=4 \
OXIDEDNS_BENCH_CLIENT_WINDOW=16 \
scripts/zone-image-evidence-gate.sh
```

It retained current and ZoneImage sub-artifacts plus `comparison.tsv`; the
comparison passed with matching trace SHA-256, `2.395x` responses/s, `0.411x`
p50, `0.516x` p99, and `0.222x` p999 latency ratios. The wrapper is the
repeatable local promotion command; physical NIC promotion should run the same
script with `OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true` and suitable
listen/client/network-device settings.

After adding explicit served-path metrics, the retained
`target/evidence/zone-image-evidence-gate-loopback-stress-metrics-smoke`
artifact passed the same wrapper gate with `2.153x` responses/s, `0.441x`
p50, `0.441x` p99, and `0.702x` p999 latency ratios. Its current-path artifact
recorded `zone_image_serve_hits=0` and `zone_image_serve_failures=0`; its
ZoneImage artifact recorded `zone_image_serve_hits=295243` and
`zone_image_serve_failures=0`. That proves the measured runtime win came from
the immutable-zone-image serving path rather than from a failure run.

After splitting served hits into direct-answer and semantic-plan buckets,
`target/evidence/zone-image-evidence-gate-loopback-direct-semantic-smoke`
was regenerated after adding client-mode provenance to the benchmark artifact
schema. It passed the wrapper gate with `client_mode=local`,
`remote_client_ssh=none`, matching trace SHA-256, `1.920x` responses/s,
`0.444x` p50, and `0.888x` p99 latency ratios. The p999 loopback ratio was
`1.977x`, so this artifact is retained as local throughput/direct-semantic
coverage evidence, not as a tail-latency promotion claim. The ZoneImage
artifact recorded `zone_image_serve_hits=776705`,
`zone_image_serve_direct_hits=515175`,
`zone_image_serve_semantic_hits=261530`, and
`zone_image_serve_failures=0`. That proves the retained live trace exercised
both the guarded direct-answer hot path and the semantic ZoneImage planner.

Interpretation: the live runtime stress replay loads delegation and DNAME
candidate records through AXFR, validates referral rows with zero answers and
DNAME rows with at least three answers, and drives those rows through the
actual UDP serving path. On loopback, enabling ZoneImage roughly doubles
responses/s and cuts median latency about in half for this stress trace, while
both paths retain zero drops and zero client validation errors. This strengthens
runtime-path evidence for the packed parent-chain lookup work, but it remains
loopback evidence and still does not satisfy the physical NIC promotion gate.

The retained artifact
`target/evidence/zone-image-network-evidence-loopback-smoke` verifies the
NIC-evidence harness plumbing with wildcard listen, explicit client
destination, UDP source bind, route capture, `/proc` snapshots, and optional
`ethtool` capture. Newer harness artifacts also include
`network/proc-net-dev-delta.tsv` and, when ethtool output is available,
`network/ethtool-delta.tsv` for quick packet/error counter review. The retained
loopback smoke records `network_device=lo`, so it is only a harness smoke test
and does not satisfy the physical-NIC promotion gate.

After moving the direct answer emitter ahead of generic section counting,
`target/evidence/zone-image-live-loopback-count-skip-smoke` retained a
1-second loopback UDP trace replay with ZoneImage serving enabled: 321,820 QPS,
p50 25.5 us, p99 60.3 us, p999 110.2 us, zero dropped responses, zero errors,
and matching loopback RX/TX packet deltas in `network/proc-net-dev-delta.tsv`.
This proves the optimized runtime path still answers the retained mixed trace
cleanly, but it remains loopback evidence only.

After broadening the direct-copy path to opaque and unknown RR types,
`target/evidence/zone-image-live-loopback-opaque-unknown-smoke` retained a
1-second loopback UDP trace replay whose generated trace includes
`opaque.perf.test. 65280 IN none opaque_unknown`. The run served 1,005 AXFR
records, replayed 264 trace queries, and recorded 355,046 QPS, p50 23.0 us,
p99 50.8 us, p999 66.6 us, zero dropped responses, zero errors, and matching
loopback RX/TX packet deltas in `network/proc-net-dev-delta.tsv`. This confirms
the widened direct-copy runtime path handles an unknown RR loaded through AXFR,
but it remains loopback evidence only.

After removing the extra QNAME wire allocation from the direct and generic
ZoneImage composers, `target/evidence/zone-image-live-loopback-qname-allocation-smoke`
retained a 1-second loopback UDP trace replay against the same generated
opaque-unknown trace. The run recorded 188,137 QPS, p50 38.1 us, p99 209.7 us,
p999 1,566.8 us, zero dropped responses, zero errors, and matching loopback
RX/TX packet deltas in `network/proc-net-dev-delta.tsv`. The later
`target/zone-image-bench/question-wire-len-no-copy.tsv` artifact extends the
same allocation-cleanup theme by removing the parsed-question wire copy. The
loopback smoke is retained as exact-code correctness evidence because runtime
QPS was noisy; the in-process prototype benchmark above is the timing evidence
for the allocation removal.

### Current Validation Snapshot

On 2026-05-29, the current development tree passed the design-doc validation
gate available on this machine:

- `cargo fmt --all --check`;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo test --workspace`;
- `python3 scripts/check-functional-requirement-references.py`;
- `python3 scripts/check-unsafe-boundaries.py`;
- `python3 scripts/check-unsafe-prone-dependencies.py`;
- `scripts/audit-safe-rust.sh`;
- `scripts/check-shell-scripts.sh`;
- `git diff --check`.

The retained prototype benchmark was revalidated with
`scripts/check-zone-image-prototype-benchmark.py`, producing
`target/zone-image-bench/prototype-check-latest.tsv` with status `passed`.
The retained direct/semantic live loopback gate was revalidated with
`scripts/compare-zone-image-benchmarks.py`, producing
`target/evidence/zone-image-evidence-gate-loopback-direct-semantic-smoke/comparison.tsv`
with status `passed`.

On 2026-06-01, the focused single-device close-out checks for the pre-AF_XDP
slice also passed:

- `python3 scripts/check-udp-batch-sweep.py --input target/evidence/udp-batch-sweep-current-local/summary.tsv --output target/evidence/udp-batch-sweep-current-local/check.tsv`;
- `python3 scripts/check-zone-image-evidence-tools.py`;
- `bash scripts/audit-invariants.sh`;
- `python3 scripts/check-doc-hygiene.py`;
- `bash scripts/check-shell-scripts.sh`;
- `cargo fmt --check`;
- `cargo check -p oxidedns-core --example zone_image_bench`;
- `cargo test -p oxidedns-core --lib zone::tests -- --test-threads=1`;
- `git diff --check`.

This closes the current single-device local batch-ceiling task. Further
loopback sweeps are evidence refreshes after code changes or new hardware
runs; they are not a substitute for physical NIC promotion evidence.

Together, the retained broad validation snapshot and the focused close-out
checks cover the local safe-Rust, shell, unit-test, differential-correctness,
and loopback performance gates for the immutable ZoneImage path. They do not
replace the physical NIC promotion gate; that still requires rerunning
`scripts/zone-image-evidence-gate.sh` with
`OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true` and real listen/client
addresses on a suitable multi-queue host. In that mode, the comparator also
requires the same non-loopback network device, `require_non_loopback_device=true`,
matching listen/client provenance, matching `client_mode=ssh`, matching
non-empty `remote_client_ssh`, a concrete non-loopback `client_server`,
distinct local/remote host identity,
matching local and remote client architecture with
`remote_client_allow_arch_mismatch=false`, matching local and remote
`dns-load-client` SHA-256 digests, matching Git/kernel/toolchain/build-profile
provenance, positive RX/TX packet and byte deltas, and zero RX/TX drop and
error deltas in each retained `network/proc-net-dev-delta.tsv` file. It also requires the
benchmark summary packet-counter rows to match the retained `/proc/net/dev`
delta file, and requires RX and TX packet deltas to meet the default `0.25`
packets-per-response floor. The standard evidence gate also requires positive
direct-answer and semantic ZoneImage served-hit counters so the hot path and
semantic planner are both represented in the retained trace, and it requires
zero ZoneImage failures unless the comparator is deliberately run with a
non-zero `--max-zone-image-failures` threshold. ZoneImage rollback counters
must remain zero for retirement evidence.

Use `OXIDEDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY=true` with the same environment to
validate SSH reachability, remote architecture, non-loopback network settings,
and build/toolchain provenance before starting either live benchmark run.

## References

- Linux kernel AF_XDP documentation:
  <https://docs.kernel.org/networking/af_xdp.html>
- Linux kernel eBPF verifier documentation:
  <https://docs.kernel.org/bpf/verifier.html>
- Linux kernel io_uring zero-copy receive documentation:
  <https://docs.kernel.org/networking/iou-zcrx.html>
- arc-swap performance notes:
  <https://docs.rs/arc-swap/latest/arc_swap/docs/performance/index.html>
- NLnet Labs adaptive radix nametree discussion:
  <https://nlnetlabs.nl/news/2020/Jun/11/adaptive-radix-nametree/>
- Knot DNS documentation:
  <https://www.knot-dns.cz/docs/>
- PowerDNS Authoritative Server performance documentation:
  <https://doc.powerdns.com/authoritative/performance.html>
