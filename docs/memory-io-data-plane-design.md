# Memory And Packet I/O Data Plane Design

Status: deferred optimization design with an experimental local `ZoneImage`
implementation slice. Implementation progress and remaining retirement work are
tracked in `docs/zone-image-implementation-status.md`.

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

### RRsets And WireArena

Store ordinary RRsets in sorted slices per owner. Linear scan is acceptable for
the common one-to-four RRset case; binary search is a measurement candidate for
larger names.

Pre-encode immutable RRsets into uncompressed wire chunks first. That gives a
simple response-composition win without immediately coupling correctness to a
full-packet template cache.

Special cases remain dynamic:

- wildcard owner substitution;
- DNAME-generated CNAME records;
- CNAME chain planning;
- EDNS OPT, DNS Cookie, NSID, EDE, TSIG, and other response metadata;
- truncation decisions;
- compression dictionary choices.

RRSIG records need a covered-type index rather than being treated as ordinary
RRsets in all cases.

### Negative DNSSEC Indexes

DNSSEC denial-of-existence should be implemented after exact positive lookup,
delegation, wildcard, CNAME, and DNAME equivalence is proven.

NSEC baseline:

- canonical owner order;
- owner-to-order position;
- RRset ID by owner;
- predecessor lookup for nonexistent names.

NSEC3 baseline:

- sorted hashed owners;
- parameter record for hash, flags, iterations, and salt;
- capped dynamic hash work for candidate closest-encloser names;
- per-worker cache only if negative responses are hot in perf data.

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

### io_uring Evaluation

io_uring belongs behind `PacketIo` as an evaluation path. It may be useful for
standard-stack batching and future zero-copy receive experiments, but the
zero-copy receive path has NIC and queue steering requirements and must not be
assumed portable.

TCP ordering remains a hard constraint. Do not overlap multiple sends or
receives on the same TCP stream unless the implementation explicitly proves
ordering.

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
zone image shadow matches
zone image shadow mismatches
zone image shadow unsupported
zone image shadow errors
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
- fallback path remains continuously tested;
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
- optional runtime shadow validation can compile and cache images without
  changing served answers.

### Phase 3: Full Name Semantics

Tasks:

- add wildcard, empty non-terminal, delegation, glue, CNAME, and DNAME support;
- add additional-data index;
- extend differential corpus;
- add an opt-in serving gate that composes supported response sections directly
  from immutable `ZoneImage` wire chunks and falls back to the current snapshot
  response path for unsupported or oversized responses.

Exit:

- current name-semantics tests pass under both models;
- packet-level sampled responses match expected behavior for the gated serving
  path;
- shadow-validation counters stay at zero mismatches/errors for the retained
  sampled query set;
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
- isolate syscall unsafe in one registered adapter;
- add batch parse/lookup/compose/send pipeline;
- retain existing socket path as fallback.

Exit:

- qps/core improves over the current UDP path;
- sampled response behavior is unchanged;
- loss and error accounting is visible;
- unsupported-platform fallback is tested.

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

It compares current `ZoneSnapshot::lookup` direct positive lookup against the
`ZoneImage::lookup_exact_plan` handle path for a generated flat authoritative
zone. It also validates a mixed semantic query set covering direct positive,
CNAME, wildcard, referral/glue, NODATA, NXDOMAIN, DNAME behavior, and an
opaque unknown RR type before timing both the current lookup path and the
`ZoneImage` semantic path. The packet validator also checks positive EDNS
option handling for NSID, DNS Cookie, and padding, signed DO handling for the
covered corpus, plus fallback boundaries for full QTYPE ANY, UDP truncation,
EDE not-ready responses, and varied no-EDNS/EDNS UDP payload ceilings before
timing the gated packet path. A
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
parity for comparable packet and record totals, and configured performance
ratios for exact lookup, mixed planning/wire emission, packet response, EDNS
optioned response, and delegation/DNAME stress paths.

Current retained prototype sample from 2026-05-29 on this development machine,
after the exact lookup allocation removal, compact delegation/DNAME indexes,
direct RR-section wire emission, the gated packet response path, arena-wire
owner/RDATA name compression, and the signed-zone RRSIG/NSEC/NSEC3 indexes.
Runtime serving also keeps a last-hit
ZoneImage cache entry so repeated queries for the active snapshot avoid the
zone-key string allocation and HashMap lookup before falling back to the
multi-zone cache. The gated packet path uses a lightweight lookup-metrics
observer so normal responses do not materialize `ResourceRecord` values only to
record termination counters, and semantic planning skips answer materialization
when the answer RR type cannot produce additional address records. The direct
answer emitter is attempted before the generic section-counting pass, so the
common single-RRset hot path patches the answer count after copying validated
RRset wire chunks. The direct-copy eligibility now follows the current
composer: it rejects RR types whose RDATA is rewritten for DNS name
compression, but admits opaque and unknown RR types after byte-for-byte
validation. The response composer also writes question names directly from
parsed labels and registers the already-written question slice with the wire
compressor, avoiding an extra QNAME wire allocation in both the direct emitter
and generic ZoneImage composer. Answer order tracking is lazy: direct positive
plans record only their RRset list, while synthesized-answer paths populate a
small ordering list with indexes into the stored synthesized answers only when
interleaving is required. Delegation and DNAME discovery now walk the packed
name graph's closest existing node and parent chain instead of scanning global
candidate RRset lists. The runtime serving path first tries a guarded exact
direct-answer candidate before full semantic planning; the candidate is allowed
only when the packed ancestor chain proves no referral, ancestor DNAME, or
additional-address processing can change the answer. The direct emitter then
compares the RRset owner to the question once and uses the stored owner-wire
length while copying each RR, avoiding repeated owner-name parsing for
multi-RDATA direct answers. Additional-data planning for ordinary
NS/MX/SRV/NAPTR/SVCB/HTTPS answers and delegation-glue discovery now parses
targets directly from immutable RDATA arenas. Wildcard owner substitution keeps
RRset handles plus stored owner-wire overrides, while DNAME CNAME synthesis
stores only owner wire and RDATA instead of a full `ResourceRecord`:

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
| `query_mix_fallback` | `do_dnssec_positive,full_any,udp_truncation,ede_not_ready` |
| `query_mix_udp_ceiling` | `no_edns_512,edns_payload_512,edns_payload_1232,edns_payload_4096` |
| `query_mix_delegation_dname_stress` | `referral_glue,dname_synthesis` |
| `serving_gate` | `minimal_any_signed_dnssec_supported_with_snapshot_fallback` |
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
| `fallback_packet_cases` | 3 |
| `fallback_packet_validation_mismatches` | 0 |
| `udp_ceiling_packet_cases` | 5 |
| `udp_ceiling_packet_validation_mismatches` | 0 |
| `ede_fallback_packet_cases` | 1 |
| `ede_fallback_packet_validation_mismatches` | 0 |
| `zone_image_compile_ms` | 11.390 |
| `zone_image_delegation_dname_stress_compile_ms` | 7.507 |
| `current_lookup_ns_per_query` | 161.341 |
| `zone_image_exact_lookup_ns_per_query` | 78.445 |
| `current_hot_lookup_ns_per_query` | 126.862 |
| `zone_image_hot_exact_lookup_ns_per_query` | 48.192 |
| `current_mixed_response_ns_per_query` | 441.714 |
| `zone_image_mixed_plan_ns_per_query` | 263.024 |
| `zone_image_mixed_wire_ns_per_query` | 284.278 |
| `zone_image_mixed_response_ns_per_query` | 395.087 |
| `current_delegation_dname_stress_response_ns_per_query` | 85,909.958 |
| `zone_image_delegation_dname_stress_plan_ns_per_query` | 685.605 |
| `zone_image_delegation_dname_stress_wire_ns_per_query` | 635.747 |
| `zone_image_delegation_dname_stress_response_ns_per_query` | 865.738 |
| `current_mixed_packet_ns_per_query` | 1,443.832 |
| `zone_image_mixed_packet_ns_per_query` | 822.145 |
| `current_hot_packet_ns_per_query` | 548.710 |
| `zone_image_hot_packet_ns_per_query` | 190.808 |
| `current_trace_packet_ns_per_query` | 1,613.812 |
| `zone_image_trace_packet_ns_per_query` | 625.646 |
| `current_optioned_packet_ns_per_query` | 612.458 |
| `zone_image_optioned_packet_ns_per_query` | 236.082 |
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
| `zone_image_delegation_dname_stress_record_count` | 500,000 |
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
| `optioned_packet_ratio` | 0.385 |
| `delegation_dname_stress_plan_ratio` | 0.008 |
| `delegation_dname_stress_wire_ratio` | 0.007 |

Interpretation: direct exact handle lookup is faster than the current snapshot
path on this flat-zone sample. The mixed semantic plan path is also faster than
the current materialized lookup after adding compact delegation and DNAME
candidate indexes to avoid scanning every RRset. The remaining gap is the
temporary `ResourceRecord` materialization adapter for compatibility paths:
direct RR-section emission from handles and wire arenas keeps most of the
plan-path gain, while the served negative authority path now uses precomputed
SOA negative TTL instead of reparsing SOA RDATA for each packet. Generic
ZoneImage responses also pre-size their response buffers from plan wire bounds
instead of relying on a small fixed starting capacity.
The delegation/DNAME stress shape validates the main scaling reason for the
packed name graph: the current snapshot path pays about 86 us/query while it
scans 2,000 delegation and 2,000 DNAME candidates, while ZoneImage semantic
planning stays below 1 us/query with byte-equivalent record counts. The gated
packet path is faster than the current packet path in this sample
after replacing its full-lookup observer with a lightweight termination/NSEC3
metrics observer, skipping additional-record materialization for answer types
that cannot reference address targets, and adding a direct answer emitter for
single opaque-RDATA RRsets whose owner is the query name. That emitter writes
the answer owner as a normal pointer to the question, copies the pre-encoded
RRset body, and appends the regular OPT encoder for EDNS responses, avoiding
per-record compressor and RDATA materialization work on direct answers whose
RDATA is already copied opaquely by the normal composer. Runtime tests verify
the serving cache reuses the same image for repeated snapshots and replaces it
when a new snapshot for the same zone is published. Arena-wire compression for
owner names plus known-name RDATA keeps packet bytes equal to the current
composer for the retained query mix without rehydrating `DomainName` owners.
The separately timed optioned EDNS packet corpus now also uses the direct
answer emitter for direct positive answers. The hot-query shape shows a strong
exact-lookup win and a positive gated packet-path win once packet parsing and
response framing dominate the repeated-name workload. The benchmark now
verifies zero byte-level packet mismatches across the retained mixed, hot, and
weighted trace packet corpora before timing, and it also verifies that the
gated path preserves positive EDNS option behavior for NSID, DNS Cookie, and
padding while preserving served DO positive signing and fallback behavior for
full QTYPE ANY, UDP truncation, EDE not-ready, and varied no-EDNS/EDNS UDP
payload ceiling cases. The focused unit suite also verifies that DO positive
signing, NODATA/NSEC proof selection, NXDOMAIN/NSEC proof selection, wildcard
proofs, referral proofs, and NSEC3 iteration-cap EDE responses serve through
ZoneImage while preserving byte-for-byte responses and the existing DNSSEC cap
metric. Promotion still needs real operator trace coverage and physical network
evidence, not only retained in-process ns/query evidence.

### Live Loopback Serving Sample

`scripts/benchmark-dns-clients.sh` can compare the current snapshot serving path
and the opt-in ZoneImage serving path through the actual OxideDNS runtime,
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
OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR=target/evidence/zone-image-live-loopback-disabled \
OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=false \
OXIDEDNS_BENCH_DURATION_SECONDS=3 \
OXIDEDNS_BENCH_RECORDS=10000 \
OXIDEDNS_BENCH_TRANSPORT=udp \
OXIDEDNS_BENCH_SERVER_THREADS=4 \
OXIDEDNS_BENCH_CLIENT_THREADS=8 \
OXIDEDNS_BENCH_CLIENT_WINDOW=64 \
scripts/benchmark-dns-clients.sh

OXIDEDNS_DNS_CLIENT_BENCHMARK_DIR=target/evidence/zone-image-live-loopback-enabled \
OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=true \
OXIDEDNS_BENCH_DURATION_SECONDS=3 \
OXIDEDNS_BENCH_RECORDS=10000 \
OXIDEDNS_BENCH_TRANSPORT=udp \
OXIDEDNS_BENCH_SERVER_THREADS=4 \
OXIDEDNS_BENCH_CLIENT_THREADS=8 \
OXIDEDNS_BENCH_CLIENT_WINDOW=64 \
scripts/benchmark-dns-clients.sh
```

Retained loopback UDP samples from 2026-05-28:

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
recorded `zone_image_serve_hits=0` and `zone_image_serve_fallbacks=0`; its
ZoneImage artifact recorded `zone_image_serve_hits=295243` and
`zone_image_serve_fallbacks=0`. That proves the measured runtime win came from
the experimental immutable-zone-image serving path rather than from a fallback
run.

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
`zone_image_serve_fallbacks=0`. That proves the retained live trace exercised
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
RX/TX packet deltas in `network/proc-net-dev-delta.tsv`. This is retained as an
exact-code correctness smoke because loopback runtime QPS was noisy; the
in-process prototype benchmark above is the timing evidence for the allocation
removal.

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

This proves the current tree satisfies the local safe-Rust, shell, unit-test,
differential-correctness, and loopback performance gates for the immutable
ZoneImage path. It does not replace the physical NIC promotion gate; that still
requires rerunning `scripts/zone-image-evidence-gate.sh` with
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
zero ZoneImage fallbacks unless the comparator is deliberately run with a
non-zero `--max-zone-image-fallbacks` threshold.

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
