# Reducing retained snapshot memory

This is a design note for further memory work, updated against the September
2026 implementation. It does not claim that snapshot ownership has already
been split into new production types.

`ZoneSnapshot` cannot simply be dropped after compiling a `ZoneImage`.
Transfers need the current records for IXFR; large-zone overlays also answer
dirty queries from that snapshot. The useful goal is to reduce duplication
without making updates, recovery, or query behavior more expensive.

## What the snapshot currently owns

| Responsibility | Why it remains live |
| --- | --- |
| Canonical RRsets and serial lineage | Validate and apply IXFR additions/deletions; identify changes relative to an installed generation |
| Name/class and empty-non-terminal indexes | Maintain existence semantics during updates and overlay lookups |
| Delegation and DNAME indexes | Resolve current semantic answers where the compact base cannot be reused |
| Persistent NSEC/NSEC3 order indexes | Apply small changes without rebuilding every denial index |
| Cached shape and SOA metadata | Publication policy, refresh scheduling, status, and resource observations |
| Builder and persistence input | Compile an image and write a lossless checkpoint or journal |
| Catalog view | Reconcile transferred membership and policy data |
| Offline oracle | Differential tests and benchmark comparisons |

[`zone.rs`](../crates/borondns-core/src/zone.rs) already exposes restricted
`TransferZoneSnapshot`, `CatalogZoneView`, and `ZoneMetadata` views.
`offline_oracle()` marks comparison-only access, but the underlying semantic
lookup also serves current overlays through a separate production path.

RRset and name-index maps use copy-on-write shards. All-IN name indexes now
store reference counts, rather than the July experiment's simple membership
sets, because incremental deletion must know when a name ceases to exist.
The [July decision](zone-image-proposal-disposition-2026-07.md) remains useful
historical evidence, not a description of today's exact allocation layout.

## A practical next step

Measure retained memory by responsibility before creating more types. Separate
at least source RRsets, name/denial indexes, compact image arenas, changed
overlay shards, build workspace, and old-generation overlap. Process RSS alone
cannot show which ownership change helped.

Then consider narrowing in this order:

1. Remove duplicated cached metadata or indexes that no production caller
   needs. Keep the existing restricted views as the API boundary.
2. Separate genuinely offline-only state from indexes used by IXFR overlays.
   Do not classify all snapshot query helpers as obsolete.
3. Rework source/image byte duplication only with a lossless transfer and
   persistence contract. A query packet is not a substitute for canonical
   stored records.
4. Consider retiring canonical source records only if another representation
   can support IXFR, catalog reconciliation, restoration, and dirty-query
   semantics without whole-zone reconstruction.

Names such as `TransferZoneData` or `ZoneImageBuilderInput` are possible design
seams, not existing types or an agreed migration requirement. Preserve
immutable publication throughout. The
[current data-plane design](memory-io-data-plane-design.md) owns that contract.

## Evidence for accepting a change

Use a reproducible signed-registry corpus or generator with at least one
million owner names, a documented RRset distribution, and realistic owner and
RDATA lengths. It should include delegations, glue, DS, DNSKEY, NSEC/NSEC3,
multiple covered RRSIG types, empty non-terminals, high fanout, multi-RRset
owners, and unknown types.

Exercise full load, repeated small IXFR, removals, background compaction,
catalog reconciliation, persistence/restart, and expiry. Replay positive,
wildcard, referral, NODATA, NXDOMAIN, and DNSSEC queries over UDP and TCP,
including queries whose overlay dependencies changed.

Report steady retained bytes and peak reload memory alongside update latency,
compact/dirty-query QPS, and packet/semantic parity. Include a small-zone
control: reducing memory for a large overlay does not justify slowing the
ordinary compact path. Use matched physical-link runs for performance claims;
in-process allocation and lookup probes explain a result but do not replace
service measurements.

A counting allocator or new profiling dependency would need its own reviewed
unsafe/instrumentation boundary. Prefer dedicated profiling runs and broad
regression thresholds over exact allocation totals in every CI run. Existing
per-arena image statistics remain useful without adding allocator hooks.
