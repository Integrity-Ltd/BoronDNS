# ZoneSnapshot Narrowing Design

Status: scoped design task, 2026-07-18. No runtime representation change is
claimed by this document.

## Objective

Reduce steady-state memory retained beside each immutable `ZoneImage` without
weakening transfer correctness, catalog reconciliation, lifecycle control, or
the offline differential oracle. The work is intentionally separate from the
ZoneImage denial-index and capacity fixes: it changes ownership and lifetime,
not DNS query semantics.

## Current Responsibilities

The current `ZoneSnapshot` is retained after publication because it combines
several different responsibilities:

1. **Transfer state:** complete RRsets, SOA/serial data, and the current source
   needed to validate and apply IXFR changes.
2. **Image builder input:** deterministic source RRsets consumed by
   `ZoneImage::compile` at publication.
3. **Catalog input:** a borrowed `CatalogZoneView` used while reconciling
   catalog membership.
4. **Control state:** origin, serial, SOA timers, state, and cached shape facts
   used by scheduling, status, and observability paths.
5. **Offline oracle:** materialized lookup behavior used by differential tests
   and retained benchmark evidence, not live serving.

Query serving is not on this list: published queries use `ZoneImage`.

## Target Ownership Model

- `TransferZoneData` owns the canonical RRsets and only the indexes required to
  validate AXFR/IXFR and apply deltas. It survives publication only while those
  transfer responsibilities require it.
- `ZoneImageBuilderInput` is a borrowed view over transfer data. Compilation
  must not clone the complete record corpus.
- `CatalogZoneView` remains borrowed and must not require query indexes or
  materialized `LookupResult` values.
- `ZoneMetadata` remains the narrow cached control-plane value for state,
  serial, SOA timers, shape, and immutable-image statistics.
- `ZoneSnapshotOfflineOracle` moves behind an explicit test/evidence boundary.
  Production builds must not retain its query indexes merely to keep the oracle
  cheap.

Dropping all source records immediately after publication is not an initial
goal: IXFR application needs a trustworthy current-zone source. The first
memory target is duplication and query-only index retirement. Record retirement
requires a separately proven transfer store or a lossless reconstruction
contract and is a later decision.

## Migration Stages

1. Add a counting-allocation evidence probe that reports snapshot construction,
   post-publication retained transfer state, ZoneImage, and peak compile/reload
   allocation separately. Keep it out of the query hot path.
2. Inventory every production `ZoneSnapshot` accessor and classify it as
   transfer, builder, catalog, control, or offline oracle. The invariant audit
   must reject new unclassified production access.
3. Extract control and catalog views without changing ownership. Existing
   `ZoneMetadata`, `TransferZoneSnapshot`, and `CatalogZoneView` are the starting
   seams.
4. Split transfer-required RRset state from offline-oracle/query indexes. Run
   AXFR, IXFR, catalog, reload, expiry, and differential suites after each
   ownership move.
5. Make offline-oracle indexes test/evidence-only or build them transiently for
   comparison runs.
6. Consider source-record retirement only after IXFR and recovery have another
   lossless, bounded-memory source of truth.

Each stage is independently reversible. No stage may reconstruct records from
query packets or make `ZoneImage` mutable.

## Representative Signed-Registry Replay Gate

Evaluation requires a retained, reproducible corpus or generator containing:

- at least one million owner names and a documented RRset/RDATA distribution;
- apex and delegated NS, glue, DS, DNSKEY, NSEC or NSEC3, and multiple RRSIG
  covered types;
- empty non-terminals, high sibling fanout, multi-RRset owners, unknown RR
  types, and realistic owner/RDATA length distributions;
- a complete AXFR load followed by representative IXFR additions, deletions,
  serial changes, catalog reconciliation, publication, and expiry/reload; and
- a fixed query trace covering positive, wildcard, referral, NODATA, NXDOMAIN,
  DNSSEC proof, and TCP/UDP composition paths.

The narrowing track may advance only when the replay demonstrates:

1. byte-for-byte response parity and zero transfer/catalog/oracle mismatches;
2. no new live query fallback to the old snapshot model;
3. measured peak-reload and steady-state retained-memory reduction, reported
   per responsibility rather than as process RSS alone;
4. no statistically meaningful compile or packet-path regression under matched
   runs, with any regression reported explicitly; and
5. unchanged safe-failure behavior for malformed transfers and denial rings.

Physical-link evidence remains the final performance gate because isolated
lookup microbenchmarks can exaggerate cache-layout effects.

## Counting-Allocator CI Decision

A permanent allocation probe is useful, but it is not added blindly to every
CI run. Wrapping the global allocator introduces an unsafe boundary or a new
instrumentation dependency, and synthetic fixtures can turn exact byte totals
into brittle gates. The implementation task should first choose and register a
safe measurement boundary, then run the probe in a dedicated profiling job.
CI should retain the measured values and compare broad regression thresholds;
the existing per-arena ZoneImage statistics remain the stable always-on input.
