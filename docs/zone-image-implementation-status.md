# ZoneImage Implementation Status

Status legend:

- `[x]`: implemented and locally validated.
- `[~]`: partially implemented, implemented behind a fallback, or validated only
  on local/loopback evidence.
- `[ ]`: not implemented.

Owner: this document tracks implementation status for the NSD-style immutable
`ZoneImage` data-plane track described in
`docs/memory-io-data-plane-design.md`. It also tracks the eventual retirement
of the old query-time `ZoneSnapshot` memory layout after `ZoneImage` becomes
the complete production query data plane.

This is an implementation tracker, not a normative DNS behavior source. DNS
requirements remain owned by `docs/OxideDNS-Secondary-SRS-v0.9.1.md`.

## Current Summary

- [x] Local immutable `ZoneImage` MVP exists.
- [x] The gated runtime path can serve supported non-DNSSEC query shapes.
- [x] Local differential, unit, prototype, and loopback evidence exists.
- [~] `ZoneImage` is still experimental and disabled by default.
- [~] The old `ZoneSnapshot` query layout remains the correctness oracle and
  fallback.
- [ ] Physical NIC promotion evidence is not complete.
- [ ] The old query-time memory layout is not retired.

Working position: the first useful local data-plane slice is implemented. The
next work is to broaden correctness coverage, collect physical evidence, then
promote `ZoneImage` from opt-in serving path to default query layout. Only after
that should the old query-time layout be phased out.

## Phase 0: Baseline And Evidence Harness

- [x] Retain current-path benchmark artifacts for comparison.
- [x] Separate parse, lookup, compose, and send timing in retained evidence.
- [x] Retain build and host provenance in benchmark artifacts.
- [x] Retain query trace input for replayed live-runtime comparisons.
- [x] Add comparator for current path versus `ZoneImage`.
- [x] Add served-path counters proving whether `ZoneImage` served or fell back.
- [x] Add direct-answer and semantic-plan served-hit counters.
- [x] Add network snapshot and `/proc/net/dev` delta artifacts.
- [x] Add physical-promotion comparator checks for non-loopback device, packet
  counters, drops, errors, provenance, client mode, remote SSH target, and
  remote binary digest.
- [x] Physical-gate preflight rejects SSH clients whose host identity matches
  the local server host.
- [ ] Run the physical gate from a separate client host over a real non-loopback
  NIC.
- [ ] Retain 10G/25G/40G-class multi-queue NIC evidence.

## Phase 1: Handle-Based Lookup

- [x] Introduce handle/plan style lookup through `ZoneImageLookupPlan`.
- [x] Avoid ordinary direct-positive `ResourceRecord` materialization on the
  fastest supported direct-answer path.
- [x] Add metrics that distinguish current lookup from `ZoneImage` lookup.
- [~] The old `ZoneSnapshot` lookup path still materializes owned response
  records and remains the fallback.
- [ ] Remove the old query-time materialization path after `ZoneImage` is the
  complete default query data plane.

## Phase 2: Exact ZoneImage Prototype

- [x] Compile an immutable `ZoneImage` from the existing safe `ZoneSnapshot`.
- [x] Build canonical packed name nodes and sorted child edges.
- [x] Store RRset metadata by integer IDs.
- [x] Store label, owner-name, RDATA, and RRset-wire arenas.
- [x] Use checked offsets and lengths instead of unsafe pointer arithmetic.
- [x] Implement exact positive lookup.
- [x] Support ANY-class direct answers where current semantics allow it.
- [x] Add exact-lookup differential tests against the current snapshot model.
- [x] Emit shape and byte statistics for the prototype benchmark.
- [x] Keep packed lookup in safe Rust.

## Phase 3: Full Name Semantics

- [x] Wildcard lookup.
- [x] Empty non-terminal behavior through closest-encloser style lookup.
- [x] CNAME handling.
- [x] DNAME synthesis and target resolution.
- [x] Delegation and referral handling.
- [x] Glue selection for delegated NS targets.
- [x] Additional A/AAAA selection for answer-section address targets.
- [x] NODATA and NXDOMAIN behavior for supported unsigned paths.
- [x] Parent-chain indexes for delegation and DNAME discovery.
- [x] Stress benchmark for delegation/DNAME candidate scans.
- [x] Opt-in `zone_image_shadow_enabled`.
- [x] Opt-in `zone_image_serve_enabled`.
- [x] Fallback for unsupported or risky query shapes.
- [~] Signed DO positive, NODATA, NXDOMAIN, wildcard, referral, and NSEC3 cap
  paths can serve through `ZoneImage`; broader default promotion still needs
  operator-trace and physical NIC evidence.
- [~] Full QTYPE ANY behavior falls back unless the configured minimal mode is
  compatible with the `ZoneImage` path.
- [~] UDP truncation edge cases fall back to the current composer.

## Phase 4: Wire Composition

- [x] Pre-encode immutable RRset wire chunks.
- [x] Direct hot answer emitter copies validated RRset wire bodies.
- [x] Direct emitter patches answer counts without a generic section-counting
  pass.
- [x] Direct emitter avoids repeated owner parsing for copied direct answers.
- [x] Generic `ZoneImage` composer writes question names directly from parsed
  labels.
- [x] Generic composer registers question-name compression state.
- [x] Known-name RDATA compression is preserved for supported generic paths.
- [x] Opaque and unknown RR types can use the direct-copy path after validation.
- [x] Additional-data planning for NS/MX/SRV/NAPTR/SVCB/HTTPS parses targets
  directly from `ZoneImage` RDATA arenas instead of rebuilding full answer
  record vectors.
- [x] Delegation glue planning parses NS targets directly from RRset RDATA.
- [x] Exact CNAME and DNAME planning reads first-hop targets directly from
  RRset RDATA instead of materializing those RRsets.
- [x] SOA TTL-override wire emission reuses stored owner-wire slices instead
  of allocating a temporary owner buffer.
- [x] Negative SOA TTL is precomputed in compiled RRsets so authority emission
  does not parse SOA RDATA on every negative response.
- [x] Wildcard owner-substitution answers keep RRset handles with stored
  owner-wire overrides instead of synthesized `ResourceRecord` vectors.
- [x] DNAME-synthesized CNAME answers store owner wire and RDATA fields without
  rebuilding a full `ResourceRecord` for the composer.
- [x] Generic response buffers are pre-sized from immutable plan wire bounds
  rather than a fixed small starting capacity.
- [x] Focused tests cover wildcard owner overrides, additional-data discovery,
  wire-record visitation from handles, and plan wire-bound accounting.
- [~] The full response composer is not yet a pure immutable template/WireArena
  pipeline.
- [~] Public `LookupResult` materialization still rebuilds temporary
  `ResourceRecord` values for compatibility outside the packet hot path.
- [x] Precompute negative SOA variants for the `ZoneImage` composer.
- [x] Add focused bounds tests for plan wire upper-bound accounting.
- [x] Run a direct-answer response-template cache experiment; rejected for now
  because local Vec/socket-path evidence showed more memory and no packet-path
  win. Revisit when io_uring fixed buffers or AF_XDP UMEM can transmit from
  reusable templates without copying.
- [x] Add composer fuzz and bounds tests targeted at the current WireArena
  writer surface: malformed wire-name helper bounds, malformed known-name RDATA
  opaque fallback, packet differential coverage, and the `zone_image_datagram`
  fuzz target.

## Phase 5: DNSSEC Denial And Signed Zones

- [x] DNSSEC-sensitive query shapes are packet-differential tested against the
  current path before serving through `ZoneImage`.
- [x] Tests cover served DO positive signing, NSEC proof selection, NSEC3
  cap/EDE, referral proofs, wildcard proofs, and remaining fallback cases.
- [x] Add RRSIG covered-type indexes to `ZoneImage`.
- [x] Add NSEC indexes to `ZoneImage`.
- [x] Add NSEC3 indexes to `ZoneImage`.
- [x] Implement bounded dynamic NSEC3 work in the `ZoneImage` path.
- [x] Add packet-level signed-zone differential corpus for `ZoneImage`.
- [~] DNSSEC-capable `ZoneImage` serving is enabled for supported opt-in paths;
  default promotion still waits on broader trace and physical evidence.

## Phase 6: Runtime Integration And Promotion

- [x] Runtime can compile and cache `ZoneImage` from a published snapshot.
- [x] Last-hit cache avoids repeated zone-key map lookup for repeated queries.
- [x] Shadow validation can compare `ZoneImage` and current snapshot answers.
- [x] Serving path records hits, direct hits, semantic hits, and fallbacks.
- [~] Runtime serving remains opt-in and experimental.
- [~] The current snapshot path remains the default query path.
- [ ] Make `ZoneImage` default for unsigned supported query traffic.
- [ ] Keep a short rollback window where the old path can still be enabled.
- [ ] Remove fallback reliance for query shapes after equivalent `ZoneImage`
  behavior and evidence exist.
- [ ] Retire `ZoneSnapshot` as the query-time data plane.
- [ ] Keep `ZoneSnapshot` or an equivalent safe builder model only for ingestion,
  validation, transfer, catalog reconciliation, and `ZoneImage` compilation.

## Phase 7: Packet I/O And NIC Evidence

- [x] Existing standard socket path continues to work as the baseline.
- [x] Benchmark harness can run local and SSH-client modes.
- [x] Benchmark artifacts retain enough network evidence for physical review.
- [x] Physical preflight rejects same-host SSH clients.
- [x] Implement standard UDP batch adapter.
- [~] Compare standard UDP batch adapter against the current socket path with
  local loopback evidence; a 2026-05-29 smoke improved from 303,943 to 350,738
  responses/s at `udp_batch_size=32` with zero drops/errors, but physical NIC
  comparison remains open.
- [ ] Add packet-capture evidence for the promoted UDP path.
- [ ] Run separate-client non-loopback physical gate.
- [ ] Run multi-queue NIC profile with CPU/RSS/IRQ affinity recorded.
- [ ] Decide whether io_uring is worth implementing.
- [ ] Decide whether AF_XDP is worth implementing for the server.

## Phase 8: Layout Tuning Experiments

- [x] Current layout uses simple packed arrays, integer IDs, and segmented
  arenas.
- [x] Current lookup avoids global delegation/DNAME scans with compact indexes.
- [x] Current benchmark records node, edge, RRset, record, hot-byte, and
  cold-byte counts.
- [x] Add opt-in zone-shape histograms for high fan-out nodes and RRset
  distribution.
- [ ] Compare current sorted-edge lookup against adaptive radix on measured
  high-fanout corpora.
- [ ] Compare current sorted-edge lookup against generated perfect hash tables
  where fan-out justifies it.
- [ ] Evaluate software prefetch only after CPU profiles show lookup-memory
  stalls.
- [ ] Evaluate huge pages only after retained evidence shows TLB pressure.
- [ ] Evaluate NUMA-local or replicated images only on suitable multi-socket or
  NUMA-relevant hosts.

## Old Query Layout Retirement Checklist

The old query-time memory layout should not be removed just because `ZoneImage`
is faster locally. Retire it only after these are true:

- [ ] `ZoneImage` supports all authoritative query semantics currently served
  by the old query path, including signed-zone denial behavior.
- [ ] Shadow validation over representative operator traces records zero
  mismatches/errors.
- [ ] Packet-level differential tests cover positive, negative, wildcard,
  delegation, CNAME, DNAME, additional-data, EDNS, truncation, DNSSEC, and
  unknown-RR cases.
- [ ] Physical benchmark evidence shows `ZoneImage` is not slower on real NIC
  profiles.
- [ ] Operational metrics expose enough fallback/mismatch detail for rollback
  during the promotion window.
- [ ] Configuration defaults switch to `ZoneImage` serving.
- [ ] The old query path remains available for one explicit rollback period.
- [ ] After the rollback period, query-serving code no longer materializes the
  old layout on the hot path.
- [ ] Transfer ingestion and validation still use a clear safe builder model.
- [ ] Documentation no longer describes the old layout as the primary serving
  data plane.

## Recommended Order

1. Run the physical promotion gate on a separate client host and real NIC.
2. Complete the pure WireArena composer and remove remaining temporary
   `ResourceRecord` materialization from served `ZoneImage` paths.
3. Promote `ZoneImage` to default for unsigned and signed supported traffic.
4. Add the standard UDP batch adapter and measure whether packet I/O is the next
   bottleneck.
5. Start the old query layout retirement checklist only after full semantic and
   physical evidence exists.
