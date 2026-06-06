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
- [x] The runtime path serves supported unsigned and DNSSEC-capable query shapes
  through `ZoneImage`.
- [x] Local differential, unit, prototype, and loopback evidence exists.
- [x] `ZoneImage` serving is enabled by default for supported query shapes,
  with no live snapshot-serving rollback switch.
- [~] The old `ZoneSnapshot` query layout remains an offline correctness oracle
  for benchmark comparisons, not a runtime fallback.
- [ ] Physical NIC promotion evidence is not complete.
- [ ] The old query-time memory layout is not retired.

Working position: the local data-plane slice is default-enabled and the live
snapshot rollback path has been removed. The single-device pre-AF_XDP work now
has repeatable local no-XDP transport-ceiling evidence; further loopback batch
runs are optional evidence refreshes, not required progress. The remaining
promotion work is to broaden physical evidence on a separate client/NIC setup
and then reduce remaining offline-oracle reliance until the old query-time
layout can be phased out.

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
- [x] The old `ZoneSnapshot` oracle lookup path still materializes owned
  response records, but it is explicitly named as offline oracle code and is
  no longer a live runtime fallback.
- [~] Remove the remaining old query-time materialization code after
  offline-oracle and builder responsibilities are fully replaced or isolated.

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
- [x] Parent-chain indexes for delegation and DNAME discovery, including
  compiled IN-class nearest-delegation and nearest-DNAME policy handles in each
  `NameNode`, with unusual classes kept on the conservative scan fallback.
- [x] Thresholded high-fanout child hash indexes, with each indexed `NameNode`
  carrying its side-index handle directly.
- [x] Stress benchmark for delegation/DNAME candidate scans.
- [x] Runtime `zone_image_shadow_enabled` diagnostic retired; old/new
  comparisons are offline test/benchmark evidence only.
- [x] Always-on runtime `ZoneImage` serving; no operator-facing snapshot-serving
  rollback switch remains.
- [x] Fallback for unsupported or risky query shapes.
- [~] Signed DO positive, NODATA, NXDOMAIN, wildcard, referral, and NSEC3 cap
  paths can serve through `ZoneImage`; broader default promotion still needs
  operator-trace and physical NIC evidence.
- [x] Minimal and full QTYPE ANY behavior serves through `ZoneImage` for
  supported exact and wildcard RRsets while preserving DNSSEC proof/signature
  suppression semantics.
- [x] UDP truncation edge cases for supported responses serve through the
  `ZoneImage` composer.

## Phase 4: Wire Composition

- [x] Pre-encode immutable RRset wire chunks.
- [x] Direct hot answer emitter copies validated RRset wire bodies.
- [x] Direct emitter patches answer counts without a generic section-counting
  pass.
- [x] Direct emitter avoids repeated owner parsing for copied direct answers.
- [x] Direct emitter relies on the private exact-node direct-plan invariant
  instead of fetching and reparsing compiled owner wire before response
  allocation.
- [x] Direct emitter writes the DNS answer count from the compiled RRset record
  count instead of incrementing a per-query emitted-record counter and patching
  the header after the copy loop.
- [x] Direct emitter fetches copied-answer owner wire, RRset wire, type, and
  record count through one immutable `ZoneImage` RRset view instead of separate
  metadata lookups on the query path.
- [x] Direct emitter appends direct-copy answer bodies from compiled record/RDATA
  metadata instead of reparsing the immutable RRset wire to skip owner names.
- [x] Direct emitter carries emitted direct-answer body length in the direct RRset
  view, avoiding a second RRset lookup before response allocation.
- [x] Direct emitter derives fallback emitted direct-answer body length from
  compiled ownerless wire length plus record count in the same branch that
  selects the fallback record slice; storing a separate emitted-length field in
  every `ImageRrset` is currently rejected by the retained memory ceiling.
- [x] Direct emitter appends direct-copy answer bodies from the selected direct
  RRset view metadata instead of re-indexing the RRset by ID after preflight.
- [x] Direct emitter carries the pre-bounds-checked compiled record slice in the
  selected direct RRset view, avoiding per-record ID arithmetic during append.
- [x] Direct emitter carries the constant compressed-owner/type/class/TTL record
  prefix in the selected direct RRset view, avoiding per-record byte conversion
  for direct-copy answers.
- [x] Direct emitter uses the shared ZoneImage response-capacity helper for
  EDNS sizing instead of reserving a fixed slack block for any OPT response.
- [x] Direct emitter writes the DNS header and section counts through the shared
  known-count `ZoneImage` response-prefix helper instead of carrying a separate
  hand-assembled header path for exact-owner answers.
- [x] Direct emitter derives direct-copy eligibility from the compiled direct
  answer body length, so direct exact-owner responses no longer need a separate
  RRset side-bitset lookup after loading compiled RRset metadata.
- [x] The selected direct RRset view is eligible-only, so the direct packet
  composer no longer carries a second post-view `direct_copy_eligible` branch.
- [x] The selected direct RRset view is also non-empty by construction, so the
  direct packet composer no longer carries a redundant zero-answer guard after
  loading that view.
- [x] Direct emitter writes `NoError` and authoritative response flags directly
  from the private direct-plan invariant instead of reading dynamic plan flag
  accessors after the invariant has been checked.
- [x] Direct emitter appends OPT records through the shared `ZoneImage` EDNS
  helper instead of carrying a separate inline direct-path EDNS branch.
- [x] Stored immutable RDATA references carry a compact `u16` DNS rdlength in
  `RdataRange`, so direct-copy and stored-record TTL-override emitters write the
  prevalidated length without a per-query fallible length conversion.
- [x] Generic `ZoneImage` composer writes question names directly from parsed
  labels.
- [x] Generic composer registers question-name compression state directly from
  parsed labels instead of scanning the serialized question wire after writing
  it; suffix length is tracked in one pass while each suffix is registered.
- [x] Packet question parsing stores the consumed question length instead of
  copying the original question wire into each parsed `Question`; compressed
  QNAME tests verify that section/EDNS offsets still use the compressed length
  while responses are re-encoded from parsed labels, and the invariant audit
  rejects reintroducing a copied question-wire buffer.
- [x] Known-name RDATA compression is preserved for supported generic paths.
- [x] Opaque and unknown RR types can use the direct-copy path after validation.
- [x] Additional-data planning for NS/MX/SRV/NAPTR/SVCB/HTTPS parses targets
  directly from `ZoneImage` RDATA arenas instead of rebuilding full answer
  record vectors.
- [x] Additional-data planning for ordinary answer RRsets now uses
  compile-time precomputed A/AAAA RRset spans, avoiding per-query RDATA target
  parsing for those answer RRsets.
- [x] Additional-data planning walks copied answer handles directly instead of
  cloning `answer_rrsets` or `answer_items` before appending additional RRsets.
- [x] Additional-data planning deduplicates the common one-to-few target RRsets
  with an inline small vector instead of allocating a heap `Vec` on the query
  path.
- [x] QTYPE=ANY planning collects same-owner RRset handles in an inline small
  vector, avoiding a heap `Vec` for the common one-to-few owner RRset set.
- [x] Minimal QTYPE=ANY planning selects the lowest class/type RRset in one
  scan instead of collecting, sorting, and truncating the same-owner RRset set.
- [x] Minimal QTYPE=ANY target-bearing single answers append the compiled
  additional-address relation span directly instead of entering the multi-RRset
  additional dedupe helper.
- [x] Concrete-qtype exact, wildcard, and CNAME/DNAME endpoint additional-target
  gates use the already matched query type instead of rereading compiled RRset
  type metadata after exact RRset lookup.
- [x] Single-answer, multi-answer, and QTYPE=ANY additional planning checks a
  compiled additional-address relation bitmap instead of classifying RR types on
  the query path.
- [x] Full QTYPE=ANY planning relies on compile-time per-owner class/type RRset
  order and no longer sorts the same-owner RRset set per query.
- [x] Response-planner concrete-class RRset helper scans stop once the compiled
  per-owner class/type span has passed the requested class or type; QCLASS=ANY
  keeps the full scan.
- [x] Referral glue planning uses compile-time precomputed A/AAAA RRset spans
  filtered by delegation-owner bailiwick, avoiding query-time NS target parsing
  and delegation-owner filtering.
- [x] Exact CNAME and DNAME planning uses compile-time precomputed single-name
  targets reached through RRset relation spans, avoiding query-time target
  RDATA parsing and canonical-key rebuilds for those first-hop targets. DNAME
  synthesis compares borrowed stored owner wire directly instead of reparsing
  owner wire on each DNAME query, and literal CNAME target resolution can reuse
  a precomputed target-node classification.
- [x] Delegation planning compares DS-at-cut query names to stored delegation
  owner wire directly, avoiding query-time owner parsing and canonical string
  allocation for that exception path; the comparison rejects label-count
  mismatches from compiled RRset owner metadata before scanning stored owner
  wire.
- [x] Ordinary IN-class delegation and inherited-DNAME discovery uses
  compile-time policy handles stored directly in `NameNode`, avoiding repeated
  parent-chain walks in the response planner and direct-answer guard. QCLASS=ANY
  may reuse those handles only for compiled images whose delegation and DNAME
  policy RRsets are all IN-class; images with non-IN policy data keep the
  existing conservative scan fallback.
- [x] High-fanout nodes store their generated child-hash side-index handle
  directly in `NameNode`, avoiding a per-label lookup through the side-index
  table before probing hash slots.
- [x] High-fanout child-hash equality checks compare already-lowercase query
  labels directly before falling back to case-insensitive byte comparison.
- [x] SOA TTL-override wire emission reuses stored owner-wire slices instead
  of allocating a temporary owner buffer.
- [x] Negative response SOA selection uses a precomputed IN apex SOA handle
  for ordinary IN and ANY-class denial responses, leaving the apex RRset scan
  only for unusual classes.
- [x] Negative SOA TTL is precomputed in compiled RRsets so authority emission
  does not parse SOA RDATA on every negative response.
- [x] Wildcard owner-substitution answers keep RRset handles with stored
  owner-wire overrides instead of synthesized `ResourceRecord` vectors.
- [x] Wildcard QTYPE=ANY planning stores a shared query-owner override once for
  all same-owner wildcard RRsets instead of serializing the query owner for
  every RRset in the answer set.
- [x] DNSSEC wildcard-synthesis detection compares borrowed plan owner wire to
  query labels directly, avoiding temporary owner-wire and query-wire buffers.
- [x] DNAME-synthesized CNAME answers store owner wire and RDATA fields without
  rebuilding a full `ResourceRecord` for the composer; common generated owner
  and target wire now stay inline in the synthesized-record plan entry.
- [x] Synthesized DNAME CNAME target resolution defers canonical-key
  construction until after the generated target is known to remain inside the
  served zone; out-of-zone DNAME targets now return with the synthesized CNAME
  and avoid a loop-detection key allocation.
- [x] Synthesized DNAME CNAME suffix replacement compares the stored owner
  wire against borrowed query labels without allocating a temporary wire-label
  vector, while still returning the generated target and wire from one checked
  pass.
- [x] Domain-name wire serialization pre-sizes output buffers before writing
  labels, reducing reallocations for synthesized DNAME CNAME owners/RDATA,
  wildcard owner overrides, and other query-time domain-to-wire paths.
- [x] Wildcard owner-override wire storage keeps the common generated owner
  name inline in the lookup plan, avoiding the per-query heap allocation for
  the retained wildcard fixture while leaving larger generated names able to
  spill safely.
- [x] Dynamic synthesized-answer buckets use inline `SmallVec` capacity for
  the common one-to-few DNAME CNAME cases, avoiding heap allocation for those
  per-query plan buckets unless they spill.
- [x] Dynamic synthesized-answer records use inline wire storage for common
  DNAME CNAME owner and target RDATA bytes, avoiding per-query heap allocation
  for those generated wire buffers unless longer names spill.
- [x] Selected DNSSEC records are direct immutable plan items or section
  handles instead of entries in synthesized dynamic-record buckets.
- [x] CNAME/DNAME chain loop tracking stores borrowed precomputed canonical
  target keys when following immutable image targets.
- [x] CNAME/DNAME chain loop tracking keeps the original query name borrowed
  and stores the original exact query node when available, so existing in-zone
  target loops compare compiled node IDs. Missing and out-of-zone generated
  targets compare compiled or synthesized target wire directly to the original
  query labels without building canonical-key strings or using a second
  `DomainName` label-vector comparison helper.
- [x] DNSSEC RRSIG augmentation walks original plan-section lengths instead of
  cloning answer, authority, or additional vectors, and deduplicates selected
  immutable RRSIG records with an inline small set. The earlier owned
  record-identity set was removed because it was built on the query path but
  never consulted for decisions.
- [x] DNSSEC selected RRSIGs are stored directly in `PlanAnswer::SelectedRecord`
  for answers and direct selected-record section vectors for authority and
  additional records, avoiding the dynamic synthesized-record buckets and index
  indirection used by truly synthesized DNAME CNAME answers.
- [x] DNSSEC selected-record dedupe seeding skips the initial dynamic-record
  scan for ordinary unaugmented plans and only rescans if an already-augmented
  plan is passed back through augmentation.
- [x] DNSSEC augmentation computes answer record count once and reuses it for
  NODATA, NXDOMAIN, and wildcard-proof decisions instead of recounting plan
  sections for each candidate check.
- [x] DNSSEC denial augmentation reads an authority-SOA plan bit instead of
  scanning authority RRsets to prove the SOA precondition.
- [x] Plan record-count accounting indexes compiled RRsets directly instead of
  doing fallible bounds-checked lookups for private plan handles generated from
  the same `ZoneImage`.
- [x] CNAME/DNAME single-name target lookup and signed-referral DS/NSEC proof
  lookup consume the already-contiguous same-kind relation subspans instead of
  scanning mixed per-RRset relation spans. Focused tests cover mixed spans with
  CNAME target plus RRSIG and referral glue plus DS proof.
- [x] ZoneImage wire-name compression emits an exact full-name suffix pointer
  immediately, avoiding label parsing and temporary suffix-offset collection for
  same-owner answer names that already match the registered question suffix.
- [x] Packet composer section-count reads use the same infallible private-plan
  accounting path instead of converting a never-failing count into `Option`
  before writing the DNS header.
- [x] Truncated-response scratch sections are pre-sized from immutable plan
  record counts before visiting wire records, avoiding incremental `Vec`
  growth on UDP ceiling and EDE retry paths.
- [x] NSEC covering proof selection compares query labels directly against
  precomputed canonical-order range keys, avoiding a query-time canonical-key
  allocation for signed negative proof lookup.
- [x] NSEC3 proof hashing feeds SHA-1 directly from `DomainName` labels instead
  of allocating a temporary canonical wire name before the per-parameter hash
  cache lookup.
- [x] NSEC3 proof range scans borrow the cached query hash by cache index
  instead of cloning the cached hash string for each matching parameter set.
- [x] NSEC3 proof range scans compare raw SHA-1 hash bytes against compiled
  owner/next hash bytes, avoiding per-query base32 string allocation for the
  signed negative proof lookup path.
- [x] NSEC3 proof range metadata stores SHA-1 owner/next hashes as fixed
  20-byte arrays instead of heap `Vec<u8>` values, and malformed SHA-1-range
  metadata is skipped during image compilation.
- [x] DNSSEC NODATA proof selection trusts the plan-carried no-answer
  precondition and uses the exact query trie node only for exact-name NSEC
  proof lookup instead of repeating requested-type RRset checks or exact-name
  walks during augmentation.
- [x] DNSSEC augmentation computes query exact/closest trie handles once and
  reuses them across NODATA, NXDOMAIN closest-encloser, and wildcard proof
  decisions instead of letting each proof branch repeat its own node walk.
- [x] Referral DNSSEC augmentation walks the original authority section length
  by index instead of cloning authority RRset handles before appending DS, NSEC,
  or NSEC3 proof RRsets.
- [x] DNSSEC wildcard-synthesis detection uses the closest-encloser node and
  wildcard child edge directly instead of rebuilding a wildcard `DomainName` and
  repeating node lookup; NXDOMAIN denial planning also reuses one generated
  wildcard child name across NSEC and NSEC3 proof selection.
- [x] Closest-encloser node discovery walks query labels through the compiled
  trie and tracks the last existing ancestor, avoiding iterative parent-domain
  construction for node-only delegation, DNAME, and wildcard paths.
- [x] Response planning computes exact and closest query trie nodes once and
  reuses those handles across delegation, direct, CNAME, DNAME, NODATA, and
  wildcard branches instead of repeating node walks for the same query.
- [x] Response planning gets exact and closest query trie handles from one
  traversal instead of walking once for exact lookup and again for the closest
  encloser on misses; wildcard DNSSEC detection uses the same combined helper.
- [x] NXDOMAIN signed-denial proof planning rebuilds the closest-encloser proof
  name from the trie node depth and query-label suffix instead of walking
  parent `DomainName` values and repeating node lookups.
- [x] CNAME/DNAME chain loop tracking keeps the common chain state inline with a
  small vector instead of allocating a heap vector for the visited canonical
  owner names.
- [x] Generic response buffers are pre-sized from carried plan wire bounds and
  EDNS option shape for ordinary responses; truncation and EDNS-padding-sensitive
  responses still reserve the UDP ceiling where that avoids retry growth.
- [x] ZoneImage wire-name compression keeps the common response suffix table
  inline instead of allocating a per-response `HashMap`; stored suffix keys use
  inline lowercase wire keys and lookups compare wire suffixes case
  insensitively without allocating.
- [x] Packet response code no longer references the `ZoneImage`
  `LookupResult` materialization APIs; served responses observe plan metrics and
  visit immutable wire records directly.
- [x] Raw RRset wire access and per-section wire append helpers are no longer
  public runtime APIs; only `append_plan_wire` remains as the retained
  prototype benchmark hook for uncompressed immutable wire-emission evidence.
- [x] Generic packet response composition now performs one section-aware
  immutable-record visit for normal responses: it writes a zero-count header,
  encodes records while counting answer/authority/additional sections, patches
  the DNS header counts before EDNS, and carries those counts into the UDP
  truncation retry path.
- [x] The EDE-stripped UDP truncation retry reuses carried immutable-plan
  section counts instead of recounting while rebuilding the same plan without
  the EDE option.
- [x] ZoneImage SERVFAIL fallback responses now use the shared ZoneImage
  DNS-header prefix and EDNS append helpers instead of routing through the old
  `ResourceRecord` response composer. The retained
  `target/zone-image-bench/zone-image-failure-prefix-path.tsv` run passed
  `target/zone-image-bench/zone-image-failure-prefix-path-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.136`, mixed
  wire ratio `0.160`, mixed packet ratio `0.998`, hot packet ratio `1.004`,
  trace packet ratio `1.011`, optioned packet ratio `1.025`, boundary packet
  ratio `1.003`, UDP-ceiling packet ratio `1.012`, delegation/DNAME stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as
  composer-boundary cleanup for the rare ZoneImage failure branch, not as a broad
  packet-path speed win.
- [x] Empty protocol shell responses now take the same shared prefix/EDNS path:
  FORMERR, REFUSED, NOTIMP, NOTIFY acknowledgements, and other no-record
  responses bypass the old `ResourceRecord`/`NameCompressor` composer before
  any record section exists. A focused EDNS NSID empty-response test covers the
  fast path, and the invariant audit rejects routing no-record responses back
  through the old composer. The retained
  `target/zone-image-bench/empty-response-zone-image-prefix.tsv` run passed
  `target/zone-image-bench/empty-response-zone-image-prefix-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.134`,
  mixed packet ratio `0.997`, hot packet ratio `0.944`, trace packet ratio
  `0.985`, optioned packet ratio `1.008`, boundary packet ratio `1.065`,
  UDP-ceiling packet ratio `1.025`, delegation/DNAME stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as protocol-shell
  composer-boundary cleanup before transport work.
- [x] Uncompressed plan-wire append helpers trust carried immutable-plan record
  counts instead of recounting each appended RRset, selected record, and
  dynamic record while writing the already planned sections.
- [x] DNSSEC NODATA augmentation now trusts lookup planning's no-answer
  classification and no longer accepts `qtype` or repeats an exact-qtype RRset
  lookup before appending exact-name NSEC proof records. The retained
  `target/zone-image-bench/dnssec-nodata-plan-precondition.tsv` run passed
  `target/zone-image-bench/dnssec-nodata-plan-precondition-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.138`, mixed
  wire ratio `0.157`, mixed packet ratio `0.972`, hot packet ratio `0.943`,
  trace packet ratio `0.993`, optioned packet ratio `0.980`, boundary packet
  ratio `1.009`, UDP-ceiling packet ratio `1.013`, delegation/DNAME stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as a
  narrow signed-denial planning/API cleanup, not as broad packet-path speed
  evidence.
- [x] Focused tests cover wildcard owner overrides, additional-data discovery,
  wire-record visitation from handles, and plan wire-bound accounting.
- [~] The full response composer is not yet a pure immutable template/WireArena
  pipeline.
- [x] Public `ZoneImage` `LookupResult`/`ResourceRecord` materialization helpers
  were removed; tests and benchmarks compare plan summaries or immutable wire
  output instead.
- [x] Public `ZoneImage` wire helper surface is narrowed: raw RRset wire access
  is test-only, per-section append helpers are private, section-count
  accounting helpers are not public runtime APIs, and the invariant audit keeps
  `append_plan_wire` as the only public benchmark wire-append hook.
- [x] The invariant audit now also requires raw RRset wire helpers and the
  direct wire-bound helper to stay behind `#[cfg(test)]`, so benchmark-only and
  unit-test inspection surfaces cannot drift back into the normal runtime
  build. The retained
  `target/zone-image-bench/zone-image-test-only-wire-helper-audit.tsv` checker
  passed at
  `target/zone-image-bench/zone-image-test-only-wire-helper-audit-check.tsv`
  with zero validation/packet mismatches, byte parity, mixed planning ratio
  `0.119`, mixed wire ratio `0.139`, mixed packet ratio `1.017`, hot packet
  ratio `1.031`, trace packet ratio `1.047`, optioned packet ratio `0.974`,
  boundary packet ratio `1.037`, UDP-ceiling packet ratio `1.012`, stress
  planning ratio `0.001`, and stress wire ratio `0.001`. This is retained as
  API-surface hardening evidence, not a packet-path speed claim.
- [x] Stored and synthesized `ZoneImage` records now carry precomputed RDATA
  compression shape for copy, single-name, SOA, and MX RDATA. The runtime
  `ZoneImage` wire-record encoder matches that compact shape instead of
  reparsing wire-name lengths for every emitted record, and copy-RDATA records
  now write their validated rdlength and bytes directly without entering the
  compressed-RDATA placeholder/patch path. The shape tag is packed into the
  existing `RdataRange` padding so `ImageRecord` remains 8 bytes and the retained
  hot-bytes-per-record gate stays flat. The retained first-step
  `target/zone-image-bench/rdata-encoding-precomputed.tsv` checker passed at
  `target/zone-image-bench/rdata-encoding-precomputed-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.132`, mixed
  wire ratio `0.161`, mixed packet ratio `1.024`, hot packet ratio `1.000`,
  trace packet ratio `1.027`, optioned packet ratio `1.012`, boundary packet
  ratio `1.026`, UDP-ceiling packet ratio `1.000`, stress planning ratio
  `0.001`, and stress wire ratio `0.001`. This is retained as per-record
  composer precompute evidence, not as completion of the immutable
  template/WireArena path.
  The follow-up `target/zone-image-bench/rdata-copy-fast-path.tsv` checker passed
  at `target/zone-image-bench/rdata-copy-fast-path-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.120`, mixed
  wire ratio `0.140`, mixed packet ratio `0.991`, hot packet ratio `1.018`,
  trace packet ratio `0.966`, optioned packet ratio `1.038`, boundary packet
  ratio `0.981`, UDP-ceiling packet ratio `0.945`, stress planning ratio
  `0.001`, and stress wire ratio `0.001`.
  The later `target/zone-image-bench/wire-record-rdlength-bytes.tsv` carries
  those prevalidated RDATA length bytes through the generic
  `ZoneImageWireRecord` view, so copy-RDATA packet encoding writes the compiled
  bytes instead of deriving them from the runtime slice length. Focused RDATA
  encoder tests, filtered ZoneImage tests, invariant audit, and check build
  passed. The checker passed at
  `target/zone-image-bench/wire-record-rdlength-bytes-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.128`, mixed
  wire ratio `0.154`, mixed packet ratio `0.980`, hot packet ratio `0.968`,
  trace packet ratio `0.981`, optioned packet ratio `0.970`, boundary packet
  ratio `0.981`, UDP-ceiling packet ratio `0.950`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as generic copy-RDATA composer precompute evidence,
  not as completion of the full immutable template/WireArena path.
  The later `target/zone-image-bench/packed-rdata-direct-enum.tsv` collapses
  the packed RDATA shape tag and decoded composer enum into one compact
  `PackedRdataEncoding` value. Runtime packet composition now matches the
  precomputed shape directly, while the size guard keeps the tag at two bytes
  and preserves `ImageRecord`/`RdataRange` size. The checker passed at
  `target/zone-image-bench/packed-rdata-direct-enum-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.138`,
  mixed wire ratio `0.161`, mixed packet ratio `1.007`, hot packet ratio
  `1.131`, trace packet ratio `1.051`, optioned packet ratio `1.077`,
  boundary packet ratio `1.018`, UDP-ceiling packet ratio `1.011`, main bytes
  per record `174.000`, and stress bytes per record `254.000`. This is retained
  as representation cleanup and duplicate-branch removal, not as a broad
  throughput claim.
  The follow-up `target/zone-image-bench/soa-rdata-validated-span.tsv` removes
  the remaining defensive second-name span recomputation from SOA RDATA
  compression. The compiler still validates the SOA shape before storing the
  packed SOA encoding, while packet emission derives the RNAME span directly
  from the carried MNAME length and RDATA length with debug assertions for the
  invariant. The checker passed at
  `target/zone-image-bench/soa-rdata-validated-span-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.156`,
  mixed wire ratio `0.180`, mixed packet ratio `1.043`, hot packet ratio
  `1.053`, trace packet ratio `1.000`, optioned packet ratio `1.005`,
  boundary packet ratio `1.023`, UDP-ceiling packet ratio `1.022`, main bytes
  per record `174.000`, and stress bytes per record `254.000`. This is retained
  as SOA compressed-RDATA invariant cleanup, not as a packet-speed claim.
  The retained `target/zone-image-bench/soa-rdata-packed-spans.tsv` follow-up
  packs both validated SOA wire-name spans into the same two-byte
  `PackedRdataEncoding` value, so the runtime SOA branch slices MNAME, RNAME,
  and timers without recomputing the second-name span from RDATA length. Focused
  encoding and layout tests cover the packed spans and two-byte size guard, and
  the invariant audit rejects returning to query-time SOA span recomputation.
  The checker passed at
  `target/zone-image-bench/soa-rdata-packed-spans-check.tsv` with zero
  validation/packet mismatches, byte parity, main image bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.149`,
  mixed wire ratio `0.172`, mixed packet ratio `1.015`, hot packet ratio
  `1.119`, trace packet ratio `1.003`, optioned packet ratio `1.000`,
  boundary packet ratio `1.006`, UDP-ceiling packet ratio `1.003`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`. This
  is retained as compact SOA precompute cleanup, not as a throughput claim.
- [x] Add retained metadata owner/SOA wire no-parse evidence:
  `target/zone-image-bench/metadata-wire-no-parse.tsv` reuses the direct
  uncompressed-owner-wire canonical-key helper for plan-summary validation and
  extracts SOA minimum TTL from validated wire-name spans during image
  compilation instead of reparsing those names into `DomainName` values.
  Focused tests cover mixed-case owner-key lowering plus compressed/trailing
  owner-wire rejection, and SOA minimum extraction with compressed/trailing
  RDATA rejection. The checker passed at
  `target/zone-image-bench/metadata-wire-no-parse-check.tsv` with zero
  validation/packet mismatches, byte parity, image bytes per record `174.000`,
  stress bytes per record `256.000`, mixed planning ratio `0.143`, mixed wire
  ratio `0.165`, mixed packet ratio `1.041`, hot packet ratio `0.854`, trace
  packet ratio `1.000`, optioned packet ratio `1.051`, boundary packet ratio
  `1.040`, UDP-ceiling packet ratio `0.990`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as metadata
  and validation-path hygiene, not as a packet-path win.
- [x] Add retained synthesized-record inline-wire evidence:
  `target/zone-image-bench/synthesized-inline-wire.tsv` stores synthesized
  owner and RDATA wire in inline buffers for common DNAME-generated CNAME
  records. The focused CNAME/DNAME target test asserts the retained DNAME case
  does not spill either generated wire buffer, and the invariant audit rejects
  returning those fields to heap `Vec` storage. The checker passed at
  `target/zone-image-bench/synthesized-inline-wire-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.148`,
  mixed wire ratio `0.169`, mixed packet ratio `1.006`, hot packet ratio
  `0.965`, trace packet ratio `0.988`, optioned packet ratio `0.977`,
  boundary packet ratio `1.007`, UDP-ceiling packet ratio `0.969`, stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as
  generated-record allocation/layout cleanup, not as a broad packet-path win.
- [x] Add retained CNAME/DNAME target-wire loop-check evidence:
  `target/zone-image-bench/indirection-target-wire-loop-check.tsv` passes
  compiled single-name target wire and DNAME synthesized-answer RDATA wire into
  loop detection, so fallback loop checks compare target wire directly to the
  original query labels instead of carrying a second `DomainName` label-vector
  comparison helper. Existing in-zone targets still use compiled node-handle
  equality. Focused CNAME/DNAME loop tests and the invariant audit passed, and
  the checker passed at
  `target/zone-image-bench/indirection-target-wire-loop-check-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.147`,
  mixed wire ratio `0.169`, mixed packet ratio `1.018`, hot packet ratio
  `1.024`, trace packet ratio `0.974`, optioned packet ratio `0.938`,
  boundary packet ratio `1.010`, UDP-ceiling packet ratio `1.020`, and
  delegation/DNAME-stress planning and wire ratios of `0.001`.
- [x] Add retained generic wire-record fixed-field carry-through:
  `target/zone-image-bench/wire-record-fixed-fields.tsv` carries prepared
  TYPE/CLASS/TTL bytes through `ZoneImageWireRecord`, so the generic packet
  encoder writes those bytes without rebuilding scalar network-order fields.
  Stored RRsets reuse the already-existing immutable RRset wire arena for those
  bytes, keeping `ImageRrset` at 44 bytes and preserving the retained hot-layout
  budget; generated records store their fixed bytes when synthesized. Focused
  RDATA/fixed-field tests, filtered ZoneImage tests, invariant audit, and check
  build passed. The checker passed at
  `target/zone-image-bench/wire-record-fixed-fields-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.147`,
  mixed wire ratio `0.167`, mixed packet ratio `1.024`, hot packet ratio
  `0.919`, trace packet ratio `0.965`, optioned packet ratio `0.951`, boundary
  packet ratio `1.014`, UDP-ceiling packet ratio `0.993`, stress planning ratio
  `0.001`, and stress wire ratio `0.001`. This is retained as bounded generic
  composer byte-assembly cleanup, not as broad packet-speed evidence.
- [x] Add retained duplicate RR-type removal from generic wire records:
  `target/zone-image-bench/wire-record-fixed-fields-no-rrtype.tsv` removes the
  separate scalar RR type from `ZoneImageWireRecord`; DNSSEC classification and
  truncation's non-SOA authority decision now derive the type from the carried
  fixed TYPE/CLASS/TTL bytes. This avoids keeping two RR-type sources in the
  transient record view while preserving the existing persistent image layout.
  Focused DNSSEC/wire-record tests, selected-record tests, invariant audit, and
  check build passed. The checker passed at
  `target/zone-image-bench/wire-record-fixed-fields-no-rrtype-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.140`,
  mixed wire ratio `0.161`, mixed packet ratio `0.980`, hot packet ratio
  `0.940`, trace packet ratio `0.967`, optioned packet ratio `0.952`, boundary
  packet ratio `1.018`, UDP-ceiling packet ratio `0.992`, stress planning ratio
  `0.001`, and stress wire ratio `0.001`.
- [x] Add retained packed RDATA wire-record carry-through:
  `target/zone-image-bench/wire-record-packed-rdata.tsv` keeps the compact
  `PackedRdataEncoding` shape in `ZoneImageWireRecord` and synthesized records,
  so stored RRset visits no longer expand the RDATA compression mode before the
  packet composer reaches the copy fast path. Focused RDATA/wire-record tests
  and the invariant audit passed. The checker passed at
  `target/zone-image-bench/wire-record-packed-rdata-check.tsv` with zero
  validation/packet mismatches, byte parity, `ZoneImageWireRecord` size 48
  bytes, main image bytes/record `170`, stress image bytes/record `250`, mixed
  planning ratio `0.131`, mixed wire ratio `0.159`, mixed packet ratio `0.983`,
  hot packet ratio `1.033`, trace packet ratio `1.004`, optioned packet ratio
  `0.978`, boundary packet ratio `1.010`, UDP-ceiling packet ratio `0.992`,
  stress planning ratio `0.001`, and stress wire ratio `0.002`.
- [x] Add retained synthesized-record fixed-field type discipline:
  `target/zone-image-bench/synthesized-fixed-fields-no-rrtype.tsv` removes the
  duplicated scalar RR type from `ZoneImageSynthesizedRecord`; synthesized
  DNAME/CNAME dynamic records now rely on the same precomputed TYPE/CLASS/TTL
  fixed bytes that the wire-record encoder already consumes. Focused
  synthesized-record and layout tests plus the invariant audit passed. The
  checker passed at
  `target/zone-image-bench/synthesized-fixed-fields-no-rrtype-check.tsv` with
  zero validation/packet mismatches, byte parity, main image bytes/record `170`,
  stress image bytes/record `250`, mixed planning ratio `0.140`, mixed wire
  ratio `0.172`, mixed packet ratio `1.031`, hot packet ratio `1.062`, trace
  packet ratio `1.038`, optioned packet ratio `1.052`, boundary packet ratio
  `1.014`, UDP-ceiling packet ratio `1.008`, stress planning ratio `0.001`,
  and stress wire ratio `0.002`.
- [x] Add retained synthesized RDATA encoding prevalidation:
  `target/zone-image-bench/synthesized-rdata-encoding-prevalidated.tsv` makes
  DNAME-generated CNAME answers pass the already-known single-name RDATA
  encoding into `ZoneImageSynthesizedRecord` instead of reparsing the generated
  target wire when the dynamic record is pushed into the plan. The focused
  CNAME/DNAME target test asserts the generated record carries
  `PackedRdataEncoding::single_name()`, and the invariant audit rejects
  reintroducing synthesized-record `zone_image_rdata_encoding()` calls. The
  checker passed at
  `target/zone-image-bench/synthesized-rdata-encoding-prevalidated-check.tsv`
  with zero validation/packet mismatches, byte parity, hot bytes per record
  `106.359`, total bytes per record `174.000`, delegation/DNAME stress bytes
  per record `256.000`, mixed planning ratio `0.153`, mixed wire ratio
  `0.176`, mixed packet ratio `1.015`, hot packet ratio `0.927`, trace packet
  ratio `1.039`, optioned packet ratio `1.052`, boundary packet ratio `1.001`,
  UDP-ceiling packet ratio `1.006`, delegation/DNAME stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as synthesized
  composer discipline, not a broad packet-speed claim.
- [x] Add retained compiled RRset fixed-field metadata:
  `target/zone-image-bench/compiled-rrset-fixed-fields.tsv` moves normal
  TYPE/CLASS/TTL bytes into `ImageRrset` and stores negative-response SOA TTL
  bytes beside them. Direct prefixes, selected DNSSEC records, stored-record
  visits, and SOA negative authority emission now consume compiled fixed bytes
  instead of slicing immutable RRset wire or rebuilding TTL bytes from scalar
  fields on the composer path. The first full negative-field version exceeded
  the stress bytes/record gate, so the retained layout stores only the negative
  TTL bytes and keeps `ImageRrset` bounded at 48 bytes. Focused ZoneImage tests
  and invariant audit passed. The checker passed at
  `target/zone-image-bench/compiled-rrset-fixed-fields-check.tsv` with zero
  validation/packet mismatches, byte parity, main image bytes/record `174`,
  stress image bytes/record `254`, mixed planning ratio `0.130`, mixed wire
  ratio `0.157`, mixed packet ratio `0.962`, hot packet ratio `0.920`, trace
  packet ratio `0.992`, optioned packet ratio `1.086`, boundary packet ratio
  `1.032`, UDP-ceiling packet ratio `1.007`, stress planning ratio `0.001`,
  and stress wire ratio `0.001`.
- [x] Add retained DNAME synthesized-CNAME fixed-field reuse:
  `target/zone-image-bench/dname-synthesized-cname-fixed-fields.tsv` makes
  DNAME-generated CNAME answers reuse the compiled DNAME RRset fixed
  TYPE/CLASS/TTL bytes with only the TYPE bytes changed to CNAME, instead of
  decoding TTL from fixed bytes and rebuilding the generated record fields from
  scalar metadata. A variant that stored those generated CNAME fixed fields in
  every single-name target was measured but narrowed because it landed exactly
  on the stress bytes/record ceiling. The retained version has no image-memory
  growth versus `compiled-rrset-fixed-fields`. Focused ZoneImage tests and
  invariant audit passed. The checker passed at
  `target/zone-image-bench/dname-synthesized-cname-fixed-fields-check.tsv`
  with zero validation/packet mismatches, byte parity, main image bytes/record
  `174`, stress image bytes/record `254`, mixed planning ratio `0.162`, mixed
  wire ratio `0.177`, mixed packet ratio `0.996`, hot packet ratio `1.135`,
  trace packet ratio `0.977`, optioned packet ratio `1.005`, boundary packet
  ratio `1.027`, UDP-ceiling packet ratio `1.010`, stress planning ratio
  `0.002`, and stress wire ratio `0.002`.
- [x] Precompute negative SOA variants for the `ZoneImage` composer.
- [x] Negative-response SOA selection reads the apex trie node directly instead
  of resolving the origin name through the trie for each NODATA/NXDOMAIN
  authority plan.
- [x] Add focused bounds tests for plan wire upper-bound accounting.
- [x] Run a direct-answer response-template cache experiment; rejected for now
  because local Vec/socket-path evidence showed more memory and no packet-path
  win. Revisit when io_uring fixed buffers or AF_XDP UMEM can transmit from
  reusable templates without copying.
- [x] Run a direct-answer compiled-record-view experiment; rejected for now
  because rebuilding record headers from compiled record metadata was slower
  than copying the prebuilt RRset wire body after the owner name. The retained
  rejected run at
  `target/zone-image-bench/direct-answer-compiled-record-view.tsv` preserved
  zero validation mismatches and passed
  `target/zone-image-bench/direct-answer-compiled-record-view-check.tsv`, but
  regressed hot packet serving to about 188 ns/query and mixed packet serving
  to about 549 ns/query on this local profile.
- [x] Run a direct-answer rrset wire-part view experiment; rejected for now
  because grouping RRset type, owner wire, and prebuilt wire into an internal
  view did not improve the local packet path. The retained rejected run at
  `target/zone-image-bench/rrset-wire-parts-direct-view.tsv` preserved zero
  validation mismatches and passed
  `target/zone-image-bench/rrset-wire-parts-direct-view-check.tsv`, but
  regressed hot packet serving to about 187 ns/query and mixed packet serving
  to about 559 ns/query versus the prior retained direct-count baseline.
- [x] Run a combined plan-count/wire-bound summary experiment; rejected for now
  because the broader summary made count-only planning heavier and the
  packet-only variant still did not beat the retained direct-count baseline.
  The retained rejected runs at
  `target/zone-image-bench/combined-plan-wire-summary.tsv` and
  `target/zone-image-bench/packet-combined-wire-summary.tsv` preserved zero
  validation mismatches and passed
  `target/zone-image-bench/combined-plan-wire-summary-check.tsv` and
  `target/zone-image-bench/packet-combined-wire-summary-check.tsv`.
- [x] Add composer fuzz and bounds tests targeted at the current WireArena
  writer surface: malformed wire-name helper bounds, malformed known-name RDATA
  opaque fallback, packet differential coverage, and the `zone_image_datagram`
  fuzz target.
- [x] Measure an inline small-buffer experiment for synthesized owner/RDATA
  storage. Rejected for now: local `profiling` evidence regressed mixed packet
  response from about 870 ns/query to about 934 ns/query after the
  precomputed-additional change.

## Phase 5: DNSSEC Denial And Signed Zones

- [x] DNSSEC-sensitive query shapes are packet-differential tested against the
  current path before serving through `ZoneImage`.
- [x] Tests cover served DO positive signing, NSEC proof selection, NSEC3
  cap/EDE, referral proofs, wildcard proofs, and boundary cases.
- [x] Add RRSIG covered-type indexes to `ZoneImage`.
- [x] RRSIG augmentation uses compile-time precomputed per-RRset relation spans,
  avoiding query-time scans of the RRSIG covered-type index and query-time
  RRSIG type-covered parsing for selected signatures.
- [x] Selected RRSIG records are kept as immutable `ZoneImage` record references
  in lookup plans instead of being copied into per-query synthesized record
  buffers; synthesized and selected records share the same per-section dynamic
  record buckets so unsigned hot-path plans do not carry separate selected
  record vectors.
- [x] Add NSEC indexes to `ZoneImage`.
- [x] NSEC covering-proof lookup uses precomputed owner/next canonical range
  keys instead of reparsing NSEC owner and next-owner names for every denial
  query.
- [x] NSEC owner/next canonical range keys are stored as compact lowercase
  arena byte ranges, so proof lookup no longer follows per-label heap vectors
  while scanning candidates.
- [x] Add NSEC3 indexes to `ZoneImage`.
- [x] Implement bounded dynamic NSEC3 work in the `ZoneImage` path.
- [x] NSEC3 hashing builds canonical owner wire directly from `DomainName`
  labels, avoiding a canonical-string/reparse/serialize round trip while
  preserving lowercase DNSSEC hashing input.
- [x] NSEC3 denial lookup caches hashes per unique NSEC3 parameter set within a
  query, avoiding repeated hash work when multiple candidate RRsets share the
  same algorithm, iteration count, and salt.
- [x] NSEC3 proof candidate metadata stores parsed parameters and owner/next
  hash labels in the compiled image, so denial lookup no longer reparses NSEC3
  owner names or RDATA while scanning candidates.
- [x] NSEC3 proof candidate metadata stores decoded owner/next hash bytes, so
  query-time NSEC3 hashing compares fixed SHA-1 bytes instead of allocating and
  comparing base32 hash strings.
- [x] NSEC3 proof candidate metadata stores those decoded hashes inline as
  fixed SHA-1 arrays; the local NSEC3 fixtures now use valid 20-byte next-hash
  values instead of one-byte placeholders.
- [x] NSEC3 proof candidate metadata interns shared algorithm/iteration/salt
  parameter sets, stores compact `u16` parameter-set handles in each range, and
  keys query hash-cache entries by that handle instead of comparing salt bytes
  while scanning candidates. The full parameter view is materialized only on
  hash-cache misses from the already-loaded range-loop descriptor.
- [x] Add packet-level signed-zone differential corpus for `ZoneImage`.
- [x] Prototype benchmark boundary coverage now includes real signed positive
  and signed NODATA DO packet cases with RRSIG/NSEC data in the fixture. The
  retained local artifact
  `target/zone-image-bench/signed-boundary-packet-coverage.tsv` reports zero
  boundary validation mismatches and passed the prototype benchmark checker.
- [x] DNSSEC-capable `ZoneImage` serving is enabled by default; internal
  plan/build failures now return ZoneImage SERVFAIL instead of using old-path
  rollback.

## Phase 6: Runtime Integration And Promotion

- [x] Runtime compiles and publishes `ZoneImage` with each active zone snapshot.
- [x] Query serving reuses the `ZoneImage` from the `ArcSwap`-published
  `PublishedZone` handle instead of a query-time shadow `Mutex<HashMap>` image
  cache or second store lookup.
- [x] `ZoneStore` selects published zones through a suffix index instead of
  scanning all configured zones on each query.
- [x] Offline validation can compare `ZoneImage` and current snapshot answers.
- [x] Serving path records hits, direct hits, semantic hits, failures, and fixed
  failure reasons.
- [x] Failure counters include fixed reasons for ordering old-path retirement.
- [x] The stale observer-unsupported fallback bucket is removed; plan
  observation is infallible on the ZoneImage serving path.
- [x] The unavailable-image fallback bucket is removed; enabled serving uses the
  compiled image attached to the active published zone.
- [x] Default ZoneImage serving checks published zone state directly and no
  longer clones `ZoneSnapshot` or calls `oracle_lookup_with_options` in packet
  serving.
- [x] Core serving APIs removed the explicitly named snapshot-rollback path; the
  runtime packet responder has no old-layout serving selector.
- [x] The remaining snapshot response composer was removed from packet-serving
  code; offline old/new comparison uses explicit benchmark helpers instead.
- [x] Core `answer_datagram`/`answer_message` convenience APIs enter
  required-provider `ZoneImage` serving by default; materialized `LookupResult`
  callbacks are no longer part of packet answering.
- [x] Snapshot-rollback serving APIs were removed instead of retained as hidden
  generated-documentation exceptions.
- [x] Runtime query metric observation records zone origin/state through the
  published-zone handle and no longer clones `ZoneSnapshot` on the default
  observation path.
- [x] Query-suffix zone lookup no longer exposes `Arc<ZoneSnapshot>` or a
  snapshot-to-image bridge; callers use `PublishedZone`, while exact-origin
  snapshots remain for transfer/catalog builder work.
- [x] Exact snapshot accessors are documented as management, transfer, catalog,
  and offline-comparison APIs; query serving is directed to `PublishedZone` and
  the published `ZoneImage`.
- [x] `scripts/audit-invariants.sh` now checks that non-test runtime source
  outside `ZoneSnapshot` itself contains no `.offline_oracle()` or direct
  `.oracle_lookup` calls, while transfer ingestion still produces
  `ZoneSnapshot` builder state for publication into `ZoneImage`.
- [x] The invariant audit also requires the remaining old snapshot query
  functions to stay behind the explicit `#[doc(hidden)]`
  `ZoneSnapshot::offline_oracle()` handle and rejects restoring direct public
  `ZoneSnapshot::oracle_lookup` methods, so they cannot drift back into ordinary
  serving API surface without tripping the boundary check.
- [x] `PublishedZone` no longer exposes generic or rollback/oracle snapshot
  accessors.
- [x] The broad stringly `ZoneStore::get` snapshot accessor was removed. The
  later broad `find_exact_snapshot_for_control` accessor was also removed;
  exact snapshot access now goes through `exact_snapshot_for_transfer(&DomainName)`,
  which returns the old snapshot together with cached control metadata for IXFR
  transfer work. Presence-only NOTIFY and catalog-member decisions use
  `contains_exact_zone_for_control` so they do not clone the old snapshot layout
  just to test membership.
- [x] The remaining exact-origin snapshot accessor is explicitly transfer-named,
  and the invariant audit rejects restoring generic `find_exact_zone` or
  `find_exact_snapshot_for_control` surfaces. This keeps full `ZoneSnapshot`
  access labeled as transfer builder state rather than query-serving data-plane
  state.
- [x] The transfer snapshot handle no longer implements `Deref<Target =
  ZoneSnapshot>`, and its old-layout fields are private. Callers must choose
  cached `TransferZoneSnapshot::metadata()` or
  `TransferZoneSnapshot::into_metadata()` for scalar/control decisions, or
  `TransferZoneSnapshot::snapshot_for_transfer()` for the narrow
  transfer/oracle work that still genuinely needs the old builder layout. The
  invariant audit rejects restoring an implicit deref or public snapshot fields
  on transfer views.
  The retained `target/zone-image-bench/transfer-snapshot-explicit-accessors.tsv`
  artifact passed its checker at
  `target/zone-image-bench/transfer-snapshot-explicit-accessors-check.tsv` with
  `100000` serial-bearing transfer views, `100000` no-serial skips, serial
  checksum `50000000`, control-metadata ratio `0.748`, explicit transfer-view
  ratio `1.351`, zero validation/packet mismatches, mixed plan ratio `0.133`,
  mixed packet ratio `0.993`, hot packet ratio `1.062`, trace packet ratio
  `1.022`, boundary packet ratio `0.990`, and UDP-ceiling packet ratio `0.996`.
  This is transfer-view API-boundary evidence, not packet hot-path throughput
  evidence.
- [x] IXFR current-zone lookup now uses the serial-gated
  `exact_snapshot_with_serial_for_transfer()` view. The cached entry serial is
  checked before exposing the old snapshot handle, so no-serial zones do not
  take the broader transfer snapshot path just to discover that IXFR cannot be
  seeded.
  The retained `target/zone-image-bench/ixfr-serial-gated-transfer-view.tsv`
  artifact passed its checker at
  `target/zone-image-bench/ixfr-serial-gated-transfer-view-check.tsv` with
  `100000` serial-bearing transfer views, `100000` no-serial skips, serial
  checksum `50000000`, control-metadata ratio `0.775`, serial-gated transfer
  view ratio `1.527`, zero validation/packet mismatches, two EDE fallback
  cases, mixed plan ratio `0.146`, mixed packet ratio `1.002`, hot packet ratio
  `0.976`, trace packet ratio `0.981`, boundary packet ratio `1.008`, and
  UDP-ceiling packet ratio `0.988`. This is transfer-control API-boundary
  evidence, not packet hot-path throughput evidence.
- [x] Refresh scheduler success recording is metadata-fed, including test
  helpers and metrics fixtures. The invariant audit rejects helper signatures
  that accept `&ZoneSnapshot` for refresh-success state and rejects metrics
  fixtures that seed scheduler state through `exact_snapshot_for_transfer()`.
  This keeps scheduler/control state on cached `ZoneMetadata` instead of hiding
  old-layout field reads behind test-only convenience APIs.
  Focused ZoneStore and ZoneImage tests passed, and the retained
  `target/zone-image-bench/exact-snapshot-control-accessor.tsv` checker passed
  at `target/zone-image-bench/exact-snapshot-control-accessor-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.120`,
  mixed wire ratio `0.148`, mixed packet ratio `0.991`, hot packet ratio
  `1.011`, trace packet ratio `0.993`, optioned packet ratio `1.009`,
  boundary packet ratio `1.028`, UDP-ceiling packet ratio `1.005`, stress
  planning ratio `0.001`, and stress wire ratio `0.001`. This is retained as
  API-boundary cleanup; the packet timings are unchanged local-gate evidence,
  not a packet-path speed claim.
- [x] The explicit offline-oracle snapshot iterator now sorts directory entries
  by cached origin key before cloning `Arc<ZoneSnapshot>` handles, instead of
  cloning snapshots and rebuilding `snapshot.origin.canonical_key()` for sort
  keys. The invariant audit rejects canonical-key rebuilds inside
  `offline_snapshots()`. The retained
  `target/zone-image-bench/offline-snapshots-cached-origin-sort.tsv` checker
  passed at
  `target/zone-image-bench/offline-snapshots-cached-origin-sort-check.tsv` with
  matching cached/rebuilt snapshot counts `512000`, matching serial checksums,
  cached-sort ratio `0.379`, mixed packet ratio `1.036`, and UDP-ceiling packet
  ratio `0.986`.
- [x] The exact-origin presence probe now carries the same control-plane naming:
  `contains_exact_zone_for_control`. The invariant audit rejects restoring the
  old generic `contains_exact_zone` API or runtime call sites, keeping this
  helper scoped to NOTIFY/catalog membership checks rather than query-serving
  lookup. The retained
  `target/zone-image-bench/exact-presence-control-accessor.tsv` checker passed
  at `target/zone-image-bench/exact-presence-control-accessor-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.118`,
  mixed wire ratio `0.142`, mixed packet ratio `1.001`, hot packet ratio
  `1.064`, trace packet ratio `1.038`, optioned packet ratio `1.039`, boundary
  packet ratio `1.015`, UDP-ceiling packet ratio `1.010`, stress planning ratio
  `0.001`, and stress wire ratio `0.001`. This is API-boundary evidence; the
  packet timings remain local parity gates, not a speedup claim.
- [x] Runtime status and metrics iteration no longer clone full snapshots:
  `ZoneStoreEntry` caches active-zone shape summaries at publication time, and
  server status, scheduler, query, shape, and zone-count metrics now read
  `ZoneStore::zone_metadata()` instead of a broad snapshot iterator. The
  metadata view now orders zones by the cached published entry origin key before
  materializing `ZoneMetadata`, avoiding canonical-origin key rebuilds for
  stable status ordering.
- [x] `ZoneMetadata` now carries the cached published origin key through status,
  scheduler, refresh, and query-metric paths. Scheduler status lookup,
  per-zone query counts, and per-zone RCODE metrics use `metadata.origin_key`
  instead of rebuilding `metadata.origin.canonical_key()` for each metric family
  on every scrape. The invariant audit rejects metric loops that rebuild
  canonical keys from `ZoneMetadata`. The retained
  `target/zone-image-bench/zone-metadata-cached-origin-key.tsv` checker passed
  at `target/zone-image-bench/zone-metadata-cached-origin-key-check.tsv` with
  matching cached/rebuilt key counts `200000`, matching key checksums, cached
  origin-key ratio `0.284`, mixed packet ratio `1.031`, and UDP-ceiling packet
  ratio `1.018`.
- [x] `ZoneMetadata` also carries the cached display origin name used by
  status, shape, scheduler, and query metric labels. Those scrape loops now use
  `metadata.origin_name` instead of rebuilding `metadata.origin.to_string()` for
  each metric line. The invariant audit rejects reintroducing display-name
  rebuilds in those metric loops. The retained
  `target/zone-image-bench/zone-metadata-cached-origin-name.tsv` checker passed
  at `target/zone-image-bench/zone-metadata-cached-origin-name-check.tsv` with
  matching cached/rebuilt name counts `200000`, matching name checksums, cached
  origin-name ratio `0.232`, mixed packet ratio `0.984`, and UDP-ceiling packet
  ratio `0.997`.
- [x] Zone count metrics no longer rescan published snapshot states to count
  active zones: the immutable `ZoneDirectory` carries an active-zone count that
  is updated during publish, replace, expire, and removal. Focused state
  transition tests cover active/loading/expired/replaced/removed zones, and the
  retained `target/zone-image-bench/zone-directory-cached-active-count.tsv`
  checker passed at
  `target/zone-image-bench/zone-directory-cached-active-count-check.tsv` with
  matching cached/linear active-count checksums, cached active-count ratio
  `0.025`, suffix lookup ratio `0.016`, byte parity, zero packet mismatches,
  `mixed_packet_ratio` `0.977`, and `udp_ceiling_packet_ratio` `1.005`. This
  is status/metrics old-layout cleanup, not a packet-throughput claim.
- [x] Runtime query observation reuses the published zone's cached canonical
  origin key instead of rebuilding it from the snapshot origin on every
  in-zone query. Focused published-zone and query-metrics tests cover the
  accessor, and the invariant audit rejects reintroducing per-query
  `published_zone.origin().canonical_key()` in the observation path.
- [x] Runtime query observation now also carries the parser-proven lowercase
  QNAME fact into published-zone suffix lookup. The hinted lookup is a
  documented `ZoneStore` API for packet paths that already proved lowercase
  labels, while the ordinary public lookup remains conservative for generic
  callers.
- [x] Published-zone lookup now lets `ZoneDirectory::find_best_match` own hidden
  zone filtering while walking suffix candidates, avoiding a second
  post-match hidden-flag branch before returning `PublishedZone`. Focused
  hidden-zone tests cover exact hidden access and visible-parent fallback, and
  the invariant audit rejects restoring the duplicate branch.
- [x] Query-suffix zone lookup builds common reversed canonical QNAME keys in an
  inline buffer and derives prefix probes from query-label lengths before
  probing the published suffix index. Focused tests cover inline storage for a
  normal multi-label QNAME and most-specific published-zone selection; the
  invariant audit guards the inline lookup-buffer alias and prefix-probe shape.
- [x] Query-suffix zone lookup now keeps the reversed canonical QNAME key itself
  in `SmallVec<[u8; 128]>`, while stored published directory keys remain
  `Vec<u8>` for the HashMap layout. Focused suffix-key tests passed, and the
  retained `target/zone-image-bench/zone-directory-inline-reverse-key.tsv`
  checker passed at
  `target/zone-image-bench/zone-directory-inline-reverse-key-check.tsv` with
  zero validation/packet mismatches, byte parity, suffix lookup ratio `0.017`
  against linear lookup, mixed packet ratio `1.024`, hot packet ratio `1.074`,
  trace packet ratio `1.034`, optioned packet ratio `1.047`, boundary packet
  ratio `0.992`, and UDP-ceiling packet ratio `1.000`. This is retained as
  allocation-discipline evidence for the runtime zone-selection boundary, not
  as an isolated suffix-lookup speed claim.
- [x] Transfer control now uses exact metadata for serial/state/timer decisions:
  NOTIFY current-serial checks, refresh failure scheduling, and loading-warning
  state checks read `ZoneStore::exact_zone_control_metadata()` instead of
  cloning a full `Arc<ZoneSnapshot>` or status-only shape histograms. Full exact
  status metadata remains available for status/metrics, and full exact snapshot
  access remains only where transfer comparison or catalog/offline tests need
  record data.
- [x] Add retained narrow control-metadata evidence:
  `target/zone-image-bench/zone-control-metadata-no-shape-clone.tsv` adds a
  retained full-status-metadata versus control-metadata benchmark. The control
  accessor preserves exact-origin found count and serial checksums while
  returning zero shape summaries/histograms for refresh/NOTIFY/loading control
  paths. The checker passed at
  `target/zone-image-bench/zone-control-metadata-no-shape-clone-check.tsv` with
  full/control found counts `200000`, matching serial checksums `100100000`,
  full shape count `200000`, control shape count `0`, control/full metadata
  ratio `0.726`, zero packet mismatches, mixed planning ratio `0.139`, mixed
  packet ratio `1.039`, and UDP-ceiling packet ratio `1.001`. This is retained
  as old-layout boundary cleanup, not as a packet-throughput claim.
- [x] Current/unchanged refresh outcomes carry `ZoneMetadata` instead of
  `Arc<ZoneSnapshot>`. Serial-hint, SOA-poll, and IXFR-current outcomes record
  scheduler state through narrow metadata; owned `ZoneSnapshot` outcomes remain
  reserved for newly transferred AXFR/IXFR builder state and catalog updates.
- [x] IXFR-current transfer access now uses a transfer-specific exact snapshot
  view that carries cached control metadata from the same directory entry. IXFR
  still borrows the current snapshot where RFC 1995 delta comparison needs the
  old builder/oracle layout, but unchanged IXFR outcomes no longer rebuild
  `ZoneMetadata` from that snapshot before returning. Focused store coverage
  verifies the view keeps shape data out of control metadata, and the invariant
  audit rejects falling back to rebuilt snapshot metadata for IXFR-current
  success.
- [x] Refresh success handling consumes outcomes into one narrow metadata value
  plus an updated-only snapshot handle. Current serial-hint and SOA-poll paths
  now consume the already-loaded control metadata when returning current, and
  test helpers now return carried `ZoneMetadata` rather than cloning successful
  outcomes back into owned `ZoneSnapshot` values. The invariant audit rejects
  restoring a test-only `into_owned` conversion from refresh success to the old
  snapshot layout.
  success handling no longer clones current metadata through a borrowed
  accessor or asks for updated snapshots through a second method. The invariant
  audit rejects restoring `success.metadata()`, `success.updated_snapshot()`,
  `current_metadata.clone()`, or the test-only `into_owned` snapshot conversion
  in the refresh path. The older retained
  `target/zone-image-bench/refresh-success-consumed-metadata.tsv` follow-up
  captured the consume-path cleanup, but it predates the current checker's
  required NOTIFY SOA validation metric. Current-schema retained evidence for
  the transfer cached-metadata boundary is
  `target/zone-image-bench/transfer-snapshot-cached-metadata-view.tsv`.
- [x] NOTIFY SOA answer-owner validation now compares parsed `DomainName`
  labels directly instead of materializing two canonical strings for each SOA
  answer. Focused tests cover exact, mixed-case, compressed-RDATA,
  owner-mismatch, and class-mismatch SOA answers, and the invariant audit
  rejects restoring `canonical_key()` inside `validate_notify_answer_soa`.
  The retained
  `target/zone-image-bench/notify-soa-owner-no-canonical-key.tsv` checker
  passed at
  `target/zone-image-bench/notify-soa-owner-no-canonical-key-check.tsv` with
  exact and mixed-case NoError counts `200000`, zero RCODE checksums, matching
  response bytes, mixed-case/exact validation ratio `0.978`, mixed packet ratio
  `1.010`, and UDP-ceiling packet ratio `0.970`.
- [x] CHAOS TXT classification now matches parsed QNAME labels directly instead
  of materializing a canonical QNAME string for `version.bind`,
  `version.server`, `hostname.bind`, and `id.server`. Focused tests cover
  mixed-case CHAOS version lookup, configured version responses, hostname/NSID
  fallback, nonprintable NSID refusal, unsupported names, and observation
  classification. The invariant audit rejects restoring `canonical_key()` in
  `classify_chaos_query`. The retained
  `target/zone-image-bench/chaos-classification-no-canonical-key.tsv` checker
  passed at
  `target/zone-image-bench/chaos-classification-no-canonical-key-check.tsv`
  with exact and mixed-case NoError counts `200000`, zero RCODE checksums,
  matching response bytes, mixed-case/exact classification ratio `1.017`, mixed
  packet ratio `0.991`, and UDP-ceiling packet ratio `1.006`.
- [x] Answered CHAOS TXT responses now also avoid the old `ResourceRecord`
  composer: the response path writes the single TXT answer directly from the
  parsed question name and configured value, uses a question-name compression
  pointer for the owner, and still uses the shared prefix/capacity/EDNS helpers.
  Focused tests cover the direct owner pointer and EDNS NSID emission, and the
  invariant audit rejects restoring `ResourceRecord`/TXT-RDATA materialization
  for answered CHAOS TXT. The retained
  `target/zone-image-bench/chaos-txt-direct-response.tsv` checker passed at
  `target/zone-image-bench/chaos-txt-direct-response-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed-case/exact CHAOS
  classification ratio `0.945`, mixed planning ratio `0.146`, mixed packet
  ratio `1.057`, hot packet ratio `1.191`, trace packet ratio `1.101`,
  optioned packet ratio `1.149`, boundary packet ratio `1.034`, UDP-ceiling
  packet ratio `1.012`, delegation/DNAME stress planning ratio `0.001`, and
  stress wire ratio `0.002`. This is retained as narrow control-response
  composer cleanup, not as a broad packet-path throughput claim.
- [x] Runtime packet serving observes `ZoneImage` lookup metrics from the plan
  instead of materializing `LookupResult` values for the metrics path.
- [x] The `LookupResult` callback API was removed from packet answering;
  ZoneImage serving is exposed through the non-materializing lookup-metrics
  observer.
- [x] Live shadow diagnostics are retired, so runtime metric observation no
  longer clones snapshots or runs old snapshot lookups as an oracle.
- [x] Runtime serving always enters the `ZoneImage` path for supported query
  shapes.
- [x] Full-ANY response mode serves supported QTYPE ANY traffic through
  `ZoneImage`; non-ANY traffic continues to use `ZoneImage` in that mode.
- [x] UDP truncation for supported `ZoneImage` responses is emitted directly
  from immutable wire records instead of falling back to the snapshot composer.
- [x] Internal ZoneImage plan/DNSSEC-plan/response-build failures no longer
  fall back to the snapshot path; they return SERVFAIL and fixed failure
  metrics.
- [~] The current snapshot path remains only as a hidden benchmark/test
  correctness oracle.
- [x] Make `ZoneImage` default for unsigned supported query traffic.
- [x] Remove the live runtime rollback switch for the old path.
- [ ] Remove hidden oracle reliance for query shapes after equivalent `ZoneImage`
  behavior and evidence exist.
- [ ] Retire `ZoneSnapshot` as the query-time data plane.
- [x] Keep `ZoneSnapshot` or an equivalent safe builder model only for ingestion,
  validation, transfer, catalog reconciliation, and `ZoneImage` compilation.

## Phase 7: Packet I/O And NIC Evidence

- [x] Existing standard socket path continues to work as the baseline.
- [x] Benchmark harness can run local and SSH-client modes.
- [x] Benchmark artifacts retain enough network evidence for physical review.
- [x] Physical preflight rejects same-host SSH clients.
- [x] Implement standard UDP batch adapter.
- [~] Compare standard UDP batch adapter against the current socket path with
  local loopback evidence; a 2026-05-29 smoke improved from 303,943 to 350,738
  responses/s at `udp_batch_size=32` with zero drops/errors. A current-layout
  2026-05-31 trace replay retained
  `target/evidence/udp-batch-loopback-current-1` at 350,726 responses/s and
  `target/evidence/udp-batch-loopback-current-32` at 367,297 responses/s, with
  zero drops/errors, `zone_image_serve_failures=0`, and batch counters showing
  1,104,781 datagrams over 34,530 receive/send batches for batch size 32.
  Physical NIC comparison remains open.
- [x] Add local packet-capture evidence for the standard UDP path:
  `target/evidence/udp-batch-loopback-current-32-pcap-sampled` retains
  `packet-capture/dns-udp.pcapng`, `dns-summary.tsv`, and `dns-sample.tsv` for
  a bounded batch-32 loopback trace replay. The sample captured 128 DNS packets,
  including 64 queries and 64 responses, with zero drops/errors and
  `zone_image_serve_failures=0`. Physical packet-capture evidence remains part
  of the separate non-loopback promotion work.
- [ ] Run separate-client non-loopback physical gate.
- [ ] Run multi-queue NIC profile with CPU/RSS/IRQ affinity recorded.
- [ ] Decide whether io_uring is worth implementing.
- [x] Add server AF_XDP scaffolding behind the UDP backend boundary:
  configuration accepts `limits.udp_backend = "std" | "af_xdp"` plus an
  optional `[xdp]` interface/queue/UMEM/ring/batch/TX-wakeup/zero-copy/mode/
  redirect-object section, and selecting `af_xdp` requires `xdp.interface` and
  `xdp.redirect_object`. The standard UDP listener now runs through a mutable
  private `PacketIo` batch interface. With the feature enabled, the server
  binds an AF_XDP socket, loads the project-built `oxidedns_xdp_redirect`
  object, configures the redirect destination port and XSK map, and attaches in
  the configured XDP mode. The feature-gated helper module has local tests for
  Ethernet/IPv4/UDP DNS payload classification, peer/target metadata
  extraction, fragmented IPv4 rejection, AF_XDP frame target construction,
  response header rewriting, owned-packet response writes with tail resize
  coverage, and UMEM/ring builder preparation against the real `xdp` crate
  APIs. The eBPF object builds locally, and the root-only veth/generic smoke
  passed on 2026-06-01 with evidence retained under
  `target/oxidedns-af-xdp-veth-smoke/`. This is local structure only, not
  physical NIC evidence.
- [x] Add reduced hot-path metrics mode for high-rate packet-path experiments:
  `[metrics].hot_path_detail = "full"` remains the default, while
  `"reduced"` keeps coarse process-wide counters and skips mutex-backed
  per-zone query maps, RCODE maps, query latency histograms, DNS Cookie
  source-prefix maps, and pipeline/cache-planning histograms from the normal
  query path. Local tests cover reduced-mode suppression while preserving full
  metrics behavior. A retained 2026-06-02 local loopback comparison using four
  server threads, four client threads, client window 16, UDP batch size 32, and
  three-second runs measured a two-run average of about 411k responses/s with
  full detail and about 479k responses/s with reduced detail, or about 103k and
  120k responses/s per configured server thread. This is local loopback
  evidence only, not physical NIC evidence.
- [x] Add saturation-only hot-path metrics-off mode for physical UDP profiling:
  `[metrics].hot_path_detail = "off"` suppresses per-query coarse counters as
  well as detailed mutex-backed series so transport and response composition can
  be measured without shared counter contention. It is a benchmark profile only;
  query, RCODE, DNS Cookie, RRL, and per-zone hot-path counters are not
  representative while the profile is active.
- [x] Add standard UDP `SO_REUSEPORT` worker scaffolding:
  `[limits].udp_reuseport_workers` defaults to `1`, preserving the current
  single standard UDP listener per configured address, and values above `1`
  bind multiple same-address standard UDP sockets before privilege drop.
  Local tests cover multi-worker reuseport binding to one effective port. A
  retained 2026-06-02 local loopback comparison with
  reduced hot-path metrics, four server threads, four client threads, client
  window 16, and UDP batch size 32 measured one Tokio worker at about 482k
  responses/s, two four-worker Tokio no-affinity runs at about 951k and 845k
  responses/s, and a four-worker Tokio `0,1,2,3` affinity run at about 782k
  responses/s. Explicit affinity was slower in that local Tokio profile,
  so it remains evidence-gated tuning.
- [x] Add dedicated standard UDP data-plane worker mode:
  `[limits].udp_runtime = "dedicated"` keeps the standard UDP socket backend
  but moves each `SO_REUSEPORT` worker socket onto its own OS thread with a
  private packet loop, bounded inbound/outbound vectors, and optional
  per-worker Linux CPU affinity. On Linux, the dedicated path now uses a
  tightly scoped unsafe `recvmmsg`/`sendmmsg` module with reusable message
  slabs, `MSG_DONTWAIT`, bounded partial-send retry, and a 1024-message batch
  cap. The stable default remains `[limits].udp_runtime = "tokio"`. A retained
  2026-06-01 local loopback comparison with reduced hot-path metrics, four
  server threads, four client threads, client window 16, and four reuseport
  workers measured Tokio batch 32 at about 936k responses/s, dedicated pre-mmsg
  batch 32 at about 879k responses/s, and dedicated mmsg batch 512 at about
  1.47M responses/s, all with zero drops/errors. Batch 1024 fell back to about
  1.19M responses/s, and a dedicated mmsg batch-512 affinity run measured about
  898k responses/s, so affinity remains evidence-gated.
- [x] Add local data-plane tuning observability:
  dedicated Linux UDP workers now export mmsg receive/send syscall counters,
  mmsg datagram counters, partial-send counters, WouldBlock retry counters, and
  labelled per-worker UDP batch/datagram counters. The DNS client benchmark
  retains aggregate mmsg rows plus active-worker and worker-imbalance summary
  rows in `benchmark-results.tsv`.
- [x] Add local UDP runtime sweep automation:
  `scripts/sweep-udp-runtime-benchmarks.sh` compares UDP runtime, reuseport
  worker count, batch size, and optional dedicated-worker CPU affinity under
  one retained query trace, then writes both full `summary.tsv` and sorted
  `best.tsv` artifacts.
- [x] Add optional privileged perf capture setup:
  `scripts/install-oxidedns-perf-helper.sh` installs one root-owned helper for
  benchmark `perf stat`/`perf record` runs on hosts where direct attach is
  blocked by kernel perf policy. Benchmark runs opt into it with
  `OXIDEDNS_BENCH_PERF_PRIVILEGED_HELPER=true`.
- [x] Add Knot-aligned comparison prep:
  `docs/knot-comparison-benchmark.md` records the source-derived kxdpgun and
  Knot benchmark contract, while
  `scripts/prepare-knot-comparison-benchmark.sh` generates shared `querydb` and
  OxideDNS trace inputs, stages a Knot-primary/OxideDNS-secondary AXFR
  comparison runbook, and normalizes retained kxdpgun/OxideDNS outputs into a
  common throughput table.
- [ ] Decide whether AF_XDP is worth implementing for the server.

## Phase 8: Layout Tuning Experiments

- [x] Current layout uses simple packed arrays, integer IDs, and segmented
  arenas.
- [x] Current lookup avoids global delegation/DNAME scans with compact indexes.
- [x] Current benchmark records node, edge, RRset, record, hot-byte, and
  cold-byte counts.
- [x] Add opt-in zone-shape histograms for high fan-out nodes and RRset
  distribution.
- [x] Add retained high-fanout first/middle/last/absent-child lookup evidence
  to the in-process ZoneImage prototype benchmark.
- [x] Add retained precomputed-additional benchmark evidence:
  `target/zone-image-bench/precomputed-additionals.tsv` improved local mixed
  packet response from about 900 ns/query to about 870 ns/query and trace packet
  response from about 554 ns/query to about 529 ns/query, with hot bytes rising
  by about 40 KiB on the 10k-record fixture. The retained benchmark check
  passed at `target/zone-image-bench/precomputed-additionals-check.tsv`.
- [x] Add retained compact relation-span benchmark evidence:
  `target/zone-image-bench/precomputed-additionals-rrsig-spans.tsv` keeps
  ordinary answer additional RRsets and RRSIG record selection in one compact
  per-RRset relation span. The retained compact layout measured about 801 KiB
  of hot bytes and 147 bytes/record on the 10k-record fixture, preserving the
  precomputed-additional hot footprint while moving RRSIG selection out of the
  query-time RRSIG index scan.
- [x] Add retained selected-RRSIG-record benchmark evidence:
  `target/zone-image-bench/precomputed-additionals-selected-rrsig-records.tsv`
  measured about 849 ns/query mixed packet, 218 ns/query hot packet, 519
  ns/query trace packet, and 320 ns/query optioned packet on the local
  in-process fixture, with zero validation mismatches, about 801 KiB hot bytes,
  and a passing check at
  `target/zone-image-bench/precomputed-additionals-selected-rrsig-records-check.tsv`.
- [x] Add retained dynamic-record-bucket benchmark evidence:
  `target/zone-image-bench/precomputed-additionals-dynamic-rrsig-records.tsv`
  keeps synthesized DNAME CNAMEs and selected immutable RRSIG references in
  shared per-section dynamic record buckets. The retained run measured about
  835 ns/query mixed packet, 244 ns/query hot packet, 533 ns/query trace
  packet, and 342 ns/query optioned packet with zero validation mismatches,
  about 801 KiB hot bytes, 147 bytes/record, and a passing check at
  `target/zone-image-bench/precomputed-additionals-dynamic-rrsig-records-check.tsv`.
- [x] Add retained referral-glue relation benchmark evidence:
  `target/zone-image-bench/precomputed-additionals-referral-glue-relations.tsv`
  keeps referral glue in compile-time relation spans. The retained run measured
  about 801 ns/query mixed packet, 216 ns/query hot packet, 528 ns/query trace
  packet, 328 ns/query optioned packet, and improved the delegation/DNAME
  stress plan path to about 510 ns/query with zero validation mismatches, about
  801 KiB hot bytes on the mixed fixture, and a passing check at
  `target/zone-image-bench/precomputed-additionals-referral-glue-relations-check.tsv`.
- [x] Add retained referral-glue no-runtime-dedupe evidence:
  `target/zone-image-bench/referral-glue-no-runtime-dedupe.tsv` removes the
  per-referral runtime `additional_rrsets.contains` scan while appending
  precomputed referral-glue relation spans to a fresh referral plan. Focused
  duplicate-NS-target glue coverage verifies compile-time relation dedupe, and
  focused referral, mixed packet, and filtered `zone_image` tests passed. The
  checker passed at
  `target/zone-image-bench/referral-glue-no-runtime-dedupe-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.121`,
  mixed wire ratio `0.150`, mixed packet ratio `1.015`, hot packet ratio
  `1.036`, trace packet ratio `1.019`, optioned packet ratio `1.030`,
  boundary packet ratio `0.986`, UDP-ceiling packet ratio `1.006`, stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as
  narrow referral planner cleanup inside the local gates.
- [x] Add retained referral-glue direct-relation append evidence:
  `target/zone-image-bench/referral-glue-direct-relation-append.tsv` removes
  the runtime referral-glue RRset iterator adapter from the planner. Referral
  plans now append directly from immutable referral-glue relation slices, while
  the RRset iterator wrapper remains test-only for relation assertions. Focused
  referral-glue and delegation/DNAME semantic tests passed, and the invariant
  audit now rejects a runtime call back through the wrapper. The checker passed
  at `target/zone-image-bench/referral-glue-direct-relation-append-check.tsv`
  with zero semantic and packet mismatches, byte parity, mixed planning ratio
  `0.148`, mixed wire ratio `0.172`, mixed packet ratio `1.032`, hot packet
  ratio `1.022`, trace packet ratio `1.008`, optioned packet ratio `0.970`,
  boundary packet ratio `0.993`, UDP-ceiling packet ratio `1.004`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as narrow relation-slice discipline cleanup, not as
  a broader transport result.
- [x] Add retained DNSSEC authority RRset dedupe-state evidence:
  `target/zone-image-bench/dnssec-authority-dedupe-state.tsv` seeds DNSSEC
  augmentation with the existing authority RRset handles and uses that inline
  set when adding NSEC/NSEC3/DS proof RRsets, avoiding repeated scans of the
  mutable authority section. Focused DNSSEC and ZoneImage tests passed,
  including `dnssec_authority_augmentation_seeds_existing_rrset_dedupe`, and the
  checker passed at
  `target/zone-image-bench/dnssec-authority-dedupe-state-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.125`, mixed
  wire ratio `0.152`, mixed packet ratio `0.975`, hot packet ratio `1.027`,
  trace packet ratio `0.998`, optioned packet ratio `1.022`, boundary packet
  ratio `1.002`, UDP-ceiling packet ratio `0.989`, stress planning ratio
  `0.001`, and stress wire ratio `0.001`. This is retained as narrow DNSSEC
  planner cleanup inside the local gates.
- [x] Add retained wildcard-owner borrowed-comparison benchmark evidence:
  `target/zone-image-bench/precomputed-additionals-wildcard-owner-borrow.tsv`
  avoids temporary wildcard-synthesis owner-wire buffers. The retained run
  measured about 807 ns/query mixed packet, 217 ns/query hot packet, 507
  ns/query trace packet, and 315 ns/query optioned packet with zero validation
  mismatches, about 801 KiB hot bytes, 147 bytes/record, and a passing check at
  `target/zone-image-bench/precomputed-additionals-wildcard-owner-borrow-check.tsv`.
- [x] Add retained precomputed CNAME/DNAME target and borrowed-DNAME-owner
  evidence:
  `target/zone-image-bench/precomputed-single-name-target-borrowed-dname-owner.tsv`
  keeps parsed first-hop CNAME/DNAME targets and canonical keys in a compact
  side table reached through existing RRset relation spans, while DNAME
  synthesis borrows stored RRset owner wire directly. The retained run measured
  about 727 ns/query mixed packet, 201 ns/query hot packet, 479 ns/query trace
  packet, 328 ns/query optioned packet, and about 541 ns/query delegation/DNAME
  stress plan time with zero validation mismatches, about 801 KiB hot bytes,
  147 bytes/record, and a passing check at
  `target/zone-image-bench/precomputed-single-name-target-borrowed-dname-owner-check.tsv`.
- [x] Add retained borrowed delegation-owner DS exception evidence:
  `target/zone-image-bench/borrowed-delegation-owner-ds.tsv` removes
  parse-and-canonical-string owner comparison from DS-at-delegation planning.
  The retained run measured about 709 ns/query mixed packet, 208 ns/query hot
  packet, 472 ns/query trace packet, 300 ns/query optioned packet, and about
  562 ns/query delegation/DNAME stress plan time with zero validation
  mismatches, about 801 KiB hot bytes, 147 bytes/record, and a passing check at
  `target/zone-image-bench/borrowed-delegation-owner-ds-check.tsv`.
- [x] Measure and reject precomputed referral DNSSEC DS/NSEC relation spans for
  now. The experiment moved signed-referral DS/NSEC discovery into RRset
  relations, but repeated local runs at
  `target/zone-image-bench/precomputed-referral-dnssec-relations.tsv`,
  `target/zone-image-bench/precomputed-referral-dnssec-relations-rerun.tsv`,
  and `target/zone-image-bench/precomputed-referral-dnssec-relations-final.tsv`
  failed the retained benchmark hot-packet ratio gate despite zero validation
  mismatches. Revisit only with a narrower signed-referral corpus or a layout
  that does not perturb the shared relation path.
- [x] Add retained precomputed NSEC range-key evidence:
  `target/zone-image-bench/precomputed-nsec-range-keys.tsv` moves NSEC
  owner/next canonical range keys into the compiled image and computes the
  queried name key once during NSEC covering lookup. The retained run measured
  about 710 ns/query mixed packet, 192 ns/query hot packet, 455 ns/query trace
  packet, 281 ns/query optioned packet, and about 503 ns/query delegation/DNAME
  stress plan time with zero validation mismatches, about 801 KiB hot bytes,
  147 bytes/record, and a passing check at
  `target/zone-image-bench/precomputed-nsec-range-keys-check.tsv`.
- [x] Add retained NSEC3 canonical-wire hashing evidence:
  `target/zone-image-bench/nsec3-canonical-wire-rerun.tsv` avoids building a
  canonical string, reparsing it as a domain, and serializing it again before
  NSEC3 hashing. The retained run measured about 687 ns/query mixed packet, 192
  ns/query hot packet, 455 ns/query trace packet, 298 ns/query optioned packet,
  and about 528 ns/query delegation/DNAME stress plan time with zero validation
  mismatches, about 801 KiB hot bytes, 147 bytes/record, and a passing check at
  `target/zone-image-bench/nsec3-canonical-wire-rerun-check.tsv`.
- [x] Add retained NSEC3 per-query hash-cache evidence:
  `target/zone-image-bench/nsec3-query-hash-cache-rerun.tsv` caches the hashed
  query owner per unique NSEC3 parameter set while scanning candidate NSEC3
  RRsets. The retained rerun measured about 689 ns/query mixed packet, 190
  ns/query hot packet, 453 ns/query trace packet, 291 ns/query optioned packet,
  and about 522 ns/query delegation/DNAME stress plan time with zero validation
  mismatches, about 801 KiB hot bytes, 147 bytes/record, and a passing check at
  `target/zone-image-bench/nsec3-query-hash-cache-rerun-check.tsv`.
- [x] Add retained precomputed NSEC3 candidate-metadata evidence:
  `target/zone-image-bench/precomputed-nsec3-range-metadata-inline-cache.tsv`
  stores parsed NSEC3 parameters plus owner/next hash labels in the compiled
  image and keeps the per-query hash cache inline without cloning parameter
  structs. The retained run measured about 703 ns/query mixed packet, 202
  ns/query hot packet, 463 ns/query trace packet, 283 ns/query optioned packet,
  and about 525 ns/query delegation/DNAME stress plan time with zero validation
  mismatches, about 801 KiB hot bytes, 147 bytes/record, and a passing check at
  `target/zone-image-bench/precomputed-nsec3-range-metadata-inline-cache-check.tsv`.
- [x] Add retained NSEC3 hash-cache inline-capacity evidence:
  `target/zone-image-bench/nsec3-hash-cache-inline-one.tsv` narrows the
  per-query NSEC3 parameter hash-cache inline capacity from two parameter sets
  to one. The common single-parameter signed-zone path stays inline, while
  unusual multi-parameter images still spill correctly. Focused NSEC3 cache,
  NSEC3 range, and DNSSEC proof-corpus tests pass, and
  `target/zone-image-bench/nsec3-hash-cache-inline-one-check.tsv` reports zero
  semantic and packet mismatches, byte parity, mixed planning ratio `0.124`,
  mixed wire ratio `0.150`, mixed packet ratio `1.019`, hot packet ratio
  `1.058`, trace packet ratio `1.030`, optioned packet ratio `1.010`,
  boundary packet ratio `1.007`, and UDP-ceiling packet ratio `1.000`. This is
  retained as narrow DNSSEC denial scratch-layout compaction inside the local
  gates.
- [x] Add retained high-fanout child lookup side-index evidence:
  `target/zone-image-bench/question-wire-len-no-copy.tsv`, building on
  `target/zone-image-bench/child-hash-inline-handle.tsv` and
  `target/zone-image-bench/high-fanout-child-hash-index-threshold-guard.tsv`,
  enables a thresholded generated open-address child hash index for nodes with
  at least 1024 children while small-fanout nodes continue directly to sorted
  edge lookup. The retained inline-handle run stores the side-index handle in
  `NameNode`, avoiding the previous binary search through the `child_hashes`
  table before probing hash slots; the stale `node_index` field was then
  removed from `ImageChildHash`. The retained question-wire run also removes
  the per-packet question-wire `Vec` copy from `Question::parse`, storing only
  the consumed wire length needed for section offsets. It reports zero
  validation mismatches, about 44.6 ns/query high-fanout exact lookup, about
  68.8 ns/query mixed planning, about 136.7 ns/query delegation/DNAME stress
  planning, and a passing check at
  `target/zone-image-bench/question-wire-len-no-copy-check.tsv`.
  The tradeoff on the 10k-record fixture is hot bytes rising from `1,012,516`
  to `1,052,564`, or 168 to 172 bytes/record, compared with the previous
  node-policy direct-build evidence.
- [~] Compare current sorted-edge lookup against adaptive-radix and generated
  perfect-hash layouts on measured high-fanout corpora. The first retained
  implementation is a simpler generated open-address child hash side index;
  adaptive radix and minimal/perfect hashing remain unimplemented until
  evidence shows the extra layout complexity is worth it.
- [x] Measure and reject first-byte bucket child lookup:
  `target/zone-image-bench/child-byte-bucket-lookup.tsv` adds a benchmark-only
  256-way first-byte range dispatch before binary searching the selected child
  label bucket. This acts as a small ART-like first dispatch check against the
  retained 10k-record high-fanout fixture. The checker passed at
  `target/zone-image-bench/child-byte-bucket-lookup-check.tsv` with matching
  found counts and index checksums, but byte-bucket lookup measured `1.543x`
  the sorted baseline while the retained generated open-address child hash
  measured `0.640x` and the benchmark `HashMap` comparison measured `0.551x`.
  The benchmark-only comparison remains as evidence; no production byte-bucket
  layout is promoted.
- [x] Measure and reject label-length bucket child lookup:
  `target/zone-image-bench/child-length-bucket-lookup.tsv` adds a benchmark-only
  length-dispatch table with per-bucket sorted labels and original-index
  mapping. The checker passed at
  `target/zone-image-bench/child-length-bucket-lookup-check.tsv` with matching
  found counts and checksums, zero validation/packet mismatches, and byte
  parity, but length-bucket lookup measured `28.868` ns/query versus sorted
  lookup at `15.740` ns/query and the retained generated child hash at `10.226`
  ns/query. It also needed `40548` side-index bytes on the 10k-record
  high-fanout fixture. The benchmark-only comparison remains as evidence; no
  production length-bucket layout is promoted.
- [x] Measure and reject last-byte bucket child lookup:
  `target/zone-image-bench/child-last-byte-bucket-lookup.tsv` adds a
  benchmark-only 256-way dispatch by the lowercased final child-label byte,
  then binary searches the selected bucket while preserving original child-edge
  indexes. The checker passed at
  `target/zone-image-bench/child-last-byte-bucket-lookup-check.tsv` with
  matching found counts and checksums, zero validation/packet mismatches, and
  byte parity, but last-byte-bucket lookup measured `22.049` ns/query versus
  sorted lookup at `15.559` ns/query and the retained generated child hash at
  `10.005` ns/query. It also needed `42084` side-index bytes on the 10k-record
  high-fanout fixture. The benchmark-only comparison remains as evidence; no
  production last-byte-bucket layout is promoted.
- [x] Measure and reject compact generated child-hash slots:
  `target/zone-image-bench/child-compact-generated-hash.tsv` compares the
  retained 2x next-power-of-two generated child hash against a compact
  `len.next_power_of_two()` table. The compact table cuts the high-fanout slot
  bytes from `131072` to `65536` on the retained 10k-record fixture, and the
  checker passed at
  `target/zone-image-bench/child-compact-generated-hash-check.tsv` with
  matching found counts and checksums. It measured `0.985x` the sorted lookup
  baseline, while the retained 2x generated hash measured `0.620x`. The
  production side index keeps the 2x table because the compact table gives up
  too much of the isolated high-fanout lookup win for a modest image-size
  reduction.
- [x] Add retained child-hash `u16` slot evidence:
  `target/zone-image-bench/child-hash-u16-slots.tsv` stores generated
  child-hash slot values as `u16` edge offsets with `u16::MAX` as the empty
  sentinel. This keeps the retained 2x next-power-of-two slot count and lookup
  algorithm, while matching the existing `NameNode.edge_count: u16` bound. The
  checker passed at `target/zone-image-bench/child-hash-u16-slots-check.tsv`
  with zero validation mismatches and matching child-lookup counts/checksums.
  On the retained 10k-record fixture, main image hot bytes dropped from the
  prior `1,054,004` to `988,468`, bytes per record dropped from `172` to
  `166`, and stress hot bytes dropped from `1,042,784` to `1,010,016`.
  The follow-up retained stats artifact
  `target/zone-image-bench/child-hash-u16-slots-stats.tsv` and checker output
  `target/zone-image-bench/child-hash-u16-slots-stats-check.tsv` make the slot
  footprint explicit: the main fixture reports one child hash, `32768` slots,
  and `65536` slot bytes; the delegation/DNAME stress fixture reports one child
  hash, `16384` slots, and `32768` slot bytes. Both checker rows validate that
  slot bytes match `u16` storage.
- [x] Add retained lowercase child-hash label-compare evidence:
  `target/zone-image-bench/lowercase-child-hash-label-eq.tsv` and rerun
  `target/zone-image-bench/lowercase-child-hash-label-eq-rerun.tsv` compare
  child-hash probe labels with a stored-lowercase helper, avoiding the generic
  two-sided ASCII-insensitive comparison for labels compiled into the lowercase
  label arena. Focused high-fanout and semantic lookup tests passed, and both
  benchmark checks passed with zero semantic and packet mismatches at
  `target/zone-image-bench/lowercase-child-hash-label-eq-check.tsv` and
  `target/zone-image-bench/lowercase-child-hash-label-eq-rerun-check.tsv`.
  The rerun measured high-fanout exact lookup ratio `0.107`, mixed planning
  ratio `0.123`, mixed wire ratio `0.156`, mixed packet ratio `1.007`, trace
  packet ratio `0.991`, optioned packet ratio `1.038`, boundary packet ratio
  `1.001`, and UDP-ceiling packet ratio `0.994`. This is retained as
  high-fanout lookup-path discipline; packet timings remain noisy and are not
  claimed as a broad packet-path win.
- [x] Add retained child-hash direct label equality evidence:
  `target/zone-image-bench/child-hash-direct-label-eq.tsv` checks stored
  lowercase child-hash labels against already-lowercase query labels with direct
  byte equality before falling back to case-insensitive comparison. Focused
  high-fanout tests cover both lowercase and uppercase query names, and the
  checker passed at `target/zone-image-bench/child-hash-direct-label-eq-check.tsv`
  with zero validation/packet mismatches, byte parity, unchanged hot bytes per
  record `98.492`, high-fanout exact lookup ratio `0.101`, and generated-hash
  child lookup ratio `0.660`. Packet ratios were mixed/noisy, so this is
  retained as isolated lookup-side cleanup rather than packet-path evidence.
- [x] Add retained single-child trie fast-path evidence:
  `target/zone-image-bench/single-child-trie-fast-path.tsv` handles the common
  one-child `NameNode` case with one stored-lowercase edge equality check before
  falling back to the retained generated-hash and binary-search paths. Focused
  single-child and high-fanout tests passed, and the invariant audit now checks
  that the low-fanout fast path preserves case-insensitive matching without
  dropping the high-fanout hash fallback. The checker passed at
  `target/zone-image-bench/single-child-trie-fast-path-check.tsv` with zero
  validation/packet mismatches, byte parity, unchanged hot bytes per record
  `106.359`, exact lookup ratio `0.222`, hot exact lookup ratio `0.226`,
  high-fanout exact lookup ratio `0.111`, mixed packet ratio `0.964`, hot
  packet ratio `0.915`, trace packet ratio `0.956`, optioned packet ratio
  `0.979`, boundary packet ratio `0.989`, UDP-ceiling packet ratio `1.015`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as narrow trie traversal cleanup before transport
  work.
- [x] Add retained leaf-node trie fast-path evidence:
  `target/zone-image-bench/leaf-child-trie-fast-path.tsv` handles zero-child
  `NameNode` lookups with an immediate miss before touching the generated-hash
  or binary-search fallback paths. Focused tests cover a missing child below a
  leaf owner while preserving closest-encloser state, and the invariant audit
  now checks the leaf-node return alongside the single-child and high-fanout
  paths. The checker passed at
  `target/zone-image-bench/leaf-child-trie-fast-path-check.tsv` with zero
  validation/packet mismatches, byte parity, unchanged hot bytes per record
  `106.359`, exact lookup ratio `0.264`, hot exact lookup ratio `0.263`,
  high-fanout exact lookup ratio `0.128`, mixed planning ratio `0.143`, mixed
  wire ratio `0.162`, mixed packet ratio `1.013`, hot packet ratio `0.917`,
  trace packet ratio `1.024`, optioned packet ratio `0.994`, boundary packet
  ratio `0.992`, UDP-ceiling packet ratio `0.994`, delegation/DNAME-stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as a
  narrow leaf-miss traversal cleanup; the packet effects remain local-gate
  neutral.
- [x] Add retained single-RRset owner lookup evidence:
  `target/zone-image-bench/single-rrset-owner-fast-path.tsv` handles the common
  one-RRset owner case with one QTYPE/QCLASS match before falling back to the
  retained compiled-order RRset scan for multi-RRset owners. Focused exact
  lookup tests cover ordinary IN, QCLASS=ANY, and NODATA semantics, and the
  invariant audit now checks that the fast path preserves QCLASS matching while
  keeping the multi-RRset early-exit scan. The checker passed at
  `target/zone-image-bench/single-rrset-owner-fast-path-check.tsv` with zero
  validation/packet mismatches, byte parity, unchanged hot bytes per record
  `106.359`, exact lookup ratio `0.217`, hot exact lookup ratio `0.227`,
  high-fanout exact lookup ratio `0.115`, mixed planning ratio `0.144`, mixed
  wire ratio `0.163`, mixed packet ratio `1.000`, hot packet ratio `1.044`,
  trace packet ratio `1.029`, optioned packet ratio `0.991`, boundary packet
  ratio `1.011`, UDP-ceiling packet ratio `1.011`, delegation/DNAME-stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as
  exact-lookup path discipline; packet timings remain near parity.
- [x] Add sparse node-local low-RRtype bitmap evidence for multi-RRset owners:
  `target/zone-image-bench/node-low-rrtype-bitmap-handle.tsv` precomputes a
  side-table bitmap only for nodes with more than one RRset, stores a compact
  `NameNode` handle to that side table, then checks it before the compiled-order
  owner RRset scan without a side-table binary search. Single-RRset owners keep
  the direct QTYPE/QCLASS fast path. Focused tests cover an A/AAAA owner in an
  image that has CNAME elsewhere, proving the image-wide bitmap remains
  conservative while the node-local bitmap rejects CNAME before scanning that
  owner. QCLASS=ANY exact lookup uses that same node-local gate before its
  retained multi-class collection scan. The invariant audit requires the sparse
  `Box<[u64]>` side table, the node-carried handle, the multi-RRset-only build
  policy, and the QCLASS=ANY gate. The checker passed at
  `target/zone-image-bench/node-low-rrtype-bitmap-handle-check.tsv` with hot
  bytes/record `106.364`, total bytes/record `174`, stress bytes/record `256`,
  absent-present low direct-preflight ratio `0.948`, mixed planning ratio
  `0.150`, absent-present low QCLASS=ANY exact ratio `0.802`, mixed packet ratio
  `1.029`, hot packet ratio `1.034`, trace packet ratio `1.023`, and
  UDP-ceiling packet ratio `1.011`. This is retained as a narrow owner-RRset
  scan guard; packet timings remain local-gate neutral.
- [x] Add retained concrete-class exact lookup handle evidence:
  `target/zone-image-bench/exact-lookup-compiled-handle.tsv` routes concrete
  QCLASS exact lookups through the compiled RRset handle lookup instead of
  scanning every RRset at the owner. QCLASS=ANY keeps the retained multi-class
  collection scan. Focused tests cover concrete-class selection from a mixed
  class/type owner and QCLASS=ANY returning both same-type classes, and the
  invariant audit now checks the split. The checker passed at
  `target/zone-image-bench/exact-lookup-compiled-handle-check.tsv` with zero
  validation/packet mismatches, byte parity, unchanged hot bytes per record
  `106.359`, exact lookup ratio `0.225`, hot exact lookup ratio `0.244`,
  high-fanout exact lookup ratio `0.120`, mixed planning ratio `0.141`, mixed
  wire ratio `0.161`, mixed packet ratio `1.052`, hot packet ratio `0.967`,
  trace packet ratio `1.090`, optioned packet ratio `1.047`, boundary packet
  ratio `1.003`, UDP-ceiling packet ratio `1.002`, delegation/DNAME-stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as
  exact planner handle discipline; packet timings remain within local gates.
- [x] Add retained single-RRset QTYPE=ANY evidence:
  `target/zone-image-bench/single-rrset-any-fast-path.tsv` extends the same
  one-RRset owner shortcut to minimal and full QTYPE=ANY planning. Single-RRset
  owners now check QCLASS and DNSSEC-proof eligibility once before returning or
  streaming that RRset, while multi-RRset owners keep the compiled-order scan.
  Focused ANY tests cover single-MX minimal and full ANY, DNSSEC-proof-only
  NODATA behavior, wildcard ANY, concrete-class ANY, and QCLASS=ANY behavior.
  The invariant audit now checks the single-RRset ANY path and the retained
  no-collect/no-sort shape. The checker passed at
  `target/zone-image-bench/single-rrset-any-fast-path-check.tsv` with zero
  validation/packet mismatches, byte parity, unchanged hot bytes per record
  `106.359`, exact lookup ratio `0.284`, hot exact lookup ratio `0.294`,
  high-fanout exact lookup ratio `0.140`, mixed planning ratio `0.141`, mixed
  wire ratio `0.160`, mixed packet ratio `1.016`, hot packet ratio `0.960`,
  trace packet ratio `0.998`, optioned packet ratio `1.009`, boundary packet
  ratio `0.978`, UDP-ceiling packet ratio `0.987`, delegation/DNAME-stress
  planning ratio `0.001`, and stress wire ratio `0.001`. This is retained as
  narrow QTYPE=ANY planning cleanup; non-ANY exact lookup ratios are reported
  for gate continuity, not as the reason to keep this branch.
- [x] Add retained additional-planning no-clone evidence:
  `target/zone-image-bench/additional-planning-no-answer-clone.tsv` removes
  per-query cloning of `answer_rrsets` and `answer_items` while walking
  precomputed additional-data spans. The retained run measured about 194
  ns/query mixed planning, about 336 ns/query delegation/DNAME stress planning,
  zero validation mismatches, and a passing check at
  `target/zone-image-bench/additional-planning-no-answer-clone-check.tsv`.
- [x] Add retained single-pass additional-planning evidence:
  `target/zone-image-bench/additional-planning-single-pass.tsv` folds the
  additional-data target pre-scan into the target-emission pass, so answer
  handles that can reference address targets are inspected once. Focused
  additional-data tests, mixed packet corpus, and the filtered `zone_image`
  suite passed. The checker passed at
  `target/zone-image-bench/additional-planning-single-pass-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.131`,
  mixed wire ratio `0.156`, mixed packet ratio `1.051`, hot packet ratio
  `1.095`, trace packet ratio `1.048`, optioned packet ratio `1.060`,
  boundary packet ratio `1.008`, UDP-ceiling packet ratio `1.015`, stress
  planning ratio `0.001`, and stress wire ratio `0.001`. This is retained as a
  narrow planner-pass cleanup inside the local gates.
- [x] Add retained additional empty-section dedupe evidence:
  `target/zone-image-bench/additional-empty-section-dedupe.tsv` records the
  invariant that answer additional-data planning starts with an empty additional
  section, then uses the existing inline `seen` set as the only duplicate check
  while populating precomputed and dynamic target RRsets. Focused additional,
  wildcard, CNAME, and filtered ZoneImage tests passed, and the checker passed
  at `target/zone-image-bench/additional-empty-section-dedupe-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.136`,
  mixed wire ratio `0.158`, mixed packet ratio `1.001`, hot packet ratio
  `1.050`, trace packet ratio `1.011`, optioned packet ratio `1.071`, boundary
  packet ratio `0.990`, UDP-ceiling packet ratio `0.984`, stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as narrow
  additional-planning duplicate-check cleanup.
- [x] Add retained direct additional-relation-slice evidence:
  `target/zone-image-bench/additional-relations-direct-slice-rerun.tsv`
  keeps the compiled additional-address bitmap as the empty-relation fast gate,
  then appends single-answer relation RRset handles and multi-answer dedupe
  candidates directly from the immutable relation slice instead of entering the
  test-only RRset iterator wrapper. Focused additional-data tests passed, and
  the checker passed at
  `target/zone-image-bench/additional-relations-direct-slice-rerun-check.tsv`
  with zero validation/packet mismatches, byte parity, mixed planning ratio
  `0.133`, mixed wire ratio `0.158`, mixed packet ratio `1.000`, hot packet
  ratio `0.981`, trace packet ratio `1.007`, optioned packet ratio `0.988`,
  boundary packet ratio `1.029`, UDP-ceiling packet ratio `1.012`, stress
  planning ratio `0.001`, and stress wire ratio `0.001`. This is retained as a
  narrow relation-slice cleanup inside the local gates.
- [x] Add retained inline dynamic-record bucket evidence:
  `target/zone-image-bench/inline-dynamic-record-buckets.tsv` keeps the first
  few synthesized or selected dynamic records inline in each plan section
  bucket. This is separate from the rejected synthesized owner/RDATA
  small-buffer experiment: owner/RDATA payloads are unchanged, only the dynamic
  bucket storage is inline. The retained run measured about 193 ns/query mixed
  planning, about 337 ns/query delegation/DNAME stress planning, hot packet and
  optioned packet ratios below the current path in that run, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/inline-dynamic-record-buckets-check.tsv`.
- [x] Add retained pre-sized domain-wire serialization evidence:
  `target/zone-image-bench/presized-domain-wire-serialization.tsv` makes
  `DomainName::to_wire` and canonical-wire serialization allocate with exact
  capacity before writing labels. The retained run measured about 186 ns/query
  mixed planning, about 315 ns/query delegation/DNAME stress planning, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/presized-domain-wire-serialization-check.tsv`.
- [x] Add retained RRSIG selected-record dedupe/no-clone evidence:
  `target/zone-image-bench/rrsig-inline-selected-dedupe-no-clone.tsv` removes
  a dead per-query owned record-identity `HashSet`, keeps selected RRSIG dedupe
  inline for common small plans, and avoids cloning plan section vectors while
  adding signatures. The retained run measured about 174 ns/query mixed
  planning, about 318 ns/query delegation/DNAME stress planning, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/rrsig-inline-selected-dedupe-no-clone-check.tsv`.
- [x] Add retained referral DNSSEC authority no-clone evidence:
  `target/zone-image-bench/referral-dnssec-no-authority-clone.tsv` avoids
  cloning authority RRset handles before adding signed-referral DS/NSEC/NSEC3
  proof RRsets. The retained run measured about 177 ns/query mixed planning,
  about 298 ns/query delegation/DNAME stress planning, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/referral-dnssec-no-authority-clone-check.tsv`.
- [x] Add retained denial wildcard node lookup evidence:
  `target/zone-image-bench/denial-wildcard-node-no-domain-build.tsv` uses
  existing closest-encloser and wildcard child nodes for wildcard-synthesis
  detection and avoids constructing the same wildcard child name twice during
  NXDOMAIN denial proof planning. The retained run measured about 186 ns/query
  mixed planning, about 314 ns/query delegation/DNAME stress planning, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/denial-wildcard-node-no-domain-build-check.tsv`.
- [x] Add retained closest-encloser trie-walk evidence:
  `target/zone-image-bench/closest-encloser-trie-walk-no-parent-build.tsv`
  changes node-only closest-encloser discovery from repeated parent
  `DomainName` construction into a direct trie walk over query labels, without
  growing the compiled image. The retained run measured about 149 ns/query
  mixed planning, about 265 ns/query delegation/DNAME stress planning, unchanged
  hot/cold bytes from the previous layout, zero validation mismatches, and a
  passing check at
  `target/zone-image-bench/closest-encloser-trie-walk-no-parent-build-check.tsv`.
- [x] Measure and reject trie-node owner-wire storage for now:
  `target/zone-image-bench/trie-node-owner-wire-closest-encloser.tsv` removed
  more closest-encloser name reconstruction but grew hot bytes to about 1013
  KiB and cold bytes to about 889 KiB on the 10k-record fixture, causing the
  retained hot-packet ratio gate to fail at
  `target/zone-image-bench/trie-node-owner-wire-closest-encloser-check.tsv`.
  Revisit only if signed-denial profiles justify a more selective owner-name
  side table.
- [x] Add retained inline CNAME-chain-state evidence:
  `target/zone-image-bench/inline-cname-chain-state.tsv` stores the common
  visited canonical owner names inline while chasing CNAME/DNAME chains. The
  retained run measured about 144 ns/query mixed planning, about 261 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, mixed/hot/trace packet ratios below the current path in that run,
  and a passing check at
  `target/zone-image-bench/inline-cname-chain-state-check.tsv`.
- [x] Add retained closest-encloser proof-name evidence:
  `target/zone-image-bench/closest-encloser-proof-name-from-trie-depth.tsv`
  derives the NXDOMAIN closest-encloser proof name from compiled trie depth and
  the query suffix, avoiding repeated parent-domain construction and node
  lookup in signed denial planning. The retained run measured about 145
  ns/query mixed planning, about 258 ns/query delegation/DNAME stress planning,
  unchanged image bytes, zero validation mismatches, and a passing check at
  `target/zone-image-bench/closest-encloser-proof-name-from-trie-depth-check.tsv`.
- [x] Add retained inline additional-dedupe evidence:
  `target/zone-image-bench/additional-dedupe-inline-smallvec.tsv` keeps the
  additional-data dedupe set inline for common small target sets instead of
  allocating a heap `Vec`. The retained run measured about 142 ns/query mixed
  planning, about 261 ns/query delegation/DNAME stress planning, unchanged
  image bytes, zero validation mismatches, mixed/hot/trace packet ratios at or
  below the current path in that run, and a passing check at
  `target/zone-image-bench/additional-dedupe-inline-smallvec-check.tsv`.
- [x] Add retained borrowed CNAME-chain target-key evidence:
  `target/zone-image-bench/borrowed-cname-chain-target-keys.tsv` keeps
  precomputed immutable CNAME/DNAME target canonical keys borrowed inside chain
  loop tracking instead of cloning each followed target key. The retained run
  measured about 142 ns/query mixed planning, about 256 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/borrowed-cname-chain-target-keys-check.tsv`.
- [x] Add retained QTYPE=ANY inline RRset collection evidence:
  `target/zone-image-bench/qtype-any-rrsets-inline-smallvec.tsv` keeps exact
  and wildcard ANY RRset collection inline for common small owner sets instead
  of allocating a heap `Vec`. The retained run measured about 143 ns/query
  mixed planning, about 260 ns/query delegation/DNAME stress planning,
  unchanged image bytes, zero validation mismatches, and a passing check at
  `target/zone-image-bench/qtype-any-rrsets-inline-smallvec-check.tsv`.
- [x] Add retained response-planner query-node reuse evidence:
  `target/zone-image-bench/response-planner-reuses-query-nodes.tsv` computes
  exact and closest query trie nodes once in response planning and reuses them
  across delegation, direct, CNAME, DNAME, NODATA, and wildcard branches. The
  retained run measured about 101 ns/query mixed planning, about 204 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, mixed/hot/trace/optioned packet ratios at or below the current
  path in that run, and a passing check at
  `target/zone-image-bench/response-planner-reuses-query-nodes-check.tsv`.
- [x] Add retained DNSSEC answer-count reuse evidence:
  `target/zone-image-bench/dnssec-augment-answer-count-once.tsv` computes
  answer record count once during DNSSEC augmentation and reuses it for NODATA,
  NXDOMAIN, and wildcard-proof decisions. The retained run measured about 102
  ns/query mixed planning, about 218 ns/query delegation/DNAME stress planning,
  unchanged image bytes, zero validation mismatches, and a passing check at
  `target/zone-image-bench/dnssec-augment-answer-count-once-check.tsv`.
- [x] Add retained NSEC direct label-compare evidence:
  `target/zone-image-bench/nsec-cover-direct-label-compare.tsv` compares query
  labels directly against precomputed NSEC canonical-order range keys instead
  of allocating a per-query canonical order key. The retained run measured
  about 101 ns/query mixed planning, about 217 ns/query delegation/DNAME stress
  planning, unchanged image bytes, zero validation mismatches, and a passing
  check at
  `target/zone-image-bench/nsec-cover-direct-label-compare-check.tsv`.
- [x] Add retained precomputed NSEC range-order evidence:
  `target/zone-image-bench/nsec-range-order-precomputed.tsv` stores whether
  each compiled NSEC owner/next range is ordinary or wrapping, so denial proof
  lookup no longer compares immutable range endpoints on every candidate scan.
  The compiler also moves the owner canonical-order key for the common
  single-record NSEC RRset case instead of cloning it. Focused NSEC and DNSSEC
  packet tests passed, and the benchmark checker passed at
  `target/zone-image-bench/nsec-range-order-precomputed-check.tsv` with zero
  semantic and packet mismatches, unchanged image bytes, mixed planning ratio
  `0.130`, mixed wire ratio `0.158`, mixed packet ratio `1.001`, boundary
  packet ratio `1.004`, UDP-ceiling packet ratio `0.999`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as denial-path metadata cleanup.
- [x] Add retained NSEC range wire-key no-parse evidence:
  `target/zone-image-bench/nsec-range-wire-key-no-parse.tsv` builds NSEC owner
  canonical-order keys directly from stored owner wire and NSEC next-owner
  keys directly from the NSEC RDATA wire, instead of reparsing either name into
  a `DomainName` just to reverse/lowercase labels. The direct scanner rejects
  compressed or malformed labels. Focused tests cover same-arena owner key
  construction, RDATA next-owner key construction with trailing bitmap bytes,
  full-name trailing-byte rejection, and compressed-label rejection. The
  retained checker
  `target/zone-image-bench/nsec-range-wire-key-no-parse-check.tsv` passed with
  zero semantic and packet mismatches, byte parity, image bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.137`,
  mixed wire ratio `0.158`, mixed packet ratio `1.024`, hot packet ratio
  `1.020`, trace packet ratio `1.046`, optioned packet ratio `1.016`,
  boundary packet ratio `0.959`, UDP-ceiling packet ratio `0.966`, and
  delegation/DNAME stress planning and wire ratios `0.001`. This is retained
  as compile-time data-model hygiene, not a query hot-path speedup claim.
- [x] Measure and reject NSEC range-cover short-circuiting:
  `target/zone-image-bench/nsec-range-cover-short-circuit.tsv` skipped the
  second endpoint comparison when the precomputed NSEC range-order bit and the
  first comparison already decided coverage. Focused NSEC and DNSSEC packet
  tests passed, and the checker passed at
  `target/zone-image-bench/nsec-range-cover-short-circuit-check.tsv` with zero
  semantic and packet mismatches, but it moved mixed planning from ratio
  `0.130` to `0.135`, mixed wire from `0.158` to `0.167`, and mixed packet
  from `1.001` to `1.006` compared with the retained range-order run. The code
  was reverted because the branch shape did not improve the supported packet
  path on this profile.
- [x] Add retained NSEC3 direct domain-hash evidence:
  `target/zone-image-bench/nsec3-direct-domain-hash.tsv` feeds the NSEC3 SHA-1
  input directly from `DomainName` labels while preserving the per-query
  parameter hash cache. The retained run measured about 99 ns/query mixed
  planning, about 212 ns/query delegation/DNAME stress planning, unchanged
  image bytes, zero validation mismatches, and a passing check at
  `target/zone-image-bench/nsec3-direct-domain-hash-check.tsv`.
- [x] Add retained DNSSEC NODATA exact-node reuse evidence:
  `target/zone-image-bench/dnssec-nodata-exact-node-once.tsv` computes the
  exact query trie node once for NODATA proof selection and reuses it for
  requested-type absence plus exact-name NSEC checks. The retained run measured
  about 101 ns/query mixed planning, about 217 ns/query delegation/DNAME stress
  planning, unchanged image bytes, zero validation mismatches, and a passing
  check at
  `target/zone-image-bench/dnssec-nodata-exact-node-once-check.tsv`.
- [x] Add retained borrowed NSEC3 hash-cache evidence:
  `target/zone-image-bench/nsec3-borrowed-hash-cache.tsv` borrows cached NSEC3
  query hashes by cache index while scanning matching parameter sets instead of
  cloning the cached hash string for each candidate. The retained run measured
  about 102 ns/query mixed planning, about 214 ns/query delegation/DNAME stress
  planning, unchanged image bytes, zero validation mismatches, mixed/hot/trace
  packet ratios below the current path in that run, and a passing check at
  `target/zone-image-bench/nsec3-borrowed-hash-cache-check.tsv`.
- [x] Add retained one-slot NSEC3 hash-cache evidence:
  `target/zone-image-bench/nsec3-hash-cache-inline-one.tsv` keeps the common
  single NSEC3 parameter set inline while allowing larger parameter sets to
  spill. The checker passed with zero semantic and packet mismatches and packet
  ratios inside the local gates; this supersedes the earlier two-inline-slot
  cache shape for current DNSSEC denial planning.
- [x] Add retained DNSSEC selected-record seed-scan skip evidence:
  `target/zone-image-bench/dnssec-skip-unaugmented-selected-seed-scan.tsv`
  skips scanning dynamic selected-record buckets when DNSSEC augmentation starts
  from an ordinary unaugmented plan; already-augmented plans still seed the
  dedupe set from existing selected records. The retained run measured about
  101 ns/query mixed planning, about 208 ns/query delegation/DNAME stress
  planning, unchanged image bytes, zero validation mismatches, and a passing
  check at
  `target/zone-image-bench/dnssec-skip-unaugmented-selected-seed-scan-check.tsv`.
- [x] Add retained wildcard ANY shared-owner override evidence:
  `target/zone-image-bench/wildcard-any-shared-owner-override.tsv` stores one
  query-owner override for all same-owner wildcard ANY answer RRsets instead of
  serializing the same query owner once per RRset. The retained run is a narrow
  boundary-path cleanup, not a broad packet-path win: it measured zero
  validation mismatches, unchanged image bytes, and a passing check at
  `target/zone-image-bench/wildcard-any-shared-owner-override-check.tsv`.
- [x] Add retained wildcard owner-override inline serialization evidence:
  `target/zone-image-bench/wildcard-owner-override-inline-serialize.tsv`
  makes single-RRset wildcard owner-substitution serialize the query-owner
  override directly into the inline owner buffer, then account from the built
  wire length instead of walking parsed owner labels separately for `wire_len()`
  and serialization. The full-ANY wildcard path already shared one override and
  now follows the same accounting discipline. Focused wildcard owner-override
  tests pass, the invariant audit guards the inline single-pass shape, and the
  checker artifact
  `target/zone-image-bench/wildcard-owner-override-inline-serialize-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed
  planning ratio `0.156`, mixed wire ratio `0.179`, mixed packet ratio
  `1.014`, hot packet ratio `0.978`, trace packet ratio `1.015`, optioned
  packet ratio `0.977`, boundary packet ratio `0.983`, UDP-ceiling packet
  ratio `0.988`, and delegation/DNAME-stress plan and wire ratios of `0.002`.
  This is narrow wildcard-owner bookkeeping cleanup, not a template or
  transport result.
- [x] Add retained direct apex-SOA lookup evidence:
  `target/zone-image-bench/negative-soa-apex-node-direct.tsv` selects negative
  authority SOA RRsets from apex trie node `0` instead of walking the origin
  name through the trie for each negative plan. The retained run measured about
  93 ns/query mixed planning, about 209 ns/query delegation/DNAME stress
  planning, unchanged image bytes, zero validation mismatches, and a passing
  check at `target/zone-image-bench/negative-soa-apex-node-direct-check.tsv`.
- [x] Add retained direct plan record-count evidence:
  `target/zone-image-bench/plan-record-count-direct-index.tsv` makes plan
  record-count accounting index compiled RRset handles directly instead of
  doing fallible bounds-checked lookups for private plan handles. The retained
  run measured about 93 ns/query mixed planning, about 198 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/plan-record-count-direct-index-check.tsv`.
- [x] Add retained direct packet-section count evidence:
  `target/zone-image-bench/packet-section-count-direct.tsv` uses the same
  infallible private-plan record-count accounting when writing DNS response
  section counts, avoiding a never-failing `Result` conversion on the packet
  composer path. The retained run measured about 94 ns/query mixed planning,
  about 112 ns/query mixed wire emission, about 199 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/packet-section-count-direct-check.tsv`.
- [x] Add retained known-count packet-composer evidence:
  `target/zone-image-bench/packet-known-counts-no-patch.tsv` computes generic
  response section counts from compiled RRset metadata before encoding, writes
  final DNS header counts up front, and removes the older count-while-encoding
  header patch path. The retained run measured about 56 ns/query mixed planning,
  about 76 ns/query mixed wire emission, about 354 ns/query mixed packet
  response, about 102 ns/query delegation/DNAME stress planning, unchanged image
  bytes, zero validation and packet mismatches, and a passing check at
  `target/zone-image-bench/packet-known-counts-no-patch-check.tsv`.
- [x] Add retained encode-only record visitor evidence:
  `target/zone-image-bench/packet-encode-only-record-visitor.tsv` removes the
  discarded section enum from the normal generic packet composer: normal
  responses visit immutable records through an encode-only callback, while
  truncation scratch collection uses split answer/authority/additional callbacks.
  The retained run measured about 56 ns/query mixed planning, about 69 ns/query
  mixed wire emission, about 361 ns/query mixed packet response, about 106
  ns/query delegation/DNAME stress planning, unchanged image bytes, zero
  validation and packet mismatches, and a passing check at
  `target/zone-image-bench/packet-encode-only-record-visitor-check.tsv`.
- [x] Add retained plan-carried section-count evidence:
  `target/zone-image-bench/plan-carried-section-counts.tsv` carries answer,
  authority, and additional record counts inside `ZoneImageLookupPlan` as RRsets
  and selected records are appended. The normal packet composer now reads
  `plan.section_record_counts()` instead of asking `ZoneImage` to walk selected
  plan handles after planning. The retained run measured about 56 ns/query mixed
  planning, about 68 ns/query mixed wire emission, about 365 ns/query mixed
  packet response, about 103 ns/query delegation/DNAME stress planning,
  unchanged image bytes, zero validation and packet mismatches, and a passing
  check at `target/zone-image-bench/plan-carried-section-counts-check.tsv`.
- [x] Add retained compact plan section-count evidence:
  `target/zone-image-bench/plan-section-counts-u32.tsv` keeps the carried
  section counts as compact `u32` fields with saturating updates, then exposes
  them as `usize` for the existing DNS header count checks. This avoids widening
  the hot query plan with three machine-word counters while preserving the
  existing fail-closed behavior once a response exceeds DNS's `u16` section
  count limits. The retained run measured about 62 ns/query mixed planning,
  about 73 ns/query mixed wire emission, about 353 ns/query mixed packet
  response, unchanged image bytes, zero validation and packet mismatches, and a
  passing check at `target/zone-image-bench/plan-section-counts-u32-check.tsv`.
- [x] Add retained generic response capacity-hint evidence:
  `target/zone-image-bench/generic-response-capacity-hint.tsv` uses carried plan
  section record counts plus fixed EDNS option shape to size ordinary generic
  `ZoneImage` response buffers instead of reserving the whole UDP ceiling for
  unpadded responses. Truncation retries and EDNS-padding-sensitive responses
  still use ceiling-sized buffers. A focused unit test asserts an unpadded
  EDNS-4096 generic response does not reserve the full 4096-byte ceiling, and
  the invariant audit rejects returning the known-count composer to full-ceiling
  allocation. The checker passed at
  `target/zone-image-bench/generic-response-capacity-hint-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.139`,
  mixed wire ratio `0.161`, mixed packet ratio `0.983`, hot packet ratio
  `0.981`, trace packet ratio `0.949`, optioned packet ratio `0.947`,
  boundary packet ratio `0.969`, UDP-ceiling packet ratio `0.965`, stress
  planning ratio `0.001`, and stress wire ratio `0.002`.
- [x] Add retained response-path EDNS capacity single-read evidence:
  `target/zone-image-bench/zone-image-edns-capacity-single-read.tsv` keeps the
  ZoneImage UDP ceiling and EDNS response-capacity hint as caller-carried
  response-path inputs instead of letting the generic capacity helper
  recalculate EDNS option sizing. The normal direct/generic path reuses the
  same hint; the NSEC3 EDE and EDE-stripped truncation paths recompute only
  after metadata changes the OPT shape. Focused tests cover generic unpadded
  capacity, rejected direct-plan generic fallback, and the DNSSEC/NSEC3 EDE
  cap. The invariant audit rejects reintroducing EDNS recomputation inside the
  shared capacity helper. The checker passed at
  `target/zone-image-bench/zone-image-edns-capacity-single-read-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.143`,
  mixed wire ratio `0.168`, mixed packet ratio `1.023`, hot packet ratio
  `1.044`, trace packet ratio `1.034`, optioned packet ratio `1.039`,
  boundary packet ratio `1.004`, UDP-ceiling packet ratio `1.011`, stress
  planning ratio `0.001`, and stress wire ratio `0.002`.
- [x] Add retained plan-carried wire-bound capacity evidence:
  `target/zone-image-bench/plan-carried-wire-bounds.tsv` extends the compact
  carried plan accounting from section record counts to wire-byte upper bounds.
  The original run carried answer, authority, and additional section wire
  bounds; the later `zone-image-derived-section-wire-bounds` slice supersedes
  the authority/additional carried fields after the runtime composer only kept
  needing the total body bound and the answer bound used by SERVFAIL
  conversion. Ordinary generic response buffers now size
  from `plan.response_body_wire_upper_bound()` plus question length and fixed
  EDNS option shape, while truncation and EDNS-padding-sensitive responses keep
  the full UDP ceiling behavior. Focused tests asserted the generic composer
  used the carried plan wire bound for an unpadded EDNS-4096 response. The
  checker passed at `target/zone-image-bench/plan-carried-wire-bounds-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.138`,
  mixed wire ratio `0.174`, mixed packet ratio `0.959`, hot packet ratio
  `0.901`, trace packet ratio `0.957`, optioned packet ratio `0.951`, boundary
  packet ratio `1.046`, UDP-ceiling packet ratio `1.006`, stress planning ratio
  `0.001`, and stress wire ratio `0.001`.
- [x] Add retained truncation kept-wire-bound evidence:
  `target/zone-image-bench/truncation-kept-wire-bounds.tsv` carries the
  uncompressed wire-byte bound for kept answer, authority, and additional
  records while the truncation scratch sections are collected, then decrements
  that bound as records are removed. The wire-record rebuild path now consumes
  the retained bound instead of a rough per-record capacity heuristic. Truncated
  UDP retries still reserve the UDP ceiling, so this is accounting discipline
  and future template-readiness evidence rather than a throughput claim. The
  checker passed at
  `target/zone-image-bench/truncation-kept-wire-bounds-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.148`,
  mixed wire ratio `0.169`, mixed packet ratio `0.994`, hot packet ratio
  `0.999`, trace packet ratio `1.002`, optioned packet ratio `1.004`, boundary
  packet ratio `1.038`, UDP-ceiling packet ratio `1.005`, stress planning ratio
  `0.001`, and stress wire ratio `0.001`.
- [x] Add retained truncation plan-accounting evidence:
  `target/zone-image-bench/truncation-plan-accounting.tsv` extends compact
  `ZoneImageLookupPlan` accounting with a carried DNSSEC-record count. This
  was retained at the time as setup-side accounting cleanup, but the later
  `zone-image-dead-dnssec-count-retired` slice supersedes the DNSSEC counter
  after final response bytes became the latency-classification source of
  truth. The body-bound side of the work remains current: truncation scratch
  setup starts from compact plan response bounds instead of summing every kept
  wire record while collecting retry scratch. Focused ZoneImage tests and the
  invariant audit passed, and the checker passed at
  `target/zone-image-bench/truncation-plan-accounting-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.153`,
  mixed wire ratio `0.180`, mixed packet ratio `0.996`, hot packet ratio
  `1.019`, trace packet ratio `1.006`, optioned packet ratio `1.026`,
  boundary packet ratio `1.041`, UDP-ceiling packet ratio `1.020`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  and stress bytes per record `254.000`.
- [x] Add retained response-shape accounting evidence:
  `target/zone-image-bench/plan-response-shape-view.tsv` bundles carried section
  counts and body wire bound into one immutable-plan response-shape view. The
  original retained run also carried a DNSSEC record count, but that part is
  superseded by `zone-image-dead-dnssec-count-retired`; the current response
  shape keeps only section counts, body bounds, and EDNS sizing that affect
  wire output. The generic and truncated composers now read that view once
  instead of pulling the same compact plan counters through separate accessor
  calls at each response-building stage. Focused accounting tests passed, and
  the checker passed at
  `target/zone-image-bench/plan-response-shape-view-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.135`, mixed
  wire ratio `0.157`, mixed packet ratio `1.045`, hot packet ratio `1.050`,
  trace packet ratio `1.041`, optioned packet ratio `1.035`, boundary packet
  ratio `0.993`, UDP-ceiling packet ratio `1.005`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  hot bytes per record `106.358`, and stress hot bytes per record `142.141`.
- [x] Add retained carried body-bound evidence:
  `target/zone-image-bench/carried-plan-body-wire-bound.tsv` moves the total
  response-body wire bound itself into compact `ZoneImageLookupPlan` state, so
  `response_shape()` no longer derives body capacity by walking planned
  records on every read. SERVFAIL conversion preserves the carried
  partial-answer bound when it clears authority/additional state. Focused
  accounting tests and the invariant audit passed, and the checker passed at
  `target/zone-image-bench/carried-plan-body-wire-bound-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.150`,
  mixed wire ratio `0.180`, mixed packet ratio `1.026`, hot packet ratio
  `1.096`, trace packet ratio `1.009`, optioned packet ratio `1.001`,
  boundary packet ratio `0.980`, UDP-ceiling packet ratio `1.010`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as response-shape accounting cleanup inside the
  local gates, not as a broad throughput claim.
- [x] Add retained carried total-record-count evidence:
  `target/zone-image-bench/carried-plan-total-record-count.tsv` makes the
  low-level `append_plan_wire` return count a compact plan field instead of
  deriving it from section counters after emission. All plan push sites update
  that total beside section counts, and SERVFAIL conversion resets it to the
  carried answer count after clearing authority/additional state. This was
  retained at the time, but the later
  `zone-image-derived-total-record-count` slice supersedes it after runtime
  response composition stopped needing a separate aggregate count. Focused
  accounting tests and the invariant audit passed, and the checker passed at
  `target/zone-image-bench/carried-plan-total-record-count-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.150`,
  mixed wire ratio `0.171`, mixed packet ratio `0.971`, hot packet ratio
  `1.035`, trace packet ratio `0.974`, optioned packet ratio `1.001`,
  boundary packet ratio `0.971`, UDP-ceiling packet ratio `1.006`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as compact wire-emission accounting cleanup, not
  as transport evidence.
- [x] Add retained derived total-record-count evidence:
  `target/zone-image-bench/zone-image-derived-total-record-count.tsv` removes
  the redundant aggregate `ZoneImageLookupPlan` record-count field and stops
  updating it on every plan mutation. Runtime response composition already
  uses carried per-section DNS counts and body wire bounds; the benchmark-only
  `append_plan_wire` count now derives its total from the section counters at
  the boundary. The invariant audit rejects restoring the aggregate field or
  per-push aggregate updates. Focused ZoneImage tests passed, and the checker
  passed at
  `target/zone-image-bench/zone-image-derived-total-record-count-check.tsv`
  with two EDE fallback cases, zero validation/packet mismatches, byte parity,
  mixed planning ratio `0.148`, mixed packet ratio `1.038`, hot packet ratio
  `1.061`, trace packet ratio `1.030`, optioned packet ratio `1.029`,
  boundary packet ratio `0.980`, UDP-ceiling packet ratio `0.991`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  and NOTIFY SOA mixed-case validation ratio `1.031`.
- [x] Add retained derived section-wire-bound evidence:
  `target/zone-image-bench/zone-image-derived-section-wire-bounds.tsv` removes
  the redundant authority/additional section wire-bound fields and their
  per-push updates from `ZoneImageLookupPlan`. Runtime response composition
  still carries the total body wire bound for buffer sizing/truncation, and it
  still carries the answer wire bound because SERVFAIL conversion preserves
  partial answers while clearing authority/additional state. Benchmark-only
  direct accounting can derive exact authority/additional wire lengths by
  walking immutable plan handles. The invariant audit rejects restoring the
  redundant fields or push-site updates. Focused ZoneImage tests passed, and
  the checker passed at
  `target/zone-image-bench/zone-image-derived-section-wire-bounds-check.tsv`
  with two EDE fallback cases, zero validation/packet mismatches, byte parity,
  mixed planning ratio `0.139`, mixed packet ratio `0.989`, hot packet ratio
  `1.011`, trace packet ratio `1.008`, optioned packet ratio `1.048`,
  boundary packet ratio `1.006`, UDP-ceiling packet ratio `1.029`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  and NOTIFY SOA mixed-case validation ratio `1.015`.
- [x] Add retained DNSSEC direct-retry gate evidence:
  `target/zone-image-bench/dnssec-direct-retry-gate.tsv` caches the DO-bit
  request state before ZoneImage planning and passes an explicit
  `allow_direct_answer_retry` flag into the generic response builder. DO-bit
  responses already skip direct preflight because DNSSEC augmentation must use
  the generic composer; this also skips the later impossible direct-answer
  retry that immediately rejected on `dnssec_requested()`. A focused DNSSEC DO
  response test asserts the observed plan is not reported as a direct answer,
  the invariant audit guards the cached request-state and retry gate, and the
  checker passed at
  `target/zone-image-bench/dnssec-direct-retry-gate-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.141`,
  mixed wire ratio `0.160`, mixed packet ratio `1.051`, hot packet ratio
  `1.074`, trace packet ratio `0.978`, optioned packet ratio `0.939`,
  boundary packet ratio `1.000`, UDP-ceiling packet ratio `1.001`,
  delegation/DNAME-stress planning ratio `0.002`, and stress wire ratio
  `0.002`. This is retained as a small DNSSEC composer branch cleanup, not as
  broad throughput evidence.
- [x] Add retained direct-answer caller DO-bit contract evidence:
  `target/zone-image-bench/direct-answer-caller-do-contract.tsv` removes the
  duplicate `metadata.dnssec_requested()` rejection from the direct-answer
  builder. The caller already skips direct preflight and direct retry for
  DO-bit requests; the direct builder now keeps that non-DNSSEC contract as a
  debug assertion and branches only on the cached direct-answer plan flag.
  Focused direct-answer and DNSSEC DO-bit serving tests passed, and the
  invariant audit now rejects reintroducing the duplicate hot-path DO-bit
  check. The checker passed at
  `target/zone-image-bench/direct-answer-caller-do-contract-check.tsv` with
  zero validation and packet mismatches, hot bytes per record `106.365`, bytes
  per record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.143`, mixed packet ratio `1.046`, hot packet ratio `1.087`, trace packet
  ratio `1.005`, boundary packet ratio `0.999`, and UDP-ceiling packet ratio
  `0.992`. This is retained as direct-answer contract cleanup before transport
  work.
- [x] Add retained ZoneImage UDP-ceiling single-read evidence:
  `target/zone-image-bench/zone-image-udp-ceiling-single-read.tsv` computes the
  request UDP ceiling once before ZoneImage direct/generic response
  composition, then threads that value through direct-answer retry and generic
  response building. This avoids re-reading the same EDNS/options state after a
  direct candidate falls through to the generic composer. Focused rejected
  direct-plan, direct-EDNS, and generic-capacity tests passed, the invariant
  audit requires the cached ceiling and rejects recomputing it in the generic
  builder, and the checker passed at
  `target/zone-image-bench/zone-image-udp-ceiling-single-read-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.144`,
  mixed wire ratio `0.170`, mixed packet ratio `1.018`, hot packet ratio
  `1.059`, trace packet ratio `1.018`, optioned packet ratio `1.052`,
  boundary packet ratio `0.966`, UDP-ceiling packet ratio `0.989`,
  delegation/DNAME-stress planning ratio `0.002`, and stress wire ratio
  `0.002`. This is retained as request-metadata plumbing cleanup before
  transport work, not as a broad throughput result.
- [x] Add retained ZoneImage capacity reserve-flag evidence:
  `target/zone-image-bench/zone-image-capacity-reserve-flag.tsv` carries the
  EDNS-padding/full-UDP-capacity reserve decision from the request path into
  the ZoneImage direct, generic, and truncation response builders. The response
  capacity helper now consumes only caller-carried sizing state, so it no longer
  accepts `RequestMetadata`/`AnswerOptions` or rechecks EDNS padding internally.
  Focused capacity and UDP-ceiling tests passed, and the invariant audit now
  rejects putting metadata/options or EDNS-padding checks back into the capacity
  hint helper. The checker passed at
  `target/zone-image-bench/zone-image-capacity-reserve-flag-check.tsv` with
  zero validation and packet mismatches, hot bytes per record `106.365`, bytes
  per record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.150`, mixed packet ratio `0.978`, hot packet ratio `1.035`, trace packet
  ratio `1.047`, boundary packet ratio `0.983`, and UDP-ceiling packet ratio
  `1.017`. This is retained as request-capacity plumbing cleanup before
  transport work.
- [x] Add retained ZoneImage response-sizing bundle evidence:
  `target/zone-image-bench/zone-image-response-sizing-bundle.tsv` carries the
  fixed header-plus-question minimum response capacity beside the cached UDP
  ceiling and EDNS response sizing in one `ZoneImageResponseSizing` value.
  Direct, generic, failure, CHAOS TXT, EDE-stripped, and truncation retry
  response builders now consume that bundle instead of recomputing the fixed
  parsed-query capacity base or threading the UDP ceiling and EDNS sizing as
  separate hot-path arguments. Focused generic-capacity tests pass, and the
  invariant audit requires the response-sizing bundle and rejects returning the
  capacity helper to metadata/options or standalone EDNS sizing inputs. The
  checker passed at
  `target/zone-image-bench/zone-image-response-sizing-bundle-check.tsv` with
  two EDE fallback packet cases, zero validation and packet mismatches, byte
  parity, main image bytes per record `174.000`, stress bytes per record
  `256.000`, mixed planning ratio `0.146`, mixed wire ratio `0.163`, mixed
  packet ratio `1.051`, hot packet ratio `1.056`, trace packet ratio `1.025`,
  optioned packet ratio `0.952`, boundary packet ratio `0.996`, UDP-ceiling
  packet ratio `0.991`, NOTIFY SOA mixed-case validation ratio `0.997`, CHAOS
  mixed-case classification ratio `0.965`, and delegation/DNAME stress
  planning and wire ratios of `0.002` and `0.002`. This is retained as
  response-sizing plumbing cleanup before transport work, not as broad
  throughput evidence.
- [x] Add retained borrowed ZoneImage provider evidence:
  `target/zone-image-bench/borrowed-zone-image-provider.tsv` changes the
  serving provider from per-query `Arc<ZoneImage>` cloning to a borrowed
  `&ZoneImage` tied to the active `PublishedZone`. Focused positive-response,
  rejected-direct-plan, and DNSSEC DO serving tests passed, the invariant audit
  requires the borrowed provider shape and default `active_zone_image_ref()`
  accessor, and the checker passed at
  `target/zone-image-bench/borrowed-zone-image-provider-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.146`, mixed
  wire ratio `0.168`, mixed packet ratio `1.033`, hot packet ratio `1.006`,
  trace packet ratio `1.039`, optioned packet ratio `1.039`, boundary packet
  ratio `1.033`, UDP-ceiling packet ratio `1.038`, delegation/DNAME-stress
  planning ratio `0.002`, and stress wire ratio `0.002`. This is retained as
  hot-path ownership cleanup before transport work, not as physical NIC
  throughput evidence.
- [x] Remove the stale active `ZoneImage` Arc-clone accessor from
  `PublishedZone`: active query serving now exposes only the borrowed
  `active_zone_image_ref()` path, while the broad optional `Arc<ZoneImage>`
  clone accessor was also removed after publication/replacement tests were
  converted to borrowed identity checks. Focused publication and replacement
  tests passed, and the invariant audit rejects restoring either clone
  accessor. The retained follow-up
  `target/zone-image-bench/published-zone-image-ref-surface.tsv`
  checker passed at
  `target/zone-image-bench/published-zone-image-ref-surface-check.tsv`
  with zero validation/packet mismatches, byte parity, mixed planning ratio
  `0.152`, mixed packet ratio `1.021`, hot packet ratio `0.998`, trace packet
  ratio `1.010`, optioned packet ratio `1.002`, boundary packet ratio `1.033`,
  and UDP-ceiling packet ratio `1.012`. This is retained as query-surface API
  discipline, not as a throughput claim.
- [x] Add retained BlobRange-length accounting cleanup:
  `target/zone-image-bench/blob-range-len-accounting.tsv` and rerun
  `target/zone-image-bench/blob-range-len-accounting-rerun.tsv` use
  already-compiled `BlobRange` lengths for immutable RRset and selected-record
  wire upper-bound accounting instead of slicing arenas only to read `.len()`.
  This is a narrow composer accounting cleanup, not a broad packet-path claim.
  Focused accounting and mixed packet tests passed, and both benchmark checks
  passed with zero semantic and packet mismatches at
  `target/zone-image-bench/blob-range-len-accounting-check.tsv` and
  `target/zone-image-bench/blob-range-len-accounting-rerun-check.tsv`. The
  rerun measured mixed planning ratio `0.131`, mixed wire ratio `0.173`, mixed
  packet ratio `0.981`, trace packet ratio `0.980`, boundary packet ratio
  `0.993`, UDP-ceiling packet ratio `0.994`, delegation/DNAME-stress planning
  ratio `0.001`, and stress wire ratio `0.002`.
- [x] Measure and supersede RRset non-owner wire-bound metadata:
  `target/zone-image-bench/rrset-non-owner-wire-bound.tsv` stores each compiled
  RRset's non-owner wire byte total in `ImageRrset`, so wildcard
  owner-override upper-bound accounting no longer walks every record just to
  add fixed RR fields and RDATA lengths. This adds hot metadata bytes but keeps
  them inside the retained gates. Focused ZoneImage tests passed, and the
  checker passed at
  `target/zone-image-bench/rrset-non-owner-wire-bound-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.130`,
  mixed wire ratio `0.159`, mixed packet ratio `1.032`, hot packet ratio
  `1.047`, trace packet ratio `1.034`, optioned packet ratio `0.987`,
  boundary packet ratio `0.997`, UDP-ceiling packet ratio `0.994`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  hot bytes per record `102.493`, and stress bytes per record `250.000`.
  The code was then narrowed to
  `target/zone-image-bench/derived-owner-override-wire-bound.tsv`, deriving
  the same non-owner byte total from already-compiled RRset wire length,
  owner-wire length, and record count instead of adding an `ImageRrset` field.
  Focused ZoneImage tests passed, and the checker passed at
  `target/zone-image-bench/derived-owner-override-wire-bound-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.132`,
  mixed wire ratio `0.161`, mixed packet ratio `1.018`, hot packet ratio
  `1.087`, trace packet ratio `1.017`, optioned packet ratio `1.019`,
  boundary packet ratio `1.010`, UDP-ceiling packet ratio `1.004`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  hot bytes per record `98.502`, and stress bytes per record `246.000`. The
  derived calculation is retained; the added hot metadata field is not.
- [x] Add retained RRset accounting single-read cleanup:
  `target/zone-image-bench/rrset-accounting-single-read.tsv` uses one private
  compiled-RRset metadata read to return record count and wire upper bound
  together for ordinary RRset list accounting and owner-override answer items,
  instead of indexing the same RRset through separate count and byte helpers.
  The dead standalone wire-bound helper was removed, and the current refresh
  keeps standalone count/wire-bound reads test-only while runtime planning uses
  private single-read plan-push helpers. Focused ZoneImage tests passed, and the
  checker passed at
  `target/zone-image-bench/rrset-accounting-single-read-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.133`,
  mixed wire ratio `0.164`, mixed packet ratio `1.012`, hot packet ratio
  `1.035`, trace packet ratio `1.026`, optioned packet ratio `0.972`,
  boundary packet ratio `0.991`, UDP-ceiling packet ratio `0.999`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  hot bytes per record `98.502`, and stress bytes per record `246.000`.
  The refresh artifact
  `target/zone-image-bench/rrset-accounting-single-read-refresh.tsv` passed
  `target/zone-image-bench/rrset-accounting-single-read-refresh-check.tsv`
  with zero validation/packet mismatches, byte parity, main image bytes/record
  `170`, stress image bytes/record `250`, mixed planning ratio `0.140`, mixed
  wire ratio `0.163`, mixed packet ratio `1.048`, hot packet ratio `1.077`,
  trace packet ratio `1.049`, optioned packet ratio `1.043`, boundary packet
  ratio `1.016`, UDP-ceiling packet ratio `1.002`, stress planning ratio
  `0.001`, and stress wire ratio `0.002`.
- [x] Add retained relation-kind subspan lookup evidence:
  `target/zone-image-bench/relation-kind-subspan.tsv` and rerun
  `target/zone-image-bench/relation-kind-subspan-rerun.tsv` use the existing
  contiguous per-RRset relation-kind emission order to return same-kind
  subspans for additional-address, referral-glue, and RRSIG relation scans,
  instead of filtering the whole mixed relation span during query planning and
  DNSSEC augmentation. This does not add image fields or hot bytes. Focused
  relation tests, mixed packet tests, DNSSEC proof-selection tests, and signed
  packet edge tests passed. Both benchmark checks passed with zero semantic and
  packet mismatches at
  `target/zone-image-bench/relation-kind-subspan-check.tsv` and
  `target/zone-image-bench/relation-kind-subspan-rerun-check.tsv`. The rerun
  measured mixed planning ratio `0.129`, mixed wire ratio `0.162`, mixed packet
  ratio `0.993`, boundary packet ratio `0.999`, UDP-ceiling packet ratio
  `1.002`, delegation/DNAME-stress planning ratio `0.001`, and stress wire
  ratio `0.002`. Hot, trace, and optioned packet ratios stayed within the
  existing local gates, so this is retained as relation-span scan discipline
  rather than a broad packet-path win.
- [x] Add retained relation-subspan single-pass finder evidence:
  `target/zone-image-bench/relation-subspan-single-pass.tsv` and rerun
  `target/zone-image-bench/relation-subspan-single-pass-rerun.tsv` keep the
  same contiguous relation-kind layout, but find the same-kind subspan with one
  direct index scan instead of iterator `position` plus a second `take_while`
  pass. This does not add image fields or hot bytes. Focused relation tests
  passed, and both benchmark checks passed with zero semantic and packet
  mismatches at
  `target/zone-image-bench/relation-subspan-single-pass-check.tsv` and
  `target/zone-image-bench/relation-subspan-single-pass-rerun-check.tsv`. The
  rerun measured mixed planning ratio `0.125`, mixed wire ratio `0.153`, mixed
  packet ratio `0.994`, trace packet ratio `1.013`, boundary packet ratio
  `0.986`, UDP-ceiling packet ratio `0.998`, delegation/DNAME-stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as a narrow
  relation helper cleanup; packet timings remain within the local gates but are
  not claimed as a broad response-path improvement.
- [x] Add retained compact relation-span offset table evidence:
  `target/zone-image-bench/relation-span-offset-table-final.tsv` replaces the
  per-RRset mixed relation start/count with a compact relation-span descriptor.
  RRsets now point at precomputed same-kind offsets for single-name targets,
  RRSIGs, referral glue, delegation DNSSEC proofs, and additional-address
  relations; signed-referral DNSSEC proof selection uses the delegation offset
  instead of rescanning the mixed span. Focused relation tests and the filtered
  ZoneImage suite passed, and the checker passed at
  `target/zone-image-bench/relation-span-offset-table-final-check.tsv` with zero
  semantic/packet mismatches, mixed planning ratio `0.121`, mixed wire ratio
  `0.147`, mixed packet ratio `1.021`, hot packet ratio `1.089`, trace packet
  ratio `1.006`, optioned packet ratio `1.052`, boundary packet ratio `1.015`,
  UDP-ceiling packet ratio `1.001`, delegation/DNAME-stress planning ratio
  `0.001`, stress wire ratio `0.002`, hot bytes per record `98.502`, and stress
  hot bytes per record `134.204`. This is retained as planner/composer metadata
  discipline, not as broad packet-path speed evidence.
- [x] Add retained direct delegation-proof offset evidence:
  `target/zone-image-bench/relation-span-direct-delegation-proof.tsv` uses the
  compact relation-span descriptor's delegation DNSSEC offset directly when
  selecting signed-referral DS/NSEC proof relations, instead of asking for
  separate same-kind DS and NSEC subspans. Focused referral-DNSSEC tests and the
  filtered ZoneImage suite passed, and the checker passed at
  `target/zone-image-bench/relation-span-direct-delegation-proof-check.tsv` with
  zero semantic/packet mismatches, mixed planning ratio `0.125`, mixed wire ratio
  `0.151`, mixed packet ratio `1.018`, hot packet ratio `1.121`, trace packet
  ratio `1.001`, optioned packet ratio `1.016`, boundary packet ratio `0.995`,
  UDP-ceiling packet ratio `0.998`, delegation/DNAME-stress planning ratio
  `0.001`, stress wire ratio `0.002`, hot bytes per record `98.502`, and stress
  hot bytes per record `134.204`. This is retained as narrow signed-referral
  planner cleanup inside the local gates.
- [x] Add retained direct single-name target offset evidence:
  `target/zone-image-bench/relation-span-direct-single-name-target.tsv` uses
  the compact relation-span descriptor's single-name target offset directly for
  CNAME/DNAME first-hop target lookup, instead of asking the generic
  same-kind-subspan helper for a one-entry relation. Focused CNAME/DNAME target
  coverage, the filtered ZoneImage suite, and `cargo fmt --all --check` passed,
  and the checker passed at
  `target/zone-image-bench/relation-span-direct-single-name-target-check.tsv`
  with zero semantic/packet mismatches, mixed planning ratio `0.128`, mixed
  wire ratio `0.154`, mixed packet ratio `0.988`, hot packet ratio `0.987`,
  trace packet ratio `0.998`, optioned packet ratio `0.995`, boundary packet
  ratio `0.981`, UDP-ceiling packet ratio `0.994`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  hot bytes per record `98.502`, and stress hot bytes per record `134.204`.
  This is retained as narrow CNAME/DNAME planner metadata cleanup with no image
  memory increase.
- [x] Add retained direct relation-consumer offset evidence:
  `target/zone-image-bench/relation-span-direct-relation-consumers.tsv` moves
  the remaining runtime additional-address, referral-glue, and RRSIG relation
  consumers from the generic same-kind-subspan helper to explicit
  relation-span offsets. The generic relation-kind inspection helper is now
  test-only. The filtered ZoneImage suite, `cargo fmt --all --check`, and a
  profiling bench-target check passed without warnings, and the checker passed
  at
  `target/zone-image-bench/relation-span-direct-relation-consumers-check.tsv`
  with zero semantic/packet mismatches, mixed planning ratio `0.125`, mixed
  wire ratio `0.147`, mixed packet ratio `1.081`, hot packet ratio `1.048`,
  trace packet ratio `1.020`, optioned packet ratio `1.108`, boundary packet
  ratio `1.007`, UDP-ceiling packet ratio `0.993`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  hot bytes per record `98.502`, and stress hot bytes per record `134.204`.
  This is retained as relation-consumer discipline and warning cleanup inside
  the local gates, not as a broad packet-path improvement.
- [x] Add retained signed-referral DNSSEC single relation-scan evidence:
  `target/zone-image-bench/signed-referral-dnssec-single-relation-scan.tsv`
  selects precomputed delegation DS/NSEC proof relations with one scan of the
  referral RRset's relation span instead of asking for the DS and NSEC subspans
  separately. Focused referral-DNSSEC, DNSSEC, and filtered ZoneImage tests
  passed, and the checker passed at
  `target/zone-image-bench/signed-referral-dnssec-single-relation-scan-check.tsv`
  with zero validation/packet mismatches, byte parity, mixed planning ratio
  `0.134`, mixed wire ratio `0.161`, mixed packet ratio `1.019`, hot packet
  ratio `1.054`, trace packet ratio `1.029`, optioned packet ratio `1.080`,
  boundary packet ratio `1.030`, UDP-ceiling packet ratio `1.037`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio `0.002`.
  This is retained as signed-referral planner cleanup, not as a broad
  packet-path win.
- [x] Add retained signed-referral owner-wire no-parse evidence:
  `target/zone-image-bench/signed-referral-owner-wire-no-parse.tsv` builds
  signed-referral DS/NSEC relation owner keys directly from stored
  uncompressed NS owner wire, and compares apex NS owners directly from wire,
  instead of reparsing the owner into a `DomainName` for `canonical_key()`.
  Focused tests cover mixed-case owner key lookup plus compressed and trailing
  owner-wire rejection. The retained checker
  `target/zone-image-bench/signed-referral-owner-wire-no-parse-check.tsv`
  passed with zero semantic and packet mismatches, byte parity, image bytes per
  record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.128`, mixed wire ratio `0.147`, mixed packet ratio `1.011`, hot packet
  ratio `0.894`, trace packet ratio `1.016`, optioned packet ratio `0.990`,
  boundary packet ratio `0.988`, UDP-ceiling packet ratio `0.990`, and
  delegation/DNAME stress planning and wire ratios `0.001`. This is retained
  as compile-time relation metadata hygiene, not a broad packet-path win.
- [x] Add retained referral-glue owner-wire no-parse evidence:
  `target/zone-image-bench/referral-glue-owner-wire-no-parse.tsv` filters
  referral-glue relation targets against the stored uncompressed delegation
  owner wire instead of rebuilding the delegation owner as a `DomainName`.
  Focused tests cover mixed-case delegation owner matching, child glue
  selection, sibling-target rejection, and malformed trailing owner-wire
  rejection. The retained checker
  `target/zone-image-bench/referral-glue-owner-wire-no-parse-check.tsv`
  passed with zero semantic and packet mismatches, byte parity, image bytes per
  record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.134`, mixed wire ratio `0.156`, mixed packet ratio `1.010`, hot packet
  ratio `0.996`, trace packet ratio `1.062`, optioned packet ratio `1.006`,
  boundary packet ratio `0.991`, UDP-ceiling packet ratio `0.987`, and
  delegation/DNAME stress planning and wire ratios `0.001`. This is retained
  as compile-time relation metadata hygiene, not a broad packet-path win.
- [x] Add retained relation target-wire no-parse evidence:
  `target/zone-image-bench/relation-target-wire-no-parse.tsv` borrows
  additional-address and referral-glue target names as validated wire slices
  from NS/MX/SRV/NAPTR/SVCB/HTTPS RDATA, checks in-zone and below-delegation
  suffixes directly from wire, and builds address lookups with direct
  canonical owner-wire keys instead of materializing target `DomainName`
  values. Focused tests cover borrowed NS/MX/SRV/SVCB target slices,
  compressed/trailing target rejection, additional relation preservation, and
  referral-glue child/sibling filtering. The retained checker
  `target/zone-image-bench/relation-target-wire-no-parse-check.tsv` passed
  with zero semantic and packet mismatches, byte parity, image bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.146`,
  mixed wire ratio `0.171`, mixed packet ratio `1.072`, hot packet ratio
  `1.168`, trace packet ratio `1.086`, optioned packet ratio `1.049`,
  boundary packet ratio `1.008`, UDP-ceiling packet ratio `1.006`, delegation
  stress planning ratio `0.001`, and stress wire ratio `0.002`. This is
  retained as compile-time relation metadata hygiene, not a broad packet-path
  win.
- [x] Add retained single-name target uncompressed-wire evidence:
  `target/zone-image-bench/single-name-target-uncompressed-wire.tsv` keeps
  CNAME/DNAME single-name target precompute on whole uncompressed RDATA wire
  instead of invoking the generic DNS name parser and compression-pointer
  machinery. Focused tests cover accepted whole uncompressed names plus
  compressed-pointer and trailing-byte rejection, and the invariant audit guards
  the helper and constructor shape. The retained checker
  `target/zone-image-bench/single-name-target-uncompressed-wire-check.tsv`
  passed with zero semantic and packet mismatches, byte parity, image bytes per
  record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.142`, mixed wire ratio `0.160`, mixed packet ratio `1.000`, hot packet
  ratio `0.923`, trace packet ratio `1.010`, optioned packet ratio `0.945`,
  boundary packet ratio `0.985`, UDP-ceiling packet ratio `0.995`, delegation
  stress planning ratio `0.001`, and stress wire ratio `0.002`. This is
  retained as compile-time target precompute hygiene, not a packet-throughput
  claim.
- [x] Add retained authoritative-skip referral DNSSEC evidence:
  `target/zone-image-bench/referral-dnssec-authoritative-skip.tsv` gates
  referral-only DNSSEC proof augmentation on non-authoritative plans, so ordinary
  authoritative positive and negative DNSSEC responses do not scan the authority
  section looking for referral NS RRsets. Focused referral-DNSSEC, DNSSEC, and
  filtered ZoneImage tests passed, and the checker passed at
  `target/zone-image-bench/referral-dnssec-authoritative-skip-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.129`,
  mixed wire ratio `0.157`, mixed packet ratio `1.055`, hot packet ratio
  `1.093`, trace packet ratio `1.059`, optioned packet ratio `1.059`, boundary
  packet ratio `1.001`, UDP-ceiling packet ratio `1.009`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio `0.002`.
  This is retained as a narrow DNSSEC planner-scan cleanup.
- [x] Measure and reject first-relation single-name target lookup:
  `target/zone-image-bench/single-name-target-first-relation.tsv` made
  CNAME/DNAME target lookup check only the first per-RRset relation, relying on
  the current builder order where `SingleNameTarget` is emitted first when it
  exists. Focused CNAME/DNAME and mixed packet tests passed, and the benchmark
  check passed with zero semantic and packet mismatches at
  `target/zone-image-bench/single-name-target-first-relation-check.tsv`.
  However, it did not improve the local profile: mixed planning was about
  61.6 ns/query with ratio `0.142`, mixed wire ratio was `0.165`, and mixed
  packet ratio was `1.010`, worse than the immediately retained
  relation-subspan finder evidence. The code change was removed; keep the
  rejected result as evidence against the implicit builder-order shortcut. It
  is superseded by
  `target/zone-image-bench/relation-span-direct-single-name-target.tsv`, which
  uses an explicit relation-span single-name target offset rather than assuming
  the target relation is first.
- [x] Measure and reject lowercase-fast wire suffix key construction:
  `target/zone-image-bench/wire-suffix-key-lowercase-fastpath.tsv` and rerun
  `target/zone-image-bench/wire-suffix-key-lowercase-fastpath-rerun.tsv` made
  `WireNameCompressor` copy already-lowercase validated wire suffix labels
  directly while preserving lowercase canonicalization for mixed-case labels.
  Focused compression and mixed packet tests passed, and both benchmark checks
  passed with zero semantic and packet mismatches at
  `target/zone-image-bench/wire-suffix-key-lowercase-fastpath-check.tsv` and
  `target/zone-image-bench/wire-suffix-key-lowercase-fastpath-rerun-check.tsv`.
  The rerun measured mixed planning ratio `0.124`, mixed wire ratio `0.156`,
  mixed packet ratio `1.018`, trace packet ratio `1.019`, boundary packet ratio
  `0.986`, UDP-ceiling packet ratio `0.993`, delegation/DNAME-stress planning
  ratio `0.001`, and stress wire ratio `0.002`. It did not produce a clear
  wire/composer improvement and mixed packet timing stayed worse than the
  retained relation-subspan baseline, so the code change was removed.
- [x] Add retained stored-wire suffix-key single-pass evidence:
  `target/zone-image-bench/stored-wire-suffix-key-single-pass.tsv` keeps the
  later stored-wire suffix-key lowercase-copy discipline but removes its
  separate full-suffix lowercase pre-scan. The compressor now builds each
  stored-wire suffix key in one pass, copying lowercase labels directly and
  lowercasing only labels that contain uppercase bytes. Focused suffix-key,
  malformed-name, and generic-capacity tests passed, and the invariant audit
  rejects reintroducing the pre-scan plus whole-suffix copy shape. The checker
  passed at
  `target/zone-image-bench/stored-wire-suffix-key-single-pass-check.tsv` with
  zero semantic and packet mismatches, byte parity, mixed planning ratio
  `0.145`, mixed wire ratio `0.170`, mixed packet ratio `1.017`, hot packet
  ratio `0.981`, trace packet ratio `0.996`, optioned packet ratio `1.020`,
  boundary packet ratio `0.983`, UDP-ceiling packet ratio `1.009`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as current-composer suffix-key scan reduction, not
  as template/WireArena completion.
- [x] Measure and reject smaller wire-compressor inline suffix table:
  `target/zone-image-bench/wire-compressor-inline-four.tsv` narrowed
  `WireNameCompressor`'s inline suffix table from eight entries to four.
  Focused compressor and mixed-packet tests passed, and the benchmark checker
  passed at `target/zone-image-bench/wire-compressor-inline-four-check.tsv`
  with zero semantic and packet mismatches and byte parity. The retained
  measurement moved the packet path the wrong way across mixed packet ratio
  `1.018`, trace packet ratio `1.037`, optioned packet ratio `1.038`,
  boundary packet ratio `1.027`, and UDP-ceiling packet ratio `1.017`, without
  reducing image bytes or removing composer work. The code change was removed;
  keep the eight-entry inline suffix table for now.
- [x] Add retained wire-compressor direct-loop evidence:
  `target/zone-image-bench/wire-compressor-direct-loops.tsv` and rerun
  `target/zone-image-bench/wire-compressor-direct-loops-rerun.tsv` replace the
  generic `WireNameCompressor` iterator/closure suffix lookup and registration
  loops with direct index loops while preserving the same inline suffix table
  and case-insensitive matching semantics. Focused compression, mixed packet,
  and signed packet tests passed, and both benchmark checks passed with zero
  semantic and packet mismatches at
  `target/zone-image-bench/wire-compressor-direct-loops-check.tsv` and
  `target/zone-image-bench/wire-compressor-direct-loops-rerun-check.tsv`. The
  rerun measured mixed planning ratio `0.125`, mixed wire ratio `0.151`, mixed
  packet ratio `0.967`, trace packet ratio `1.004`, boundary packet ratio
  `0.985`, UDP-ceiling packet ratio `0.979`, delegation/DNAME-stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as a narrow
  packet-composer loop cleanup inside the existing local gates, not as a broad
  template-path completion.
- [x] Add retained wire-compressor pointer-during-parse evidence:
  `target/zone-image-bench/wire-compressor-pointer-during-parse.tsv` and rerun
  `target/zone-image-bench/wire-compressor-pointer-during-parse-rerun.tsv`
  fold compression-pointer discovery into the validated wire-name label scan,
  removing a separate pass over label offsets before registering newly written
  suffixes. The older standalone wire-label offset helper is now test-only.
  Focused compression, mixed packet, signed packet, and UDP-ceiling tests
  passed, and both benchmark checks passed with zero semantic and packet
  mismatches at
  `target/zone-image-bench/wire-compressor-pointer-during-parse-check.tsv` and
  `target/zone-image-bench/wire-compressor-pointer-during-parse-rerun-check.tsv`.
  The rerun measured mixed planning ratio `0.122`, mixed wire ratio `0.150`,
  mixed packet ratio `0.973`, hot packet ratio `0.989`, trace packet ratio
  `0.978`, delegation/DNAME-stress planning ratio `0.001`, and stress wire
  ratio `0.002`. Boundary and UDP-ceiling packet ratios were noisy at `1.044`
  and `1.042` on the rerun after measuring `0.987` and `0.983` on the first
  run, so this is retained only as generic wire-name composer work reduction,
  not as boundary-path evidence.
- [x] Add retained wire-compressor post-pointer offset pruning evidence:
  `target/zone-image-bench/wire-compressor-skip-post-pointer-offsets.tsv` and
  rerun `target/zone-image-bench/wire-compressor-skip-post-pointer-offsets-rerun.tsv`
  keep validating the full input wire name while no longer storing label
  offsets after the selected compression pointer, because those suffixes cannot
  be written or registered by the current response. Focused compression, mixed
  packet, signed packet, and UDP-ceiling tests passed, and both benchmark
  checks passed with zero semantic and packet mismatches at
  `target/zone-image-bench/wire-compressor-skip-post-pointer-offsets-check.tsv`
  and
  `target/zone-image-bench/wire-compressor-skip-post-pointer-offsets-rerun-check.tsv`.
  The rerun measured mixed planning ratio `0.123`, mixed wire ratio `0.150`,
  mixed packet ratio `0.997`, hot packet ratio `1.023`, trace packet ratio
  `0.987`, optioned packet ratio `1.022`, boundary packet ratio `0.987`,
  UDP-ceiling packet ratio `0.996`, delegation/DNAME-stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as bounded
  compressor bookkeeping discipline with no semantic drift and no material
  packet-path slowdown claim.
- [x] Add retained wire-compressor prechecked suffix registration evidence:
  `target/zone-image-bench/wire-compressor-prechecked-suffix-register.tsv`
  registers only the suffixes already proven absent while searching for a
  compression pointer, avoiding a second suffix-table scan for each
  pre-pointer suffix. The focused compressor tests passed, and the benchmark
  checker passed with zero semantic and packet mismatches at
  `target/zone-image-bench/wire-compressor-prechecked-suffix-register-check.tsv`.
  The retained run measured mixed planning ratio `0.123`, mixed wire ratio
  `0.153`, mixed packet ratio `1.030`, hot packet ratio `1.028`, trace packet
  ratio `1.011`, optioned packet ratio `1.054`, boundary packet ratio `1.002`,
  UDP-ceiling packet ratio `1.024`, delegation/DNAME-stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as a local
  compressor duplicate-work removal inside the existing gates, not as a broad
  packet-path timing claim.
- [x] Re-evaluate and retain duplicate full-suffix lookup skipping:
  `target/zone-image-bench/wire-compressor-skip-duplicate-full-suffix.tsv` and
  rerun `target/zone-image-bench/wire-compressor-skip-duplicate-full-suffix-rerun.tsv`
  originally skipped the full-name suffix lookup inside the wire-label parser
  after the exact full-name fast path had already missed. Focused compressor
  tests, mixed packet tests, and the benchmark checker passed with zero
  validation/packet mismatches at
  `target/zone-image-bench/wire-compressor-skip-duplicate-full-suffix-check.tsv`.
  The rerun preserved byte parity but did not justify the added branch: mixed,
  hot, trace, optioned, boundary, and UDP-ceiling packet ratios were `1.041`,
  `1.098`, `1.061`, `1.100`, `1.013`, and `1.014`, so the code change was
  removed at that point. After the later compressor/accounting cleanups, the
  same duplicate-miss skip was re-evaluated and retained at
  `target/zone-image-bench/wire-compressor-skip-full-miss-recheck.tsv`: the
  generic composer still emits exact full-name suffix hits immediately, but the
  label parser no longer rechecks the same full suffix after a proven fast-path
  miss. Focused compressor tests pass, and
  `target/zone-image-bench/wire-compressor-skip-full-miss-recheck-check.tsv`
  reports zero validation mismatches, unchanged response bytes, mixed packet
  ratio `1.038`, hot packet ratio `1.008`, trace packet ratio `1.047`,
  optioned packet ratio `1.043`, boundary packet ratio `0.988`, and
  UDP-ceiling packet ratio `0.981`. This is retained as narrow compressor
  duplicate-work cleanup inside the current gates, not as a broad packet-path
  timing claim.
- [x] Add retained wire-compressor no-offset-scratch evidence:
  `target/zone-image-bench/wire-compressor-no-offset-scratch.tsv` keeps the
  exact-suffix fast path and duplicate-miss skip above, but changes the
  generic wire-name parser to return only the write boundary and selected
  pointer. The composer then registers pre-pointer suffixes in a direct pass
  instead of building a temporary label-offset `SmallVec` for each encoded
  stored wire name. Focused compressor and ZoneImage tests pass, and
  `target/zone-image-bench/wire-compressor-no-offset-scratch-check.tsv`
  reports zero validation mismatches, unchanged response bytes, mixed packet
  ratio `1.005`, hot packet ratio `1.018`, trace packet ratio `1.011`,
  optioned packet ratio `0.967`, boundary packet ratio `0.987`, and
  UDP-ceiling packet ratio `0.995`. This is retained as local generic-composer
  scratch removal, not as evidence that the future immutable template composer
  is complete.
- [x] Add retained direct question-compressor seed evidence:
  `target/zone-image-bench/wire-compressor-direct-question-seed.tsv` removes
  the duplicate suffix-table probe from parsed question-label compressor
  seeding. The `ZoneImage` response composers create a fresh compressor for
  each packet, so question suffixes can be inserted directly while retaining a
  debug assertion that this path seeds an empty suffix table. Focused
  compressor and ZoneImage tests pass, and
  `target/zone-image-bench/wire-compressor-direct-question-seed-check.tsv`
  reports zero validation mismatches, unchanged response bytes, mixed packet
  ratio `1.008`, hot packet ratio `1.017`, trace packet ratio `1.011`,
  optioned packet ratio `1.013`, boundary packet ratio `1.007`, and
  UDP-ceiling packet ratio `1.008`. This is retained as response-compressor
  seeding discipline inside the current mutable composer, not as completion of
  the template/WireArena path.
- [x] Add retained parsed-label suffix key length evidence:
  `target/zone-image-bench/question-compression-carried-suffix-key-len.tsv`
  reuses the suffix wire length already carried by parsed-question compressor
  seeding when building each canonical suffix key. This removes the remaining
  per-suffix `name_wire_len` recomputation from that path while keeping the same
  response compression semantics. Focused wire-compressor tests pass, the
  invariant audit guards the carried-length helper shape, and the checker
  artifact
  `target/zone-image-bench/question-compression-carried-suffix-key-len-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed
  planning ratio `0.141`, mixed wire ratio `0.162`, mixed packet ratio
  `0.994`, hot packet ratio `0.973`, trace packet ratio `0.941`, optioned
  packet ratio `0.920`, boundary packet ratio `0.966`, and UDP-ceiling packet
  ratio `0.952`. This is retained as small current-composer bookkeeping
  cleanup, not as template/WireArena completion.
- [x] Add retained parsed QNAME wire-length compressor seed evidence:
  `target/zone-image-bench/question-compression-parsed-qname-wire-len.tsv`
  starts parsed-question compressor seeding from the QNAME wire length already
  stored by `Question::parse`, avoiding the remaining full-label length walk
  before suffix registration. The compressed-QNAME regression also asserts that
  a compressed query name is still re-encoded normally in the response while
  the stored parsed length feeds this bookkeeping path. The invariant audit
  guards the `Question::qname_wire_len()` seeding shape, and the checker
  artifact
  `target/zone-image-bench/question-compression-parsed-qname-wire-len-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed
  planning ratio `0.163`, mixed wire ratio `0.172`, mixed packet ratio
  `0.990`, hot packet ratio `0.913`, trace packet ratio `1.020`, optioned
  packet ratio `1.049`, boundary packet ratio `1.023`, and UDP-ceiling packet
  ratio `1.013`. This is retained as small current-composer bookkeeping
  cleanup, not as template/WireArena completion.
- [x] Add retained parsed QTYPE/QCLASS response-byte evidence:
  `target/zone-image-bench/question-qtype-qclass-wire-bytes.tsv` stores the
  parsed question's four QTYPE/QCLASS bytes on `Question`, so response question
  echo copies those bytes instead of converting the scalar `qtype` and `qclass`
  values back to network order in every response. The compressed-QNAME
  regression covers compressed query-name parsing, parsed QTYPE/QCLASS bytes,
  and response re-encoding, while the invariant audit still rejects restoring a
  copied question-wire buffer. The checker artifact
  `target/zone-image-bench/question-qtype-qclass-wire-bytes-check.tsv` passed
  with zero validation and packet mismatches, byte parity, mixed planning ratio
  `0.141`, mixed wire ratio `0.163`, mixed packet ratio `0.980`, hot packet
  ratio `0.966`, trace packet ratio `0.999`, optioned packet ratio `1.030`,
  boundary packet ratio `0.994`, UDP-ceiling packet ratio `1.012`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
  This is retained as parser/composer response-echo bookkeeping cleanup, not as
  template/WireArena completion.
- [x] Add retained parsed QNAME wire-length storage evidence:
  `target/zone-image-bench/question-qname-wire-len-stored.tsv` keeps the
  parsed-question no-copy shape but stores the parsed QNAME wire length directly
  on `Question`, deriving total question length only for section offsets and
  capacity sizing. This removes the subtract-four step from the response
  compressor seed path while preserving response echo of parsed labels plus
  parsed QTYPE/QCLASS bytes. The compressed-QNAME regression asserts total
  question length, QNAME wire length, carried lowercase state, and the parsed
  QTYPE/QCLASS tail bytes. The checker artifact
  `target/zone-image-bench/question-qname-wire-len-stored-check.tsv` passed with
  zero validation and packet mismatches, byte parity, mixed planning ratio
  `0.145`, mixed wire ratio `0.170`, mixed packet ratio `1.038`, hot packet
  ratio `0.980`, trace packet ratio `1.015`, optioned packet ratio `1.011`,
  boundary packet ratio `0.970`, UDP-ceiling packet ratio `0.953`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
  This is retained as parser/composer length-state cleanup, not as
  template/WireArena completion.
- [x] Add retained wire-compressor direct label equality evidence:
  `target/zone-image-bench/wire-compressor-direct-label-eq.tsv` and rerun
  `target/zone-image-bench/wire-compressor-direct-label-eq-rerun.tsv` check
  already-lowercase stored suffix labels with direct byte equality before
  falling back to case-insensitive comparison. Focused compressor and ZoneImage
  serving tests pass, and the rerun checker at
  `target/zone-image-bench/wire-compressor-direct-label-eq-rerun-check.tsv`
  reports zero semantic and packet mismatches, byte parity, mixed planning ratio
  `0.115`, mixed wire ratio `0.144`, mixed packet ratio `1.037`, hot packet
  ratio `1.117`, trace packet ratio `1.058`, optioned packet ratio `1.067`,
  boundary packet ratio `1.035`, and UDP-ceiling packet ratio `1.046`. This is
  retained as a narrow comparison fast path inside current packet-composer gates,
  not as a broad packet-speed claim.
- [x] Add retained wire-compressor direct suffix equality evidence:
  `target/zone-image-bench/wire-compressor-direct-suffix-eq.tsv` adds a
  whole-suffix equality fast path before the label-by-label parser in
  `wire_suffix_matches_key`, so already-canonical stored suffixes can match the
  compressor table without re-walking each label. Mixed-case suffixes still use
  the existing checked case-insensitive path. Focused suffix-key and ZoneImage
  compression tests passed, and the checker passed at
  `target/zone-image-bench/wire-compressor-direct-suffix-eq-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.150`,
  mixed wire ratio `0.171`, mixed packet ratio `1.018`, hot packet ratio
  `1.034`, trace packet ratio `1.048`, optioned packet ratio `1.044`, boundary
  packet ratio `1.026`, and UDP-ceiling packet ratio `1.057`. This is retained
  as current-composer comparison work reduction inside the local gates, not as a
  broad packet-speed claim.
- [x] Add retained wire-compressor lowercase suffix-key evidence:
  `target/zone-image-bench/wire-compressor-lowercase-suffix-key-fast-path.tsv`
  copies validated already-lowercase stored wire suffixes directly into the
  compressor suffix-key table instead of lowercasing every label byte during key
  construction. Mixed-case suffixes keep the existing canonicalization path.
  Focused suffix-key tests pass, the invariant audit guards the direct-copy
  branch, and the checker artifact
  `target/zone-image-bench/wire-compressor-lowercase-suffix-key-fast-path-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed
  planning ratio `0.153`, mixed wire ratio `0.171`, mixed packet ratio
  `0.998`, hot packet ratio `1.100`, trace packet ratio `0.994`, optioned
  packet ratio `1.017`, boundary packet ratio `0.997`, and UDP-ceiling packet
  ratio `0.990`. This is retained as a narrow current-composer suffix-key fast
  path, not as a template/WireArena completion claim.
- [x] Add retained parsed-label lowercase suffix-key evidence:
  `target/zone-image-bench/question-compression-lowercase-label-key-fast-path.tsv`
  applies the same already-lowercase direct-copy discipline to parsed question
  labels when seeding a fresh `ZoneImage` response compressor. Lowercase QNAME
  suffix keys now copy parsed label bytes directly into the inline suffix-key
  table, while mixed-case QNAMEs keep the canonicalizing path. Focused
  suffix-key tests pass, the invariant audit guards the parsed-label predicate
  and direct-copy branch, and the checker artifact
  `target/zone-image-bench/question-compression-lowercase-label-key-fast-path-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed planning
  ratio `0.143`, mixed wire ratio `0.164`, mixed packet ratio `1.032`, hot
  packet ratio `0.942`, trace packet ratio `1.016`, optioned packet ratio
  `0.985`, boundary packet ratio `0.999`, UDP-ceiling packet ratio `1.015`,
  and delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
  This is retained as parsed-question compressor bookkeeping cleanup inside the
  current composer, not as a broad packet-speed or template-composer claim.
- [x] Add retained carried lowercase-QNAME evidence:
  `target/zone-image-bench/question-compression-carried-lowercase-qname.tsv`
  carries the parsed QNAME's lowercase state on `Question` and passes that fact
  into both normal and truncation `ZoneImage` response compressor seeding. The
  parsed-label suffix-key helper now trusts the once-carried full-QNAME fact for
  each suffix instead of reproving lowercase status for every suffix registered
  from the question name. Focused suffix-key and parsed-question tests pass, the
  invariant audit guards the carried field and compressor seed argument, and the
  checker artifact
  `target/zone-image-bench/question-compression-carried-lowercase-qname-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed planning
  ratio `0.150`, mixed wire ratio `0.165`, mixed packet ratio `1.035`, hot
  packet ratio `1.048`, trace packet ratio `1.012`, optioned packet ratio
  `1.041`, boundary packet ratio `0.986`, UDP-ceiling packet ratio `0.999`,
  and delegation/DNAME stress planning and wire ratios of `0.002` and `0.002`.
  This is retained as a small parsed-question compressor seed cleanup, not as
  template/WireArena or transport-buffer completion.
- [x] Add retained parser-carried lowercase-QNAME evidence:
  `target/zone-image-bench/question-parse-carried-lowercase-qname.tsv` moves the
  lowercase-QNAME proof into the DNS name parser walk used by `Question::parse`.
  The existing `DomainName::parse` API remains intact for other callers, while
  the packet hot path consumes `parse_with_ascii_lowercase()` so response
  compressor seeding no longer needs a separate post-parse scan of parsed label
  bytes. Focused compressed-QNAME tests cover lowercase and mixed-case parsed
  questions, the invariant audit rejects reintroducing the post-parse label scan,
  and the checker artifact
  `target/zone-image-bench/question-parse-carried-lowercase-qname-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed planning
  ratio `0.146`, mixed wire ratio `0.172`, mixed packet ratio `0.990`, hot
  packet ratio `0.987`, trace packet ratio `0.980`, optioned packet ratio
  `1.003`, boundary packet ratio `0.975`, UDP-ceiling packet ratio `0.991`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`. This
  is retained as parser/composer duplicate-scan cleanup on the local UDP path,
  not as template/WireArena or transport-buffer completion.
- [x] Add retained inline compressed-QNAME pointer tracking evidence:
  `target/zone-image-bench/question-parse-inline-pointer-tracking.tsv` keeps
  DNS compression pointer loop tracking in inline `SmallVec<[usize; 4]>`
  storage while preserving the parser-carried lowercase-QNAME result. A focused
  nested-compression parser test covers lowercase and mixed-case names reached
  through pointer chains, and the invariant audit rejects reintroducing
  heap-backed `Vec` pointer scratch in `parse_with_ascii_lowercase()`. The
  checker artifact
  `target/zone-image-bench/question-parse-inline-pointer-tracking-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed planning
  ratio `0.146`, mixed wire ratio `0.157`, mixed packet ratio `1.025`, hot
  packet ratio `0.994`, trace packet ratio `1.002`, optioned packet ratio
  `0.986`, boundary packet ratio `1.002`, UDP-ceiling packet ratio `0.993`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`. This
  is retained as parser scratch-allocation hardening for compressed names, not
  as a response-template or transport-buffer milestone.
- [x] Add retained parsed question-wire-length reuse evidence:
  `target/zone-image-bench/question-wire-len-reuse.tsv` uses the consumed
  question wire length stored by `Question::parse` for ZoneImage response
  capacity sizing and the shared response-prefix helper, instead of recomputing
  the encoded QNAME length from parsed labels. The old label-walk helper is
  removed after the current and oracle composers both use the stored length.
  Focused ZoneImage tests and formatting pass, and
  `target/zone-image-bench/question-wire-len-reuse-check.tsv` reports zero
  validation mismatches, unchanged response bytes, mixed planning ratio
  `0.125`, mixed wire ratio `0.157`, mixed packet ratio `1.034`, hot packet
  ratio `1.101`, trace packet ratio `1.030`, optioned packet ratio `1.042`,
  boundary packet ratio `1.019`, and UDP-ceiling packet ratio `1.020`. This is
  retained as small composer bookkeeping cleanup; packet timings remain within
  the local checker gates and do not close the immutable template-composer gap.
- [x] Add retained single UDP-ceiling composer evidence:
  `target/zone-image-bench/zone-image-single-udp-ceiling.tsv` computes the
  request UDP ceiling once in the generic `ZoneImage` response builder and
  threads that value through EDNS OPT emission, the UDP truncation gate, and
  truncated/EDE retry response helpers. Focused ZoneImage UDP-ceiling and
  truncation tests pass, and
  `target/zone-image-bench/zone-image-single-udp-ceiling-check.tsv` reports
  zero validation mismatches, unchanged response bytes, mixed packet ratio
  `1.007`, hot packet ratio `1.028`, trace packet ratio `1.010`, optioned
  packet ratio `0.987`, boundary packet ratio `0.987`, and UDP-ceiling packet
  ratio `0.998`. This is retained as local response-composer bookkeeping
  cleanup; the old snapshot composer keeps its separate ceiling handling for
  offline oracle paths.
- [x] Add retained direct EDNS OPT append evidence:
  `target/zone-image-bench/direct-edns-opt-append.tsv` removes the temporary
  EDNS option RDATA `Vec` from response composition. OPT records now reserve
  the rdlength field, append NSID, DNS Cookie, EDE, TCP keepalive, and padding
  options directly into the final response buffer, then patch rdlength in
  place. Focused EDNS and ZoneImage tests pass, and
  `target/zone-image-bench/direct-edns-opt-append-check.tsv` reports zero
  validation mismatches, unchanged response bytes, mixed packet ratio `0.976`,
  hot packet ratio `1.051`, trace packet ratio `1.033`, optioned packet ratio
  `1.018`, boundary packet ratio `0.986`, and UDP-ceiling packet ratio
  `0.998`. This is retained as allocation-discipline cleanup for the current
  response composer, not as completion of the immutable template/WireArena
  path.
- [x] Add retained authority-SOA plan-bit evidence:
  `target/zone-image-bench/authority-soa-plan-bit.tsv` keeps authority SOA
  presence as explicit `ZoneImageLookupPlan` state, so DNSSEC denial
  augmentation no longer scans authority RRsets to check whether NODATA or
  NXDOMAIN proof insertion is allowed. Focused denial-plan tests and broad
  ZoneImage tests pass, and
  `target/zone-image-bench/authority-soa-plan-bit-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.119`, mixed wire ratio `0.148`, mixed
  packet ratio `1.053`, hot packet ratio `0.960`, trace packet ratio `1.057`,
  optioned packet ratio `1.091`, boundary packet ratio `1.011`, and
  UDP-ceiling packet ratio `1.009`. This is retained as DNSSEC-denial planning
  bookkeeping cleanup inside existing packet gates.
- [x] Add retained first-authority-SOA composer evidence:
  `target/zone-image-bench/authority-first-soa-fast-path.tsv` adds a compact
  `ZoneImageLookupPlan` flag for plans whose first authority RRset is the
  negative-response SOA. The authority append and visit paths now use that flag
  to apply the precomputed negative-SOA TTL override directly to the first
  authority RRset and copy/visit the remaining authority RRsets without scanning
  each one for SOA. The follow-up indexed-emission slice below removed the old
  scanned-SOA fallback entirely.
  Focused ZoneImage tests and the invariant audit passed, and the checker
  passed at
  `target/zone-image-bench/authority-first-soa-fast-path-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.142`,
  mixed wire ratio `0.166`, mixed packet ratio `0.984`, hot packet ratio
  `0.994`, trace packet ratio `1.011`, optioned packet ratio `1.003`,
  boundary packet ratio `1.027`, UDP-ceiling packet ratio `1.002`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.002`,
  main image bytes per record `174`, and stress image bytes per record `254`.
  This is retained as authority-section composer work reduction inside the
  local gates, not as template/WireArena completion.
- [x] Add retained authority-SOA indexed emission evidence:
  `target/zone-image-bench/authority-soa-indexed-emission.tsv` carries the
  authority SOA position in `ZoneImageLookupPlan`, so uncommon authority
  sections where the negative SOA is not first split around the known SOA
  position instead of checking every authority RRset for a TTL override. The
  older scanned-SOA fallback and per-RRset SOA type check are removed. A focused
  test covers a non-first authority SOA with a visible negative-TTL override,
  and the checker passed at
  `target/zone-image-bench/authority-soa-indexed-emission-check.tsv` with zero
  semantic and packet mismatches, byte parity, main bytes per record `174.000`,
  stress bytes per record `254.000`, mixed planning ratio `0.148`, mixed wire
  ratio `0.168`, mixed packet ratio `0.994`, hot packet ratio `0.997`, trace
  packet ratio `0.979`, optioned packet ratio `0.968`, boundary packet ratio
  `1.019`, and UDP-ceiling packet ratio `0.996`. This is retained as
  authority-section composer scan removal before transport work.
- [x] Measure and reject counted generic UDP composer emission:
  `target/zone-image-bench/generic-composer-counted-emission.tsv` plus rerun
  `target/zone-image-bench/generic-composer-counted-emission-rerun.tsv`
  replaced the generic UDP pre-accounting pass with section-counted record
  emission and DNS header patching. The variant preserved packet bytes and zero
  mismatches, but the retained checks at
  `target/zone-image-bench/generic-composer-counted-emission-check.tsv` and
  `target/zone-image-bench/generic-composer-counted-emission-rerun-check.tsv`
  did not show a clean packet-path win: the rerun measured mixed packet ratio
  `0.973`, hot packet ratio `0.980`, trace packet ratio `0.998`, optioned
  packet ratio `1.049`, boundary packet ratio `0.992`, and UDP-ceiling packet
  ratio `1.001`. A UDP-only finalization run at
  `target/zone-image-bench/generic-composer-counted-udp-emission.tsv` still
  showed noisy trace, optioned, boundary, and UDP-ceiling regressions
  (`1.051`, `1.043`, `1.010`, and `1.031`). A smaller UDP capacity hint at
  `target/zone-image-bench/generic-composer-counted-udp-cap-hint.tsv` worsened
  mixed and hot packet ratios to `1.044` and `1.161`. The code change was
  removed at that point; later one-pass composer work superseded this rejected
  variant by carrying section counts through truncation retry and passing the
  current checker gates.
- [x] Supersede rejected full-ANY compile-order sorting with retained
  current-layout evidence:
  `target/zone-image-bench/full-any-compile-order.tsv` and rerun
  `target/zone-image-bench/full-any-compile-order-rerun.tsv` moved same-owner
  RRset ordering into the compiled image by grouping RRsets as owner/class/type
  and removed the full-ANY per-query sort. Focused ANY-ordering and packet
  parity tests passed with zero semantic and packet mismatches, and both checks
  passed at `target/zone-image-bench/full-any-compile-order-check.tsv` and
  `target/zone-image-bench/full-any-compile-order-rerun-check.tsv`. The rerun
  still regressed broad packet ratios: mixed packet `1.034`, hot packet
  `1.084`, trace packet `1.072`, optioned packet `1.103`, boundary packet
  `1.008`, and UDP-ceiling packet `1.014`. The code change was removed; the
  focused mixed-class ANY ordering test remains, and the query-time sort stays
  until a narrower template/full-ANY path has cleaner packet evidence.
  A current-layout retest at
  `target/zone-image-bench/full-any-compiled-order.tsv` again passed the checker
  with zero validation/packet mismatches and byte parity, but regressed broad
  packet ratios further, so the code was again reverted and the full-ANY sort
  remained intentionally in place at that point.
  The current
  `target/zone-image-bench/any-compile-order-no-sort.tsv` run repeats the
  compile-order approach after later planner/composer cleanup: `RrsetGroupKey`
  now orders same-owner RRsets by class/type at image build time, minimal ANY
  returns the first matching non-DNSSEC RRset from that compiled order, and
  full ANY appends matching RRsets without a query-time sort. Focused ANY and
  full ZoneImage tests pass, and
  `target/zone-image-bench/any-compile-order-no-sort-check.tsv` reports zero
  validation mismatches, unchanged response bytes, mixed planning ratio
  `0.130`, mixed wire ratio `0.152`, mixed packet ratio `1.045`, hot packet
  ratio `1.076`, trace packet ratio `1.050`, optioned packet ratio `1.049`,
  boundary packet ratio `1.020`, UDP-ceiling packet ratio `1.038`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  hot bytes per record `98.502`, and stress hot bytes per record `134.204`.
  The no-sort path is now retained because the current evidence stays inside
  local gates.
- [x] Add retained full-ANY precomputed-additional evidence:
  `target/zone-image-bench/any-precomputed-additional-spans.tsv` routes exact
  and wildcard QTYPE=ANY answer RRset lists through the same precomputed
  additional-address relation spans used by single-answer plans, instead of
  re-walking generic plan items or keeping a dynamic-record additional fallback
  that no live planner uses. Focused ANY tests cover target-bearing exact and
  wildcard full-ANY answers, and
  `target/zone-image-bench/any-precomputed-additional-spans-check.tsv` reports
  zero validation mismatches, unchanged response bytes, mixed planning ratio
  `0.120`, mixed wire ratio `0.147`, mixed packet ratio `1.033`, hot packet
  ratio `1.092`, trace packet ratio `1.082`, optioned packet ratio `1.059`,
  boundary packet ratio `1.000`, UDP-ceiling packet ratio `0.996`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.001`.
- [x] Add retained truncation scratch preallocation evidence:
  `target/zone-image-bench/truncation-scratch-prealloc.tsv` pre-sizes
  truncated-response answer, authority, and additional scratch vectors from
  immutable plan record counts before visiting plan wire records. This is a
  boundary-path allocation-discipline cleanup rather than a broad packet-path
  win; the retained run measured about 95 ns/query mixed planning, about 195
  ns/query delegation/DNAME stress planning, unchanged image bytes, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/truncation-scratch-prealloc-check.tsv`.
- [x] Add retained truncation inline-section evidence:
  `target/zone-image-bench/truncated-smallvec-boundary-metrics.tsv` keeps the
  common truncated-response answer, authority, and additional scratch sections
  inline while preserving heap spillover for large sections. The benchmark and
  checker now retain boundary and UDP-ceiling packet timing/byte metrics, not
  just mismatch counts. The retained run measured about 73 ns/query mixed
  planning, about 86 ns/query mixed wire emission, about 431 ns/query mixed
  packet response, about 3418 ns/query boundary packet response, about 2342
  ns/query UDP-ceiling packet response, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/truncated-smallvec-boundary-metrics-check.tsv`.
- [x] Add retained truncation accounting-reuse evidence:
  `target/zone-image-bench/truncation-reuses-plan-accounting.tsv` passes the
  section record counts from the first immutable plan-accounting pass into the
  truncated-response builder instead of recomputing them when a UDP response
  crosses the ceiling. This is a narrow boundary-path accounting cleanup rather
  than a broad packet-path win; the retained run measured about 71 ns/query
  mixed planning, about 90 ns/query mixed wire emission, about 425 ns/query
  mixed packet response, about 3379 ns/query boundary packet response, about
  2339 ns/query UDP-ceiling packet response, unchanged image bytes, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/truncation-reuses-plan-accounting-check.tsv`.
- [x] Add retained truncation ceiling-capacity evidence:
  `target/zone-image-bench/truncated-ceiling-capacity.tsv` pre-sizes each
  truncated `ZoneImage` retry response buffer to the UDP ceiling, instead of
  starting from only the DNS header plus question capacity and growing while
  records are emitted. Focused truncation and UDP-ceiling tests passed, and the
  benchmark checker passed with zero semantic and packet mismatches at
  `target/zone-image-bench/truncated-ceiling-capacity-check.tsv`. The retained
  run measured mixed planning ratio `0.136`, mixed wire ratio `0.167`, mixed
  packet ratio `0.988`, hot packet ratio `1.043`, trace packet ratio `0.995`,
  optioned packet ratio `1.065`, boundary packet ratio `1.009`, UDP-ceiling
  packet ratio `1.007`, delegation/DNAME-stress planning ratio `0.001`, and
  stress wire ratio `0.002`. This is retained as bounded truncation allocation
  cleanup inside the existing gates, not as a broad packet-path timing claim.
- [x] Add retained truncation kept-record inline-capacity evidence:
  `target/zone-image-bench/truncation-kept-records-inline-half.tsv` narrows the
  truncated-response kept-record scratch sections to four inline answer
  records, four inline authority records, and eight inline additional records.
  Large truncated sections still spill, while common retry bookkeeping carries
  less inline state. Focused truncation and UDP-ceiling tests pass, and
  `target/zone-image-bench/truncation-kept-records-inline-half-check.tsv`
  reports zero semantic and packet mismatches, byte parity, mixed planning
  ratio `0.122`, mixed wire ratio `0.148`, mixed packet ratio `1.010`, hot
  packet ratio `1.001`, trace packet ratio `0.993`, optioned packet ratio
  `0.981`, boundary packet ratio `0.994`, and UDP-ceiling packet ratio
  `0.992`. This is retained as narrow truncation retry scratch-layout
  compaction inside the existing gates.
- [x] Add retained single-pass query-node handle evidence:
  `target/zone-image-bench/query-node-handles-single-pass.tsv` computes exact
  and closest query trie handles in one traversal for response planning, and
  uses the same helper in wildcard DNSSEC detection instead of separate exact
  and closest-encloser walks. The retained run measured about 90 ns/query mixed
  planning, about 104 ns/query mixed wire emission, about 181 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/query-node-handles-single-pass-check.tsv`.
- [x] Add retained DNSSEC query-node handle reuse evidence:
  `target/zone-image-bench/dnssec-query-node-handle-reuse.tsv` computes
  query exact/closest trie handles once inside DNSSEC augmentation and reuses
  them for NODATA, NXDOMAIN closest-encloser, and wildcard proof decisions.
  The retained run measured about 89 ns/query mixed planning, about 107
  ns/query mixed wire emission, about 193 ns/query delegation/DNAME stress
  planning, unchanged image bytes, zero validation mismatches, and a passing
  check at `target/zone-image-bench/dnssec-query-node-handle-reuse-check.tsv`.
- [x] Add retained lazy synthesized DNAME target-key evidence:
  `target/zone-image-bench/dname-lazy-synthesized-target-key.tsv` defers
  canonical-key construction for synthesized DNAME CNAME targets until after
  the generated target passes the in-zone check. The retained run measured
  about 89 ns/query mixed planning, about 102 ns/query mixed wire emission,
  about 185 ns/query delegation/DNAME stress planning, unchanged image bytes,
  zero validation mismatches, and a passing check at
  `target/zone-image-bench/dname-lazy-synthesized-target-key-check.tsv`.
- [x] Add retained borrowed original-query chain-state evidence:
  `target/zone-image-bench/chain-original-qname-borrowed.tsv` keeps the
  original query as a borrowed `DomainName` in CNAME/DNAME loop tracking,
  avoiding the previous initial canonical-key allocation while still comparing
  targets case-insensitively. The retained run measured about 77 ns/query mixed
  planning, about 93 ns/query mixed wire emission, about 164 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/chain-original-qname-borrowed-check.tsv`.
- [x] Add retained original-node chain-loop evidence:
  `target/zone-image-bench/chain-original-node-loop.tsv` carries the original
  exact query node in `ChainState` when it is known, allowing CNAME/DNAME loop
  detection for existing in-zone targets to compare compiled node IDs instead
  of comparing labels against the original query name each hop. The retained
  checker passed at `target/zone-image-bench/chain-original-node-loop-check.tsv`
  with zero validation mismatches, byte parity, mixed packet ratio `0.995`,
  boundary packet ratio `0.993`, UDP-ceiling packet ratio `0.992`, unchanged
  image bytes, and delegation/DNAME stress planning still inside the retained
  gate.
- [x] Add retained chain visited-node inline-capacity evidence:
  `target/zone-image-bench/chain-visited-node-inline-four.tsv` narrows the
  CNAME/DNAME chain loop-tracking visited-node scratch from eight to four
  inline node IDs, keeping the common short-chain case inline while allowing
  uncommon longer chains to spill. Focused CNAME loop and DNAME target tests
  pass, and `target/zone-image-bench/chain-visited-node-inline-four-check.tsv`
  reports zero semantic and packet mismatches, byte parity, mixed planning
  ratio `0.130`, mixed wire ratio `0.156`, mixed packet ratio `1.010`, hot
  packet ratio `1.040`, trace packet ratio `0.999`, optioned packet ratio
  `0.998`, boundary packet ratio `1.009`, and UDP-ceiling packet ratio
  `1.002`. This is retained as CNAME/DNAME chain-state layout compaction
  inside the local gates.
- [x] Add retained exact positive additional-gate evidence:
  `target/zone-image-bench/exact-positive-additional-gate.tsv` skips the
  generic additional-data planner for exact positive RRsets whose type cannot
  reference address targets. The retained rerun at
  `target/zone-image-bench/exact-positive-additional-gate-rerun.tsv` passed
  the checker at
  `target/zone-image-bench/exact-positive-additional-gate-rerun-check.tsv`
  with zero validation mismatches, byte parity, mixed planning ratio `0.163`,
  mixed wire ratio `0.187`, mixed packet ratio `1.023`, boundary packet ratio
  `0.986`, UDP-ceiling packet ratio `1.002`, and unchanged image bytes. This
  is retained as no-op planner cleanup, not as a broad packet-path win.
- [x] Measure and reject QTYPE=ANY additional-planner gating:
  `target/zone-image-bench/any-additional-planner-gate.tsv` skipped the
  generic additional-data planner for exact and wildcard ANY answers whose
  selected RRsets could not reference address targets. Focused ANY,
  additional-data, mixed-packet, and signed-edge packet tests passed, and the
  checker passed at
  `target/zone-image-bench/any-additional-planner-gate-check.tsv` with zero
  validation mismatches. The retained run measured mixed planning ratio
  `0.166`, mixed packet ratio `1.019`, boundary packet ratio `1.003`, and
  UDP-ceiling packet ratio `1.002`; compared with the prior retained exact
  positive additional-gate rerun, it did not improve planning and worsened the
  boundary packet ratio, so the code was reverted.
- [x] Measure and reject inline dynamic wire buffers for now:
  `target/zone-image-bench/inline-dynamic-wire-buffers.tsv` changed wildcard
  owner overrides and synthesized DNAME CNAME owner/RDATA buffers from `Vec` to
  inline `SmallVec` storage. It removed common small heap allocations but grew
  every lookup plan enough to slow the retained local profile to about 104
  ns/query mixed planning and about 210 ns/query delegation/DNAME stress
  planning, so the code was reverted. The artifact had zero validation
  mismatches and a passing check at
  `target/zone-image-bench/inline-dynamic-wire-buffers-check.tsv`.
- [x] Add retained wildcard owner-override inline-wire evidence:
  `target/zone-image-bench/owner-override-inline-wire.tsv` narrows the earlier
  rejected inline-buffer experiment to wildcard owner overrides only. The plan
  still stores a shared override for wildcard ANY, but the generated owner wire
  is now an inline `SmallVec<[u8; 64]>` and focused wildcard tests assert the
  retained fixture does not spill. The checker passed at
  `target/zone-image-bench/owner-override-inline-wire-check.tsv` with zero
  validation mismatches. The retained run measured mixed planning ratio
  `0.162`, mixed packet ratio `1.008`, hot packet ratio `1.039`, trace packet
  ratio `1.054`, optioned packet ratio `1.099`, boundary packet ratio `0.999`,
  and UDP-ceiling packet ratio `1.001`, keeping the packet-path no-slowdown
  gates green while removing the common wildcard-owner heap allocation.
- [x] Add retained owner-override direct-body accounting evidence:
  `target/zone-image-bench/owner-override-direct-body-metrics.tsv` reuses the
  compiled ownerless direct-copy length when planning wildcard/owner-override
  RRsets, so the owner-override wire-bound helper does not recompute non-owner
  RR bytes from the stored full-owner RRset wire for direct-copy answer shapes.
  Non-direct RDATA shapes keep the generic stored-wire fallback. The
  checker passed at
  `target/zone-image-bench/owner-override-direct-body-metrics-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.147`,
  mixed wire ratio `0.170`, mixed packet ratio `0.973`, hot packet ratio `0.978`,
  trace packet ratio `0.994`, optioned packet ratio `0.979`, boundary packet
  ratio `1.015`, UDP-ceiling packet ratio `1.012`, delegation/DNAME stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as
  narrow owner-override accounting cleanup rather than a broad packet-speed
  claim.
- [x] Retain per-RRset ownerless wire-length metadata without growing RRsets:
  `target/zone-image-bench/fixed-field-rrset-ownerless-len.tsv` moves the
  remaining owner-override non-owner byte derivation into compiled `ImageRrset`
  metadata, while removing duplicate scalar `rr_type`/`class` fields and reading
  TYPE/CLASS from carried fixed fields. This keeps `ImageRrset` at 48 bytes and
  keeps owner-override planning on a direct metadata read instead of deriving
  non-owner byte counts from stored full-owner RRset wire. The earlier naive
  `target/zone-image-bench/ownerless-wire-len-precompute.tsv` field-add remains
  rejected because it grew the stress fixture to `260.000` bytes/record. The
  retained checker passed at
  `target/zone-image-bench/fixed-field-rrset-ownerless-len-check.tsv` with zero
  validation/packet mismatches, base image bytes/record `174.000`,
  delegation/DNAME stress bytes/record `256.000`, mixed planning ratio `0.137`,
  mixed wire ratio `0.152`, mixed packet ratio `1.004`, hot packet ratio
  `1.004`, trace packet ratio `0.987`, optioned packet ratio `0.998`, boundary
  packet ratio `0.979`, UDP-ceiling packet ratio `0.989`, delegation/DNAME
  stress planning ratio `0.001`, and stress wire ratio `0.002`.
- [x] Add retained direct selected-section record evidence:
  `target/zone-image-bench/direct-selected-answer-record.tsv` first stored
  answer-section selected DNSSEC records directly in the immutable answer plan
  item instead of pushing them through `dynamic_answers`; the follow-up retained
  artifact `target/zone-image-bench/direct-selected-section-records.tsv`
  removes the selected-record variant from all dynamic buckets and stores
  authority/additional selected records in direct section vectors. Focused RRSIG
  tests assert selected answer, authority, and additional records stay out of
  synthesized dynamic buckets, while signed DNSSEC proof coverage still passes.
  The checker passed at
  `target/zone-image-bench/direct-selected-section-records-check.tsv` with zero
  validation mismatches. The retained run measured mixed planning ratio
  `0.147`, mixed packet ratio `0.992`, hot packet ratio `1.023`, trace packet
  ratio `1.005`, optioned packet ratio `1.003`, boundary packet ratio `0.990`,
  and UDP-ceiling packet ratio `0.996`.
- [x] Add retained direct synthesized-record helper evidence:
  `target/zone-image-bench/direct-synthesized-record-helpers.tsv` narrows the
  older rejected direct dynamic-record experiment to the only records that
  still live in the dynamic answer bucket: truly synthesized DNAME CNAME
  records. The answer composer now appends and counts synthesized records
  directly instead of constructing a transient wire-record view for that helper
  path. Focused DNAME and signed packet tests passed, and the checker passed at
  `target/zone-image-bench/direct-synthesized-record-helpers-check.tsv` with
  zero validation mismatches. The retained run measured mixed planning ratio
  `0.148`, mixed wire ratio `0.183`, mixed packet ratio `1.017`, hot packet
  ratio `1.076`, trace packet ratio `1.027`, optioned packet ratio `1.057`,
  boundary packet ratio `0.984`, UDP-ceiling packet ratio `0.992`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.002`.
- [x] Add retained inline wire-name compressor suffix-table evidence:
  `target/zone-image-bench/inline-wire-name-compressor-suffixes.tsv` replaces
  the generic `ZoneImage` packet composer's per-response `HashMap<Vec<u8>,
  u16>` suffix table with an inline small suffix table. The retained run
  measured about 435 ns/query mixed packet response, about 178 ns/query hot
  packet response, about 334 ns/query trace packet response, about 165 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/inline-wire-name-compressor-suffixes-check.tsv`.
- [x] Add retained combined packet plan-accounting evidence:
  `target/zone-image-bench/combined-packet-plan-accounting.tsv` computes
  generic packet response section counts and wire upper bounds in one private
  immutable-plan accounting pass before composing the packet. The retained run
  measured about 78 ns/query mixed planning, about 95 ns/query mixed wire
  emission, about 429 ns/query mixed packet response, about 169 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/combined-packet-plan-accounting-check.tsv`.
- [x] Measure and initially reject generic composer count patching:
  `target/zone-image-bench/generic-composer-count-patch.tsv` removed that
  private pre-encode accounting pass from the normal generic packet composer by
  emitting immutable plan records first, counting records during emission, and
  patching ANCOUNT/NSCOUNT/ARCOUNT before appending EDNS. Focused ZoneImage
  serving tests and the benchmark checker passed with zero mismatches and byte
  parity, but the retained local run regressed mixed packet ratio to `1.032`,
  hot packet ratio to `1.129`, trace packet ratio to `1.039`, and optioned
  packet ratio to `1.052`; only boundary and UDP-ceiling stayed flat or
  slightly improved. The code was reverted at that point. This historical
  rejection was later superseded by the narrower retained
  `target/zone-image-bench/one-pass-plan-record-composer.tsv` path, which also
  carried section counts into truncation retry, and then by
  `target/zone-image-bench/packet-known-counts-no-patch.tsv`, which writes
  known counts from compiled RRset metadata without a header patch. The normal
  path now uses `target/zone-image-bench/packet-encode-only-record-visitor.tsv`
  to avoid rebuilding section tags while encoding.
- [x] Add retained truncated wire-record response preallocation evidence:
  `target/zone-image-bench/truncated-wire-record-response-prealloc.tsv`
  pre-sizes truncated-response rebuild buffers from retained immutable
  wire-record owner/RDATA lengths instead of starting at header-plus-question
  capacity. The retained run measured about 75 ns/query mixed planning, about
  90 ns/query mixed wire emission, about 430 ns/query mixed packet response,
  about 163 ns/query delegation/DNAME stress planning, unchanged image bytes,
  zero validation mismatches, and a passing check at
  `target/zone-image-bench/truncated-wire-record-response-prealloc-check.tsv`.
- [x] Add retained precomputed referral DNSSEC proof relation evidence:
  `target/zone-image-bench/referral-dnssec-proof-relations.tsv` precomputes
  delegation-owner DS/NSEC proof relations for signed referrals, so DNSSEC
  referral augmentation can select those immutable RRsets without reparsing the
  NS owner and doing same-owner lookups per query. This is a signed-referral
  data-model closure rather than a broad mixed-profile win; the retained run
  measured about 82 ns/query mixed planning, about 96 ns/query mixed wire
  emission, about 439 ns/query mixed packet response, about 169 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/referral-dnssec-proof-relations-check.tsv`.
- [x] Add retained NXDOMAIN borrowed proof-label evidence:
  `target/zone-image-bench/nxdomain-borrowed-proof-labels.tsv` routes
  closest-encloser and wildcard-child NSEC/NSEC3 proof lookups through
  borrowed query-label views, avoiding temporary `DomainName` construction for
  those NXDOMAIN signed-denial proof names. This is a focused allocation and
  data-model cleanup rather than a broad mixed-profile win; the retained run
  measured about 79 ns/query mixed planning, about 94 ns/query mixed wire
  emission, about 448 ns/query mixed packet response, about 168 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/nxdomain-borrowed-proof-labels-check.tsv`.
- [x] Add retained lowercase denial label-view evidence:
  `target/zone-image-bench/query-lowercase-denial-label-view.tsv` carries the
  parser-proven lowercase-QNAME fact through NSEC/NSEC3 proof label views.
  Lowercase packet labels are compared and hashed directly for NSEC range checks
  and NSEC3 SHA-1 input, while public callers and mixed-case packets keep the
  conservative canonicalizing path. Focused DNSSEC NODATA, NSEC3 range, and
  NSEC3 EDE cap tests passed, the invariant audit guards the label-view hint,
  and the checker passed at
  `target/zone-image-bench/query-lowercase-denial-label-view-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.144`,
  mixed wire ratio `0.168`, mixed packet ratio `0.948`, hot packet ratio
  `0.996`, trace packet ratio `1.044`, optioned packet ratio `0.982`, boundary
  packet ratio `0.994`, UDP-ceiling packet ratio `1.015`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as duplicate lowercase-work removal in DNSSEC denial
  proof selection, not as physical throughput evidence.
- [x] Add retained DNAME synthesized target-wire reuse evidence:
  `target/zone-image-bench/dname-synthesized-target-wire-reuse.tsv` returns
  the synthesized DNAME target `DomainName` and its wire form from one checked
  suffix-replacement pass, so the synthesized CNAME RDATA does not serialize
  the generated target in a second pass. The retained run measured about 80
  ns/query mixed planning, about 94 ns/query mixed wire emission, about 426
  ns/query mixed packet response, about 166 ns/query delegation/DNAME stress
  planning, unchanged image bytes, zero validation mismatches, and a passing
  check at
  `target/zone-image-bench/dname-synthesized-target-wire-reuse-check.tsv`.
- [x] Add retained single-name target stored-wire evidence:
  `target/zone-image-bench/single-name-target-wire-range.tsv` keeps CNAME/DNAME
  target chain semantics on the precomputed `DomainName`, but DNAME synthesis
  now appends the already-compiled single-name RDATA wire from the target
  RRset's first record instead of serializing the stored target name on each
  query. The allocating `with_replaced_wire_suffix_and_wire` helper is now
  test-only; runtime uses the stored-wire variant. Focused CNAME/DNAME tests
  and the full ZoneImage test filter pass, and
  `target/zone-image-bench/single-name-target-wire-range-check.tsv` reports
  zero validation mismatches, unchanged response bytes, mixed planning ratio
  `0.129`, mixed wire ratio `0.151`, mixed packet ratio `1.001`, hot packet
  ratio `1.063`, trace packet ratio `1.037`, optioned packet ratio `1.010`,
  boundary packet ratio `1.015`, UDP-ceiling packet ratio `1.001`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.002`,
  hot bytes per record `98.499`, and stress hot bytes per record `134.204`.
  This is retained as narrow DNAME target-wire serialization cleanup without
  adding hot image metadata.
- [x] Add retained single-name target RDATA-range evidence:
  `target/zone-image-bench/single-name-target-rdata-range.tsv` carries the
  already-validated CNAME/DNAME target `RdataRange` in `ImageSingleNameTarget`,
  so target-wire access slices the RDATA arena directly from the precomputed
  target view instead of re-indexing the owning RRset's first record at query
  time. Focused CNAME/DNAME target tests and the invariant audit cover this
  direct arena-slice path, and
  `target/zone-image-bench/single-name-target-rdata-range-check.tsv` reports
  zero validation mismatches, unchanged response bytes, mixed planning ratio
  `0.140`, mixed wire ratio `0.164`, mixed packet ratio `1.000`, hot packet
  ratio `0.945`, trace packet ratio `0.975`, optioned packet ratio `0.987`,
  boundary packet ratio `1.002`, UDP-ceiling packet ratio `0.992`,
  delegation/DNAME stress planning and wire ratios of `0.001`, hot bytes per
  record `106.359` under the `160.000` gate, and stress hot bytes per record
  `144.140` under the `160.000` gate. Total bytes per record remain within the
  checker limits, with the stress case exactly at the retained `256.000` ceiling.
- [x] Add retained DNAME synthesized-target node-hint evidence:
  `target/zone-image-bench/dname-target-node-hint.tsv` uses the precomputed
  literal DNAME target classification when resolving the generated CNAME target:
  existing in-zone targets walk only the query prefix from the compiled target
  node, known-missing in-zone targets skip the target-node walk, and out-of-zone
  literal targets keep the conservative full lookup because left-prefixing can
  synthesize an in-zone name. Focused DNAME tests cover that conservative case,
  and `target/zone-image-bench/dname-target-node-hint-check.tsv` reports zero
  validation mismatches, unchanged response bytes, mixed planning ratio
  `0.108`, mixed wire ratio `0.130`, mixed packet ratio `0.993`, hot packet
  ratio `1.040`, trace packet ratio `1.011`, optioned packet ratio `1.001`,
  boundary packet ratio `1.011`, UDP-ceiling packet ratio `1.003`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.001`.
- [x] Add retained DNAME owner-label-count evidence:
  `target/zone-image-bench/dname-owner-label-count.tsv` uses the existing
  `ImageRrset` padding after `record_count` to carry a compiled owner label
  count without increasing the hot RRset struct size. DNAME synthesis passes
  that count into the stored-wire suffix-replacement helper instead of parsing
  the stored DNAME owner wire only to find the query-prefix boundary. Focused
  DNAME tests, filtered ZoneImage tests, invariant audit, and check build
  passed. The checker passed at
  `target/zone-image-bench/dname-owner-label-count-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.132`,
  mixed wire ratio `0.152`, mixed packet ratio `0.996`, hot packet ratio
  `0.980`, trace packet ratio `0.996`, optioned packet ratio `0.991`, boundary
  packet ratio `1.031`, UDP-ceiling packet ratio `1.002`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as DNAME synthesized-target planning cleanup, not
  a broad packet-path timing claim.
- [x] Add retained DS-at-delegation owner-label-count evidence:
  `target/zone-image-bench/ds-delegation-owner-label-count.tsv` reuses the
  compiled `ImageRrset::owner_label_count` for the DS-at-cut exception, so
  below-cut DS queries can reject owner mismatches before scanning stored
  delegation owner wire. Focused DS-at-delegation tests, filtered ZoneImage
  tests, invariant audit, and check build passed. The checker passed at
  `target/zone-image-bench/ds-delegation-owner-label-count-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.129`,
  mixed wire ratio `0.161`, mixed packet ratio `0.995`, hot packet ratio
  `0.992`, trace packet ratio `0.991`, optioned packet ratio `0.992`, boundary
  packet ratio `1.038`, UDP-ceiling packet ratio `1.005`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as narrow delegation-exception planning cleanup,
  not a broad packet-path timing claim.
- [x] Add retained semantic DS-at-delegation node-owner evidence:
  `target/zone-image-bench/semantic-ds-delegation-node-owner.tsv` removes the
  remaining semantic planner stored-owner wire scan for the DS-at-delegation
  exception. The referral guard now accepts DS at the delegation owner only when
  the query resolved to the exact trie node and that node owns the compiled
  delegation policy RRset; below-cut DS queries still return the referral, and
  safe QCLASS=ANY images use the same compiled ownership check. Focused
  DS-at-delegation and node-policy tests passed, and the invariant audit now
  rejects reintroducing a stored-owner wire scan in `lookup_response_plan`. The
  checker passed at
  `target/zone-image-bench/semantic-ds-delegation-node-owner-check.tsv` with
  zero validation/packet mismatches, byte parity, hot bytes per record
  `106.359`, total bytes per record `174.000`, delegation/DNAME stress bytes
  per record `256.000`, mixed planning ratio `0.142`, mixed wire ratio
  `0.163`, mixed packet ratio `1.016`, hot packet ratio `1.038`, trace packet
  ratio `1.007`, optioned packet ratio `0.985`, boundary packet ratio `1.008`,
  UDP-ceiling packet ratio `1.002`, delegation/DNAME-stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as semantic
  delegation planner cleanup, not as a broad packet-speed claim.
- [x] Add retained NSEC3 fixed digest-buffer evidence:
  `target/zone-image-bench/nsec3-fixed-digest-buffer.tsv` keeps iterative
  NSEC3 SHA-1 hashes in the fixed 20-byte digest buffer instead of converting
  each intermediate hash to a heap `Vec<u8>`. This is a DNSSEC/NSEC3
  allocation cleanup rather than a broad mixed-profile win; the retained run
  measured about 83 ns/query mixed planning, about 97 ns/query mixed wire
  emission, about 434 ns/query mixed packet response, about 169 ns/query
  delegation/DNAME stress planning, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/nsec3-fixed-digest-buffer-check.tsv`.
- [x] Add retained NSEC arena-key evidence:
  `target/zone-image-bench/nsec-range-arena-keys.tsv` stores NSEC owner/next
  canonical range keys as compact lowercase length-prefixed byte ranges in the
  image arena instead of two heap `Vec<Vec<u8>>` keys per range. NSEC proof
  lookup now compares query label views directly against those arena keys, and
  the old `DomainName::canonical_order_key` heap helper was removed. Focused
  NSEC/DNSSEC tests and the full ZoneImage test filter pass, and
  `target/zone-image-bench/nsec-range-arena-keys-check.tsv` reports zero
  validation mismatches, unchanged response bytes, mixed planning ratio
  `0.117`, mixed wire ratio `0.140`, mixed packet ratio `1.073`, hot packet
  ratio `1.113`, trace packet ratio `1.041`, optioned packet ratio `1.115`,
  boundary packet ratio `1.000`, UDP-ceiling packet ratio `1.002`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  hot bytes per record `98.499`, and stress hot bytes per record `134.204`.
  The retained 10k fixture records main image hot bytes `988532` and cold bytes
  `680682`, keeping the change inside local gates while reducing NSEC metadata
  pointer chasing.
- [x] Add retained DNSSEC query-node gating evidence:
  `target/zone-image-bench/dnssec-query-node-gated-to-wildcard.tsv` avoids
  exact/closest query-node walks during DNSSEC augmentation for ordinary
  positive plans whose answer section has only direct immutable RRsets, while
  still doing the walk for denial responses and possible wildcard synthesis.
  This is a targeted positive-DO planning cleanup rather than a broad
  mixed-profile win; the retained run measured about 82 ns/query mixed
  planning, about 96 ns/query mixed wire emission, about 429 ns/query mixed
  packet response, about 177 ns/query delegation/DNAME stress planning,
  unchanged image bytes, zero validation mismatches, and a passing check at
  `target/zone-image-bench/dnssec-query-node-gated-to-wildcard-check.tsv`.
- [x] Add retained explicit wildcard-synthesis plan flag evidence:
  `target/zone-image-bench/wildcard-synthesis-denial-only-handles.tsv`
  replaces the conservative "any custom answer item might be wildcard" DNSSEC
  gate with an explicit plan flag set by wildcard owner-substitution paths.
  DNSSEC augmentation now uses that flag directly for wildcard proof selection
  and reserves exact/closest query-node walks for denial responses. This lets
  DNAME-synthesized positive responses keep their generated CNAME record
  without paying wildcard-proof classification work. The retained run measured
  about 80 ns/query mixed planning, about 91 ns/query mixed wire emission,
  about 429 ns/query mixed packet response, about 161 ns/query delegation/DNAME
  stress planning, unchanged image bytes, zero validation mismatches, and a
  passing check at
  `target/zone-image-bench/wildcard-synthesis-denial-only-handles-check.tsv`.
- [x] Add retained indirection target-node reuse evidence:
  `target/zone-image-bench/indirection-target-node-reuse.tsv` computes the
  generated CNAME/DNAME target node once and reuses it for requested-type
  lookup, CNAME-chain lookup, and NODATA/NXDOMAIN classification instead of
  walking the compiled trie separately for each branch. This is a targeted
  CNAME/DNAME planning cleanup rather than a broad packet-path win; the
  retained run measured about 79 ns/query mixed planning, about 92 ns/query
  mixed wire emission, about 442 ns/query mixed packet response, about 158
  ns/query delegation/DNAME stress planning, unchanged image bytes, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/indirection-target-node-reuse-check.tsv`.
- [x] Add retained indirection chain node-identity evidence:
  `target/zone-image-bench/indirection-chain-node-identity.tsv` tracks
  existing in-zone CNAME/DNAME chain targets by compiled trie node handle
  instead of building a canonical-key string for generated in-zone DNAME
  targets. Missing precomputed CNAME targets still use borrowed keys where
  needed. This is a targeted indirection planning cleanup rather than a broad
  packet-path win; the retained run measured about 70 ns/query mixed planning,
  about 86 ns/query mixed wire emission, about 433 ns/query mixed packet
  response, about 137 ns/query delegation/DNAME stress planning, unchanged
  image bytes, zero validation mismatches, and a passing check at
  `target/zone-image-bench/indirection-chain-node-identity-check.tsv`.
- [x] Add retained referral NSEC3 owner-wire evidence:
  `target/zone-image-bench/referral-nsec3-owner-wire.tsv` hashes the stored
  delegation-owner wire name directly for the referral NSEC3 fallback path,
  avoiding the previous query-time owner-wire parse into a `DomainName` when no
  precomputed DS/NSEC referral proof relation applies. This is a targeted
  signed-referral planning cleanup rather than a broad packet-path win; the
  retained run measured about 74 ns/query mixed planning, about 92 ns/query
  mixed wire emission, about 446 ns/query mixed packet response, about 147
  ns/query delegation/DNAME stress planning, unchanged image bytes, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/referral-nsec3-owner-wire-check.tsv`.
- [x] Add retained single-name target-node hint evidence:
  `target/zone-image-bench/single-name-target-node-hint.tsv` stores each
  literal CNAME/DNAME single-name target's in-zone/existing-node classification
  in the compiled image, so ordinary CNAME target resolution can reuse a
  precomputed node handle instead of walking the trie for the static target on
  each query. Dynamic DNAME-generated targets still classify the synthesized
  target once per query. The retained run measured about 69 ns/query mixed
  planning, about 84 ns/query mixed wire emission, about 418 ns/query mixed
  packet response, about 140 ns/query delegation/DNAME stress planning, 16
  additional hot bytes on the 10k-record fixture, zero validation mismatches,
  and a passing check at
  `target/zone-image-bench/single-name-target-node-hint-check.tsv`.
- [x] Add retained DNAME out-of-zone target hint split evidence:
  `target/zone-image-bench/dname-out-of-zone-parent-suffix-hint.tsv` splits
  literal out-of-zone DNAME targets into parent-suffix targets that can
  synthesize back into the zone and unrelated out-of-zone targets that cannot.
  Parent-suffix targets keep the conservative synthesized-target lookup;
  unrelated out-of-zone targets now stay out-of-zone without a trie walk for
  the synthesized name. Focused tests cover both cases, the invariant audit
  guards the builder/runtime classification split, and the checker artifact
  `target/zone-image-bench/dname-out-of-zone-parent-suffix-hint-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed
  planning ratio `0.166`, mixed wire ratio `0.191`, mixed packet ratio
  `1.035`, hot packet ratio `1.130`, trace packet ratio `1.040`, boundary
  packet ratio `1.024`, UDP-ceiling packet ratio `1.037`, delegation/DNAME
  stress planning ratio `0.002`, and unchanged image bytes per record
  (`174.000` base, `256.000` stress). This is narrow DNAME planner no-scan
  cleanup, not a packet-throughput claim.
- [x] Add retained DNAME unrelated out-of-zone wire-only evidence:
  `target/zone-image-bench/dname-out-of-zone-wire-only.tsv` keeps the
  unrelated out-of-zone DNAME branch terminal after the compiled target hint
  proves the generated CNAME target cannot re-enter the zone. That branch now
  uses the counted suffix-replacement helper to build only the generated CNAME
  RDATA wire and avoids materializing a synthesized `DomainName` that would
  not be used for target lookup or CNAME continuation. Focused suffix and DNAME
  tests pass, the invariant audit guards the wire-only branch, and the checker
  artifact `target/zone-image-bench/dname-out-of-zone-wire-only-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed
  planning ratio `0.168`, mixed wire ratio `0.190`, mixed packet ratio
  `1.045`, hot packet ratio `0.979`, trace packet ratio `1.063`, optioned
  packet ratio `1.050`, boundary packet ratio `1.000`, UDP-ceiling packet
  ratio `1.014`, delegation/DNAME stress planning ratio `0.002`, and
  delegation/DNAME stress wire ratio `0.002`. This is narrow DNAME
  allocation/planning cleanup, not template/WireArena completion.
- [x] Add retained DNAME target-wire inline serialization evidence:
  `target/zone-image-bench/dname-target-wire-inline-serialize.tsv` makes the
  counted suffix-replacement helper write generated DNAME CNAME target wire
  directly into the inline name buffer, avoiding the earlier prefix-label
  length sum whose only purpose was pre-sizing that same buffer before
  serialization. The synthesized-name path still builds a `DomainName` when
  target classification or CNAME continuation needs it, while the terminal
  out-of-zone branch remains wire-only. Focused suffix and DNAME tests pass,
  the invariant audit guards the no-prefix-sizing-walk shape, and the checker
  artifact `target/zone-image-bench/dname-target-wire-inline-serialize-check.tsv`
  passed with zero validation and packet mismatches, byte parity, mixed
  planning ratio `0.152`, mixed wire ratio `0.166`, mixed packet ratio
  `1.005`, hot packet ratio `0.964`, trace packet ratio `1.000`, optioned
  packet ratio `0.990`, boundary packet ratio `1.007`, UDP-ceiling packet
  ratio `1.013`, and delegation/DNAME stress plan and wire ratios of `0.002`.
  This is narrow DNAME generated-target bookkeeping cleanup, not
  template/WireArena completion.
- [x] Add retained CNAME handle-only resolution evidence:
  `target/zone-image-bench/cname-handle-only-resolution.tsv` narrows
  `resolve_cname_at` so live CNAME continuation always receives the already
  discovered CNAME RRset handle instead of carrying a name-based fallback
  lookup. The broader `find_rrset` helper is now test-only inspection surface.
  Focused CNAME and full ZoneImage tests pass, and
  `target/zone-image-bench/cname-handle-only-resolution-check.tsv` reports zero
  validation mismatches, unchanged response bytes, mixed planning ratio
  `0.122`, mixed wire ratio `0.150`, mixed packet ratio `1.050`, hot packet
  ratio `1.053`, trace packet ratio `1.044`, optioned packet ratio `0.999`,
  boundary packet ratio `1.016`, UDP-ceiling packet ratio `1.017`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.001`.
- [x] Add retained single-name target key-retirement evidence:
  `target/zone-image-bench/single-name-target-node-key-retired.tsv` removes the
  leftover per-target canonical-key string and missing-target loop key path now
  that existing in-zone CNAME targets are tracked by compiled node handle and
  missing or out-of-zone targets terminate immediately. The retained run
  measured about 70 ns/query mixed planning, about 87 ns/query mixed wire
  emission, about 417 ns/query mixed packet response, about 142 ns/query
  delegation/DNAME stress planning, about 48 fewer hot bytes and 36 fewer cold
  bytes on the 10k-record fixture compared with the preceding node-hint slice,
  zero validation mismatches, and a passing check at
  `target/zone-image-bench/single-name-target-node-key-retired-check.tsv`.
- [x] Measure and reject synthesized DNAME additional-target node storage:
  `target/zone-image-bench/dname-synthesized-additional-node.tsv` stored the
  generated DNAME CNAME target's compiled node handle on the synthesized record
  so additional-data planning could avoid reparsing the CNAME RDATA. It
  preserved zero validation mismatches, but the retained local run did not
  improve the planning profile and regressed packet timing to about 451
  ns/query mixed packet response, so the code was reverted. The rejected
  artifact has a passing check at
  `target/zone-image-bench/dname-synthesized-additional-node-check.tsv`.
- [x] Add retained apex SOA handle evidence:
  `target/zone-image-bench/apex-soa-handle.tsv` stores the normal IN apex SOA
  RRset handle in the compiled image, so IN and ANY-class NODATA/NXDOMAIN
  planning does not scan apex RRsets to find the negative-response SOA. The
  retained run measured about 70 ns/query mixed planning, about 86 ns/query
  mixed wire emission, about 430 ns/query mixed packet response, about 142
  ns/query delegation/DNAME stress planning, unchanged image bytes, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/apex-soa-handle-check.tsv`.
- [x] Measure and reject direct-answer template wire storage:
  `target/zone-image-bench/direct-answer-template-wire.tsv` stored each
  direct-answer RRset's question-pointer answer-section bytes in the image.
  It preserved zero validation mismatches, but it increased the 10k-record
  fixture from about 160 to 184 bytes per record and regressed mixed packet
  response timing to about 434 ns/query, so the code was reverted.
- [x] Measure and reject direct-answer owner-length substitution:
  `target/zone-image-bench/direct-answer-owner-length.tsv` keeps the compact
  RRset wire layout but let the direct positive-answer fast path use the
  encoded question-name length as the immutable RR owner span. The broad
  workspace test caught that the generic builder may offer custom CNAME and
  wildcard plans with one final RRset to the direct-response helper; after
  adding the required plain-direct-plan gate, the owner-length substitution no
  longer produced a retained packet-path win, so the code was reverted.
- [x] Add retained direct fast-path shape-gate evidence:
  `target/zone-image-bench/direct-fast-path-shape-gate.tsv` rejects custom
  answer-item plans before the direct positive-answer packet helper tries to
  compare owners or parse immutable RRset wire. This keeps CNAME, wildcard, and
  generated-answer plans on the generic composer path and preserves the direct
  helper for plain exact-owner RRset responses. The retained run measured about
  73 ns/query mixed planning, about 87 ns/query mixed wire emission, about 417
  ns/query mixed packet response, unchanged image bytes, zero validation
  mismatches, a focused wildcard-CNAME-to-final-A rejection test, and a passing
  check at `target/zone-image-bench/direct-fast-path-shape-gate-check.tsv`.
- [x] Add retained direct fast-path owner-precheck evidence:
  `target/zone-image-bench/direct-owner-precheck.tsv` compares the compiled
  RRset owner wire against parsed question labels before allocating or encoding
  the direct exact-owner response, and reserves EDNS slack only when EDNS is
  present. A focused mixed-case owner test verifies the precheck remains
  case-insensitive. The retained run measured about 70 ns/query mixed planning,
  about 90 ns/query mixed wire emission, about 431 ns/query mixed packet
  response, about 192 ns/query hot packet response, unchanged image bytes, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/direct-owner-precheck-check.tsv`. This is retained
  as direct-composer allocation discipline; the broad packet timing stayed
  within the local gate but was not a packet-path win.
- [x] Add retained direct answer-count header evidence:
  `target/zone-image-bench/direct-answer-compiled-count-header.tsv` writes the
  direct exact-owner response answer count from immutable RRset metadata instead
  of counting copied records and patching the header afterward. The focused
  direct fast-path tests cover two-record direct answers and opaque unknown
  RRsets; the retained run preserves zero validation mismatches and passes
  `target/zone-image-bench/direct-answer-compiled-count-header-check.tsv`.
  This is direct-composer accounting cleanup inside the local gates, not a
  broad packet-path win claim.
- [x] Add retained single direct-RRset view evidence:
  `target/zone-image-bench/direct-answer-single-rrset-view.tsv` fetches
  copied-answer owner wire, RRset wire, and record count from one immutable
  `ZoneImage` view before the direct exact-owner packet copy. The retained run
  preserves zero validation mismatches, byte parity, unchanged image bytes, and
  passes
  `target/zone-image-bench/direct-answer-single-rrset-view-check.tsv`. This is
  direct metadata-access cleanup inside the local gates, not a broad packet-path
  win claim.
- [x] Add retained direct-copy eligibility bitmap evidence:
  `target/zone-image-bench/direct-copy-eligibility-bitmap.tsv` moves the direct
  fast-path "can this RRset be copied without RDATA recompression" decision
  from a packet-time RR-type comparison chain into a compact compiled
  `ZoneImage` RRset bitmap. Focused direct-answer tests verify ordinary A
  RRsets are eligible and compressible CNAME RDATA is not. The retained checker
  passed at `target/zone-image-bench/direct-copy-eligibility-bitmap-check.tsv`
  with zero validation mismatches, byte parity, mixed packet ratio `1.001`, hot
  packet ratio `1.101`, and total image bytes still reported as 172 bytes per
  record on the generated 10k-record fixture. This is retained as a small
  precomputed direct-composer shape decision, not as a broad packet-path win.
  The later
  `target/zone-image-bench/direct-copy-eligibility-body-len.tsv` supersedes the
  side bitmap: direct-copy eligibility is derived from compiled
  `ImageRrset::direct_answer_body_len`, which is zero for ineligible RRsets and
  non-zero for any non-empty direct-copy body. The direct view therefore needs
  no second side-bitset lookup after loading the compiled RRset. The invariant
  audit rejects reintroducing `direct_copy_rrset_flags`, and the checker passed
  at `target/zone-image-bench/direct-copy-eligibility-body-len-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed packet ratio `1.011`,
  hot packet ratio `1.073`, trace packet ratio `1.049`, optioned packet ratio
  `1.058`, UDP-ceiling packet ratio `1.001`, hot bytes per record `106.358`,
  and stress hot bytes per record `142.141`.
  The follow-up `target/zone-image-bench/direct-eligible-view.tsv` makes that
  direct RRset view eligible-only: ineligible RRsets return `None` from the view
  constructor instead of carrying a post-view `direct_copy_eligible` flag for the
  packet composer to branch on. Focused direct-answer tests and the invariant
  audit passed, and the checker passed at
  `target/zone-image-bench/direct-eligible-view-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.144`, mixed
  wire ratio `0.160`, mixed packet ratio `0.992`, hot packet ratio `0.991`,
  trace packet ratio `1.029`, optioned packet ratio `1.046`, UDP-ceiling packet
  ratio `1.008`, hot bytes per record `106.358`, and stress hot bytes per record
  `142.141`. This is retained as direct-composer branch removal, not a broad
  packet-throughput claim.
  The retained `target/zone-image-bench/direct-nonempty-view.tsv` follow-up
  removes the now-redundant `answer_count == 0` guard from the direct packet
  composer. The eligible direct view rejects zero-body RRsets and documents the
  non-empty invariant with a debug assertion. Focused direct-answer tests and the
  invariant audit passed, and the checker passed at
  `target/zone-image-bench/direct-nonempty-view-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.141`, mixed
  wire ratio `0.163`, mixed packet ratio `0.977`, hot packet ratio `1.020`,
  trace packet ratio `1.011`, optioned packet ratio `1.044`, boundary packet
  ratio `0.988`, UDP-ceiling packet ratio `1.004`, hot bytes per record
  `106.358`, and stress hot bytes per record `142.141`.
  The retained `target/zone-image-bench/direct-known-flags.tsv` run then writes
  direct response `NoError` and authoritative flags from the direct-plan
  invariant instead of calling the plan flag accessors again during header
  assembly. The debug assertions remain as the local invariant check, and the
  invariant audit rejects reintroducing dynamic flag reads in the direct header.
  Focused direct-answer tests and the invariant audit passed, and the checker
  passed at `target/zone-image-bench/direct-known-flags-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.149`, mixed
  wire ratio `0.169`, mixed packet ratio `1.011`, hot packet ratio `0.996`,
  trace packet ratio `1.020`, optioned packet ratio `1.034`, boundary packet
  ratio `0.982`, UDP-ceiling packet ratio `1.017`, hot bytes per record
  `106.358`, and stress hot bytes per record `142.141`.
  The follow-up `target/zone-image-bench/direct-shared-edns-append.tsv` routes
  direct OPT emission through the same `append_zone_image_response_edns` helper
  used by the generic and truncated `ZoneImage` composers, removing the inline
  direct-path `encode_opt_record` branch while preserving the same response
  bytes. The invariant audit now requires the shared helper in the direct
  response builder and rejects reintroducing inline direct OPT encoding. The
  checker passed at
  `target/zone-image-bench/direct-shared-edns-append-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.137`, mixed
  wire ratio `0.162`, mixed packet ratio `0.963`, hot packet ratio `0.953`,
  trace packet ratio `0.946`, optioned packet ratio `0.957`, boundary packet
  ratio `0.989`, UDP-ceiling packet ratio `0.995`, hot bytes per record
  `106.358`, and stress hot bytes per record `142.141`.
- [x] Add retained rejected-direct-plan reuse evidence:
  `target/zone-image-bench/rejected-direct-plan-reuse.tsv` keeps a direct
  semantic plan when direct-copy emission rejects it, then feeds that same plan
  to the generic composer instead of running semantic response planning again.
  This keeps the previously rejected direct-copy eligibility gate out of the
  planner: CNAME/PTR/SOA-style direct semantic plans can still be attempted and
  then composed generically from the retained plan. Focused tests cover a CNAME
  direct semantic plan rejected by direct-copy emission and then served by the
  generic `ZoneImage` composer with direct-answer metrics left false. The
  invariant audit now requires rejected direct-plan retention. The checker
  passed at `target/zone-image-bench/rejected-direct-plan-reuse-check.tsv` with
  zero validation/packet mismatches, byte parity, unchanged hot bytes per
  record `106.359`, exact lookup ratio `0.189`, hot exact lookup ratio
  `0.226`, high-fanout exact lookup ratio `0.117`, mixed planning ratio
  `0.141`, mixed wire ratio `0.165`, mixed packet ratio `0.978`, hot packet
  ratio `0.901`, trace packet ratio `0.966`, optioned packet ratio `0.936`,
  boundary packet ratio `0.999`, UDP-ceiling packet ratio `0.996`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as direct/generic planner handoff cleanup before
  transport work.
- [x] Measure and reject gating direct plans on direct-copy eligibility:
  `target/zone-image-bench/direct-plan-eligibility-gate.tsv` moved the
  direct-copy eligibility check from packet composition into
  `lookup_direct_answer_plan`, avoiding throwaway direct plans for compressible
  CNAME/PTR/SOA-style RDATA. The checker passed at
  `target/zone-image-bench/direct-plan-eligibility-gate-check.tsv` with zero
  validation mismatches and byte parity, but exact lookup regressed to about 52
  ns/query, mixed packet response regressed to about 422 ns/query, and optioned
  packet response regressed to about 282 ns/query on this profile, so the code
  was reverted.
- [x] Measure and reject incremental truncated-DNSSEC retained-count tracking:
  `target/zone-image-bench/truncation-dnssec-count-incremental.tsv` replaced
  the truncated `ZoneImage` retry loop's per-iteration DNSSEC-record scan with
  an initially counted retained-DNSSEC total that was decremented as records
  were removed. Focused truncation tests and the signed packet corpus passed,
  and the benchmark checker passed at
  `target/zone-image-bench/truncation-dnssec-count-incremental-check.tsv` with
  zero validation mismatches and byte parity, but boundary packet ratio
  regressed to `1.030` and UDP-ceiling packet ratio regressed to `1.047`, so
  the code was reverted.
- [x] Measure and reject retained truncation wire-bound decrementing:
  `target/zone-image-bench/truncation-retained-wire-bound.tsv` reused the
  immutable plan wire upper bound for truncated-response retries and decremented
  that bound as records were removed. Focused truncation tests and the signed
  packet corpus passed, and the benchmark checker passed at
  `target/zone-image-bench/truncation-retained-wire-bound-check.tsv` with zero
  validation mismatches and byte parity, but it did not improve the target
  boundary/UDP truncation path and regressed the local mixed, trace, and
  optioned packet ratios versus the retained truncation-accounting baseline
  (`mixed_packet_ratio` `1.029`, `trace_packet_ratio` `1.042`,
  `optioned_packet_ratio` `1.080`), so the code was reverted.
- [x] Add retained question-compression label-seed evidence:
  `target/zone-image-bench/question-compression-label-seed.tsv` seeds the
  generic and truncated `ZoneImage` response compressor from parsed question
  labels after writing the question, avoiding the previous scan of serialized
  question wire. The retained run measured about 70 ns/query mixed planning,
  about 84 ns/query mixed wire emission, about 391 ns/query mixed packet
  response, about 180 ns/query hot packet response, unchanged image bytes, zero
  validation mismatches, and a passing check at
  `target/zone-image-bench/question-compression-label-seed-check.tsv`.
- [x] Add retained single-pass label compression evidence:
  `target/zone-image-bench/question-compression-single-pass-labels.tsv` keeps
  the parsed-label compressor seed and tracks remaining suffix wire length in
  one pass instead of recomputing each label suffix length while registering
  question-name compression pointers. The retained run measured about 75
  ns/query mixed planning, about 85 ns/query mixed wire emission, about 405
  ns/query mixed packet response, about 192 ns/query hot packet response,
  unchanged image bytes, zero validation mismatches, and a passing check at
  `target/zone-image-bench/question-compression-single-pass-labels-check.tsv`.
  This is retained as a small composer work cleanup, not a broad packet-path
  timing claim.
- [x] Add retained minimal ANY single-pass selection evidence:
  `target/zone-image-bench/minimal-any-single-pass-selection.tsv` keeps full
  QTYPE=ANY ordering unchanged, but handles the default minimal ANY policy by
  selecting the lowest class/type same-owner RRset in one scan instead of
  collecting all candidates, sorting them, and truncating to one. Focused tests
  cover both `ZoneImage` ANY planning and the public minimal ANY response. The
  retained run measured about 72 ns/query mixed planning, about 93 ns/query
  mixed wire emission, about 398 ns/query mixed packet response, about 179
  ns/query hot packet response, unchanged image bytes, zero validation
  mismatches, and a passing check at
  `target/zone-image-bench/minimal-any-single-pass-selection-check.tsv`.
- [x] Measure and reject inline generated-owner wire storage:
  `target/zone-image-bench/inline-generated-owner-wire.tsv` stored wildcard
  owner overrides and synthesized-answer owner names in inline `SmallVec`
  buffers instead of heap `Vec` values. It preserved zero validation
  mismatches and image bytes, but the retained local run regressed mixed
  planning to about 82 ns/query, mixed wire emission to about 100 ns/query, and
  mixed packet response to about 439 ns/query, so the code was reverted.
- [x] Measure and reject inline synthesized-record wire storage:
  `target/zone-image-bench/inline-synthesized-record-wire.tsv` narrowed the
  inline-buffer experiment to DNAME-generated CNAME owner and target wire. It
  preserved zero semantic and packet mismatches, but made every
  `ZoneImageLookupPlan` carry larger inline dynamic-record buffers and moved
  mixed planning from about 57 ns/query to about 69 ns/query, mixed wire
  emission from about 71 ns/query to about 79 ns/query, and
  delegation/DNAME-stress planning from about 124 ns/query to about
  142 ns/query. The checker passed at
  `target/zone-image-bench/inline-synthesized-record-wire-check.tsv`, but the
  code was reverted because the supported packet path did not benefit.
- [x] Measure and reject direct dynamic-record wire-length accounting:
  `target/zone-image-bench/direct-dynamic-record-wire-len.tsv` computed
  synthesized and selected dynamic-record lengths without first constructing a
  transient wire-record view. The retained run preserved zero validation
  mismatches and image bytes, but did not produce a clear packet-path win:
  mixed packet response was about 421 ns/query while trace and optioned packet
  ratios worsened relative to the retained truncation-accounting baseline, so
  the code was reverted. A later, narrower synthesized-record-only helper
  cleanup was retained after selected DNSSEC records moved out of dynamic
  buckets.
- [x] Measure and supersede the first per-record RDATA encoding-hint experiment:
  `target/zone-image-bench/precomputed-rdata-encoding.tsv` moved the
  ZoneImage packet composer's known-RDATA shape classification into immutable
  `ImageRecord` metadata. It preserved zero validation mismatches, but raised
  image bytes per record from 160 to 168 and worsened retained local packet
  timings across mixed, hot, trace, optioned, boundary, and UDP-ceiling packet
  cases, so that hot-metadata version was reverted. This rejection is superseded
  only by the later retained compact `RdataRange` packing that keeps
  `ImageRecord` at 8 bytes.
- [x] Measure and reject per-node IN delegation/DNAME covering handles:
  `target/zone-image-bench/in-covering-handles.tsv` moved ordinary IN-class
  delegation and DNAME ancestor discovery into each compiled trie node. It
  preserved zero validation mismatches and improved delegation/DNAME stress
  planning by about 2.5%, but raised image bytes per record from 160 to 168 and
  regressed mixed, hot, boundary, and UDP-ceiling packet timings, so the code
  was reverted.
- [x] Add retained unused `ZoneImage` side-array removal evidence:
  `target/zone-image-bench/drop-unused-zoneimage-side-arrays.tsv` removes the
  old published-image side arrays that collected delegation, DNAME, and NSEC
  RRset handles after relation spans, trie walks, and precomputed NSEC ranges
  became the serving model. The retained run preserved zero validation
  mismatches, kept the 10k-record fixture at 160 bytes/record, trimmed the
  delegation/DNAME stress image from 229 to 227 bytes/record, measured about 73
  ns/query mixed planning, about 84 ns/query mixed wire emission, about 412
  ns/query mixed packet response, and passed
  `target/zone-image-bench/drop-unused-zoneimage-side-arrays-check.tsv`.
- [x] Measure and reject direct question-label compressor registration:
  `target/zone-image-bench/question-label-compressor-register.tsv` avoided
  reparsing the already-encoded question owner when seeding the generic
  `ZoneImage` packet composer's wire-name compressor. It preserved zero
  validation mismatches and image bytes, and passed
  `target/zone-image-bench/question-label-compressor-register-check.tsv`, but
  regressed hot packet timing and mixed wire emission relative to the retained
  side-array cleanup baseline, so the code was reverted.
- [x] Measure and reject direct-answer body helper relocation:
  `target/zone-image-bench/direct-answer-zoneimage-body-helper.tsv` and
  `target/zone-image-bench/direct-answer-zoneimage-body-helper-rerun.tsv`
  moved direct-answer RRset body emission from the packet composer into
  `ZoneImage` so the fast path could avoid several fallible public accessors.
  The experiment preserved zero validation mismatches and image bytes, and the
  first run passed
  `target/zone-image-bench/direct-answer-zoneimage-body-helper-check.tsv`, but
  repeated local evidence did not produce a stable broad packet-path win and
  regressed mixed packet response, so the code was reverted.
- [x] Add retained DNAME suffix-comparison allocation cleanup:
  `target/zone-image-bench/dname-wire-suffix-no-alloc.tsv` removes the
  temporary wire-label vector from generated DNAME CNAME suffix replacement.
  The retained run preserved zero validation mismatches, kept image bytes at
  160 bytes/record and delegation/DNAME stress bytes at 227 bytes/record,
  measured about 71 ns/query mixed planning, about 414 ns/query mixed packet
  response, about 135 ns/query delegation/DNAME stress planning, about 148
  ns/query delegation/DNAME stress wire emission, and passed
  `target/zone-image-bench/dname-wire-suffix-no-alloc-check.tsv`.
- [x] Add retained NSEC3 raw-hash range comparison:
  `target/zone-image-bench/nsec3-raw-hash-ranges.tsv` stores decoded NSEC3
  owner/next hash bytes and keeps query hash-cache entries as fixed SHA-1
  bytes instead of base32 strings. The retained run preserved zero validation
  mismatches, kept image bytes at 160 bytes/record and delegation/DNAME stress
  bytes at 227 bytes/record, measured about 68 ns/query mixed planning, about
  84 ns/query mixed wire emission, about 413 ns/query mixed packet response,
  and passed `target/zone-image-bench/nsec3-raw-hash-ranges-check.tsv`.
- [x] Add retained NSEC3 fixed-hash-array metadata:
  `target/zone-image-bench/nsec3-fixed-hash-arrays.tsv` changes decoded NSEC3
  owner/next hash storage from heap vectors to inline SHA-1 arrays. The
  retained run preserved zero validation mismatches, kept image bytes at 160
  bytes/record and delegation/DNAME stress bytes at 227 bytes/record, measured
  about 67 ns/query mixed planning, about 83 ns/query mixed wire emission,
  about 418 ns/query mixed packet response, about 132 ns/query
  delegation/DNAME stress planning, and passed
  `target/zone-image-bench/nsec3-fixed-hash-arrays-check.tsv`. This is
  retained for NSEC3 data-model discipline and heap removal; it is not claimed
  as a broad packet-path win on this local profile.
- [x] Add retained NSEC3 owner-wire no-parse compile evidence:
  `target/zone-image-bench/nsec3-owner-wire-no-parse.tsv` keeps NSEC3 owner
  hash extraction on the stored uncompressed owner wire and decodes the
  base32hex hash label directly into fixed SHA-1 bytes instead of reparsing the
  owner into a `DomainName`, rebuilding owner/origin canonical strings, or
  decoding through a temporary vector. Focused owner-hash tests cover exact
  owner shape, case-insensitive origin suffix matching, rejection of extra
  prefix labels, and malformed/compressed owner-wire rejection. The retained
  checker `target/zone-image-bench/nsec3-owner-wire-no-parse-check.tsv` passed
  with zero semantic and packet mismatches, byte parity across mixed/hot/trace/
  optioned/boundary/UDP-ceiling packets, image bytes per record `174.000`,
  stress bytes per record `256.000`, mixed planning ratio `0.142`, mixed wire
  ratio `0.164`, mixed packet ratio `1.026`, hot packet ratio `1.088`, trace
  packet ratio `1.003`, optioned packet ratio `1.027`, boundary packet ratio
  `1.010`, UDP-ceiling packet ratio `1.021`, and delegation/DNAME stress
  planning and wire ratios `0.002`. This is retained as compile-time
  data-model discipline rather than a query hot-path optimization claim.
- [x] Add retained NSEC3 parameter-set descriptor-reuse evidence:
  `target/zone-image-bench/nsec3-param-set-descriptor-reuse.tsv` supersedes the
  earlier rejected broad interning experiment with a narrower layout: shared
  algorithm/iteration/salt tuples live in an image-wide parameter-set table,
  each NSEC3 range stores a compact `u16` handle, query hash-cache entries are
  keyed by that handle, and full parameter/salt views are materialized only on
  cache misses from the already-loaded range-loop descriptor. The focused NSEC3
  range test proves two ranges with the same parameters share one parameter
  set, and the invariant audit requires the parameter-set table, range handle,
  handle-keyed runtime hash cache, lazy miss-path parameter materialization, and
  descriptor reuse. The checker passed at
  `target/zone-image-bench/nsec3-param-set-descriptor-reuse-check.tsv` with
  zero trace and boundary packet mismatches, hot bytes/record `106.364`,
  bytes/record `174`, stress bytes/record `256`, mixed planning ratio `0.144`,
  mixed packet ratio `0.987`, hot packet ratio `0.985`, trace packet ratio
  `0.999`, boundary packet ratio `0.999`, and UDP-ceiling packet ratio `1.005`.
  This is retained as signed-denial data-path discipline, not as a broad
  packet-speed claim.
- [x] Add retained NSEC3 salt arena-range evidence:
  `target/zone-image-bench/nsec3-salt-arena-range.tsv` was the intermediate
  heap-removal step before the retained parameter-set handle layout: each NSEC3
  range stored `hash_algorithm`, `iterations`, and a `BlobRange` into the
  existing RDATA arena for the salt. Focused NSEC3 and full ZoneImage tests
  passed, and `target/zone-image-bench/nsec3-salt-arena-range-check.tsv`
  reported zero validation mismatches, unchanged response bytes, mixed planning
  ratio `0.133`, mixed wire ratio `0.154`, mixed packet ratio `1.008`, hot packet
  ratio `1.047`, trace packet ratio `1.020`, optioned packet ratio `1.040`,
  boundary packet ratio `0.993`, UDP-ceiling packet ratio `0.992`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  hot bytes per record `98.499`, and stress hot bytes per record `134.204`.
  This is retained as a focused NSEC3 metadata heap-removal cleanup rather than
  a parameter-table/indexing change.
- [x] Measure and reject NSEC3 SHA-1 label batching:
  `target/zone-image-bench/nsec3-sha1-label-batching.tsv` and
  `target/zone-image-bench/nsec3-sha1-label-stack-buffer.tsv` batched
  canonical label bytes before feeding SHA-1 instead of calling the digest
  writer per byte. Both variants preserved zero validation mismatches and
  passed their retained checks, but neither produced a stable planning or
  packet-path win over the fixed-hash-array baseline; the stack-buffer rerun
  still regressed mixed packet and UDP-ceiling timing on this local profile, so
  the code was reverted.
- [x] Measure and reject QTYPE=ANY concrete-qclass sort skipping:
  `target/zone-image-bench/qtype-any-specific-class-skip-sort.tsv` and
  `target/zone-image-bench/qtype-any-specific-class-skip-sort-rerun.tsv`
  skipped same-owner RRset sorting for concrete qclasses, relying on builder
  emission order while preserving the runtime sort for QCLASS=ANY. The focused
  ANY tests, broad packet differential checks, and benchmark checker all
  passed, but repeated local evidence did not produce a packet-path win and
  regressed mixed packet response versus the retained NSEC3 baseline, so the
  code was reverted.
- [x] Measure and reject per-node minimal-ANY RRset hints:
  `target/zone-image-bench/minimal-any-node-hints.tsv` stored preselected
  minimal-QTYPE=ANY RRset handles on every `NameNode` for QCLASS=IN and
  QCLASS=ANY. Focused ANY tests passed and the benchmark preserved zero
  semantic and packet mismatches, but the retained checker at
  `target/zone-image-bench/minimal-any-node-hints-check.tsv` failed because the
  delegation/DNAME stress fixture rose to `260.000` bytes per record against
  the `256.000` maximum. The code was reverted; this shortcut is not worth a
  permanent per-node field without a narrower representation.
- [x] Measure and reject wire-compressor suffix-length guard:
  `target/zone-image-bench/wire-compressor-suffix-len-guard.tsv` added a
  length equality guard before case-insensitive wire-suffix comparison in the
  generic `ZoneImage` packet compressor. Compression tests and the benchmark
  checker passed with zero mismatches, but the retained local run regressed
  mixed wire emission plus mixed, hot, trace, and optioned packet timings, so
  the code was reverted.
- [x] Measure and reject direct RRset accounting field reads:
  `target/zone-image-bench/rrset-accounting-direct-fields.tsv` made section
  count and wire-bound accounting read immutable RRset record counts and wire
  lengths directly instead of going through the existing helper calls. Focused
  accounting tests and the benchmark checker passed with zero mismatches, but
  the retained local run regressed mixed wire emission, mixed/hot/trace/optioned
  packet timing, and boundary/UDP-ceiling timing, so the code was reverted.
- [x] Measure and reject direct-answer exact-node fallback reuse:
  `target/zone-image-bench/direct-fallback-exact-node-reuse.tsv` reused the
  exact trie node found by the guarded direct-answer attempt when falling back
  to semantic planning for exact existing names. Focused direct-answer tests and
  the benchmark checker passed with zero mismatches, but the retained local run
  regressed mixed, hot, trace, optioned, boundary, and UDP-ceiling packet
  ratios on this profile, so the code was reverted.
- [x] Measure and reject direct-answer handle-first metrics emission:
  `target/zone-image-bench/direct-answer-handle-first.tsv` let the runtime
  direct-answer path carry only the selected RRset handle into packet emission
  and emit a fixed direct-answer metric instead of constructing a one-RRset
  plan first. Focused direct-answer tests and the benchmark checker passed with
  zero mismatches, but the retained local run regressed mixed, hot, trace, and
  optioned packet ratios on this profile, so the code was reverted.
- [x] Measure and reject direct-answer count prewrite:
  `target/zone-image-bench/direct-answer-count-prewrite.tsv` wrote the compiled
  RRset record count into the direct-answer header before copying RRset records
  instead of patching the emitted answer count after the direct copy loop.
  Focused direct-answer tests and the benchmark checker passed with zero
  mismatches, but the retained local run regressed mixed, hot, trace, optioned,
  boundary, and UDP-ceiling packet ratios on this profile, so the code was
  reverted.
- [x] Measure and reject direct-answer record-prefix precompute:
  `target/zone-image-bench/direct-answer-prefix-precompute.tsv` moved the
  constant compressed-owner/type/class/TTL direct-answer record prefix into
  `ImageRrset` instead of constructing the 10-byte prefix when the direct
  RRset view is selected. Focused ZoneImage tests passed and the benchmark kept
  zero semantic and packet mismatches, but the checker failed because the extra
  hot metadata raised the delegation/DNAME stress image to `258.000` bytes per
  record, above the retained `256.000` ceiling. A current-tree retest at
  `target/zone-image-bench/direct-answer-prefix-metadata-check.tsv` failed for
  the same reason, raising the stress image to `268.000` bytes per record while
  pushing stress hot bytes to `156.144` bytes per record. The code was
  reverted; the current design keeps the prefix in the selected direct view
  without growing every compiled RRset.
- [x] Measure and reject additional-planning single-pass gating:
  `target/zone-image-bench/additional-planning-single-pass.tsv` removed the
  preliminary "does any answer need additional address targets" scan and folded
  that gate into the answer loop that pushes precomputed additional RRsets.
  Focused additional-data tests, the mixed packet differential corpus, and the
  benchmark checker passed with zero mismatches, but the retained local run
  regressed the common mixed, hot, trace, and optioned packet ratios on this
  profile, so the code was reverted.
- [x] Remove dead old-layout DNSSEC augmentation from `ZoneSnapshot`:
  the old materialized `LookupResult` DNSSEC augmentation API and its NSEC3
  string-hash helpers were no longer called by runtime serving, tests, or
  benchmarks after DNSSEC-capable serving moved to `ZoneImage`. This removes a
  stale branch of the old query data model and adds an invariant-audit guard so
  `augment_lookup_result_with_dnssec` and the old snapshot NSEC3 helpers cannot
  silently reappear.
- [x] Move the remaining old materialized lookup API behind an explicit
  offline-oracle handle: tests and benchmarks now call the old owned-record
  query path through `ZoneSnapshot::offline_oracle().lookup(...)`, while
  `ZoneSnapshot` itself no longer exposes direct public `oracle_lookup` or
  generic serving-style lookup methods. The invariant audit rejects non-test
  runtime uses of the offline-oracle handle and rejects restoring generic
  `lookup`/`lookup_with_options` serving-style names on `ZoneSnapshot`.
- [x] Compile `ZoneImage` directly from snapshot RRsets:
  `target/zone-image-bench/compile-from-rrset-iter.tsv` moves the image
  compiler off `ZoneSnapshot::records()`, so publication-time image compilation
  no longer materializes a full `Vec<ResourceRecord>` just to regroup records
  into compiled RRsets. `ZoneSnapshot` exposes crate-private RRset/RDATA
  iteration for the safe builder path, while the old `records()` API remains
  available for AXFR/IXFR state updates and offline oracle code. Focused
  ZoneImage tests passed, and the benchmark checker passed at
  `target/zone-image-bench/compile-from-rrset-iter-check.tsv` with zero
  semantic and packet mismatches, byte parity, compile time `15.952 ms`, stress
  compile time `16.488 ms`, mixed planning ratio `0.117`, mixed wire ratio
  `0.140`, mixed packet ratio `1.026`, optioned packet ratio `0.992`,
  boundary packet ratio `0.980`, and UDP-ceiling packet ratio `0.971`. This is
  retained as builder/oracle-boundary cleanup, not as a packet hot-path change.
- [x] Borrow RDATA during deterministic `ZoneImage` compilation:
  `target/zone-image-bench/compile-borrowed-rrset-rdata.tsv` removes the
  temporary `BTreeMap<RrsetGroupKey, Vec<Vec<u8>>>` from `ZoneImage::compile`.
  The compiler now sorts borrowed snapshot RRset references for deterministic
  image order, sorts borrowed RDATA slices per RRset, and passes those slices
  into the builder without cloning every RDATA payload before immutable arena
  insertion. Focused ZoneImage tests passed, and the benchmark checker passed
  at `target/zone-image-bench/compile-borrowed-rrset-rdata-check.tsv` with zero
  semantic and packet mismatches, byte parity, compile time `5.802 ms`, stress
  compile time `7.086 ms`, mixed planning ratio `0.132`, mixed wire ratio
  `0.163`, mixed packet ratio `1.009`, trace packet ratio `1.002`, optioned
  packet ratio `0.991`, boundary packet ratio `1.035`, and UDP-ceiling packet
  ratio `1.003`. This keeps the previous builder/oracle-boundary cleanup and
  removes another publication-time clone/regroup pass.
- [x] Reuse sorted RRset owner keys during `ZoneImage` compilation:
  `target/zone-image-bench/compile-owner-key-reuse.tsv` threads the
  already-computed canonical owner key from the deterministic sort into the
  builder's RRset index insertion, avoiding a second canonical string build per
  compiled RRset. Focused ZoneImage tests passed, and the benchmark checker
  passed at `target/zone-image-bench/compile-owner-key-reuse-check.tsv` with
  zero semantic and packet mismatches, byte parity, compile time `5.444 ms`,
  stress compile time `11.810 ms`, mixed planning ratio `0.115`, mixed wire
  ratio `0.132`, mixed packet ratio `0.993`, trace packet ratio `0.970`,
  optioned packet ratio `1.032`, boundary packet ratio `1.005`, and
  UDP-ceiling packet ratio `0.994`. This is retained as publication-time
  builder allocation cleanup, not as a packet hot-path speed claim.
- [x] Parse RFC 9432 catalog zones from a narrow borrowed view:
  catalog-zone reconciliation now scans `CatalogZoneView` RRsets and RDATA
  slices for version TXT and member PTR records instead of naming the full
  `ZoneSnapshot` API or materializing the full snapshot through
  `ZoneSnapshot::records()`. Focused catalog tests passed, and the invariant
  audit now rejects reintroducing full snapshot record materialization or direct
  `ZoneSnapshot` dependency in the runtime catalog parser. This narrows
  whole-snapshot materialization toward explicitly named transfer rebuild use;
  it is management-path cleanup, not packet-path benchmark evidence.
- [x] Keep whole-snapshot record materialization crate-internal and
  transfer-named:
  `ZoneSnapshot::records()` has been removed as a generic materializer name.
  IXFR rebuilds now use crate-internal `ZoneSnapshot::transfer_records()`, and
  the invariant audit rejects restoring a generic whole-snapshot `records()`
  helper or re-exposing `Rrset` `ResourceRecord` materialization as public
  serving-style APIs.
- [x] Narrow public snapshot SOA access:
  `ZoneSnapshot::soa_record_view()` exposes a borrowed SOA view for cross-crate
  transfer query construction, while owned SOA materialization is renamed to the
  crate-internal `transfer_soa_record()` helper for IXFR delta-chain
  validation. The server IXFR query path now builds the query from that borrowed
   view instead of materializing an owned `ResourceRecord`, and the invariant
   audit rejects reintroducing a public `ZoneSnapshot::soa_record()` API. This is
   transfer-boundary cleanup, not packet-path benchmark evidence.
- [x] Keep RRset record materialization crate-internal:
  `Rrset::records()` and `Rrset::records_with_owner()` are no longer public
  APIs. They remain crate-internal helpers for the old offline oracle and
  transfer builder paths until those paths are either kept as explicit builder
  code or replaced with narrower borrowed views.
- [x] Guard old snapshot oracle boundary and documentation:
  `scripts/audit-invariants.sh` now rejects removing the `#[doc(hidden)]`
  annotation from the explicit `ZoneSnapshot::offline_oracle()` handle and
  rejects restoring direct public `ZoneSnapshot::oracle_lookup` methods. This
  is boundary hardening for the offline oracle, not packet-path performance
  evidence.
- [x] Publish transferred snapshots through shared `Arc<ZoneSnapshot>` handles:
  AXFR and IXFR updated outcomes now wrap the newly built snapshot once,
  publish that same handle through `ZoneStore::insert_snapshot_arc_for_transfer`,
  consume the published entry's cached control metadata, and keep the shared
  handle for success/catalog follow-up. This removes the previous full
  `ZoneSnapshot` clone and hand-built server-side metadata rebuild between
  transfer completion, publication, scheduler recording, serial logging, and
  catalog follow-up while preserving narrow `ZoneMetadata` outcomes for
  unchanged refreshes. Catalog follow-up uses the carried metadata origin key
  for its catalog configuration lookup before borrowing the snapshot for catalog
  RRset parsing.
  Focused AXFR, IXFR, refresh-current, refresh-AXFR-fallback, and
  catalog follow-up tests passed, and the invariant audit rejects restoring
  full-snapshot clones in the refresh updated path. The retained
  `target/zone-image-bench/transfer-snapshot-arc-publication.tsv` checker
  passed at
  `target/zone-image-bench/transfer-snapshot-arc-publication-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.141`,
  mixed packet ratio `0.982`, hot packet ratio `0.954`, trace packet ratio
  `0.969`, boundary packet ratio `1.008`, and UDP-ceiling packet ratio `1.021`.
  This is transfer-control old-layout cleanup, not packet hot-path evidence.
- [x] Add retained transfer snapshot cached-metadata evidence:
  `target/zone-image-bench/transfer-snapshot-cached-metadata-view.tsv` keeps
  the IXFR-current cached-metadata view inside the full local benchmark gates.
  The checker passed at
  `target/zone-image-bench/transfer-snapshot-cached-metadata-view-check.tsv`
  with zero trace and boundary packet mismatches, hot bytes/record `106.364`,
  bytes/record `174`, stress bytes/record `256`, control/full metadata ratio
  `0.767`, mixed planning ratio `0.153`, mixed packet ratio `1.002`, hot packet
  ratio `0.985`, trace packet ratio `0.980`, boundary packet ratio `0.989`,
  and UDP-ceiling packet ratio `0.988`. This is old-layout transfer-boundary
  cleanup, not packet hot-path evidence.
- [x] Use inline lowercase label keys while attaching compiled RRsets:
  `target/zone-image-bench/attach-inline-label-key.tsv` removes the
  per-RRset `Vec<Vec<u8>>` built only to walk the builder trie when attaching
  RRsets and computing single-name target node hints. The builder now borrows
  the relative label slice, walks labels in reverse, uses an inline lowercase
  label key for existing-edge lookup, and allocates a `Vec<u8>` only when a new
  trie edge is inserted. Focused ZoneImage tests passed, and the benchmark
  checker passed at `target/zone-image-bench/attach-inline-label-key-check.tsv`
  with zero semantic and packet mismatches, byte parity, compile time
  `5.337 ms`, stress compile time `7.998 ms`, mixed planning ratio `0.123`,
  mixed wire ratio `0.174`, mixed packet ratio `1.009`, trace packet ratio
  `1.047`, optioned packet ratio `1.050`, boundary packet ratio `1.012`, and
  UDP-ceiling packet ratio `1.029`. This is retained as another
  publication-time builder allocation cleanup.
- [x] Measure and reject owner-bucket RRset index:
  `target/zone-image-bench/owner-bucket-rrset-index-rejected.tsv` changed the
  builder RRset index from `(owner, type, class)` keys to owner-key buckets so
  relation precompute could look up by borrowed owner key and scan the common
  one-to-few type/class list. Correctness held, with zero semantic and packet
  mismatches and packet ratios inside the local gates, but compile time
  regressed to `8.291 ms` versus the previous retained
  `attach-inline-label-key` compile time of `5.337 ms`; the code was reverted.
  The checker output is retained at
  `target/zone-image-bench/owner-bucket-rrset-index-rejected-check.tsv`.
- [x] Measure and reject relation owner-key clone unrolling:
  `target/zone-image-bench/relation-owner-key-clone-unroll-rejected.tsv`
  unrolled DS/NSEC and A/AAAA builder relation lookups so the second lookup
  consumed the canonical owner key instead of cloning it again. Correctness
  held, the benchmark checker passed at
  `target/zone-image-bench/relation-owner-key-clone-unroll-rejected-check.tsv`
  with zero semantic and packet mismatches, byte parity, mixed planning ratio
  `0.125`, mixed wire ratio `0.159`, mixed packet ratio `1.014`, boundary
  packet ratio `1.016`, and UDP-ceiling packet ratio `0.984`, but stress
  compile time regressed to `9.654 ms` versus the recent retained
  `minimal-any-single-additional-span` stress compile time of `6.105 ms`; the
  code was reverted.
- [x] Add retained compiled node-policy hint evidence:
  `target/zone-image-bench/question-wire-len-no-copy.tsv`, building on
  `target/zone-image-bench/child-hash-inline-handle.tsv` and
  `target/zone-image-bench/node-policy-direct-build.tsv`, precomputes IN-class
  nearest delegation and nearest-DNAME policy into each `NameNode`, deriving
  inherited DNAME from the parent node when exact-owner DNAME must be skipped.
  Node policy handles are computed during final node emission instead of first
  allocating a temporary builder-side policy vector, and high-fanout nodes now
  store their child-hash side-index handle directly. Parsed questions now store
  only the consumed wire length instead of copying the question wire. The
  retained run reports zero validation mismatches, delegation/DNAME stress plan
  and wire ratios of `0.002`, main-zone hot bytes of `1,052,564`, stress-zone
  hot bytes of `1,041,776`, main/stress hot-byte-per-record checks of
  `104.910` and `130.173`, and mixed/hot/trace/optioned/boundary/UDP-ceiling
  packet ratios within the retained local gates. This is retained as
  allocation and build/layout cleanup, not a claimed packet-path win.
  `target/zone-image-bench/question-wire-len-no-copy-check.tsv` passed.
- [x] Add retained QCLASS=ANY policy-handle gate evidence:
  `target/zone-image-bench/qclass-any-policy-handles.tsv` keeps the non-IN
  class scan fallback for images containing non-IN delegation or DNAME policy
  RRsets, while allowing QCLASS=ANY to reuse compiled IN policy handles for
  IN-only images. The focused node-policy test covers both sides of the gate,
  and `scripts/audit-invariants.sh` now checks the stored image flags and
  planner/direct-answer guards. The checker passed at
  `target/zone-image-bench/qclass-any-policy-handles-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.131`,
  mixed wire ratio `0.162`, mixed packet ratio `0.994`, hot packet ratio
  `0.997`, trace packet ratio `0.996`, optioned packet ratio `0.991`,
  boundary packet ratio `1.035`, UDP-ceiling packet ratio `1.021`, and
  delegation/DNAME-stress planning and wire ratios of `0.001`.
- [x] Add retained direct delegation policy-owner evidence:
  `target/zone-image-bench/direct-delegation-policy-owner.tsv` lets the
  direct-answer DS delegation guard reuse the compiled IN/safe-ANY policy RRset
  handle by comparing the RRset owner label count against the current node
  depth. That avoids rescanning the current node for ordinary IN and IN-only
  QCLASS=ANY images while keeping the mixed-class fallback scan unchanged.
  Focused node-policy coverage and `scripts/audit-invariants.sh` cover the
  ownership-depth invariant. The checker passed at
  `target/zone-image-bench/direct-delegation-policy-owner-check.tsv` with zero
  validation/packet mismatches, byte parity, hot bytes per record `106.359`,
  total bytes per record `174.000`, delegation/DNAME stress bytes per record
  `256.000`, mixed planning ratio `0.143`, mixed wire ratio `0.167`, mixed
  packet ratio `1.050`, hot packet ratio `1.117`, trace packet ratio `1.049`,
  optioned packet ratio `1.005`, boundary packet ratio `1.215`,
  UDP-ceiling packet ratio `1.007`, delegation/DNAME-stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as policy-branch
  discipline for the direct path, not as a broad packet-speed claim.
- [x] Add retained packet-differential coverage checks:
  `scripts/check-zone-image-prototype-benchmark.py` now requires benchmark
  query mixes for positive, negative, wildcard, delegation/referral, CNAME,
  DNAME, additional-data, EDNS, truncation, DNSSEC, and unknown-RR packet
  cases, plus positive packet-case counts, zero mismatches for each retained
  packet corpus, and memory-layout ceilings for main/stress hot bytes per
  record plus total bytes per record.
- [x] Add retained signed-boundary packet coverage for the prototype benchmark.
  The boundary mix now requires `dnssec_positive_do` and `dnssec_nodata_do`
  cases backed by RRSIG/NSEC fixture data, and the retained run at
  `target/zone-image-bench/signed-boundary-packet-coverage.tsv` passed with
  zero packet validation mismatches and byte parity.
- [x] Extend `zone_image_datagram` fuzz fixture coverage:
  `fuzz/fuzz_targets/zone_image_datagram.rs` now shapes direct, CNAME, DNAME,
  wildcard, referral/glue, SRV additional, QTYPE=ANY, basic DNSSEC DO, EDNS,
  opaque unknown, and malformed known-name RDATA packets through the required
  `ZoneImage` provider. Stable validation covered
  `cargo check --manifest-path fuzz/Cargo.toml` and
  `cargo run --manifest-path fuzz/Cargo.toml --bin zone_image_datagram -- -runs=8`.
  The campaign runner now supports `--toolchain nightly`/`CARGO_TOOLCHAIN` and
  prepends the selected toolchain cargo directory so cargo-fuzz's inner
  `cargo build` does not accidentally use a sandboxed cargo wrapper. A retained
  60-second ASan campaign passed at
  `target/fuzz-evidence/zone-image-local-20260531-nightly-60s/campaign-summary.tsv`
  for `zone_image_datagram` with 1,396,283 runs in 61 seconds. Earlier short
  validation also covered direct nightly cargo at
  `target/fuzz-evidence/zone-image-local-20260531-direct-nightly/campaign-summary.tsv`
  and a `--toolchain nightly` smoke at
  `target/fuzz-evidence/zone-image-local-20260531-toolchain-smoke/campaign-summary.tsv`.
  A release-grade campaign still means an overnight or release-window ASan run,
  not this default local gate.
- [x] Add retained infallible DNSSEC augmentation cleanup:
  `target/zone-image-bench/dnssec-augmentation-infallible.tsv` removes the
  now-unreachable fallible `Result` plumbing from `ZoneImage` DNSSEC
  augmentation after NSEC/NSEC3 proof selection became compiled metadata and
  checked hashing lookups that return optional proof handles. The runtime
  `dnssec_plan_error` failure metric label was removed with it. Focused
  `ZoneImage` DNSSEC proof/signature tests passed, and the benchmark checker
  passed at
  `target/zone-image-bench/dnssec-augmentation-infallible-check.tsv` with zero
  semantic and packet mismatches, mixed planning ratio `0.156`, mixed wire
  ratio `0.184`, mixed packet ratio `1.021`, hot packet ratio `1.067`, trace
  packet ratio `1.035`, optioned packet ratio `1.072`, boundary packet ratio
  `1.094`, UDP-ceiling packet ratio `1.086`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as API and
  dead-metric cleanup, not as a packet-path speed claim.
- [x] Add retained DNSSEC denial SOA-precondition cleanup:
  `target/zone-image-bench/dnssec-denial-soa-precondition-once.tsv` computes
  the negative-response authority-SOA precondition once before NODATA and
  NXDOMAIN proof selection and narrows the check to authority RRset handles,
  since selected authority records are immutable RRSIG handles and cannot
  satisfy the SOA requirement. Focused `ZoneImage` DNSSEC denial/proof tests
  passed, and the benchmark checker passed at
  `target/zone-image-bench/dnssec-denial-soa-precondition-once-check.tsv` with
  zero semantic and packet mismatches, mixed planning ratio `0.158`, mixed wire
  ratio `0.192`, mixed packet ratio `1.001`, hot packet ratio `1.063`, trace
  packet ratio `1.060`, optioned packet ratio `1.097`, boundary packet ratio
  `0.988`, UDP-ceiling packet ratio `0.992`, delegation/DNAME stress planning
  ratio `0.002`, and stress wire ratio `0.002`. This is retained as narrow
  DNSSEC planner cleanup.
- [x] Add retained DNSSEC denial SOA-first precondition cleanup:
  `target/zone-image-bench/dnssec-denial-soa-first-precondition.tsv` keeps the
  existing negative-response SOA precondition but checks the common SOA-first
  authority layout directly before falling back to the general authority RRset
  scan for unusual pre-seeded plans. Focused DNSSEC, NODATA, NXDOMAIN, and
  filtered ZoneImage tests passed, and the checker passed at
  `target/zone-image-bench/dnssec-denial-soa-first-precondition-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.128`,
  mixed wire ratio `0.150`, mixed packet ratio `1.115`, hot packet ratio
  `1.225`, trace packet ratio `1.117`, optioned packet ratio `1.233`, boundary
  packet ratio `1.020`, UDP-ceiling packet ratio `1.036`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio `0.002`.
  This is retained only as a narrow denial-precondition helper cleanup; broad
  packet timings are noisy and near the local gate in this run.
- [x] Add retained direct-preflight retry skip:
  `target/zone-image-bench/direct-preflight-retry-skip.tsv` keeps the early
  direct-answer attempt but stops the generic `ZoneImage` response builder from
  retrying the same direct plan after that attempt already rejected it. This
  removes duplicate direct-copy/owner/UDP-ceiling preflight work for exact
  positives that must fall through to the generic composer, such as known-name
  RDATA responses. Focused direct-answer, ZoneImage serving, DNSSEC, and
  truncation tests passed, and the checker passed at
  `target/zone-image-bench/direct-preflight-retry-skip-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.131`,
  mixed wire ratio `0.167`, mixed packet ratio `0.972`, hot packet ratio
  `1.031`, trace packet ratio `1.015`, optioned packet ratio `1.047`,
  boundary packet ratio `0.995`, UDP-ceiling packet ratio `1.003`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as narrow composer preflight cleanup; the generic
  composer remains a mutable builder rather than a complete immutable template
  path.
- [x] Add retained direct exact-plan owner invariant cleanup:
  `target/zone-image-bench/direct-answer-plan-owner-invariant.tsv` removes the
  direct RRset view's owner-wire field and stops reparsing compiled owner wire
  before direct response allocation. Direct-answer plans are private exact-node
  planner products with no custom answer, authority, or additional sections, so
  the direct composer can trust the plan marker and keep owner matching in the
  lookup invariant. Focused direct-answer tests, filtered ZoneImage tests,
  invariant audit, and check build passed. The checker passed at
  `target/zone-image-bench/direct-answer-plan-owner-invariant-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.129`,
  mixed wire ratio `0.157`, mixed packet ratio `1.010`, hot packet ratio
  `0.976`, trace packet ratio `0.970`, optioned packet ratio `0.934`, boundary
  packet ratio `1.025`, UDP-ceiling packet ratio `1.001`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as direct hot-path invariant tightening, not a broad
  packet-path timing claim.
- [x] Add retained direct-preflight target-type gate:
  `target/zone-image-bench/direct-preflight-target-type-gate.tsv` rejects
  RR types that can require additional address records before the direct-answer
  preflight does trie, delegation, DNAME, or exact-RRset lookup work. Those
  responses must use the semantic/generic `ZoneImage` path so additionals can
  be emitted. Focused direct-answer tests passed, and the checker passed at
  `target/zone-image-bench/direct-preflight-target-type-gate-check.tsv` with
  zero semantic and packet mismatches, byte parity, exact lookup ratio `0.105`,
  hot exact lookup ratio `0.190`, high-fanout exact lookup ratio `0.104`,
  mixed planning ratio `0.113`, mixed wire ratio `0.138`, mixed packet ratio
  `1.023`, hot packet ratio `1.033`, trace packet ratio `1.000`, optioned
  packet ratio `0.999`, boundary packet ratio `0.986`, UDP-ceiling packet
  ratio `0.993`, delegation/DNAME stress planning ratio `0.001`, and stress
  wire ratio `0.001`. This is retained as direct preflight branch pruning; it
  does not complete the immutable template/WireArena composer path.
- [x] Add retained direct-answer compressed-capacity sizing:
  `target/zone-image-bench/direct-answer-compressed-capacity.tsv` sizes the
  direct exact-owner response allocation from emitted wire length: stored RRset
  wire minus repeated full owner names plus the two-byte compression pointer
  emitted for each answer. A focused helper test checks the capacity math and
  malformed compiled-wire guard, direct-answer and ZoneImage serving tests
  passed, and the checker passed at
  `target/zone-image-bench/direct-answer-compressed-capacity-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.136`,
  mixed wire ratio `0.158`, mixed packet ratio `1.000`, hot packet ratio
  `1.101`, trace packet ratio `1.019`, optioned packet ratio `1.016`,
  boundary packet ratio `0.999`, UDP-ceiling packet ratio `1.016`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as direct-composer allocation sizing cleanup, not
  as evidence that full response templates are ready.
  The follow-up `target/zone-image-bench/direct-answer-edns-capacity-hint.tsv`
  reuses the shared `ZoneImage` response-capacity helper for direct exact-owner
  answers, so EDNS responses reserve for the actual OPT option shape instead of
  a fixed 64-byte slack block. The focused direct EDNS test checks byte parity
  with the reference response and asserts the direct response capacity is exact
  for the NSID case. The checker passed at
  `target/zone-image-bench/direct-answer-edns-capacity-hint-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.144`,
  mixed wire ratio `0.169`, mixed packet ratio `0.993`, hot packet ratio
  `0.960`, trace packet ratio `0.973`, optioned packet ratio `0.994`,
  boundary packet ratio `1.014`, UDP-ceiling packet ratio `1.005`, main bytes
  per record `174.000`, and stress bytes per record `254.000`. This is
  retained as direct-composer allocation discipline before transport work.
  The next retained check,
  `target/zone-image-bench/direct-answer-shared-prefix.tsv`, routes the direct
  exact-owner DNS header and section-count write through the same known-count
  `ZoneImage` response-prefix helper used by generic composition. The invariant
  audit now rejects reintroducing a private direct header assembly path. The
  checker passed at
  `target/zone-image-bench/direct-answer-shared-prefix-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.145`, mixed
  wire ratio `0.163`, mixed packet ratio `0.976`, hot packet ratio `0.942`,
  trace packet ratio `1.022`, optioned packet ratio `1.030`, boundary packet
  ratio `0.996`, UDP-ceiling packet ratio `0.972`, main bytes per record
  `174.000`, and stress bytes per record `254.000`. This is retained as
  direct-composer header discipline, not as a broad packet-path timing claim.
- [x] Add retained direct-answer compiled-record body emission:
  `target/zone-image-bench/direct-answer-compiled-record-body.tsv` keeps the
  direct exact-owner response body as a query-time append over compiled
  record/RDATA metadata instead of parsing the immutable RRset wire to skip each
  stored owner name. The earlier full direct-body materialization experiment was
  not retained because it pushed the stress fixture over the retained total
  bytes-per-record ceiling. Focused direct-answer tests cover the compiled body
  length and owner-pointer positions, and the checker passed at
  `target/zone-image-bench/direct-answer-compiled-record-body-check.tsv` with
  zero semantic and packet mismatches, byte parity, exact lookup ratio `0.155`,
  hot exact lookup ratio `0.216`, high-fanout exact lookup ratio `0.116`, mixed
  planning ratio `0.125`, mixed wire ratio `0.153`, mixed packet ratio `1.000`,
  hot packet ratio `1.009`, trace packet ratio `1.017`, optioned packet ratio
  `1.027`, boundary packet ratio `1.042`, UDP-ceiling packet ratio `1.009`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  main bytes per record `166.000`, and stress bytes per record `246.000`. This
  is retained as direct-composer parse avoidance without duplicate body
  templates.
- [x] Add retained direct-answer view body-length cleanup:
  `target/zone-image-bench/direct-answer-view-body-len.tsv` carries the emitted
  direct-answer body length in the selected direct RRset view, so the response
  builder does not perform a second RRset lookup and eligibility check before
  allocation. The append helper is correspondingly scoped to already-eligible
  direct RRsets. Focused direct-answer tests passed, and the checker passed at
  `target/zone-image-bench/direct-answer-view-body-len-check.tsv` with zero
  semantic and packet mismatches, byte parity, exact lookup ratio `0.151`, hot
  exact lookup ratio `0.216`, high-fanout exact lookup ratio `0.112`, mixed
  planning ratio `0.123`, mixed wire ratio `0.148`, mixed packet ratio `1.021`,
  hot packet ratio `0.991`, trace packet ratio `1.026`, optioned packet ratio
  `1.026`, boundary packet ratio `1.009`, UDP-ceiling packet ratio `1.015`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  main bytes per record `166.000`, and stress bytes per record `246.000`. This
  is retained as direct metadata-access cleanup, not as a broad packet-path
  speed claim.
- [x] Add retained compiled direct-answer body-length evidence:
  `target/zone-image-bench/direct-answer-compiled-body-len.tsv` stores the
  emitted direct-answer body length in compiled `ImageRrset` metadata. This
  removes the remaining per-query body-length arithmetic from direct response
  allocation while keeping the rejected all-RRset duplicate body template out of
  the image. Focused direct-answer tests passed, and the checker passed at
  `target/zone-image-bench/direct-answer-compiled-body-len-check.tsv` with zero
  semantic and packet mismatches, byte parity, exact lookup ratio `0.236`, hot
  exact lookup ratio `0.205`, high-fanout exact lookup ratio `0.107`, mixed
  planning ratio `0.117`, mixed wire ratio `0.148`, mixed packet ratio `0.981`,
  hot packet ratio `1.022`, trace packet ratio `1.039`, optioned packet ratio
  `1.063`, boundary packet ratio `1.026`, UDP-ceiling packet ratio `1.022`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  main bytes per record `170.000`, and stress bytes per record `250.000`. This
  earlier artifact is retained as compact direct-composer precomputation from a
  smaller image layout; the current tree does not keep the emitted-length field
  because the later `direct-answer-emitted-body-len` retest exceeds the
  `256.000` delegation/DNAME stress bytes-per-record ceiling.
- [x] Add retained direct-answer selected-view append evidence:
  `target/zone-image-bench/direct-answer-view-append-metadata.tsv` carries the
  immutable RRset append metadata in the selected direct RRset view, so direct
  answer emission no longer re-indexes the RRset by ID after preflight. Focused
  direct-answer tests passed, and the checker passed at
  `target/zone-image-bench/direct-answer-view-append-metadata-check.tsv` with
  zero semantic and packet mismatches, byte parity, exact lookup ratio `0.194`,
  hot exact lookup ratio `0.210`, high-fanout exact lookup ratio `0.107`, mixed
  planning ratio `0.116`, mixed wire ratio `0.146`, mixed packet ratio `1.005`,
  hot packet ratio `1.029`, trace packet ratio `1.031`, optioned packet ratio
  `1.054`, boundary packet ratio `1.038`, UDP-ceiling packet ratio `1.035`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  main bytes per record `170.000`, and stress bytes per record `250.000`. This
  is retained as narrow direct-view metadata cleanup, not as evidence that the
  full immutable template/WireArena path is complete.
- [x] Add retained direct-answer record-slice view evidence:
  `target/zone-image-bench/direct-answer-record-slice-view.tsv` carries the
  pre-bounds-checked compiled record slice in the selected direct RRset view, so
  direct answer emission walks that slice instead of recomputing record indexes
  after preflight. Focused direct-answer tests passed, and the checker passed at
  `target/zone-image-bench/direct-answer-record-slice-view-check.tsv` with zero
  semantic and packet mismatches, byte parity, exact lookup ratio `0.163`, hot
  exact lookup ratio `0.205`, high-fanout exact lookup ratio `0.108`, mixed
  planning ratio `0.115`, mixed wire ratio `0.140`, mixed packet ratio `1.000`,
  hot packet ratio `1.061`, trace packet ratio `1.053`, optioned packet ratio
  `1.063`, boundary packet ratio `1.022`, UDP-ceiling packet ratio `1.007`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  main bytes per record `170.000`, and stress bytes per record `250.000`. This
  is retained as direct-answer slice-view cleanup with no image memory increase.
- [x] Add retained direct-answer record-prefix view evidence:
  `target/zone-image-bench/direct-answer-record-prefix-view.tsv` carries the
  constant compressed-owner/type/class/TTL record prefix in the selected direct
  RRset view, so direct-answer emission writes one prepared prefix per record
  instead of converting those fields on every append. Focused direct-answer
  tests passed, and the checker passed at
  `target/zone-image-bench/direct-answer-record-prefix-view-check.tsv` with zero
  semantic and packet mismatches, byte parity, exact lookup ratio `0.181`, hot
  exact lookup ratio `0.214`, high-fanout exact lookup ratio `0.099`, mixed
  planning ratio `0.112`, mixed wire ratio `0.135`, mixed packet ratio `1.014`,
  hot packet ratio `0.958`, trace packet ratio `0.987`, optioned packet ratio
  `0.999`, boundary packet ratio `1.047`, UDP-ceiling packet ratio `0.981`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  main bytes per record `170.000`, and stress bytes per record `250.000`. This
  is retained as direct-answer transient-view cleanup with no image memory
  increase, not as a broad generic-composer claim.
- [x] Add retained direct-answer prefix fixed-field reuse:
  `target/zone-image-bench/direct-prefix-fixed-fields.tsv` builds the selected
  direct RRset view's compressed-owner/type/class/TTL record prefix from the
  immutable RRset wire's preencoded TYPE/CLASS/TTL bytes, instead of rebuilding
  those bytes from scalar RRset metadata when the view is selected. Focused
  direct-answer tests and the invariant audit passed. The checker passed at
  `target/zone-image-bench/direct-prefix-fixed-fields-check.tsv` with zero
  validation/packet mismatches, byte parity, main image bytes/record `170`,
  stress image bytes/record `250`, mixed planning ratio `0.139`, mixed wire
  ratio `0.168`, mixed packet ratio `1.053`, hot packet ratio `1.084`, trace
  packet ratio `1.023`, optioned packet ratio `1.037`, boundary packet ratio
  `1.040`, UDP-ceiling packet ratio `0.993`, stress planning ratio `0.001`,
  and stress wire ratio `0.002`. This is retained as a narrow direct-view
  scalar-rebuild cleanup with no image memory increase.
- [x] Measure and reject generic wire-record direct-copy RDATA view flag:
  `target/zone-image-bench/wire-record-direct-copy-rdata-view.tsv` carried the
  compiled direct-copy RDATA decision through every transient `ZoneImage`
  wire-record view so the generic composer could bypass its RDATA compression
  match and rdlength patch for opaque records. The checker passed at
  `target/zone-image-bench/wire-record-direct-copy-rdata-view-check.tsv` with
  zero semantic and packet mismatches, byte parity, mixed wire ratio `0.158`,
  mixed packet ratio `1.026`, hot packet ratio `1.077`, trace packet ratio
  `1.022`, optioned packet ratio `1.066`, boundary packet ratio `1.016`,
  UDP-ceiling packet ratio `1.016`, main bytes per record `170.000`, and stress
  bytes per record `250.000`. It was not retained in code because it added
  transient record-view surface without improving the packet path over the
  retained direct-answer selected-view cleanup.
- [x] Measure and reject per-record checked RDATA length storage:
  `target/zone-image-bench/record-rdata-len-field-candidate.tsv` stored the
  already-validated DNS `rdlength` as a `u16` in each compiled `ImageRecord` so
  direct-answer emission and selected-record accounting could avoid reading the
  `BlobRange` length. The checker passed at
  `target/zone-image-bench/record-rdata-len-field-candidate-check.tsv` with zero
  semantic and packet mismatches, byte parity, mixed wire ratio `0.149`, mixed
  packet ratio `1.033`, hot packet ratio `1.014`, trace packet ratio `1.065`,
  optioned packet ratio `1.076`, boundary packet ratio `1.019`, UDP-ceiling
  packet ratio `0.966`, main bytes per record `174.000`, and stress bytes per
  record `254.000`. It was not retained in code because the extra per-record
  hot metadata nearly consumed the stress fixture memory gate without a broad
  packet-path win.
- [x] Retain compact RDATA range rdlength metadata and infallible stored-record
  appends without hot-byte growth:
  `target/zone-image-bench/stored-record-ttl-override-split.tsv` replaces
  compiled record `BlobRange` RDATA references with a compact `RdataRange` whose
  length is the DNS `u16` rdlength already checked at compile time. This lets
  direct-copy emission, selected stored-record emission, and stored-record
  TTL-override emission write the prevalidated rdlength bytes instead of
  converting `rdata.len()` per record. The common stored-RRset, selected-record,
  and owner-override append/visit helpers no longer carry a per-record optional
  TTL override; the rare negative-SOA path uses a separate explicit-TTL helper.
  The focused
  `compact_rdata_range_keeps_image_record_and_rrset_metadata_bounded` test
  asserts that `ImageRecord` stays the same size as the old `BlobRange` record
  metadata and that `ImageRrset` remains bounded. The benchmark check passed
  with zero semantic and packet mismatches
  and byte parity; the retained run kept main hot bytes per record
  `102.491`, total bytes per record `170.000`, stress bytes per record
  `250.000`, mixed planning ratio `0.118`, mixed wire ratio `0.144`, mixed
  packet ratio `1.018`, hot packet ratio `0.991`, trace packet ratio `1.031`,
  optioned packet ratio `1.019`, boundary packet ratio `0.999`, and
  UDP-ceiling packet ratio `1.009`. This is retained as
  no-growth representation cleanup, not as a broad packet-speed claim.
- [x] Retain synthesized dynamic-record rdlength precompute:
  `target/zone-image-bench/dynamic-record-rdlength-infallible.tsv` keeps the
  remaining truly synthesized DNAME CNAME records in dynamic plan storage, but
  stores their checked DNS `rdlength` bytes when the record is pushed into the
  plan. The generic benchmark append hook and synthesized-record append helper
  now write those prevalidated bytes directly and return counts without a
  fallible per-query length conversion. The checker passed at
  `target/zone-image-bench/dynamic-record-rdlength-infallible-check.tsv` with
  zero semantic and packet mismatches, byte parity, main hot bytes per record
  `102.491`, total bytes per record `170.000`, stress bytes per record
  `250.000`, mixed planning ratio `0.130`, mixed wire ratio `0.152`, mixed
  packet ratio `0.988`, hot packet ratio `1.005`, trace packet ratio `0.997`,
  optioned packet ratio `0.990`, boundary packet ratio `1.016`, and
  UDP-ceiling packet ratio `1.005`. This is retained as final synthesized
  append-path discipline before transport work, not as a packet-throughput
  claim.
- [x] Retain selected-record wire-length handles:
  `target/zone-image-bench/selected-record-wire-len-handle.tsv` carries the
  immutable selected DNSSEC record wire length in each selected-record plan
  handle when RRSIG records are appended to the plan. Section accounting now
  reads that precomputed length instead of indexing the selected RRset and
  record again before the later append/visit pass. The checker passed at
  `target/zone-image-bench/selected-record-wire-len-handle-check.tsv` with
  zero semantic and packet mismatches, byte parity, main hot bytes per record
  `102.491`, total bytes per record `170.000`, stress bytes per record
  `250.000`, mixed planning ratio `0.123`, mixed wire ratio `0.147`, mixed
  packet ratio `1.018`, hot packet ratio `0.990`, trace packet ratio `1.009`,
  optioned packet ratio `1.014`, boundary packet ratio `0.990`, and
  UDP-ceiling packet ratio `0.995`. This is retained as selected-DNSSEC
  accounting discipline with flat image memory, not as a broad packet-speed
  claim.
- [x] Retain RRSIG relation RDATA-length precompute:
  `target/zone-image-bench/rrsig-relation-rdata-len.tsv` moves the selected
  RRSIG RDATA-length read from query-time handle creation into the immutable
  RRSIG relation. Selected DNSSEC handles compute their carried wire length
  from the relation RDATA length plus the immutable RRset owner length, avoiding
  a selected-record table lookup while keeping the relation table compact. The
  earlier full-wire-length relation candidate was superseded because it raised
  the stress fixture to `253.000` bytes per record. The retained checker passed
  at `target/zone-image-bench/rrsig-relation-rdata-len-check.tsv` with zero
  semantic and packet mismatches, byte parity, main hot bytes per record
  `102.491`, total bytes per record `170.000`, stress hot bytes per record
  `138.267`, stress bytes per record `250.000`, mixed planning ratio `0.116`,
  mixed wire ratio `0.139`, mixed packet ratio `0.973`, hot packet ratio
  `0.901`, trace packet ratio `0.943`, optioned packet ratio `0.939`,
  boundary packet ratio `0.985`, and UDP-ceiling packet ratio `0.996`. This
  is retained as compact relation-level selected-DNSSEC precompute with no
  measured image-memory growth.
- [x] Retain RRSIG relation owner-wire-length precompute:
  `target/zone-image-bench/rrsig-relation-owner-wire-len.tsv` also carries the
  selected RRSIG owner wire length as a checked `u8` in the immutable relation,
  so selected-record handle creation no longer reads the RRset owner arena just
  to compute carried wire length. The broader `u32` full-wire-length relation
  candidate was rejected because it raised the current stress fixture to
  `259.000` bytes per record. The retained checker passed at
  `target/zone-image-bench/rrsig-relation-owner-wire-len-check.tsv` with zero
  semantic and packet mismatches, byte parity, main hot bytes per record
  `106.359`, total bytes per record `174.000`, stress hot bytes per record
  `144.140`, stress bytes per record `256.000`, mixed planning ratio `0.141`,
  mixed wire ratio `0.164`, mixed packet ratio `0.990`, hot packet ratio
  `1.005`, trace packet ratio `0.974`, optioned packet ratio `0.971`,
  boundary packet ratio `0.991`, UDP-ceiling packet ratio `0.993`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.002`.
- [x] Reject full selected-RRSIG relation wire length:
  `target/zone-image-bench/rrsig-relation-wire-len.tsv` rechecked replacing
  the compact owner/RDATA length pair with one `u32` final wire length in
  `ImageRrsetRelation`. The checker rejected that shape at
  `target/zone-image-bench/rrsig-relation-wire-len-check.tsv` because
  delegation/DNAME stress bytes per record rose to `259.000`, above the
  retained `256.000` ceiling. The code keeps the compact 12-byte relation
  layout and a focused layout test now guards that size, so selected-record
  handle creation still derives the final wire length from relation-carried
  owner/RDATA lengths instead of spending extra hot relation bytes.
- [x] Retain runtime RRSIG empty-relation trust:
  `target/zone-image-bench/rrsig-runtime-empty-relation-trust.tsv` removes the
  duplicate runtime covered-RRSIG type check from selected-signature
  augmentation. The compile path already emits no RRSIG relations for RRSIG
  RRsets, so runtime augmentation now trusts the empty relation slice. Focused
  DNSSEC tests cover an RRSIG RRset containing a synthetic RRSIG-over-RRSIG
  record and prove no selected RRSIG is appended for an RRSIG query. The checker
  passed at
  `target/zone-image-bench/rrsig-runtime-empty-relation-trust-check.tsv` with
  zero semantic and packet mismatches, byte parity, main hot bytes per record
  `106.359`, total bytes per record `174.000`, stress hot bytes per record
  `144.140`, stress bytes per record `256.000`, mixed planning ratio `0.137`,
  mixed wire ratio `0.160`, mixed packet ratio `0.996`, hot packet ratio
  `1.012`, trace packet ratio `1.006`, optioned packet ratio `1.017`,
  boundary packet ratio `0.988`, UDP-ceiling packet ratio `0.996`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.002`.
- [x] Retain RRSIG relation bitmap gate:
  `target/zone-image-bench/rrsig-relation-bitmap-gate.tsv` adds a compact
  per-RRset bitmap for RRsets that actually have selected RRSIG relations.
  Runtime RRSIG augmentation now returns before relation-span lookup for RRsets
  that compile-time metadata proves have no RRSIG relation, while still
  trusting the empty relation slice contract for RRSIG RRsets. Focused DNSSEC
  tests assert the bitmap is set for a signed A RRset and clear for the RRSIG
  RRset itself. The checker passed at
  `target/zone-image-bench/rrsig-relation-bitmap-gate-check.tsv` with zero
  trace and boundary packet mismatches, hot bytes/record `106.365`,
  bytes/record `174`, stress bytes/record `256`, mixed planning ratio `0.149`,
  mixed packet ratio `0.962`, hot packet ratio `0.954`, trace packet ratio
  `0.982`, boundary packet ratio `1.005`, and UDP-ceiling packet ratio `1.002`.
  This is retained as per-query DNSSEC relation-span gating with a tiny hot-byte
  increase that remains inside the existing memory gates.
- [x] Retain direct RRSIG relation-slice consumption:
  `target/zone-image-bench/rrsig-direct-relation-slice.tsv` removes the runtime
  selected-RRSIG iterator wrapper from `push_rrsig_for_rrset`; runtime
  augmentation now consumes the compiled relation slice directly, and the RRset
  iterator wrapper remains test-only. The checker passed at
  `target/zone-image-bench/rrsig-direct-relation-slice-check.tsv` with zero
  trace and boundary packet mismatches, hot bytes/record `106.365`,
  bytes/record `174`, stress bytes/record `256`, mixed planning ratio `0.149`,
  mixed packet ratio `0.994`, hot packet ratio `0.998`, trace packet ratio
  `0.998`, boundary packet ratio `0.955`, and UDP-ceiling packet ratio `0.952`.
  This is retained as relation-slice discipline and a small query-path cleanup,
  not as broad throughput evidence.
- [x] Retain selected-record fixed-field handles:
  `target/zone-image-bench/selected-record-fixed-fields.tsv` carries immutable
  selected RRset TYPE/CLASS/TTL fixed fields in each selected DNSSEC plan handle
  alongside the selected record's precomputed wire length. Selected-record
  append and visit paths now write the carried fixed fields directly instead of
  re-indexing the selected RRset during the later emission pass. The checker
  passed at `target/zone-image-bench/selected-record-fixed-fields-check.tsv`
  with zero semantic and packet mismatches, byte parity, main bytes per record
  `174.000`, stress bytes per record `254.000`, mixed planning ratio `0.143`,
  mixed wire ratio `0.161`, mixed packet ratio `1.032`, hot packet ratio
  `1.094`, trace packet ratio `1.062`, optioned packet ratio `1.036`,
  boundary packet ratio `1.018`, and UDP-ceiling packet ratio `1.021`. This is
  retained as transient selected-record handle cleanup; it does not grow the
  compiled `ZoneImage`.
- [x] Retain selected-record RDATA range handles:
  `target/zone-image-bench/selected-record-rdata-range-handle.tsv` carries the
  immutable selected RRSIG `RdataRange` in the transient selected DNSSEC plan
  handle. Selected-record append and visit paths now read the carried RDATA
  range, rdlength bytes, and compact RDATA encoding instead of re-indexing the
  selected record table during emission. The checker passed at
  `target/zone-image-bench/selected-record-rdata-range-handle-check.tsv` with
  zero semantic and packet mismatches, byte parity, main bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.139`,
  mixed wire ratio `0.158`, mixed packet ratio `0.999`, hot packet ratio
  `0.954`, trace packet ratio `0.962`, optioned packet ratio `0.943`,
  boundary packet ratio `0.995`, UDP-ceiling packet ratio `0.992`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as transient selected-record emission cleanup with
  no compiled image growth.
- [x] Retain selected-record stale-index removal:
  `target/zone-image-bench/selected-record-no-record-index.tsv` removes the
  selected record table index from the transient selected DNSSEC plan handle
  after the handle already carries wire length, fixed fields, and the selected
  RDATA range. Handle construction still uses the immutable relation's
  `record_index` to copy the `RdataRange`, but later plan accounting, append,
  visit, and dedupe no longer carry the stale index. A test guard keeps
  `ZoneImageSelectedRecord` at `24` bytes. The checker passed at
  `target/zone-image-bench/selected-record-no-record-index-check.tsv` with zero
  semantic and packet mismatches, byte parity, main bytes per record `174.000`,
  stress bytes per record `256.000`, mixed planning ratio `0.144`, mixed wire
  ratio `0.165`, mixed packet ratio `0.997`, hot packet ratio `1.086`, trace
  packet ratio `0.988`, optioned packet ratio `1.018`, boundary packet ratio
  `0.996`, UDP-ceiling packet ratio `0.990`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as transient
  plan-shape cleanup, not as packet-speed evidence.
- [x] Measure and reject selected-record owner-wire range handles:
  `target/zone-image-bench/selected-record-owner-wire-range.tsv` replaced the
  selected RRset handle with the selected owner-wire `BlobRange` so selected
  RRSIG append and visit paths would not re-index the RRset to recover owner
  wire. It passed the checker at
  `target/zone-image-bench/selected-record-owner-wire-range-check.tsv` with zero
  semantic and packet mismatches, but grew `ZoneImageSelectedRecord` from `24` to
  `28` bytes and measured worse than the retained no-index handle shape on this
  local run: mixed planning ratio `0.162`, mixed wire ratio `0.184`, mixed packet
  ratio `1.026`, hot packet ratio `1.021`, trace packet ratio `1.007`,
  optioned packet ratio `1.016`, boundary packet ratio `1.021`, and UDP-ceiling
  packet ratio `1.015`. The code change was removed; the retained shape keeps
  the compact RRset handle and only drops the stale selected record index.
- [x] Gate authority SOA TTL-override work behind explicit plan state:
  `target/zone-image-bench/authority-soa-ttl-override-gate.tsv` keeps the
  common authority-section composer and visitor path on immutable RRset wire
  copies unless the plan already knows it carries an authority SOA. The rare
  negative-SOA path still rewrites TTL from the compiled negative TTL metadata,
  but ordinary authority RRsets no longer pay a per-RRset SOA/TTL override
  check. The checker passed at
  `target/zone-image-bench/authority-soa-ttl-override-gate-check.tsv` with
  zero semantic and packet mismatches, byte parity, hot bytes per record
  `102.491`, total bytes per record `170.000`, stress bytes per record
  `250.000`, mixed planning ratio `0.123`, mixed wire ratio `0.148`, mixed
  packet ratio `0.997`, hot packet ratio `1.009`, trace packet ratio `1.013`,
  optioned packet ratio `0.992`, boundary packet ratio `1.034`, and
  UDP-ceiling packet ratio `0.988`. This is retained as composer discipline
  and branch isolation before transport work, not as evidence of a broad
  packet-speed win.
- [x] Measure and reject direct-answer `BlobRange` rdlength lookup:
  `target/zone-image-bench/direct-answer-blob-rdlength-candidate.tsv` used the
  compiled RDATA `BlobRange` length for direct-answer `rdlength` instead of
  measuring the sliced RDATA bytes. The checker passed at
  `target/zone-image-bench/direct-answer-blob-rdlength-candidate-check.tsv`
  with zero semantic and packet mismatches, byte parity, exact lookup ratio
  `0.172`, hot exact lookup ratio `0.216`, high-fanout exact lookup ratio
  `0.115`, mixed planning ratio `0.120`, mixed wire ratio `0.153`, mixed packet
  ratio `1.009`, hot packet ratio `1.107`, trace packet ratio `1.038`, optioned
  packet ratio `1.112`, boundary packet ratio `1.044`, UDP-ceiling packet ratio
  `1.039`, main bytes per record `170.000`, and stress bytes per record
  `250.000`. It was not retained in code because the no-memory micro-cleanup
  produced weaker packet evidence than the retained direct-answer prefix/slice
  view.
- [x] Add retained truncated DNSSEC-count retry cleanup:
  `target/zone-image-bench/truncated-dnssec-count-retained.tsv` changes the
  `ZoneImage` UDP truncation retry composer from rescanning all retained wire
  records on every retry to keeping a DNSSEC-record count that is decremented
  as records are removed. A focused helper test covers the immutable wire
  record type classification, truncation/DNSSEC/ZoneImage serving tests passed,
  and the checker passed at
  `target/zone-image-bench/truncated-dnssec-count-retained-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.143`,
  mixed wire ratio `0.161`, mixed packet ratio `0.975`, hot packet ratio
  `0.975`, trace packet ratio `1.000`, optioned packet ratio `1.039`,
  boundary packet ratio `0.951`, UDP-ceiling packet ratio `0.951`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as truncated generic-composer retry cleanup, not
  as completion of the immutable template/WireArena path. The later
  `zone-image-dead-dnssec-count-retired` run supersedes the DNSSEC-count part
  by removing the counter entirely once final response bytes drive DNSSEC
  latency classification.
- [x] Add retained truncated DNSSEC-count collection cleanup:
  `target/zone-image-bench/truncation-dnssec-count-while-collecting.tsv`
  extends the retained retry count by accumulating DNSSEC wire-record counts
  while truncated answer, authority, and additional scratch sections are first
  collected. The retry composer no longer performs a separate post-collection
  scan of all kept records before entering the removal loop. Focused ZoneImage
  tests and formatting pass, and the checker passed at
  `target/zone-image-bench/truncation-dnssec-count-while-collecting-check.tsv`
  with zero validation/packet mismatches, byte parity, mixed planning ratio
  `0.132`, mixed wire ratio `0.168`, mixed packet ratio `1.023`, hot packet
  ratio `0.975`, trace packet ratio `1.000`, optioned packet ratio `0.955`,
  boundary packet ratio `0.988`, UDP-ceiling packet ratio `1.000`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as setup-pass removal for the truncated composer,
  not as completion of the immutable template/WireArena path.
- [x] Add retained section-aware truncated scratch collection evidence:
  `target/zone-image-bench/truncation-section-aware-collect.tsv` changes that
  scratch collection to the section-aware immutable-plan visitor and keeps one
  retained DNSSEC counter instead of three per-section counters plus a final
  sum. Focused ZoneImage and DNSSEC tests pass, and the checker passed at
  `target/zone-image-bench/truncation-section-aware-collect-check.tsv` with
  zero semantic and packet mismatches, byte parity, mixed packet ratio `1.022`,
  hot packet ratio `1.022`, trace packet ratio `1.000`, optioned packet ratio
  `0.931`, boundary packet ratio `1.022`, UDP-ceiling packet ratio `0.989`,
  total image bytes per record `170.000`, and stress bytes per record
  `250.000`. This is retained as retry-composer bookkeeping cleanup inside the
  current mutable composer.
- [x] Add retained truncated authority-index collection evidence:
  `target/zone-image-bench/truncated-authority-index-while-collecting.tsv`
  records the next removable non-SOA authority index while authority scratch
  records are collected, removing the initial post-collection reverse scan.
  The retry loop still moves the retained index backward after each authority
  removal. Focused ZoneImage and DNSSEC tests pass, and the checker passed at
  `target/zone-image-bench/truncated-authority-index-while-collecting-check.tsv`
  with zero semantic and packet mismatches, byte parity, mixed packet ratio
  `1.002`, hot packet ratio `1.011`, trace packet ratio `0.990`, optioned
  packet ratio `0.970`, boundary packet ratio `1.010`, UDP-ceiling packet
  ratio `0.990`, total image bytes per record `170.000`, and stress bytes per
  record `250.000`.
- [x] Add retained truncated authority-index stack evidence:
  `target/zone-image-bench/truncated-authority-index-stack.tsv` extends the
  retained authority-index cleanup by collecting all removable non-SOA
  authority indices into a small stack. The retry loop pops indices in the same
  last-non-SOA removal order and no longer rescans the authority scratch section
  after each authority removal. Focused ZoneImage and DNSSEC tests pass, and
  the checker passed at
  `target/zone-image-bench/truncated-authority-index-stack-check.tsv` with zero
  semantic and packet mismatches, byte parity, mixed packet ratio `1.048`, hot
  packet ratio `1.130`, trace packet ratio `1.046`, optioned packet ratio
  `1.031`, boundary packet ratio `1.081`, UDP-ceiling packet ratio `1.006`,
  total image bytes per record `170.000`, and stress bytes per record
  `250.000`. This is retained as retry-loop rescan removal inside the current
  mutable composer, not as a broad packet-path speed claim.
- [x] Add retained compact truncated authority-index stack evidence:
  `target/zone-image-bench/truncated-authority-index-u16-stack.tsv` narrows the
  removable authority-index stack from `usize` to `u16`, matching the DNS
  section-count bound already checked before truncation retry can run. Focused
  ZoneImage and DNSSEC tests pass, and the checker passed at
  `target/zone-image-bench/truncated-authority-index-u16-stack-check.tsv` with
  zero semantic and packet mismatches, byte parity, mixed packet ratio `1.016`,
  hot packet ratio `0.969`, trace packet ratio `0.990`, optioned packet ratio
  `0.971`, boundary packet ratio `1.006`, UDP-ceiling packet ratio `0.982`,
  total image bytes per record `170.000`, and stress bytes per record
  `250.000`. This keeps the retry-loop rescan removal while reducing truncation
  scratch state. The invariant audit now also requires the debug assertion that
  makes the DNS section-count bound explicit before the compact `u16` index cast.
- [x] Add retained truncated DNSSEC-count metadata gate:
  `target/zone-image-bench/truncation-dnssec-count-gated.tsv` skips DNSSEC
  wire-record classification while collecting truncated scratch sections when
  response metadata already proves the plan was not DNSSEC-augmented. Signed
  truncated responses keep the retained count path above; unsigned oversized
  responses avoid the classification branch entirely during setup. Focused
  ZoneImage tests and formatting pass, and the checker passed at
  `target/zone-image-bench/truncation-dnssec-count-gated-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.126`,
  mixed wire ratio `0.154`, mixed packet ratio `1.059`, hot packet ratio
  `1.072`, trace packet ratio `1.047`, optioned packet ratio `1.076`,
  boundary packet ratio `0.971`, UDP-ceiling packet ratio `0.958`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as a targeted truncation-path gate; broad packet
  ratios remain inside local checker gates but are not treated as a broad win.
- [x] Add retained truncated DNSSEC removal-loop gate:
  `target/zone-image-bench/truncation-dnssec-removal-gated.tsv` extends the
  metadata gate to the truncation retry removal loop, so unsigned oversized
  responses also skip DNSSEC wire-record classification when records are
  removed. Focused ZoneImage tests passed, and the checker passed at
  `target/zone-image-bench/truncation-dnssec-removal-gated-check.tsv` with zero
  validation/packet mismatches, byte parity, mixed planning ratio `0.135`,
  mixed wire ratio `0.156`, mixed packet ratio `1.008`, hot packet ratio
  `1.010`, trace packet ratio `1.021`, optioned packet ratio `1.052`,
  boundary packet ratio `0.995`, UDP-ceiling packet ratio `1.001`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as narrow truncation retry cleanup; it is not a
  broad packet-path timing claim.
- [x] Add retained truncated DNSSEC zero-count gate:
  `target/zone-image-bench/truncation-dnssec-zero-count-gate.tsv` stops DNSSEC
  wire-record classification in the truncation retry removal loop once the
  retained DNSSEC record count has reached zero. Focused ZoneImage tests
  passed, and the checker passed at
  `target/zone-image-bench/truncation-dnssec-zero-count-gate-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.143`,
  mixed wire ratio `0.167`, mixed packet ratio `1.027`, hot packet ratio
  `1.025`, trace packet ratio `1.016`, optioned packet ratio `1.009`,
  boundary packet ratio `0.986`, UDP-ceiling packet ratio `0.992`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as narrow truncation retry bookkeeping cleanup, not
  as a broad packet-path timing claim. It is now historical evidence; the live
  implementation no longer carries truncation DNSSEC counters.
- [x] Measure and reject split truncated DNSSEC collection:
  `target/zone-image-bench/truncation-dnssec-collection-split.tsv` split
  truncated scratch-section collection into separate DNSSEC and non-DNSSEC
  closures so unsigned oversized responses would not carry the per-record
  metadata gate branch. Focused ZoneImage tests passed and the checker passed
  at
  `target/zone-image-bench/truncation-dnssec-collection-split-check.tsv` with
  zero validation/packet mismatches and byte parity, but boundary packet ratio
  regressed to `1.050` and UDP-ceiling packet ratio regressed to `1.049`
  against the retained gated path. The split code was removed; the narrower
  metadata-gated single traversal remains.
- [x] Add retained truncated authority-removal index cleanup:
  `target/zone-image-bench/truncated-authority-index-retained.tsv` keeps the
  last removable non-SOA authority index while the `ZoneImage` UDP truncation
  retry composer removes authority records, instead of rescanning the authority
  section from the end on each retry after additionals are exhausted. A focused
  helper test covers the backward index movement over SOA and non-SOA records,
  truncation/DNSSEC/ZoneImage serving tests passed, and the checker passed at
  `target/zone-image-bench/truncated-authority-index-retained-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.132`,
  mixed wire ratio `0.161`, mixed packet ratio `1.028`, hot packet ratio
  `1.002`, trace packet ratio `1.014`, optioned packet ratio `1.023`,
  boundary packet ratio `1.005`, UDP-ceiling packet ratio `1.000`,
  delegation/DNAME-stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This was retained as truncated retry bookkeeping cleanup at that
  point, then superseded by
  `target/zone-image-bench/truncated-authority-index-while-collecting.tsv` and
  `target/zone-image-bench/truncated-authority-index-stack.tsv`, which remove
  the setup scan and the per-removal authority rescans.
- [x] Add retained truncated EDE direct-retry evidence:
  `target/zone-image-bench/truncated-ede-direct-retry.tsv` lets the
  `ZoneImage` UDP truncation path try the common "strip EDE and rebuild"
  response directly from the immutable plan before collecting mutable
  kept-record scratch vectors for record removal. If the stripped response
  still exceeds the UDP ceiling, it falls back to the existing retained
  wire-record removal loop. Focused EDE and filtered ZoneImage tests passed,
  and the checker passed at
  `target/zone-image-bench/truncated-ede-direct-retry-check.tsv` with zero
  semantic/packet mismatches, mixed planning ratio `0.129`, mixed wire ratio
  `0.160`, mixed packet ratio `1.019`, hot packet ratio `1.049`, trace packet
  ratio `1.011`, optioned packet ratio `1.053`, boundary packet ratio `0.985`,
  UDP-ceiling packet ratio `1.002`, delegation/DNAME stress planning ratio
  `0.001`, stress wire ratio `0.002`, hot bytes per record `98.502`, and stress
  hot bytes per record `134.204`. This is retained as narrow truncation/EDE
  scratch deferral inside the local gates, not as completion of the immutable
  template/WireArena path. The later `zone-image-ede-stripped-sizing` run
  tightens the fallback side by carrying the stripped OPT sizing into the
  record-removal retry when the direct stripped rebuild is still oversized.
- [x] Add retained truncation tail-authority pop evidence:
  `target/zone-image-bench/truncation-tail-authority-pop.tsv` keeps the retained
  removable-authority index stack, but skips `SmallVec::remove` shifting when the
  next removable non-SOA authority record is already the section tail. Non-tail
  removals still use ordered removal so response order is preserved. Focused
  UDP-ceiling and truncation tests passed, and the checker passed at
  `target/zone-image-bench/truncation-tail-authority-pop-check.tsv` with zero
  semantic and packet mismatches, byte parity, mixed planning ratio `0.143`,
  mixed wire ratio `0.165`, mixed packet ratio `1.033`, hot packet ratio
  `1.058`, trace packet ratio `1.052`, optioned packet ratio `1.027`,
  boundary packet ratio `1.003`, UDP-ceiling packet ratio `1.001`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio `0.002`.
  This is retained as narrow retry-loop bookkeeping cleanup, not as packet-speed
  evidence.
- [x] Add retained wire-record carried-rdlength accounting evidence:
  `target/zone-image-bench/wire-record-uncompressed-len-rdlength.tsv` changes
  truncation body-wire-bound decrement accounting to read the carried
  `ZoneImageWireRecord::rdlength_bytes` instead of using the runtime RDATA slice
  length. The wire record already carries a checked DNS rdlength for emission, so
  this keeps truncation accounting on prevalidated metadata without growing the
  image or plan. Focused coverage in
  `zone_image_wire_record_dnssec_classification_tracks_types` asserts the helper
  follows the carried rdlength, UDP-ceiling tests passed, and the checker passed
  at `target/zone-image-bench/wire-record-uncompressed-len-rdlength-check.tsv`
  with zero semantic and packet mismatches, byte parity, mixed planning ratio
  `0.140`, mixed wire ratio `0.157`, mixed packet ratio `0.965`, hot packet ratio
  `0.964`, trace packet ratio `0.978`, optioned packet ratio `0.975`, boundary
  packet ratio `0.998`, UDP-ceiling packet ratio `0.990`, delegation/DNAME stress
  planning ratio `0.001`, and stress wire ratio `0.002`.
- [x] Add retained infallible response-planning cleanup:
  `target/zone-image-bench/response-planning-infallible.tsv` removes the
  remaining unreachable `Result` plumbing from `ZoneImage` semantic response
  planning after CNAME, DNAME, wildcard, and additional-data planning no longer
  surface build errors. The runtime `plan_error` failure metric label was
  removed with it, leaving response-build failure as the only reachable
  ZoneImage serve-failure bucket. Focused planning, packet, DNSSEC, and runtime
  metric tests passed, and the benchmark checker passed at
  `target/zone-image-bench/response-planning-infallible-check.tsv` with zero
  semantic and packet mismatches, mixed planning ratio `0.128`, mixed wire
  ratio `0.160`, mixed packet ratio `0.999`, hot packet ratio `1.025`, trace
  packet ratio `1.013`, optioned packet ratio `1.033`, boundary packet ratio
  `0.999`, UDP-ceiling packet ratio `0.996`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as API,
  metrics, and planner cleanup.
- [x] Add retained compiled-RDATA rdlength bound:
  `target/zone-image-bench/compile-rdata-rdlength-bound.tsv` moves immutable
  RR wire preencoding from a lossy `rdata.len() as u16` cast to a checked
  compile-time conversion, so an oversized in-memory RDATA value fails
  `ZoneImage` compilation before any packet composer can emit a wrapped
  rdlength. Focused coverage is in
  `compile_rejects_rdata_that_cannot_fit_wire_rdlength`, the invariant audit
  now guards the checked conversion, and the benchmark checker passed at
  `target/zone-image-bench/compile-rdata-rdlength-bound-check.tsv` with zero
  semantic and packet mismatches, mixed planning ratio `0.131`, mixed wire
  ratio `0.164`, mixed packet ratio `1.004`, hot packet ratio `1.024`, trace
  packet ratio `1.003`, optioned packet ratio `1.049`, boundary packet ratio
  `1.000`, UDP-ceiling packet ratio `0.998`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.001`. This is retained as
  compile-time bounds hardening before transport work, not as a packet-path
  speedup.
- [x] Add retained wildcard additional-planner gate:
  `target/zone-image-bench/wildcard-additional-gate.tsv` extends the existing
  exact-positive additional-data gate to non-ANY wildcard answers whose RR type
  cannot reference address targets. This leaves wildcard MX/SRV/NAPTR/SVCB/HTTPS
  and full-ANY wildcard planning on the existing conservative path, including
  the broader QTYPE=ANY gate that was previously measured and rejected.
  Focused tests cover target-bearing wildcard MX and non-target wildcard A, and
  the benchmark checker passed at
  `target/zone-image-bench/wildcard-additional-gate-check.tsv` with zero
  semantic and packet mismatches, mixed planning ratio `0.122`, mixed wire
  ratio `0.148`, mixed packet ratio `0.998`, hot packet ratio `1.040`, trace
  packet ratio `1.006`, optioned packet ratio `0.981`, boundary packet ratio
  `0.986`, UDP-ceiling packet ratio `0.994`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.001`. This is retained as a narrow
  wildcard planner-pass reduction.
- [x] Add retained CNAME/DNAME indirection additional-planner gate:
  `target/zone-image-bench/indirection-additional-gate.tsv` skips the generic
  additional-data planner when a CNAME or DNAME chain terminates out of zone, at
  an in-zone missing name, at a malformed CNAME target, or at a final RRset type
  that cannot reference address targets. Target-bearing final RRsets such as SRV
  append their precomputed additional-address relation span directly, and the
  dynamic-record branch now checks the same RR type predicate before attempting
  target-name parsing. Focused tests cover CNAME-to-A and CNAME-to-SRV behavior,
  and the benchmark checker passed at
  `target/zone-image-bench/indirection-additional-gate-check.tsv` with zero
  semantic and packet mismatches, mixed planning ratio `0.136`, mixed wire ratio
  `0.156`, mixed packet ratio `1.015`, hot packet ratio `1.020`, trace packet
  ratio `1.018`, optioned packet ratio `0.919`, boundary packet ratio `1.004`,
  UDP-ceiling packet ratio `1.005`, delegation/DNAME stress planning ratio
  `0.001`, and stress wire ratio `0.001`. This is retained as narrow
  indirection planner-pass cleanup, not as a packet-path speed claim.
- [x] Add retained single-answer additional-span cleanup:
  `target/zone-image-bench/single-answer-additional-span.tsv` lets exact,
  wildcard, and CNAME/DNAME endpoint plans with one target-bearing answer RRset
  append that RRset's compiled additional-address relation span directly. The
  compile path already deduplicates repeated target-address RRsets inside each
  relation span, and focused tests cover duplicate MX targets collapsing to one
  additional. The benchmark checker passed at
  `target/zone-image-bench/single-answer-additional-span-check.tsv` with zero
  semantic and packet mismatches, mixed planning ratio `0.130`, mixed wire ratio
  `0.158`, mixed packet ratio `0.969`, hot packet ratio `1.039`, trace packet
  ratio `1.012`, optioned packet ratio `0.984`, boundary packet ratio `0.993`,
  UDP-ceiling packet ratio `0.999`, delegation/DNAME stress planning ratio
  `0.001`, and stress wire ratio `0.001`. This is retained as single-RRset
  planner bookkeeping cleanup.
- [x] Add retained minimal-ANY single-additional-span cleanup:
  `target/zone-image-bench/minimal-any-single-additional-span.tsv` extends the
  same direct relation-span path to minimal QTYPE=ANY when the selected answer
  RRset is the only target-bearing answer. That path now avoids allocating and
  scanning the multi-RRset additional dedupe helper for the default minimal-ANY
  one-answer case; later full-ANY work streams compiled-order answer RRsets and
  dedupes additionals during that same pass. Focused coverage in
  `qtype_any_plan_serves_exact_and_wildcard_rrsets` now includes a single-MX
  minimal-ANY owner with one additional address RRset. The benchmark checker
  passed at
  `target/zone-image-bench/minimal-any-single-additional-span-check.tsv` with
  zero semantic and packet mismatches, byte parity, mixed planning ratio
  `0.130`, mixed wire ratio `0.152`, mixed packet ratio `1.000`, hot packet
  ratio `1.013`, trace packet ratio `1.010`, optioned packet ratio `0.998`,
  boundary packet ratio `1.019`, UDP-ceiling packet ratio `0.993`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as minimal-ANY planner bookkeeping cleanup.
- [x] Add retained minimal-ANY scalar selection evidence:
  `target/zone-image-bench/minimal-any-scalar-selection.tsv` keeps the same
  compiled-order minimal ANY semantics but returns the selected exact or wildcard
  RRset through a scalar helper instead of building the one-entry RRset list used
  by full ANY. Focused ANY and broad ZoneImage/DNSSEC tests pass, and the
  checker passed at
  `target/zone-image-bench/minimal-any-scalar-selection-check.tsv` with zero
  validation and packet mismatches, byte parity, mixed planning ratio `0.126`,
  mixed wire ratio `0.152`, mixed packet ratio `1.011`, hot packet ratio
  `0.970`, trace packet ratio `1.001`, optioned packet ratio `0.975`, boundary
  packet ratio `1.014`, UDP-ceiling packet ratio `1.002`,
  delegation/DNAME-stress planning ratio `0.001`, stress wire ratio `0.001`,
  total image bytes per record `170.000`, and stress bytes per record
  `250.000`. This is retained as scalar minimal-ANY planner cleanup, not as a
  broad packet-path speed claim.
- [x] Add retained full-ANY streamed planning cleanup:
  `target/zone-image-bench/full-any-streamed-planning.tsv` removes the remaining
  temporary full-ANY RRset list. Exact and wildcard full-ANY planning now walks
  the compiled owner RRset order once, pushes matching answer RRsets directly
  into the plan, and dedupes additional-address relation spans during that same
  pass. The checker passed at
  `target/zone-image-bench/full-any-streamed-planning-check.tsv` with zero
  semantic and packet mismatches, byte parity, main bytes per record `174.000`,
  stress bytes per record `254.000`, mixed planning ratio `0.138`, mixed wire
  ratio `0.159`, mixed packet ratio `0.965`, hot packet ratio `0.916`, trace
  packet ratio `0.981`, optioned packet ratio `0.977`, boundary packet ratio
  `1.020`, and UDP-ceiling packet ratio `0.995`. This is retained as QTYPE=ANY
  planner allocation/rewalk cleanup before transport work.
- [x] Add retained semantic additional qtype-predicate cleanup:
  `target/zone-image-bench/semantic-additional-qtype-predicate.tsv` uses the
  concrete query type directly for exact positive, wildcard, and CNAME/DNAME
  endpoint additional-target predicates after the RRset has already been found
  by that type. This removes three redundant compiled-RRset type reads from
  semantic response planning while preserving the conservative QTYPE=ANY and
  target-bearing paths. The benchmark checker passed at
  `target/zone-image-bench/semantic-additional-qtype-predicate-check.tsv` with
  zero semantic and packet mismatches, byte parity, exact lookup ratio `0.130`,
  hot exact lookup ratio `0.204`, high-fanout exact lookup ratio `0.108`, mixed
  planning ratio `0.114`, mixed wire ratio `0.149`, mixed packet ratio `1.025`,
  hot packet ratio `0.973`, trace packet ratio `1.037`, optioned packet ratio
  `0.800`, boundary packet ratio `1.034`, UDP-ceiling packet ratio `0.997`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as semantic planner metadata-read cleanup, not as a
  broad packet-path speed claim.
- [x] Add retained additional-relation bitmap evidence:
  `target/zone-image-bench/additional-relation-flag.tsv` adds a compact compiled
  RRset bitmap for RRsets that actually have precomputed additional-address
  relation spans. Multi-answer and QTYPE=ANY additional planning now checks that
  relation-availability bit instead of reclassifying RR types per query, so
  target-bearing RRsets with no address relation also skip the dedupe path. The
  benchmark checker passed at
  `target/zone-image-bench/additional-relation-flag-check.tsv` with zero
  semantic and packet mismatches, byte parity, exact lookup ratio `0.122`, hot
  exact lookup ratio `0.204`, high-fanout exact lookup ratio `0.102`, mixed
  planning ratio `0.132`, mixed wire ratio `0.158`, mixed packet ratio `1.046`,
  hot packet ratio `1.079`, trace packet ratio `1.042`, optioned packet ratio
  `1.040`, boundary packet ratio `0.963`, UDP-ceiling packet ratio `1.002`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
  main hot bytes per record `98.499`, and stress hot bytes per record `134.267`.
  The follow-up `target/zone-image-bench/single-answer-relation-bitmap.tsv` run
  extends the same compiled relation-availability gate to single-answer
  exact/wildcard/indirection paths, including a target-bearing SRV RRset with no
  retained address relation. Its checker passed at
  `target/zone-image-bench/single-answer-relation-bitmap-check.tsv` with zero
  semantic and packet mismatches, byte parity, exact lookup ratio `0.176`, hot
  exact lookup ratio `0.214`, high-fanout exact lookup ratio `0.103`, mixed
  planning ratio `0.118`, mixed wire ratio `0.147`, mixed packet ratio `1.042`,
  hot packet ratio `1.040`, trace packet ratio `1.072`, optioned packet ratio
  `1.101`, boundary packet ratio `1.027`, UDP-ceiling packet ratio `1.014`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.001`,
	  main hot bytes per record `102.491`, and stress hot bytes per record
	  `138.267`.
	  This is retained as relation-driven planner discipline with bounded memory
	  cost, not as a broad packet-path speed claim.
- [x] Add retained single-answer additional-type gate:
  `target/zone-image-bench/single-answer-additional-type-gate.tsv` makes the
  single-answer additional helper return before the relation bitmap or
  relation-span lookup for RR types that cannot legally contribute address
  additionals. Target-bearing NS/MX/SRV/NAPTR/SVCB/HTTPS answers keep the
  compiled relation path, and the helper reports whether additionals were
  appended so exact A/AAAA/TXT-style plans can keep direct-answer eligibility
  without inspecting the additional section. Focused additional-span tests pass,
  the invariant audit guards the type gate, and the checker passed at
  `target/zone-image-bench/single-answer-additional-type-gate-check.tsv` with
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.162`,
  mixed wire ratio `0.184`, mixed packet ratio `1.004`, hot packet ratio `1.006`,
  trace packet ratio `1.003`, optioned packet ratio `1.017`, boundary packet
  ratio `1.013`, and UDP-ceiling packet ratio `1.004`. This is retained as
  relation-path avoidance for common non-target single answers, not as a broad
  packet-throughput claim.
- [x] Add retained concrete-class RRset span early-exit evidence:
  `target/zone-image-bench/concrete-class-rrset-scan-early-exit.tsv` uses the
  compiled per-owner class/type RRset order to stop response-planner
  exact-type helper and ANY RRset scans early for concrete QCLASS values.
  QCLASS=ANY keeps scanning all owner RRsets, preserving cross-class behavior.
  Focused coverage in
  `qtype_any_plan_serves_exact_and_wildcard_rrsets` now checks concrete class
  3 ANY selection and exact A lookup after earlier class-1 RRsets. The
  benchmark checker passed at
  `target/zone-image-bench/concrete-class-rrset-scan-early-exit-check.tsv`
  with zero semantic and packet mismatches, byte parity, exact lookup ratio
  `0.211`, hot exact lookup ratio `0.222`, high-fanout exact lookup ratio
  `0.109`, mixed planning ratio `0.124`, mixed wire ratio `0.147`, mixed
  packet ratio `1.036`, hot packet ratio `1.066`, trace packet ratio `1.030`,
  optioned packet ratio `1.055`, boundary packet ratio `1.036`, UDP-ceiling
  packet ratio `1.006`, delegation/DNAME stress planning ratio `0.001`, and
  stress wire ratio `0.001`. This is retained as exact/ANY owner-span scan
  reduction inside local packet gates.
- [x] Measure and reject public exact-plan class/type early exit:
  `target/zone-image-bench/lookup-exact-plan-class-early-exit-rejected.tsv`
  applied the same concrete-class early-exit logic to the older
  `lookup_exact_plan` helper. Correctness held, and the checker passed at
  `target/zone-image-bench/lookup-exact-plan-class-early-exit-rejected-check.tsv`
  with zero semantic and packet mismatches, byte parity, mixed planning ratio
  `0.124`, mixed wire ratio `0.150`, mixed packet ratio `1.002`, boundary
  packet ratio `0.986`, and UDP-ceiling packet ratio `1.008`; however the
  retained fixture's `ZoneImage` exact lookup time regressed to `40.805 ns`
  from the previous retained `34.465 ns`, and compile timings were noisy. The
  code was reverted because the current fixture mostly has tiny owner RRset
  spans where the extra branch is not justified.
- [x] Add retained unsigned-DNSSEC augmentation skip:
  `target/zone-image-bench/dnssec-unsigned-augmentation-skip.tsv` adds a
  compile-time `ZoneImage` flag for whether DNSSEC augmentation can add
  anything. Images with no NSEC/NSEC3 ranges and no RRSIG or delegation-DNSSEC
  relation spans now return the semantic plan immediately for DO-bit
  augmentation. Focused tests cover unchanged unsigned plans and signed images
  keeping the augmentation path enabled. The benchmark checker passed at
  `target/zone-image-bench/dnssec-unsigned-augmentation-skip-check.tsv` with
  zero semantic and packet mismatches, mixed planning ratio `0.136`, mixed wire
  ratio `0.160`, mixed packet ratio `1.003`, hot packet ratio `1.026`, trace
  packet ratio `0.998`, optioned packet ratio `1.012`, boundary packet ratio
  `0.942`, UDP-ceiling packet ratio `0.939`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as unsigned
  DO-query augmentation bookkeeping cleanup; the main retained benchmark fixture
  still includes signed-record boundary coverage.
- [x] Add retained DNSSEC capability sub-gates:
  `target/zone-image-bench/dnssec-capability-gates.tsv` splits the coarse
  DNSSEC augmentation capability into denial, referral, and RRSIG gates computed
  when the `ZoneImage` is compiled. DO-bit augmentation now skips the denial
  branch when no NSEC/NSEC3 ranges exist, skips referral proof work when no
  delegation proof or NSEC3 fallback can add records, and skips selected-RRSIG
  walks when no RRSIG relation spans exist. Focused tests cover unsigned,
  RRSIG-only, and denial-only images, and the benchmark checker passed at
  `target/zone-image-bench/dnssec-capability-gates-check.tsv` with zero
  semantic and packet mismatches, mixed planning ratio `0.135`, mixed wire
  ratio `0.164`, mixed packet ratio `1.016`, hot packet ratio `0.972`, trace
  packet ratio `1.043`, optioned packet ratio `1.007`, boundary packet ratio
  `0.999`, UDP-ceiling packet ratio `0.979`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as safe
  compile-time branch pruning for partial DNSSEC images, not as a broad
  packet-path speed claim.
- [x] Add retained DNSSEC dedupe-state seed gating:
  `target/zone-image-bench/dnssec-state-seeding-gates.tsv` uses those compiled
  DNSSEC capability sub-gates before seeding augmentation dedupe state. Images
  that can only add RRSIGs no longer clone the authority RRset list for proof
  insertion, and images that can only add denial/referral proof RRsets no longer
  scan selected-record identities. Focused tests cover RRSIG-only and
  denial-only state seeding. The benchmark checker passed at
  `target/zone-image-bench/dnssec-state-seeding-gates-check.tsv` with zero
  semantic and packet mismatches, mixed planning ratio `0.137`, mixed wire
  ratio `0.168`, mixed packet ratio `1.007`, hot packet ratio `1.060`, trace
  packet ratio `0.962`, optioned packet ratio `1.044`, boundary packet ratio
  `0.978`, UDP-ceiling packet ratio `1.023`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.001`. This is retained as partial
  DNSSEC image bookkeeping cleanup.
- [x] Add retained lazy DNSSEC authority-dedupe seeding:
  `target/zone-image-bench/dnssec-lazy-authority-dedupe-seed.tsv` defers the
  authority RRset dedupe clone until the first DNSSEC proof RRset is actually
  inserted. RRSIG-only DO-bit responses and positive responses in zones that
  merely have denial/referral capability no longer seed authority proof state
  unless a denial/referral branch emits an authority RRset. Focused tests prove
  that RRSIG augmentation leaves authority dedupe unseeded, while authority
  proof insertion still seeds from the current authority section and dedupes an
  existing SOA. The benchmark checker passed at
  `target/zone-image-bench/dnssec-lazy-authority-dedupe-seed-check.tsv` with
  zero semantic and packet mismatches, mixed planning ratio `0.137`, mixed wire
  ratio `0.159`, mixed packet ratio `1.034`, hot packet ratio `1.098`, trace
  packet ratio `1.049`, optioned packet ratio `1.013`, boundary packet ratio
  `1.015`, UDP-ceiling packet ratio `1.028`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.001`. This is retained as lazy
  per-query DNSSEC bookkeeping cleanup.
- [x] Add retained clone-free DNSSEC authority dedupe evidence:
  `target/zone-image-bench/dnssec-authority-dedupe-clone-free.tsv` removes the
  remaining authority RRset dedupe clone. DNSSEC proof insertion now checks the
  existing authority section directly and tracks only proof RRsets appended
  during augmentation, so an existing SOA/NSEC/DS is still deduped without
  copying the whole section into state. Focused DNSSEC dedupe tests, the
  filtered ZoneImage suite, and the profiling bench-target check passed, and
  the benchmark checker passed at
  `target/zone-image-bench/dnssec-authority-dedupe-clone-free-check.tsv` with
  zero semantic/packet mismatches, mixed planning ratio `0.122`, mixed wire
  ratio `0.152`, mixed packet ratio `1.057`, hot packet ratio `1.099`, trace
  packet ratio `1.033`, optioned packet ratio `1.026`, boundary packet ratio
  `1.001`, UDP-ceiling packet ratio `0.999`, delegation/DNAME stress planning
  ratio `0.001`, stress wire ratio `0.002`, hot bytes per record `98.502`, and
  stress hot bytes per record `134.204`. This is retained as clone-removal
  bookkeeping cleanup inside the local gates.
- [x] Add retained DNSSEC authority dedupe fast-path evidence:
  `target/zone-image-bench/dnssec-authority-dedupe-fast-path.tsv` checks the
  small appended-proof dedupe set before scanning the full authority section
  for repeated DNSSEC proof candidates. Existing authority RRsets are still
  deduped by the full section scan, while repeated NSEC/NSEC3/DS insertions
  appended during the same augmentation return from the narrow set first.
  Focused DNSSEC and ZoneImage tests pass, and
  `target/zone-image-bench/dnssec-authority-dedupe-fast-path-check.tsv`
  reports zero validation mismatches, unchanged response bytes, mixed planning
  ratio `0.131`, mixed wire ratio `0.178`, mixed packet ratio `0.991`, trace
  packet ratio `1.012`, optioned packet ratio `1.020`, boundary packet ratio
  `1.001`, and UDP-ceiling packet ratio `0.989`. This is retained as narrow
  DNSSEC proof-dedupe ordering cleanup.
- [x] Add retained DNSSEC authority dedupe single-scan evidence:
  `target/zone-image-bench/dnssec-authority-dedupe-single-scan.tsv` keeps the
  appended-proof fast path but removes the second appended-set scan for newly
  appended DNSSEC authority proof RRsets. Existing authority RRsets still use
  the full authority-section duplicate check before the append set is created.
  Focused DNSSEC and ZoneImage tests pass without warning debt, and
  `target/zone-image-bench/dnssec-authority-dedupe-single-scan-check.tsv`
  reports zero validation mismatches, unchanged response bytes, mixed planning
  ratio `0.138`, mixed wire ratio `0.157`, mixed packet ratio `1.013`, trace
  packet ratio `1.050`, optioned packet ratio `1.098`, boundary packet ratio
  `1.010`, and UDP-ceiling packet ratio `1.013`. This is retained as narrow
  per-query DNSSEC dedupe bookkeeping cleanup; packet timings remain noisy.
- [x] Add retained appended-authority inline-capacity evidence:
  `target/zone-image-bench/dnssec-appended-authority-inline-two.tsv` narrows
  the DNSSEC authority-proof appended-set scratch from four to two inline
  RRset handles. Existing authority RRsets are still checked before insertion,
  repeated appended proof candidates still dedupe through the narrow set, and
  larger proof sets spill. Focused DNSSEC proof/dedupe tests pass, and
  `target/zone-image-bench/dnssec-appended-authority-inline-two-check.tsv`
  reports zero semantic and packet mismatches, byte parity, mixed planning
  ratio `0.132`, mixed wire ratio `0.161`, mixed packet ratio `1.042`, hot
  packet ratio `1.003`, trace packet ratio `0.995`, optioned packet ratio
  `1.015`, boundary packet ratio `1.014`, and UDP-ceiling packet ratio
  `1.002`. This is retained as narrow DNSSEC authority-proof scratch-layout
  compaction inside the local gates.
- [x] Add retained always-inline DNSSEC authority appended-set evidence:
  `target/zone-image-bench/dnssec-authority-appended-inline-set-rerun.tsv`
  keeps that two-entry appended-proof set as direct inline DNSSEC state instead
  of wrapping it in an `Option`. RRSIG-only and denial-only tests now assert an
  empty inline set rather than unseeded optional state, while proof insertion
  checks the appended set before the original authority prefix and then pushes
  newly appended proof RRsets directly. Focused DNSSEC tests passed, and
  `target/zone-image-bench/dnssec-authority-appended-inline-set-rerun-check.tsv`
  reports zero validation/packet mismatches, byte parity, mixed planning ratio
  `0.127`, mixed wire ratio `0.151`, mixed packet ratio `0.993`, hot packet
  ratio `1.042`, trace packet ratio `1.010`, optioned packet ratio `0.975`,
  boundary packet ratio `1.037`, UDP-ceiling packet ratio `1.024`, stress
  planning ratio `0.001`, and stress wire ratio `0.001`. This is retained as
  narrow DNSSEC authority-proof state cleanup; packet timings remain noisy but
  inside local gates.
- [x] Add retained selected-record dedupe inline-capacity evidence:
  `target/zone-image-bench/selected-record-dedupe-inline-four.tsv` narrows the
  DNSSEC selected-record dedupe scratch from eight to four inline records,
  matching the common small RRSIG augmentation shape while spilling only for
  larger signed sections. Focused selected-RRSIG and signed-packet tests pass,
  and `target/zone-image-bench/selected-record-dedupe-inline-four-check.tsv`
  reports zero semantic and packet mismatches, byte parity, mixed planning
  ratio `0.119`, mixed wire ratio `0.145`, mixed packet ratio `1.035`, hot
  packet ratio `1.110`, trace packet ratio `1.035`, optioned packet ratio
  `1.076`, boundary packet ratio `1.020`, and UDP-ceiling packet ratio
  `1.018`. This is retained as narrow DNSSEC scratch-layout compaction inside
  the local gates; packet timings remain noisy.
- [x] Add retained referral NS plan-handle evidence:
  `target/zone-image-bench/referral-ns-plan-handle.tsv` carries the referral
  delegation NS RRset handle in `ZoneImageLookupPlan`, letting referral DNSSEC
  augmentation use the precomputed DS/NSEC relation or NSEC3 fallback directly
  instead of scanning authority RRsets to find the referral NS. Focused
  referral DNSSEC tests and broad ZoneImage tests pass, and
  `target/zone-image-bench/referral-ns-plan-handle-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.114`, mixed wire ratio `0.139`, mixed
  packet ratio `1.009`, hot packet ratio `1.017`, trace packet ratio `1.027`,
  optioned packet ratio `1.047`, boundary packet ratio `1.013`, and
  UDP-ceiling packet ratio `1.027`. This is retained as referral DNSSEC
  planning-handle cleanup inside the local gates.
- [x] Remove retained legacy referral DNSSEC authority scan:
  `target/zone-image-bench/referral-dnssec-strict-plan-handle.tsv` removes the
  old fallback that scanned authority RRsets to rediscover an NS RRset when a
  non-authoritative plan lacked `referral_ns_rrset`. Actual referral plans now
  must carry the NS handle; a focused regression covers the legacy-shaped plan,
  and the invariant audit rejects reintroducing the authority-section scan. The
  checker artifact
  `target/zone-image-bench/referral-dnssec-strict-plan-handle-check.tsv` reports
  zero validation/packet mismatches, byte parity, mixed planning ratio `0.143`,
  mixed wire ratio `0.166`, mixed packet ratio `1.047`, hot packet ratio
  `1.098`, trace packet ratio `1.025`, optioned packet ratio `1.024`, boundary
  packet ratio `1.000`, UDP-ceiling packet ratio `0.994`, delegation/DNAME stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as
  plan-shape discipline for signed referrals, not a broad packet-path speed win.
- [x] Add retained DNSSEC authority original-prefix evidence:
  `target/zone-image-bench/dnssec-authority-original-prefix.tsv` records the
  authority RRset count before DNSSEC augmentation and limits existing-authority
  duplicate checks to that prefix. Repeated proof RRsets appended during the
  same augmentation are deduped only by the narrow appended-proof set instead
  of rescanning the growing authority suffix. Focused ZoneImage tests pass,
  including the repeated appended-proof assertion, and
  `target/zone-image-bench/dnssec-authority-original-prefix-check.tsv` reports
  zero validation mismatches, unchanged response bytes, mixed planning ratio
  `0.132`, mixed wire ratio `0.158`, mixed packet ratio `1.044`, hot packet
  ratio `0.997`, trace packet ratio `0.974`, optioned packet ratio `0.994`,
  boundary packet ratio `1.007`, UDP-ceiling packet ratio `0.979`,
  delegation/DNAME stress planning ratio `0.001`, stress wire ratio `0.002`,
  hot bytes per record `98.502`, and stress hot bytes per record `134.204`.
  This is retained as another DNSSEC authority proof-planning scan reduction;
  packet timings remain within the local gates.
- [x] Add retained DNSSEC answer-presence denial gate:
  `target/zone-image-bench/dnssec-answer-presence-denial-gate.tsv` replaces
  full answer-record counting in the denial-candidate gate with a short-circuit
  answer-presence check. Positive DO-bit responses in DNSSEC-capable zones no
  longer sum all answer RRset record counts just to prove NODATA/NXDOMAIN
  denial proof planning is irrelevant; full record counting remains test-only
  and composer accounting still uses the exact section accounting path. Focused
  tests cover exact, wildcard, DNAME-positive, and NXDOMAIN plans. The benchmark
  checker passed at
  `target/zone-image-bench/dnssec-answer-presence-denial-gate-check.tsv` with
  zero semantic and packet mismatches, mixed planning ratio `0.121`, mixed wire
  ratio `0.144`, mixed packet ratio `0.975`, hot packet ratio `0.950`, trace
  packet ratio `0.969`, optioned packet ratio `0.946`, boundary packet ratio
  `0.996`, UDP-ceiling packet ratio `0.993`, delegation/DNAME stress planning
  ratio `0.001`, and stress wire ratio `0.001`. This is retained as
  DNSSEC-denial branch bookkeeping cleanup.
- [x] Add retained DNSSEC answer-presence plan-shape evidence:
  `target/zone-image-bench/dnssec-answer-presence-plan-shape.tsv` narrows the
  same denial/wildcard candidate classifier again: answer presence now follows
  the response plan shape instead of reading compiled RRset record counts. This
  relies on the compile invariant that image RRsets are built from grouped
  snapshot records and are non-empty; the builder now debug-asserts that
  invariant, and record-count helpers are test-only. Focused DNSSEC and
  ZoneImage tests passed, and the benchmark checker passed at
  `target/zone-image-bench/dnssec-answer-presence-plan-shape-check.tsv` with
  zero semantic and packet mismatches, unchanged response bytes, mixed planning
  ratio `0.122`, mixed wire ratio `0.149`, mixed packet ratio `0.997`, hot
  packet ratio `0.981`, trace packet ratio `1.003`, optioned packet ratio
  `0.985`, boundary packet ratio `0.989`, UDP-ceiling packet ratio `0.991`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.001`. This is retained as a small DNSSEC classifier cleanup before
  transport work.
- [x] Add retained DNSSEC answer-presence plan-bit evidence:
  `target/zone-image-bench/plan-answer-presence-bit.tsv` makes that classifier
  explicit `ZoneImageLookupPlan` state. Direct RRset, wildcard-owner,
  synthesized DNAME CNAME, and selected DNSSEC answer insertion paths set a
  cached answer-presence bit, and DNSSEC denial/wildcard augmentation reads the
  bit instead of re-deriving the answer shape. Focused DNSSEC tests and broad
  ZoneImage tests pass, and
  `target/zone-image-bench/plan-answer-presence-bit-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.131`, mixed wire ratio `0.150`, mixed
  packet ratio `1.003`, hot packet ratio `1.081`, trace packet ratio `1.081`,
  optioned packet ratio `1.036`, boundary packet ratio `1.034`, and UDP-ceiling
  packet ratio `1.017`. This is retained as DNSSEC classifier state cleanup,
  not as a broad packet-speed claim.
- [x] Add retained plan-state flag compaction evidence:
  `target/zone-image-bench/plan-state-flags.tsv` stores answer presence,
  authority SOA presence, wildcard synthesis, DNSSEC augmentation, and NSEC3 cap
  state in one compact `ZoneImageLookupPlan` flag byte rather than separate
  boolean fields. Focused DNSSEC tests and broad ZoneImage tests pass, and
  `target/zone-image-bench/plan-state-flags-check.tsv` reports zero semantic
  and packet mismatches, byte parity, hot bytes per record `102.491`, total
  bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.113`, mixed wire ratio `0.138`, mixed
  packet ratio `1.014`, hot packet ratio `1.034`, trace packet ratio `1.016`,
  optioned packet ratio `1.013`, boundary packet ratio `0.993`, and UDP-ceiling
  packet ratio `1.009`. This is retained as per-query plan-layout cleanup.
- [x] Add retained direct plan-state accessor evidence:
  `target/zone-image-bench/direct-plan-state-access.tsv` keeps the compact
  `ZoneImageLookupPlan` flags but removes the remaining `ZoneImage` helper
  indirection for answer-presence, authority-SOA, and first-authority-SOA
  checks. DNSSEC denial/wildcard classification and authority-section emission
  now read those flags through plan accessors directly. The checker passed at
  `target/zone-image-bench/direct-plan-state-access-check.tsv` with zero
  semantic and packet mismatches, byte parity, main bytes per record `174.000`,
  stress bytes per record `254.000`, mixed planning ratio `0.153`, mixed wire
  ratio `0.183`, mixed packet ratio `1.002`, hot packet ratio `0.905`, trace
  packet ratio `0.952`, optioned packet ratio `0.888`, boundary packet ratio
  `0.989`, and UDP-ceiling packet ratio `0.984`. This is retained as plan-state
  ownership cleanup rather than a broad packet-speed claim.
- [x] Add retained DNSSEC denial candidate single-evaluation evidence:
  `target/zone-image-bench/dnssec-denial-candidate-single-eval.tsv` removes the
  remaining duplicate denial query-node classifier helper. DNSSEC denial
  augmentation now computes NODATA and NXDOMAIN candidates once, reuses their
  combined `denial_candidate` for authority-SOA and query-node-handle decisions,
  and keeps wildcard proof classification separate. Focused DNSSEC candidate
  tests pass, the invariant audit rejects the old helper, and
  `target/zone-image-bench/dnssec-denial-candidate-single-eval-check.tsv`
  reports zero semantic and packet mismatches, byte parity, mixed planning ratio
  `0.139`, mixed wire ratio `0.159`, mixed packet ratio `1.028`, hot packet
  ratio `1.074`, trace packet ratio `1.066`, boundary packet ratio `0.981`,
  and UDP-ceiling packet ratio `1.007`. This is retained as duplicate
  classifier-branch cleanup before transport work, not as a throughput claim.
- [x] Add retained DNSSEC denial callsite-candidate gate evidence:
  `target/zone-image-bench/dnssec-denial-callsite-candidate-gates.tsv` moves
  the NODATA, NXDOMAIN, and wildcard proof helper candidate gates to the DNSSEC
  augmentation callsite. The helpers no longer accept duplicate candidate
  booleans and only run after the already-computed plan predicates have passed;
  lowercase-QNAME hints and query-node handles are still threaded through the
  selected proof paths. Focused DNSSEC/NSEC tests passed, and the invariant
  audit now rejects helper signatures that reintroduce candidate booleans. The
  checker passed at
  `target/zone-image-bench/dnssec-denial-callsite-candidate-gates-check.tsv`
  with zero validation and packet mismatches, hot bytes per record `106.365`,
  bytes per record `174.000`, stress bytes per record `256.000`, mixed planning
  ratio `0.157`, mixed packet ratio `1.007`, hot packet ratio `1.082`, trace
  packet ratio `1.050`, boundary packet ratio `0.986`, and UDP-ceiling packet
  ratio `1.017`. This is retained as callsite branch cleanup before transport
  work, not as broad throughput evidence.
- [x] Add retained DNSSEC denial authority-SOA query-node gate evidence:
  `target/zone-image-bench/dnssec-denial-soa-gated-query-node.tsv` moves the
  exact/closest query-node trie lookup behind the already-computed
  authority-SOA precondition. NODATA and NXDOMAIN proof helpers still gate on
  their plan predicates plus authority SOA at the callsite, but plans without
  the SOA proof precondition no longer compute query-node handles they cannot
  use. Focused DNSSEC/NSEC tests passed, and the invariant audit rejects moving
  the query-node lookup back outside the authority-SOA gate. The checker passed
  at
  `target/zone-image-bench/dnssec-denial-soa-gated-query-node-check.tsv` with
  zero validation and packet mismatches, hot bytes per record `106.365`, bytes
  per record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.146`, mixed packet ratio `1.018`, hot packet ratio `1.087`, trace packet
  ratio `1.063`, boundary packet ratio `1.010`, and UDP-ceiling packet ratio
  `1.016`. This is retained as another narrow denial-branch cleanup before
  transport work.
- [x] Add retained DNSSEC pre-state no-candidate gate evidence:
  `target/zone-image-bench/dnssec-prestate-no-candidate-gate.tsv` computes
  referral, NODATA, NXDOMAIN, and wildcard DNSSEC augmentation candidacy before
  constructing `ZoneImageDnssecState`. Proof-family-only images now return the
  semantic plan unchanged for positive non-wildcard responses that cannot use
  NSEC/NSEC3 denial proof helpers, so those queries avoid DNSSEC augmentation
  scratch setup entirely. A focused positive NSEC-only regression test passed,
  and the invariant audit now rejects removing the pre-state no-candidate
  return. The checker passed at
  `target/zone-image-bench/dnssec-prestate-no-candidate-gate-check.tsv` with
  zero validation and packet mismatches, hot bytes per record `106.365`, bytes
  per record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.142`, mixed packet ratio `0.992`, hot packet ratio `0.949`, trace packet
  ratio `0.984`, boundary packet ratio `0.997`, and UDP-ceiling packet ratio
  `0.995`. This is retained as DNSSEC augmentation scratch avoidance before
  transport work.
- [x] Add retained DNSSEC NODATA plan-precondition evidence:
  `target/zone-image-bench/dnssec-nodata-plan-precondition.tsv` removes `qtype`
  from the DNSSEC augmentation API and stops repeating an exact-qtype RRset
  lookup in the NODATA proof branch; lookup planning's answer-presence bit is
  now the owned precondition, and the exact qname node is used only for
  exact-name NSEC proof selection. Focused NODATA DNSSEC tests pass, and
  `target/zone-image-bench/dnssec-nodata-plan-precondition-check.tsv` reports
  zero semantic and packet mismatches, byte parity, main bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.138`,
  mixed wire ratio `0.157`, mixed packet ratio `0.972`, hot packet ratio
  `0.943`, trace packet ratio `0.993`, optioned packet ratio `0.980`, boundary
  packet ratio `1.009`, and UDP-ceiling packet ratio `1.013`. This is retained
  as a narrow signed-denial planning/API cleanup.
- [x] Add retained owner-override direct-copy metrics evidence:
  `target/zone-image-bench/owner-override-direct-body-metrics.tsv` reuses the
  compiled ownerless direct-copy length for wildcard/owner-override RRsets when
  computing carried plan wire bounds. Focused owner-override tests pass, and
  `target/zone-image-bench/owner-override-direct-body-metrics-check.tsv` reports
  zero semantic and packet mismatches, byte parity, main bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.147`,
  mixed wire ratio `0.170`, mixed packet ratio `0.973`, hot packet ratio
  `0.978`, trace packet ratio `0.994`, optioned packet ratio `0.979`, boundary
  packet ratio `1.015`, and UDP-ceiling packet ratio `1.012`. This is retained
  as narrow owner-override accounting cleanup.
- [x] Add retained direct-answer plan-flag evidence:
  `target/zone-image-bench/direct-answer-plan-flag.tsv` carries simple
  direct-answer composer eligibility as explicit `ZoneImageLookupPlan` state, so
  the direct response builder skips repeated section-shape checks and still
  validates direct-copy RRset eligibility and owner matching before emitting
  bytes. Focused direct-plan and direct-response tests pass, and
  `target/zone-image-bench/direct-answer-plan-flag-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.116`, mixed wire ratio `0.137`, mixed
  packet ratio `1.007`, hot packet ratio `0.926`, trace packet ratio `0.990`,
  optioned packet ratio `1.010`, boundary packet ratio `1.001`, and UDP-ceiling
  packet ratio `1.007`. This is retained as direct-composer preflight cleanup.
- [x] Add retained absent-RRtype direct-preflight evidence:
  `target/zone-image-bench/direct-preflight-rrtype-bitmap.tsv` compiles a
  conservative 256-bit low-RRtype presence bitmap into `ZoneImage`, so direct
  answer planning can return before trie lookup when the queried low RR type is
  known absent from the image. RR types above 255 keep the old conservative
  path, avoiding false negatives for private or future RR types. Focused tests
  cover absent low RR types and high/private RR types, and the checker artifact
  `target/zone-image-bench/direct-preflight-rrtype-bitmap-check.tsv` reports
  zero semantic and packet mismatches, byte parity, hot bytes per record
  `106.362`, total bytes per record `174.000`, absent low direct-preflight ratio
  `0.099`, exact lookup ratio `0.226`, hot exact lookup ratio `0.245`, mixed
  planning ratio `0.135`, mixed wire ratio `0.158`, mixed packet ratio `0.989`,
  hot packet ratio `0.923`, trace packet ratio `1.007`, optioned packet ratio
  `1.013`, boundary packet ratio `0.961`, UDP-ceiling packet ratio `0.991`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.002`. The artifact's isolated timing rows show absent low direct preflight
  at `2.382 ns/query` versus `24.054 ns/query` for the conservative absent
  high-type path on this host.
- [x] Add retained semantic absent-RRtype exact-probe evidence:
  `target/zone-image-bench/semantic-absent-rrtype-bitmap.tsv` reuses the same
  compiled low-RRtype bitmap in generic response planning. When the requested
  low RR type is absent from the compiled image, the exact-qtype RRset probe is
  skipped before CNAME/DNAME and denial handling continue normally. Focused
  tests cover an absent-low query at a CNAME owner and compare the resulting
  plan with the old snapshot oracle. The checker artifact
  `target/zone-image-bench/semantic-absent-rrtype-bitmap-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `106.362`,
  total bytes per record `174.000`, absent low direct-preflight ratio `0.093`,
  absent low response-plan ratio `0.964`, exact lookup ratio `0.222`, hot exact
  lookup ratio `0.255`, mixed planning ratio `0.149`, mixed wire ratio `0.177`,
  mixed packet ratio `1.010`, hot packet ratio `1.027`, trace packet ratio
  `0.987`, optioned packet ratio `0.980`, boundary packet ratio `0.966`,
  UDP-ceiling packet ratio `0.999`, delegation/DNAME stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as a small
  semantic-planning no-regression cleanup rather than a broad packet-throughput
  claim.
- [x] Add retained public exact absent-RRtype scan gate:
  `target/zone-image-bench/exact-lookup-low-rrtype-gate.tsv` applies the same
  low-RRtype bitmap to the older public `lookup_exact_plan` helper after exact
  node classification. Existing names with globally absent low RR types now
  return `NoData` before owner RRset scanning, while missing and out-of-zone
  names keep `NameError`/`OutOfZone` classification and high/private RR types
  keep the conservative scan. The checker artifact
  `target/zone-image-bench/exact-lookup-low-rrtype-gate-check.tsv` reports zero
  semantic and packet mismatches, byte parity, absent low exact lookup ratio
  `0.951`, absent low direct-preflight ratio `0.104`, absent low response-plan
  ratio `0.979`, mixed planning ratio `0.142`, mixed wire ratio `0.162`, mixed
  packet ratio `0.993`, hot packet ratio `0.896`, trace packet ratio `0.989`,
  boundary packet ratio `0.949`, UDP-ceiling packet ratio `0.988`, exact lookup
  ratio `0.199`, hot exact lookup ratio `0.236`, high-fanout exact lookup ratio
  `0.114`, base image bytes per record `174.000`, and stress bytes per record
  `256.000`. This is retained as a narrow no-scan cleanup for the compatibility
  exact helper, not as broad packet-throughput evidence.
- [x] Add retained indirection-free absent-RRtype fallback evidence:
  `target/zone-image-bench/indirection-free-absent-rrtype-bitmap.tsv` extends
  the same compiled low-RRtype bitmap gate to generic CNAME and DNAME fallback
  probes. Images with no CNAME RRsets skip the CNAME fallback lookup for
  non-CNAME queries, and images with no DNAME RRsets skip the inherited-DNAME
  fallback and direct-answer DNAME guard after the absent exact-qtype probe is
  skipped. Images that contain those indirection RRsets keep the old fallback
  behavior. The indirection-free benchmark fixture uses the same `bench.test.`
  owner shape as the baseline so the check compares compiled indirection
  presence rather than label depth. The checker artifact
  `target/zone-image-bench/indirection-free-absent-rrtype-bitmap-check.tsv`
  reports zero semantic and packet mismatches, byte parity, absent low
  direct-preflight ratio `0.098`, absent low response-plan ratio `0.981`,
  indirection-free absent low response-plan ratio `0.976`, exact lookup ratio
  `0.280`, hot exact lookup ratio `0.237`, mixed planning ratio `0.141`, mixed
  wire ratio `0.172`, mixed packet ratio `1.037`, hot packet ratio `1.031`,
  trace packet ratio `1.018`, optioned packet ratio `1.023`, boundary packet
  ratio `0.961`, UDP-ceiling packet ratio `0.984`, delegation/DNAME stress
  planning ratio `0.001`, and stress wire ratio `0.002`. This is retained as a
  narrow fallback-probe no-regression cleanup.
- [x] Add retained wildcard absent-RRtype fallback evidence:
  `target/zone-image-bench/wildcard-low-rrtype-gates.tsv` applies the same
  compiled low-RRtype bitmap discipline to wildcard planning. Wildcard exact
  RRset probes are skipped when the requested low RR type is known absent from
  the image, and wildcard CNAME fallback probes are skipped when the image has
  no CNAME RRsets. High/private RR types keep the conservative path. Focused
  tests cover the no-CNAME wildcard NODATA shape against the old snapshot
  oracle, and the invariant audit now requires the wildcard gates. The checker
  artifact `target/zone-image-bench/wildcard-low-rrtype-gates-check.tsv`
  reports zero semantic and packet mismatches, byte parity, base image bytes per
  record `174.000`, delegation/DNAME stress bytes per record `256.000`, absent
  low direct-preflight ratio `0.098`, absent low response-plan ratio `0.971`,
  indirection-free absent low response-plan ratio `0.963`, mixed planning ratio
  `0.148`, mixed wire ratio `0.165`, mixed packet ratio `0.978`, hot packet
  ratio `0.973`, trace packet ratio `0.932`, optioned packet ratio `0.975`,
  boundary packet ratio `1.003`, UDP-ceiling packet ratio `0.998`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as a wildcard planner symmetry cleanup, not as a
  transport throughput claim.
- [x] Add retained indirection-target absent-RRtype evidence:
  `target/zone-image-bench/indirection-target-low-rrtype-gates.tsv` applies the
  same compiled low-RRtype bitmap gates after CNAME/DNAME target resolution has
  reached a known in-zone target node. Requested-type target-node probes are
  skipped when the low RR type is absent from the image, target CNAME fallback
  probes are skipped when the image has no CNAME RRsets, and QTYPE=CNAME avoids
  repeating the same CNAME lookup after the requested-type probe. Focused DNAME
  target-resolution tests compare the absent-A/no-CNAME target NODATA shape
  against the old snapshot oracle, and the invariant audit guards the target
  gates. The checker artifact
  `target/zone-image-bench/indirection-target-low-rrtype-gates-check.tsv`
  reports zero semantic and packet mismatches, byte parity, base image bytes per
  record `174.000`, delegation/DNAME stress bytes per record `256.000`, absent
  low direct-preflight ratio `0.103`, absent low response-plan ratio `0.986`,
  indirection-free absent low response-plan ratio `1.000`, mixed planning ratio
  `0.144`, mixed wire ratio `0.156`, mixed packet ratio `0.985`, hot packet
  ratio `1.057`, trace packet ratio `0.974`, optioned packet ratio `0.952`,
  boundary packet ratio `0.958`, UDP-ceiling packet ratio `0.987`,
  delegation/DNAME stress planning ratio `0.001`, and stress wire ratio
  `0.002`. This is retained as target-resolution planner work reduction, not
  as a transport result.
- [x] Add retained multi-record direct-answer body-template evidence:
  `target/zone-image-bench/direct-answer-body-template.tsv` compiles the
  compressed-owner direct answer body for multi-record direct-copy RRsets, while
  single-record direct-copy RRsets keep the previous record-slice emission path
  to avoid duplicating cold wire bytes across ordinary A/AAAA-heavy zones. The
  checker passed at
  `target/zone-image-bench/direct-answer-body-template-check.tsv` with zero
  semantic and packet mismatches, byte parity, hot bytes per record `106.359`,
  total bytes per record `174.000`, delegation/DNAME stress bytes per record
  `256.000`, mixed planning ratio `0.147`, mixed wire ratio `0.172`, mixed
  packet ratio `0.997`, hot packet ratio `0.955`, trace packet ratio `0.998`,
  optioned packet ratio `1.000`, boundary packet ratio `1.016`, UDP-ceiling
  packet ratio `0.998`, delegation/DNAME stress planning ratio `0.001`, and
  stress wire ratio `0.002`. This is retained as a bounded direct-composer
  template cleanup; applying the template to every single-record direct RRset
  was rejected again at
  `target/zone-image-bench/single-record-direct-body-template-check.tsv`
  because it raised the delegation/DNAME stress image to `272.000` bytes per
  record, above the retained `256.000` ceiling.
- [x] Add retained direct-template branch cleanup evidence:
  `target/zone-image-bench/direct-template-branch-no-record-slice.tsv` keeps the
  compiled multi-record direct-answer body template on a narrower hot path: the
  direct RRset view now selects the template body without first fetching the
  fallback record slice, and computes the emitted body length in the same branch
  that selects the body representation. Single-record direct RRsets still use
  the bounded record-slice fallback rather than duplicating cold wire. Focused
  direct-answer and delegation/DNAME semantic tests passed. The checker passed
  at `target/zone-image-bench/direct-template-branch-no-record-slice-check.tsv`
  with zero semantic and packet mismatches, byte parity, hot bytes per record
  `106.362`, total bytes per record `174.000`, delegation/DNAME stress bytes
  per record `256.000`, mixed planning ratio `0.146`, mixed wire ratio
  `0.170`, mixed packet ratio `0.975`, hot packet ratio `0.930`, trace packet
  ratio `0.946`, optioned packet ratio `0.941`, boundary packet ratio `0.988`,
  UDP-ceiling packet ratio `0.988`, delegation/DNAME stress planning ratio
  `0.002`, and stress wire ratio `0.002`. This is retained as direct-template
  hot-path cleanup before transport work, not as a new template coverage claim.
- [x] Measure and reject direct-answer emitted-body-length storage:
  `target/zone-image-bench/direct-answer-emitted-body-len.tsv` tried storing the
  emitted compressed direct-answer body length in every `ImageRrset`, removing
  the fallback branch's per-query `ownerless_wire_len + 2 * record_count`
  arithmetic. The checker artifact
  `target/zone-image-bench/direct-answer-emitted-body-len-check.tsv` preserved
  zero validation and packet mismatches plus byte parity, with mixed packet
  ratio `0.959`, hot packet ratio `0.998`, trace packet ratio `1.063`, and
  UDP-ceiling packet ratio `1.012`, but failed the retained memory guard:
  delegation/DNAME stress bytes per record rose to `260.000`, above the
  `256.000` ceiling. The code change was reverted; the measured result keeps
  the current branch-local length derivation as the better pre-transport tradeoff.
- [x] Add retained authoritative plan-flag evidence:
  `target/zone-image-bench/authoritative-plan-flag.tsv` folds the plan's
  authoritative/referral state into the same compact `ZoneImageLookupPlan` flag
  byte, keeping plan predicates explicit without a separate boolean field.
  Focused ZoneImage and serving tests pass, and
  `target/zone-image-bench/authoritative-plan-flag-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.117`, mixed wire ratio `0.143`, mixed
  packet ratio `1.008`, hot packet ratio `1.035`, trace packet ratio `1.047`,
  optioned packet ratio `1.032`, boundary packet ratio `1.051`, and UDP-ceiling
  packet ratio `1.047`. This is retained as plan-state compaction.
- [x] Add retained answer-RRset inline-capacity evidence:
  `target/zone-image-bench/answer-rrsets-inline-one.tsv` narrows
  `ZoneImageLookupPlan`'s inline answer-RRset handle capacity to the common
  single-RRset answer shape, leaving multi-RRset QTYPE=ANY paths to spill only
  when they actually need more handles. Focused ANY, mixed-packet, and
  UDP-ceiling tests pass, and
  `target/zone-image-bench/answer-rrsets-inline-one-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.119`, mixed wire ratio `0.146`, mixed
  packet ratio `1.003`, hot packet ratio `1.036`, trace packet ratio `1.033`,
  optioned packet ratio `1.058`, boundary packet ratio `1.018`, and UDP-ceiling
  packet ratio `1.006`. This is retained as per-query plan-layout compaction.
- [x] Add retained authority-RRset inline-capacity evidence:
  `target/zone-image-bench/authority-rrsets-inline-two.tsv` narrows
  `ZoneImageLookupPlan`'s inline authority-RRset capacity to two handles, which
  covers the common SOA plus one proof/referral shape while allowing larger
  DNSSEC proof sets to spill only when they need more handles. Focused denial,
  referral-DNSSEC, and DNSSEC proof-corpus tests pass, and
  `target/zone-image-bench/authority-rrsets-inline-two-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.129`, mixed wire ratio `0.150`, mixed
  packet ratio `1.000`, hot packet ratio `0.972`, trace packet ratio `0.987`,
  optioned packet ratio `0.939`, boundary packet ratio `1.039`, and UDP-ceiling
  packet ratio `0.991`. This is retained as per-query authority-plan layout
  compaction.
- [x] Add retained compact authority-SOA index evidence:
  `target/zone-image-bench/authority-soa-index-u16.tsv` narrows
  `ZoneImageLookupPlan`'s authority SOA position to DNS-section-bounded `u16`
  storage with an explicit sentinel. Focused authority-SOA and compact-plan
  tests passed, and the invariant audit now rejects widening this per-query
  section index. The checker passed at
  `target/zone-image-bench/authority-soa-index-u16-check.tsv` with zero
  semantic and packet mismatches, byte parity, unchanged image bytes per record
  (`174` main, `256` stress), mixed planning ratio `0.146`, mixed wire ratio
  `0.166`, mixed packet ratio `1.008`, hot packet ratio `1.019`, trace packet
  ratio `0.995`, optioned packet ratio `0.994`, boundary packet ratio `1.005`,
  UDP-ceiling packet ratio `0.997`, delegation/DNAME-stress planning ratio
  `0.001`, and stress wire ratio `0.002`. This is retained as narrow
  per-query authority-plan layout compaction.
- [x] Retain authority RRset type from plan metrics:
  `target/zone-image-bench/authority-metrics-rrtype.tsv` carries the compiled
  RR type inside the transient RRset plan metrics loaded from immutable
  `ImageRrset` metadata. Authority planning now derives SOA state from those
  metrics instead of accepting a second RR-type scalar from each caller, so
  DNSSEC authority insertion and negative-response authority planning stay on
  the same single compiled-metadata read used for record counts and wire
  bounds. Focused authority tests passed, and the invariant audit rejects
  reintroducing explicit `RecordType` arguments on authority RRset pushes. The
  checker passed at
  `target/zone-image-bench/authority-metrics-rrtype-check.tsv` with zero
  validation and packet mismatches, hot bytes per record `106.365`,
  bytes per record `174.000`, stress bytes per record `256.000`, mixed
  planning ratio `0.140`, mixed packet ratio `0.960`, hot packet ratio
  `0.930`, trace packet ratio `0.983`, boundary packet ratio `1.018`, and
  UDP-ceiling packet ratio `1.026`. This is retained as authority-plan metadata
  discipline, not as broad throughput evidence.
- [x] Add retained compact DNAME dynamic-index evidence:
  `target/zone-image-bench/dname-indirection-dynamic-index-u16.tsv` narrows the
  transient DNAME indirection target handle for synthesized CNAME answers to the
  same DNS-answer-count-bounded `u16` index used by `PlanAnswer::DynamicRecord`.
  The handle widens only when resolving the stored dynamic-answer RDATA slice.
  Focused DNAME tests and compact-index tests passed, and the invariant audit
  now rejects widening this transient DNAME handle. The checker passed at
  `target/zone-image-bench/dname-indirection-dynamic-index-u16-check.tsv` with
  zero semantic and packet mismatches, byte parity, unchanged image bytes per
  record (`174` main, `256` stress), mixed planning ratio `0.142`, mixed wire
  ratio `0.166`, mixed packet ratio `0.996`, hot packet ratio `0.985`, trace
  packet ratio `0.998`, optioned packet ratio `1.037`, boundary packet ratio
  `1.019`, UDP-ceiling packet ratio `1.022`, delegation/DNAME-stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as narrow
  DNAME transient-plan layout compaction.
- [x] Add retained compact DNSSEC original-authority-count evidence:
  `target/zone-image-bench/dnssec-original-authority-count-u16.tsv` narrows the
  DNSSEC augmentation scratch count for the original authority RRset prefix to
  DNS-section-bounded `u16` storage. Duplicate-proof checks widen it only when
  slicing the immutable plan's original authority prefix. Focused DNSSEC and
  compact-index tests passed, and the invariant audit now rejects widening this
  transient prefix count. The checker passed at
  `target/zone-image-bench/dnssec-original-authority-count-u16-check.tsv` with
  zero semantic and packet mismatches, byte parity, unchanged image bytes per
  record (`174` main, `256` stress), mixed planning ratio `0.145`, mixed wire
  ratio `0.165`, mixed packet ratio `1.024`, hot packet ratio `1.075`, trace
  packet ratio `1.047`, optioned packet ratio `1.064`, boundary packet ratio
  `1.008`, UDP-ceiling packet ratio `1.034`, delegation/DNAME-stress planning
  ratio `0.001`, and stress wire ratio `0.002`. This is retained as narrow
  DNSSEC transient-state layout compaction.
- [x] Add retained additional-RRset inline-capacity evidence:
  `target/zone-image-bench/additional-rrsets-inline-four.tsv` narrows
  `ZoneImageLookupPlan`'s inline additional-RRset capacity to four handles,
  keeping room for common multi-target additional sections while reducing the
  common plan object from the previous eight-handle inline storage. Focused
  additional, QTYPE=ANY, mixed-packet, and UDP-ceiling tests pass, and
  `target/zone-image-bench/additional-rrsets-inline-four-check.tsv` reports
  zero semantic and packet mismatches, byte parity, hot bytes per record
  `102.491`, total bytes per record `170.000`, delegation/DNAME stress bytes
  per record `250.000`, mixed planning ratio `0.125`, mixed wire ratio `0.151`,
  mixed packet ratio `1.047`, hot packet ratio `1.064`, trace packet ratio
  `1.044`, optioned packet ratio `1.035`, boundary packet ratio `1.019`, and
  UDP-ceiling packet ratio `0.997`. This is retained as per-query
  additional-plan layout compaction.
- [x] Add retained selected-section inline-capacity evidence:
  `target/zone-image-bench/selected-section-inline-one.tsv` narrows
  `ZoneImageLookupPlan`'s selected-authority and selected-additional RRSIG
  handle inline capacity to one handle per section, matching the common direct
  section-signature case while allowing larger signed sections to spill only
  when needed. Focused selected-RRSIG, DNSSEC proof-corpus, and signed-packet
  edge tests pass, and
  `target/zone-image-bench/selected-section-inline-one-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.129`, mixed wire ratio `0.157`, mixed
  packet ratio `1.012`, hot packet ratio `0.916`, trace packet ratio `0.980`,
  optioned packet ratio `0.941`, boundary packet ratio `1.012`, and UDP-ceiling
  packet ratio `0.999`. This is retained as selected-section plan-layout
  compaction.
- [x] Add retained dynamic synthesized-answer inline-capacity evidence:
  `target/zone-image-bench/dynamic-answer-inline-one.tsv` narrows
  `ZoneImageLookupPlan`'s dynamic synthesized-answer inline capacity to one
  record, matching the common DNAME-synthesized CNAME shape while allowing
  uncommon multi-record synthesized sections to spill only when needed. Focused
  DNAME target-resolution and mixed-packet tests pass, and
  `target/zone-image-bench/dynamic-answer-inline-one-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `102.491`,
  total bytes per record `170.000`, delegation/DNAME stress bytes per record
  `250.000`, mixed planning ratio `0.124`, mixed wire ratio `0.145`, mixed
  packet ratio `0.995`, hot packet ratio `0.940`, trace packet ratio `0.957`,
  optioned packet ratio `0.959`, boundary packet ratio `1.014`, and UDP-ceiling
  packet ratio `0.996`. This is retained as synthesized-answer plan-layout
  compaction.
- [x] Add retained compact answer-item index evidence:
  `target/zone-image-bench/plan-answer-compact-indexes.tsv` narrows
  `PlanAnswer` owner-override and dynamic synthesized-record indexes from
  pointer-sized `usize` values to DNS-answer-count-bounded `u16` values.
  Focused plan-layout and wildcard direct-plan tests cover the compact
  `PlanAnswer` size, alignment, and owner-override behavior, and the invariant
  audit guards the explicit DNS-count bound at the push sites. The checker
  passed at `target/zone-image-bench/plan-answer-compact-indexes-check.tsv`
  with zero validation/packet mismatches, byte parity, `PlanAnswer` size `28`
  bytes, main image bytes per record `174.000`, stress bytes per record
  `256.000`, mixed planning ratio `0.139`, mixed wire ratio `0.161`, mixed
  packet ratio `0.999`, hot packet ratio `0.896`, trace packet ratio `1.000`,
  optioned packet ratio `0.997`, boundary packet ratio `1.002`, UDP-ceiling
  packet ratio `0.991`, and delegation/DNAME stress planning and wire ratios
  of `0.001` and `0.002`. This is retained as per-query plan item layout
  compaction, not as a broad throughput claim.
- [x] Add retained DNSSEC empty proof-family gates:
  `target/zone-image-bench/dnssec-denial-proof-family-callsite-gates.tsv`
  gates NSEC and NSEC3 denial-proof helper entry on whether the compiled
  `ZoneImage` actually contains that proof family. NSEC-only zones no longer
  construct NSEC3 hash cache state for denial/referral helper calls, NSEC3-only
  zones no longer enter empty NSEC range scans, exact NODATA skips the
  exact-name NSEC probe when the image has no NSEC proof family, and
  NXDOMAIN/wildcard callsites only enter each proof family when that family is
  present in the compiled image. Focused tests cover both empty-family helper
  exits without seeding authority dedupe state, NSEC-only NXDOMAIN proof
  selection, and NSEC3-only exact NODATA proof selection. The benchmark checker
  passed at
  `target/zone-image-bench/dnssec-denial-proof-family-callsite-gates-check.tsv`
  with zero trace and boundary packet mismatches, hot bytes/record `106.364`,
  bytes/record `174`, stress bytes/record `256`, mixed planning ratio `0.150`,
  mixed packet ratio `0.998`, hot packet ratio `1.026`, trace packet ratio
  `1.017`, boundary packet ratio `1.006`, and UDP-ceiling packet ratio `1.017`.
  This is retained as proof-family branch pruning for partial DNSSEC images.
- [x] Add retained carried plan-count append evidence:
  `target/zone-image-bench/carried-plan-count-append.tsv` removes record-count
  recomputation from the low-level uncompressed `append_plan_wire` section
  appenders. The writer still appends from immutable RRset, selected-record,
  owner-override, and dynamic-record handles, but returns the already carried
  plan record total after writing instead of accumulating another per-section
  counter. Focused plan wire-bound and ZoneImage tests pass, and
  `target/zone-image-bench/carried-plan-count-append-check.tsv` reports zero
  semantic and packet mismatches, byte parity, hot bytes per record `106.362`,
  delegation/DNAME stress bytes per record `256.000`, mixed planning ratio
  `0.151`, mixed wire ratio `0.169`, mixed packet ratio `0.982`, hot packet
  ratio `0.902`, trace packet ratio `1.017`, optioned packet ratio `1.019`,
  boundary packet ratio `1.003`, UDP-ceiling packet ratio `1.000`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
  This is retained as composer accounting cleanup before transport backends.
- [x] Add retained truncation authority-removability evidence:
  `target/zone-image-bench/truncation-authority-removability.tsv` changes the
  truncated response scratch collector to consume a `ZoneImage` authority
  visitor that carries plan-derived removability. The retry path still protects
  the negative SOA authority record, but it no longer rereads every retained
  authority wire record's RR type just to decide whether the record can be
  removed before the SOA. Focused authority-removability and layout tests pass,
  and the invariant audit rejects reintroducing the per-authority-record SOA
  classification in truncation scratch collection. The checker passed at
  `target/zone-image-bench/truncation-authority-removability-check.tsv` with
  zero semantic and packet mismatches, byte parity, main image bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.149`,
  mixed wire ratio `0.174`, mixed packet ratio `1.000`, hot packet ratio
  `0.969`, trace packet ratio `1.006`, optioned packet ratio `0.991`, boundary
  packet ratio `1.015`, UDP-ceiling packet ratio `1.032`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
  This is retained as truncation-composer bookkeeping cleanup, not as transport
  work.
- [x] Add retained DNS-width response-shape count evidence:
  `target/zone-image-bench/response-shape-dns-counts-u16.tsv` moves final DNS
  section-count bounds into `ZoneImageLookupPlan::response_shape()`. The bundled
  response shape now carries answer, authority, and additional counts as
  `u16`, so the known-count packet builder writes those carried counts directly
  instead of reconverting them from `usize` for every response. Focused compact
  plan-layout tests cover the DNS-width fields, and the invariant audit rejects
  builder-side `u16::try_from(response_shape.*)` conversions. The checker
  passed at `target/zone-image-bench/response-shape-dns-counts-u16-check.tsv`
  with zero semantic and packet mismatches, byte parity, main image bytes per
  record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.148`, mixed wire ratio `0.174`, mixed packet ratio `0.991`, hot packet
  ratio `0.922`, trace packet ratio `0.952`, optioned packet ratio `0.945`,
  boundary packet ratio `1.001`, UDP-ceiling packet ratio `0.986`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
  This is retained as response-header bookkeeping cleanup before transport
  backends.
- [x] Add retained truncation carried retry-count evidence:
  `target/zone-image-bench/truncation-carried-retry-counts.tsv` carries the
  DNS-width answer, authority, and additional counts through UDP truncation
  retry and decrements them as records are removed. The wire-record retry
  composer now receives those counts directly and only asserts scratch-vector
  parity in debug builds instead of converting vector lengths to DNS counts for
  every retry attempt. Focused truncation tests and the invariant audit pass,
  and the audit rejects reintroducing `u16::try_from(*.len())` conversions in
  the wire-record rebuild path. The checker passed at
  `target/zone-image-bench/truncation-carried-retry-counts-check.tsv` with zero
  semantic and packet mismatches, byte parity, main image bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.144`,
  mixed wire ratio `0.167`, mixed packet ratio `1.010`, hot packet ratio
  `1.020`, trace packet ratio `1.027`, optioned packet ratio `0.999`, boundary
  packet ratio `0.963`, UDP-ceiling packet ratio `0.981`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
  This is retained as truncation retry bookkeeping cleanup before transport
  backends.
- [x] Add retained truncation section-local retry encode evidence:
  `target/zone-image-bench/truncation-section-local-retry-encode.tsv` keeps the
  carried-count retry composer but encodes answer, authority, and additional
  scratch sections through explicit section-local loops instead of a chained
  iterator over all retained sections. Focused truncation tests pass, and the
  invariant audit rejects reintroducing chained section iteration in the
  wire-record retry rebuild. The checker passed at
  `target/zone-image-bench/truncation-section-local-retry-encode-check.tsv`
  with zero semantic and packet mismatches, byte parity, main image bytes per
  record `174.000`, stress bytes per record `256.000`, mixed planning ratio
  `0.146`, mixed wire ratio `0.173`, mixed packet ratio `0.933`, hot packet
  ratio `0.989`, trace packet ratio `0.957`, optioned packet ratio `0.945`,
  boundary packet ratio `0.978`, UDP-ceiling packet ratio `0.984`, and
  delegation/DNAME stress planning and wire ratios of `0.001` and `0.002`.
  This is retained as truncation retry composer cleanup before transport
  backends.
- [x] Add retained truncation retry section-count byte evidence:
  `target/zone-image-bench/truncation-retry-count-bytes.tsv` carries mutable
  retry section counts as one response-shape-derived value that starts from the
  plan's preencoded section-count bytes. Record-removal retries now patch only
  the removed section's two count bytes and the wire-record retry composer
  consumes those carried bytes plus the carried EDNS additional count, instead
  of rebuilding answer/authority/additional count bytes from separate counters
  on every retry attempt. Focused count-byte tests pass, and the invariant
  audit rejects reintroducing retry count-byte reencoding in the wire-record
  rebuild path. The checker passed at
  `target/zone-image-bench/truncation-retry-count-bytes-check.tsv` with two EDE
  fallback packet cases, zero semantic and packet mismatches, byte parity, main
  image bytes per record `174.000`, stress bytes per record `256.000`, mixed
  planning ratio `0.144`, mixed wire ratio `0.163`, mixed packet ratio `1.011`,
  hot packet ratio `1.024`, trace packet ratio `0.996`, optioned packet ratio
  `1.002`, boundary packet ratio `1.020`, UDP-ceiling packet ratio `0.996`,
  NOTIFY SOA mixed-case validation ratio `0.998`, CHAOS mixed-case
  classification ratio `0.957`, and delegation/DNAME stress planning and wire
  ratios of `0.002` and `0.002`. This is retained as truncation retry
  response-header bookkeeping cleanup before transport backends.
- [x] Add retained plan response-flag bit evidence:
  `target/zone-image-bench/response-shape-plan-flag-bits.tsv` carries the
  plan-derived AA/Rcode response flag bits in `ZoneImagePlanResponseShape`, so
  known-count and truncation retry packet builders consume the bundled response
  shape instead of rereading plan response semantics during header assembly.
  Focused plan-accounting tests pass, and the invariant audit rejects
  reintroducing separate `rcode`/authoritative inputs in the known-count and
  retry composers. The checker passed at
  `target/zone-image-bench/response-shape-plan-flag-bits-check.tsv` with zero
  semantic and packet mismatches, byte parity, main image bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.152`,
  mixed wire ratio `0.174`, mixed packet ratio `1.012`, hot packet ratio
  `1.035`, trace packet ratio `1.024`, optioned packet ratio `0.995`, boundary
  packet ratio `0.996`, UDP-ceiling packet ratio `1.019`, and delegation/DNAME
  stress planning and wire ratios of `0.001` and `0.002`. This is retained as
  response-header bookkeeping cleanup before transport backends.
- [x] Add retained response section-count byte evidence:
  `target/zone-image-bench/response-shape-section-count-bytes.tsv` carries the
  no-EDNS DNS section-count header bytes in `ZoneImagePlanResponseShape`.
  Ordinary known-count packet composition copies those bytes through the shared
  prefix helper, and only the EDNS additional-count adjustment uses the
  response-shape helper to rebuild the six section-count bytes. Direct response
  count bytes and mutable truncation-retry count bytes are tightened in the
  later `direct-rrset-section-count-bytes` and `truncation-retry-count-bytes`
  follow-ups. Focused plan-accounting tests cover the carried bytes and EDNS
  adjustment, and the invariant audit rejects known-count composer reencoding
  of response-shape counts. The checker passed at
  `target/zone-image-bench/response-shape-section-count-bytes-check.tsv` with
  zero semantic and packet mismatches, byte parity, main image bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.149`,
  mixed wire ratio `0.173`, mixed packet ratio `1.013`, hot packet ratio
  `0.978`, trace packet ratio `0.995`, optioned packet ratio `1.018`, boundary
  packet ratio `0.979`, UDP-ceiling packet ratio `0.994`, and delegation/DNAME
  stress planning and wire ratios of `0.001` and `0.002`. This is retained as
  response-header byte bookkeeping cleanup before transport backends.
- [x] Add retained direct-RRset section-count byte evidence:
  `target/zone-image-bench/direct-rrset-section-count-bytes.tsv` carries
  no-EDNS and EDNS-adjusted DNS section-count header bytes in the
  `ZoneImageDirectRrset` view, so the direct exact-owner composer consumes the
  same immutable-view response shape instead of reencoding answer/additional
  counts in `dns.rs`. Focused direct-plan and direct-body tests pass, and the
  invariant audit rejects returning direct response count-byte encoding to the
  composer. The checker passed at
  `target/zone-image-bench/direct-rrset-section-count-bytes-check.tsv` with
  zero semantic and packet mismatches, byte parity, main image bytes per record
  `174.000`, stress bytes per record `256.000`, mixed planning ratio `0.149`,
  mixed wire ratio `0.172`, mixed packet ratio `0.974`, hot packet ratio
  `1.000`, trace packet ratio `1.034`, optioned packet ratio `1.006`, boundary
  packet ratio `0.965`, UDP-ceiling packet ratio `0.991`, and delegation/DNAME
  stress planning and wire ratios of `0.001` and `0.002`. This is retained as
  direct-composer response-header bookkeeping cleanup before transport backends.
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
- [ ] Offline/live differential replay over representative operator traces
  records zero validation mismatches, zero packet mismatches, and zero
  `ZoneImage` serve failures without reintroducing live shadow validation.
- [x] Packet-level differential tests cover positive, negative, wildcard,
  delegation, CNAME, DNAME, additional-data, EDNS, truncation, DNSSEC, and
  unknown-RR cases.
- [ ] Physical benchmark evidence shows `ZoneImage` is not slower on real NIC
  profiles.
- [x] Operational metrics expose fixed ZoneImage failure detail; live rollback
  metrics are retired.
- [x] Configuration no longer exposes a snapshot-serving rollback switch.
- [x] The old query path is no longer available as a live runtime rollback.
- [x] Query-serving code no longer materializes the old layout on the hot path.
- [x] Transfer ingestion and validation still use a clear safe builder model.
- [x] Documentation no longer describes the old layout as the primary serving
  data plane.

## Pre-AF_XDP Gap Order

These are the local, XDP-free gaps to close before deciding whether server-side
AF_XDP is justified.

1. [x] Close the local pre-AF_XDP immutable-composer gap without requiring full
   response templates. The runtime path no longer materializes old
   `LookupResult` values, packet composition uses immutable plan/wire-record
   views with retained bounds and compression evidence, and measured
   full-template variants that grew memory or slowed packets are recorded as
   rejected. Full response templates remain optional future work, gated by
   transport-buffer evidence such as io_uring fixed buffers or AF_XDP UMEM
   rather than a blocker for the current local data-model slice. Selected DNSSEC
   signatures remain immutable record references, while truly generated DNAME
   CNAME records stay synthesized buffers because inline/template variants were
   measured and rejected under current gates.
2. [x] Move the locally justified per-query planning work into compile-time
   spans and templates.
   Negative SOA variants, ordinary answer additional RRsets, referral glue, and
   RRSIG record relations are precomputed. Referral glue now appends those
   deduplicated compile-time relation spans directly to fresh referral plans
   without a runtime duplicate scan. CNAME/DNAME first-hop targets are also
   pre-parsed and relation-addressed, DNAME owner matching borrows stored
   RRset owner wire, and DNAME synthesized CNAME RDATA appends the target's
   stored single-name wire instead of serializing the target name per query.
   DS-at-delegation owner matching now uses exact trie-node state plus compiled
   policy RRset owner depth instead of scanning stored delegation owner wire. NSEC
   covering ranges are precomputed as canonical order keys, and proof lookup
   compares query labels directly against those keys without allocating a
   per-query canonical key. NSEC3 hashing feeds SHA-1
   directly from query labels and borrows cached per-parameter query hashes
   while scanning precomputed NSEC3 candidate metadata.
   DNSSEC authority proof insertion now checks only the original authority
   section prefix and tracks proof RRsets appended during augmentation, so
   repeated proof candidates are deduped without cloning or rescanning the
   growing authority section.
   Additional-data planning now walks copied answer handles directly without
   cloning answer vectors, folds target detection and target emission into one
   pass, starts from an empty additional section, and keeps its target dedupe set
   inline for common one-to-few additions without a second populated-section
   duplicate scan.
   QTYPE=ANY same-owner RRset collection also stays inline for common owner
   shapes, and wildcard ANY owner overrides share one serialized query owner
   across all synthesized-answer RRsets. Dynamic
   synthesized-answer buckets keep common one-to-few entries inline, while all
   selected RRSIG records are direct immutable answer items or section handles
   instead of dynamic-record entries. Synthesized DNAME CNAME helpers now append
   and count directly from prevalidated rdlength bytes without a transient
   dynamic wire-record view or fallible append result. Stored and synthesized
   `ZoneImage` records now also carry compact precomputed RDATA compression shape,
   so the composer does not reparse copy/single-name/SOA/MX RDATA shapes per
   emitted record. Wildcard owner-override planning also reuses the compiled
   direct-answer body length for direct-copy answer RRsets when computing
   carried wire bounds, leaving the stored full-owner wire arithmetic only for
   non-direct RDATA shapes, and single-RRset wildcard owner-substitution
   accounts from the already-built query-owner override wire instead of walking
   parsed owner labels separately for length and serialization. Multi-record
   direct-copy RRsets now also keep a bounded compiled compressed-owner body
   template, while single-record direct RRsets deliberately stay on the previous
   record-slice emission path to keep generated image bytes within the retained
   ceiling. CNAME/DNAME
   chain loop tracking borrows precomputed immutable target keys
   instead of cloning every followed target key. DNSSEC RRSIG augmentation now
   avoids cloning plan section vectors, uses inline selected-record dedupe, and
   scans only the contiguous RRSIG relation subspan for each covered RRset.
   Additional-address, referral-glue, single-name target, and signed-referral
   DS/NSEC proof relation lookups also use same-kind subspans from the
   already-contiguous compiled relation order instead of filtering whole mixed
   relation spans; the subspan finder itself uses one direct index scan. RRsets
   now point at compact relation-span descriptors with precomputed same-kind
   offsets, so these consumers no longer rediscover relation-kind starts from
   the mixed relation slice on every query. Signed-referral DNSSEC proof
   selection now reads the compact delegation-proof offset directly, and
   CNAME/DNAME single-name target lookup reads the compact single-name target
   offset directly. Additional-address, referral-glue, and RRSIG consumers also
   read their explicit offsets directly; the generic relation-kind helper is now
   test-only inspection surface.
   `target/zone-image-bench/relation-kind-subspan-consumers.tsv` is retained
   for this cleanup and passed the checker at
   `target/zone-image-bench/relation-kind-subspan-consumers-check.tsv` with
   zero validation/packet mismatches, byte parity, mixed planning ratio
   `0.131`, mixed wire ratio `0.178`, mixed packet ratio `1.015`, boundary
   packet ratio `0.995`, UDP-ceiling packet ratio `0.987`, stress planning
   ratio `0.001`, and stress wire ratio `0.002`. DNSSEC selected-record dedupe
   skips selected-record seed scans for ordinary unaugmented plans. DNSSEC
   signed-referral proof selection now scans the referral RRset's relation span
   once to find either precomputed DS or NSEC proof relation, instead of
   requesting both same-kind subspans separately. Referral-only DNSSEC proof
   augmentation now also returns immediately for authoritative response plans,
   avoiding an authority-section NS scan for ordinary positive and negative
   DNSSEC responses. Actual referral plans carry the delegation NS RRset handle
   so referral DNSSEC augmentation no longer scans the authority section to
   rediscover it. DNSSEC denial/wildcard proof checks now classify answer
   presence from explicit plan state instead of reading compiled RRset record
   counts or re-deriving plan shape, relying on the compile invariant that image
   RRset handles are non-empty. Per-query plan boolean state is stored in one
   compact flag byte, and denial/classifier plus authority composer code read
   that state through direct plan accessors. The negative authority-SOA
   precondition is tracked as plan state instead of scanning authority RRsets,
   authority SOA state is derived from the same compiled RRset plan metrics
   that carry record counts and wire bounds instead of a duplicate caller
   RR-type scalar, and the denial query-node gate now reuses the
   already-computed NODATA/NXDOMAIN candidate booleans plus authority-SOA
   precondition instead of calling a second classifier helper or walking the
   trie when no SOA proof can be emitted. Proof-family-only positive
   non-wildcard plans now return before allocating DNSSEC augmentation scratch.
   NODATA, NXDOMAIN, and wildcard proof helper entry is also gated at the DNSSEC
   augmentation callsite so those helpers no longer carry duplicate candidate
   booleans.
   NODATA proof selection also trusts that plan-carried no-answer precondition,
   so DNSSEC augmentation no longer accepts `qtype` or repeats exact-qtype
   RRset lookup before exact-name NSEC proof selection.
   DNSSEC augmentation now reuses one exact/closest query-node lookup across
   NODATA, NXDOMAIN closest-encloser, and wildcard proof decisions.
   DNSSEC augmentation skips that query-node lookup for ordinary positive
   direct-RRset plans and DNAME-synthesized positive plans that were not marked
   by the wildcard owner-substitution path; wildcard proof selection now uses
   the explicit plan flag without a trie walk.
   Signed-referral proof augmentation avoids cloning the authority section.
   Signed-referral DS/NSEC proof selection now uses precomputed delegation
   relations instead of reparsing the NS owner and looking up same-owner proof
   RRsets per query. Signed-referral NSEC3 fallback hashes stored delegation
   owner wire directly instead of parsing the owner into a `DomainName`.
   NXDOMAIN closest-encloser and wildcard-child NSEC/NSEC3 proof lookups now
   compare and hash borrowed query-label views instead of constructing
   temporary `DomainName` values for those proof names.
   NSEC3 iterative SHA-1 hashing now keeps intermediate hashes in the fixed
   digest output buffer instead of allocating a `Vec<u8>` per iteration.
   NSEC3 range lookup also compares raw hash bytes from compiled range metadata
   and the per-query hash cache instead of allocating base32 hash strings.
   Compiled NSEC3 range metadata stores valid SHA-1 owner/next hashes inline as
   fixed arrays rather than heap vectors, and ranges now carry compact
   parameter-set handles so the per-query hash cache does not recompare
   algorithm/iteration/salt tuples for every candidate; the salt-bearing
   parameter view is also materialized only on hash-cache misses from the
   descriptor already loaded for the iteration cap. The retained
   `target/zone-image-bench/nsec3-param-set-descriptor-reuse.tsv` checker passed
   with mixed planning ratio `0.144`, mixed packet ratio `0.987`, trace packet
   ratio `0.999`, boundary packet ratio `0.999`, and UDP-ceiling packet ratio
   `1.005`. DNSSEC augmentation now returns a plan directly instead of carrying
   an unreachable fallible planning result, and the dead DNSSEC plan-error
   serve-failure metric label has been removed.
   Exact NODATA, NXDOMAIN, and wildcard denial augmentation also gate helper
   entry on compiled NSEC/NSEC3 proof-family presence, so partial DNSSEC images
   skip empty proof-family setup before selection; the retained
   `target/zone-image-bench/dnssec-denial-proof-family-callsite-gates.tsv`
   checker passed with mixed planning ratio `0.150`, mixed packet ratio
   `0.998`, trace packet ratio `1.017`, boundary packet ratio `1.006`, and
   UDP-ceiling packet ratio `1.017`.
   DNSSEC denial proof planning also computes the authority-SOA precondition
   once and checks only authority RRset handles, because selected authority
   records are RRSIG handles. Authority proof insertion checks the small
   appended-proof dedupe set before scanning the full authority section, so
   repeated proof candidates appended during the same augmentation take the
   narrow duplicate path, and newly appended proof RRsets avoid a second
   appended-set scan after the full authority duplicate check has passed.
   Semantic response planning now also returns a plan directly; CNAME, DNAME,
   wildcard, and additional-data planning no longer carry unreachable build
   error plumbing, and the dead response plan-error serve-failure metric label
   has been removed.
   Closest-encloser node discovery now walks the compiled trie without parent
   `DomainName` construction, and response planning reuses exact/closest query
   node handles across all major branches instead of repeating node walks.
   Wildcard-synthesis detection uses node/edge handles instead of rebuilding a
   wildcard domain name for lookup.
   Minimal QTYPE=ANY planning selects the first retained RRset from the
   compiled per-owner class/type order through a scalar helper instead of
   collect/sort/truncate or a one-entry RRset list, and target-bearing
   minimal-ANY single answers append their compiled additional-address relation
   span directly. Single-RRset owners bypass the ANY scan with one
   QCLASS/DNSSEC-proof eligibility check for both minimal and full ANY. Full ANY
   streams matching same-owner RRsets from that same compiled order into the
   plan without a query-time sort or temporary RRset list, and dedupes
   additional-address relation spans during that pass.
   Concrete-class exact and ANY RRset scans now also stop once that compiled
   class/type order has passed the requested class or type, while QCLASS=ANY
   keeps scanning all classes.
   Exact positive planning also skips the generic additional-data planner when
   the answer RR type cannot reference address targets.
   Non-ANY wildcard planning now applies the same gate for RR types that cannot
   reference address targets, and exact/wildcard full-ANY plans append
   additional-address RRsets directly from the answer RRset list's precomputed
   relation spans. CNAME/DNAME indirection also skips the generic planner when
   the chain endpoint cannot contribute additional-address targets, while the
   single target-bearing endpoint case appends the precomputed relation span
   directly. Single-answer exact and wildcard target-bearing plans also append
   that compiled span directly; the compile path deduplicates repeated
   target-address RRsets within each relation span. Those concrete exact,
   wildcard, and indirection predicates use the matched query type directly
   instead of rereading the compiled RRset type after exact RRset lookup.
   Single-answer, multi-answer, and QTYPE=ANY additional planning also check a
   compiled relation-availability bitmap before entering relation iteration or
   the dedupe path, so query-time code follows actual precomputed
   additional-address relation availability rather than RR-type classification.
   Single-answer exact, wildcard, and indirection endpoint plans now first skip
   even that bitmap/relation-span path for RR types that cannot legally have
   address additionals; retained
   `target/zone-image-bench/single-answer-additional-type-gate.tsv` evidence
   passed with zero validation/packet mismatches, byte parity, mixed packet ratio
   `1.004`, and UDP-ceiling packet ratio `1.004`.
   The old generic dynamic-record additional planner is removed because no live
   plan shape uses it.
   CNAME/DNAME single-name target precompute now builds target `DomainName`
   values only from whole uncompressed RDATA wire, rejecting compression
   pointers and trailing bytes without routing through the generic DNS
   message-name parser.
   DO-bit DNSSEC augmentation also checks a compile-time image flag before
   building augmentation state, so unsigned images without NSEC/NSEC3 ranges,
   RRSIG relations, or delegation-DNSSEC relations return the semantic plan
   directly.
   Direct-answer response building now also trusts the caller-side DO-bit gate:
   DNSSEC-requested responses never enter the direct builder, and the helper
   keeps that as a debug assertion instead of repeating a runtime
   `dnssec_requested()` branch.
   Generic packet composition now keeps the common wire-name compression suffix
   table inline instead of allocating a per-response hash table, and its suffix
   lookup/registration helpers use direct loops on that small table. Pointer
   discovery now happens while validating wire-name label offsets, avoiding an
   extra offset scan before suffix registration, and suffixes already checked
   as absent during that pointer search are registered without a second
   suffix-table lookup. Exact full-name suffix hits now emit the existing
   pointer before label parsing or temporary offset collection, covering common
   same-owner answer names, and exact full-name misses are not rechecked by the
   label parser. Stored wire-name parsing now returns only the write boundary
   and selected pointer, so pre-pointer suffix registration no longer builds a
   temporary label-offset list. Parsed question-name suffix seeding also pushes
   directly into the fresh response compressor without a duplicate suffix-table
   scan, starts from the parsed QNAME wire length stored on `Question`, and
   reuses the carried suffix wire length plus the parser-carried
   lowercase-QNAME fact when building canonical suffix keys.
   That avoids both the full-name length walk and per-suffix length
   recomputation in the compressor seed path. Stored canonical suffix labels
   are checked with direct byte equality before falling back to
   case-insensitive comparison for mixed-case candidates, and validated
   already-lowercase stored suffixes and parsed question-label suffixes copy
   directly into suffix-key storage instead of lowercasing every label byte
   during key construction.
   The generic response composer also computes each request's UDP ceiling and
   EDNS-padding/full-UDP-capacity reserve decision once, then threads those
   values through OPT emission, capacity sizing, truncation checks, and
   truncation retry helpers. EDNS OPT response options are now appended
   directly into the final response buffer with an in-place rdlength patch,
   avoiding the previous temporary option-RDATA allocation for NSID, DNS Cookie,
   EDE, TCP keepalive, and padding responses. The retained
   `target/zone-image-bench/wire-name-exact-suffix-fast-path.tsv` run passed the
   checker at `target/zone-image-bench/wire-name-exact-suffix-fast-path-check.tsv`
   with zero validation/packet mismatches, byte parity, mixed packet ratio
   `0.987`, trace packet ratio `0.998`, boundary packet ratio `1.010`,
   UDP-ceiling packet ratio `0.991`, and unchanged hot bytes per record
   `98.492`.
   Generic packet composition now combines section-count and wire-bound
   accounting in one immutable-plan pass.
   Generic and truncated packet composition now seed question-name compression
   from parsed labels instead of scanning serialized question wire, and compute
   registered suffix lengths in one pass.
   Truncated `ZoneImage` response rebuilds pre-size packet buffers from
   retained immutable wire-record lengths, uses UDP-ceiling-sized retry
   buffers, reuses the plan-carried section counts for truncation scratch
   sizing, and starts retry metadata from plan-carried DNSSEC-record and body
   wire-bound counters instead of classifying and summing every kept wire record
   while collecting truncation scratch. Removed-record body-bound decrement also
   reads each wire record's carried rdlength bytes instead of the RDATA slice
   length. It also
   keeps the next removable non-SOA authority index across retries instead of
   rescanning the authority section from the end after additionals are exhausted,
   and pops tail removable authority records without shifting the retained
   scratch vector. For oversized EDE responses, truncation now tries an
   EDE-stripped rebuild directly from the immutable plan before collecting
   kept-record scratch vectors for record removal.
   Authority-section emission also uses compact first-authority-SOA state and
   the carried authority SOA position to apply negative-SOA TTL override to the
   known SOA RRset and copy or visit the remaining authority RRsets without
   scanning each one for SOA.
   Selected DNSSEC plan handles carry immutable fixed fields, wire length, and
   the selected record's compact RDATA range. Their RRSIG relations keep checked
   owner/RDATA lengths in a guarded compact 12-byte layout, because a full
   relation-carried selected wire length still exceeds the stress memory gate.
   Selected-record append and visit paths do not rediscover RRset
   TYPE/CLASS/TTL fields or record RDATA metadata during emission, handle
   creation does not reread owner/RDATA lengths from the selected record, and
   the transient handle no longer retains the stale selected record table index
   after copying the RDATA range. RRSIG augmentation also uses a compact
   relation-presence bitmap before relation-span lookup and consumes the
   compiled relation slice directly, while trusting compile-time empty RRSIG
   relation slices for RRSIG RRsets instead of rereading the covered
   RRset type on the runtime path.
   Synthesized DNAME CNAME target replacement now returns the generated target
   and its wire form from one checked suffix-replacement pass, and the stored
   DNAME owner wire is compared directly against borrowed query labels without
   a temporary wire-label vector. When the compiled target hint proves an
   unrelated out-of-zone DNAME target is terminal, the planner now uses the
   counted wire-only replacement path and avoids materializing a synthesized
   `DomainName`. The generated target-wire helper writes prefix labels straight
   into the inline name buffer and accounts from the completed wire, so it no
   longer walks those prefix labels only to pre-size the same buffer.
   Literal CNAME/DNAME single-name targets now carry precomputed
   in-zone/existing-node classifications, so static CNAME target resolution can
   reuse the compiled node handle directly. DNAME synthesized-target resolution
   also uses that classification to walk only the prepended query-label prefix
   from existing in-zone target nodes, or to skip the target-node walk for
   known-missing in-zone targets. Out-of-zone literal DNAME targets are split:
   parent-suffix targets keep the full synthesized-target lookup because a
   prepended label prefix can make them in-zone, while unrelated out-of-zone
   targets stay out-of-zone without that trie walk.
   CNAME/DNAME target resolution now reuses one exact target-node walk for
   requested-type lookup, chained CNAME lookup, and NODATA/NXDOMAIN
   classification. Live CNAME continuation is handle-only: callers pass the
   discovered CNAME RRset directly, and name-based RRset lookup is test-only.
   CNAME/DNAME loop tracking keeps the original query name borrowed and stores
   the original exact query node when available; existing in-zone followed
   targets compare compiled trie node handles for loop detection, while missing
   and out-of-zone targets compare compiled or synthesized target wire to the
   original query labels without a canonical-key loop-tracking string.
   NXDOMAIN signed-denial proof planning derives the closest-encloser proof name
   from the trie depth and query-label suffix instead of walking parent domains.
   NSEC denial range lookup now stores the owner-before-next range-order bit in
   compiled metadata, avoiding a repeated immutable endpoint comparison while
   scanning candidate ranges.
   Negative SOA selection reads the precomputed IN apex SOA handle for ordinary
   IN and ANY-class denial responses instead of walking the origin name or
   scanning apex RRsets on every negative response.
   Ordinary IN-class delegation and inherited-DNAME checks now read compiled
   policy handles from `NameNode` instead of walking ancestor nodes in the
   response planner and direct-answer guard; non-IN class queries still use the
   conservative scan path. The direct-answer DS delegation guard also compares
   compiled policy RRset owner label count against node depth for IN and
   safe-ANY images instead of rescanning the current node to decide whether the
   delegation handle is owned by the query node. High-fanout nodes also read
   their generated child hash side-index handle directly from `NameNode`
   instead of searching the side-index table before probing hash slots.
   Direct positive-answer packet composition rejects custom CNAME, wildcard, and
   generated-answer plans before attempting exact-owner direct RRset emission
   and rejects target-bearing RR types before direct-preflight trie lookups.
   Direct responses now trust the private exact-node plan marker instead of
   fetching and reparsing compiled owner wire to re-prove that the RRset owner
   matches the parsed question. They also write the DNS answer count from
   compiled RRset metadata instead of patching the header after copying records,
   fetch copied-answer metadata through one eligible-only non-empty immutable
   RRset view, and derive direct-copy eligibility from the compiled direct-answer
   body length without a separate RRset side-bitset lookup, post-view eligibility
   branch, or post-view zero-answer guard. Direct response headers also write
   the fixed `NoError`/authoritative flags from the direct-plan invariant instead
   of rereading dynamic plan flag accessors. Direct
   answer body emission now walks compiled record/RDATA metadata instead of
   reparsing immutable RRset wire to skip stored owner names, and the selected
   direct RRset view carries the emitted body length used for response
   allocation. Template RRsets read that length from the compiled template body,
   while fallback record-slice RRsets derive it from compiled ownerless length
   plus record count in the same branch that selects the body representation.
   The append step uses selected direct RRset view metadata plus a
   pre-bounds-checked compiled record slice instead of re-indexing the RRset by
   ID after preflight. The
   selected direct view also carries the constant compressed-owner/type/class/TTL
   record prefix used by direct-copy answers. The direct response allocation is
   sized from emitted compressed-answer length instead of stored full-owner
   RRset wire length. Stored immutable RDATA references now carry a compact
   prevalidated `u16` rdlength without growing `ImageRecord`, so direct-copy and
   stored-record TTL-override emission do not reconvert RDATA slice lengths per
   emitted record. Selected stored records no longer carry a fallible append
   edge, and the common no-override stored-RRset/owner-override helpers are
   split from the rare negative-SOA explicit-TTL override helper. Authority
   sections now use the plan's authority-SOA flag to stay on the immutable
   no-override copy/visit path unless a negative-SOA TTL rewrite is actually
   possible. Direct exact-owner OPT emission now uses the shared `ZoneImage`
   EDNS append helper rather than a separate inline direct-path branch. When the
   request path already tried and rejected the same direct plan, that rejected
   semantic plan is retained for the generic composer, so the generic response
   builder skips both duplicate direct-builder retry and duplicate semantic
   planning before composing from immutable wire records. Direct preflight now
   also checks a compiled low-RRtype presence bitmap before trie lookup, so
   absent low RR types skip pointless exact-owner direct planning while high
   private/future RR types keep the conservative path. The public
   `lookup_exact_plan` compatibility helper now also checks that bitmap after
   node classification and before exact-owner RRset scans, preserving
   `NameError`/`OutOfZone` outcomes for missing names. Generic semantic
   planning reuses the same bitmap to skip exact-qtype RRset probes for absent
   low RR types before continuing through CNAME/DNAME and denial handling, and
   images with no CNAME or DNAME RRsets skip the matching generic indirection
   fallback probe; the direct-answer DNAME guard also returns immediately for
   DNAME-free images. Wildcard planning now uses the same gates for wildcard
   exact-qtype probes and wildcard CNAME fallback probes, and CNAME/DNAME target
   resolution uses them for requested-type target-node probes plus target CNAME
   fallback probes.
   Direct-answer preflight now proves the exact RRset exists before running
   delegation and DNAME direct-answer guards, so existing names with an absent
   but globally present low RR type skip cut-policy work before falling back to
   semantic planning. The retained
   `target/zone-image-bench/direct-preflight-rrset-first.tsv` run passed the
   checker at `target/zone-image-bench/direct-preflight-rrset-first-check.tsv`
   with zero validation/packet mismatches, byte parity, absent-present-low
   direct-preflight ratio `1.003` against the absent-high conservative path,
   zero absent direct-preflight answer RRsets, mixed packet ratio `0.982`, hot
   packet ratio `0.977`, trace packet ratio `0.971`, and UDP-ceiling packet
   ratio `0.987`.
   Domain-to-wire serialization pre-sizes output buffers for
   synthesized/override wire names; some synthesized DNSSEC/additional shapes
   still need measured template work. Wildcard owner-override wire names now
   stay inline for common generated owner lengths, after narrowing the broader
   rejected inline generated-owner experiment to the wildcard-owner-only path
   and retaining packet-ratio evidence. A narrower inline synthesized-record
   wire experiment for DNAME CNAMEs was also measured and rejected because
   larger per-plan inline buffers slowed planning and wire emission. Selected
   DNSSEC records now stay as direct immutable plan items or section handles,
   leaving only truly synthesized answers on the dynamic-answer bucket; that
   remaining bucket's append/count helpers are now synthesized-record-specific.
   Remaining candidates in this section are now evidence-gated optional work,
   not known local blockers before transport work.
3. [~] Compare sorted child edges against adaptive-radix and generated perfect
   hash layouts using retained high-fanout evidence, and keep only changes that
   improve packet-path timing or a clearly isolated lookup bottleneck. A
   thresholded generated open-address child hash index is retained for nodes
   with at least 1024 children; adaptive radix and minimal/perfect hash layouts
   still need separate evidence before implementation. A benchmark-only
   first-byte child-label bucket was measured and rejected because it was slower
   than both sorted lookup and the retained generated child hash on the current
   high-fanout fixture. A benchmark-only label-length bucket was also measured
   and rejected: it preserved lookup counts/checksums but was slower than both
   sorted lookup and generated hash while adding `40548` side-index bytes. A
   benchmark-only last-byte child-label bucket was measured and rejected: it
   preserved lookup counts/checksums, but measured `1.417x` sorted lookup and
   added `42084` side-index bytes on the retained high-fanout fixture. A
   compact generated hash was also measured and rejected: it halves slot bytes
   but largely gives back the generated-hash lookup win.
   The retained generated child hash now stores slot values as `u16` per-node
   edge offsets, preserving the 2x slot policy while reducing image hot bytes.
   Its probe equality path now also checks already-lowercase query labels with
   direct byte equality before falling back to case-insensitive comparison; the
   retained `target/zone-image-bench/child-hash-direct-label-eq.tsv` run keeps
   zero mismatches and measures high-fanout exact lookup ratio `0.101`.
   The child-hash descriptor now also stores the power-of-two slot mask
   directly, so hash probes do not recreate it from the slot count on every
   high-fanout lookup. The retained
   `target/zone-image-bench/child-hash-precomputed-mask.tsv` run passed the
   checker at `target/zone-image-bench/child-hash-precomputed-mask-check.tsv`
   with zero validation/packet mismatches, byte parity, high-fanout exact
   lookup ratio `0.121`, generated child-hash ratio `0.645`, mixed packet ratio
   `0.959`, hot packet ratio `0.939`, trace packet ratio `0.971`, and
   UDP-ceiling packet ratio `1.006`.
   Single-child trie nodes now bypass binary search with one
   stored-lowercase edge equality check before the generated-hash/binary-search
   fallback path; `target/zone-image-bench/single-child-trie-fast-path.tsv`
   kept zero mismatches and measured exact lookup ratio `0.222`.
   Leaf trie nodes now also return a child miss immediately before the
   generated-hash/binary-search fallback path;
   `target/zone-image-bench/leaf-child-trie-fast-path.tsv` kept zero
   mismatches and measured UDP-ceiling packet ratio `0.994`.
   Fanout 2-4 trie nodes now scan stored-lowercase child labels linearly before
   generated-hash/binary-search fallback, matching an adaptive small-node shape
   without adding side-index bytes. Focused mixed-case small-child lookup and
   high-fanout hash tests passed, the invariant audit requires the fanout-4
   threshold, and the retained
   `target/zone-image-bench/small-child-linear-lookup.tsv` checker passed at
   `target/zone-image-bench/small-child-linear-lookup-check.tsv` with matching
   small-child found counts/checksums, small-child linear ratio `0.541`, zero
   validation/packet mismatches, byte parity, mixed packet ratio `0.959`, hot
   packet ratio `0.969`, trace packet ratio `0.975`, and UDP-ceiling packet
   ratio `1.010`.
   Single-RRset owner lookup now also bypasses the compiled-order RRset scan
   with one QTYPE/QCLASS match before falling back to the multi-RRset scan;
   `target/zone-image-bench/single-rrset-owner-fast-path.tsv` kept zero
   mismatches and measured exact lookup ratio `0.217`.
   Multi-RRset owner lookup now has a sparse node-local low-RRtype bitmap side
   table, built only for nodes with more than one RRset and addressed by a
   compact `NameNode` handle, so common absent-present low types can skip the
   compiled-order owner RRset scan without a side-table binary search. The
   retained `target/zone-image-bench/node-low-rrtype-bitmap-handle.tsv` checker
   passed with hot bytes/record `106.364`, total bytes/record `174`, stress
   bytes/record `256`, absent-present low QCLASS=ANY exact ratio `0.802`, mixed
   packet ratio `1.029`, trace packet ratio `1.023`, and UDP-ceiling packet
   ratio `1.011`.
4. [~] Reduce old `ZoneSnapshot` reliance to ingestion, validation, transfer,
   catalog reconciliation, and offline oracle use. The live runtime path is
   `ZoneImage`, and the stale `ZoneSnapshot` materialized DNSSEC augmentation
   branch has been removed. `ZoneImage` compilation now iterates borrowed
   snapshot RRsets and RDATA slices directly instead of materializing a full
   `Vec<ResourceRecord>` through `ZoneSnapshot::records()` or cloning them into
   a temporary grouping map, then keeps deterministic image order by sorting
   compiled RRsets. That sorted owner key is also reused for the builder RRset
   index, avoiding a second canonical owner-string build for each compiled
   RRset. Builder trie attachment now borrows relative labels and uses inline
   lowercase lookup keys instead of building an owned reversed label vector for
   every attached RRset. The broad string-key `ZoneStore::get` snapshot
   accessor has been removed, and presence-only NOTIFY/catalog membership
   checks use `contains_exact_zone_for_control` instead of cloning
   `Arc<ZoneSnapshot>`. The
   runtime status and metrics path now reads cached `ZoneStore` metadata,
   including publication-time active-zone shape summaries, instead of cloning
   and rescanning full snapshots through a broad snapshot iterator; query
   observation also reads a cached canonical origin key from `PublishedZone`
   instead of rebuilding it from the snapshot origin per query. The retained
   `target/zone-image-bench/published-zone-key-suffix-baseline.tsv` run keeps
   the measured-faster vector prefix-list suffix lookup after an inline
   temporary-key experiment was rejected as slower; its checker passed with
   zero semantic and packet mismatches and a suffix/linear directory lookup
   ratio of `0.013`. The follow-up
   `target/zone-image-bench/query-inline-parser-and-zone-suffix-scratch.tsv`
   keeps that one-key suffix lookup and moves the common per-query prefix-length
   list into inline `SmallVec<[usize; 8]>` storage; its checker passed with
   matching directory found counts/checksums and a suffix/linear directory
   lookup ratio of `0.014`. The retained
   `target/zone-image-bench/query-lowercase-zone-suffix-key.tsv` run threads the
   parser-carried lowercase-QNAME fact into the same suffix lookup so lowercase
   queries copy label bytes directly into the reversed suffix key while mixed
   case queries keep canonicalization; its checker passed with byte parity,
   zero packet mismatches, matching directory found counts/checksums, and a
   suffix/linear directory lookup ratio of `0.014`. This is retained as
   duplicate lowercase-work removal, not as a broad packet-throughput claim. The
   retained `target/zone-image-bench/zone-directory-inline-reverse-key.tsv` run
   keeps the query-time reversed suffix key itself inline for common QNAMEs,
   avoiding a heap `Vec<u8>` allocation before published-zone lookup; its
   checker passed with byte parity, zero packet mismatches, matching directory
   found counts/checksums, and a suffix/linear directory lookup ratio of
   `0.017`. This is retained as zone-selection allocation discipline, not as an
   isolated suffix-lookup speed claim. The
   retained `target/zone-image-bench/query-lowercase-zone-image-trie.tsv` run
   carries that same parser-proven lowercase-QNAME fact into `ZoneImage` direct
   and semantic trie lookup, so child hash probes, single-child equality, and
   binary-search comparisons can skip per-byte lowercasing for lowercase packet
   QNAMEs while public wrappers keep the conservative canonicalizing path. Its
   checker passed with byte parity, zero packet mismatches,
   `mixed_plan_ratio` `0.148`, `mixed_packet_ratio` `1.008`, and
   `zone_directory_suffix_lookup_ratio` `0.015`. The retained
   `target/zone-image-bench/query-lowercase-dnssec-augmentation.tsv` run
   threads the parser-proven lowercase-QNAME fact into DNSSEC denial
   augmentation's query-node lookup while the public augmentation wrapper stays
   conservative for generic callers; its checker passed with byte parity, zero
   packet mismatches, `mixed_plan_ratio` `0.150`, `mixed_packet_ratio` `0.972`,
   `boundary_packet_ratio` `0.988`, `udp_ceiling_packet_ratio` `1.026`, and
   `zone_directory_suffix_lookup_ratio` `0.015`. This is retained as duplicate
   lowercase-work removal for the DO denial path, not as a broad
   packet-throughput claim. The retained
   `target/zone-image-bench/query-lowercase-denial-label-view.tsv` run carries
   the same lowercase-QNAME fact through NSEC/NSEC3 proof label views, so NSEC
   range comparison and NSEC3 SHA-1 input skip per-byte lowercasing for
   lowercase packet labels while public/mixed-case paths stay conservative. Its
   checker passed with byte parity, zero packet mismatches, `mixed_plan_ratio`
   `0.144`, `mixed_packet_ratio` `0.948`, `boundary_packet_ratio` `0.994`,
   `udp_ceiling_packet_ratio` `1.015`, and `zone_directory_suffix_lookup_ratio`
   `0.014`. This is retained as further duplicate lowercase-work removal in
   DNSSEC denial proof selection, not as a broad packet-throughput claim. The
   retained `target/zone-image-bench/query-observation-lowercase-suffix-hint.tsv`
   run keeps the lowercase-hinted published-zone lookup as the cross-crate
   packet/metrics boundary and makes the lowercase directory fixture measure
   that same hinted API; its checker passed at
   `target/zone-image-bench/query-observation-lowercase-suffix-hint-check.tsv`
   with byte parity, zero packet mismatches,
   `zone_directory_suffix_lookup_ratio` `0.017`, `mixed_plan_ratio` `0.148`,
   `mixed_packet_ratio` `1.013`, `hot_packet_ratio` `0.978`, and
   `udp_ceiling_packet_ratio` `1.018`. This is retained as duplicate
   lowercase-work and API-boundary evidence, not as a broad throughput claim.
   The follow-up
   `target/zone-image-bench/published-zone-directory-hidden-filter.tsv` keeps
   hidden-zone filtering inside the directory suffix walk and removes the
   redundant post-match filter; its checker passed at
   `target/zone-image-bench/published-zone-directory-hidden-filter-check.tsv`
   with matching directory found counts/checksums, suffix lookup ratio `0.019`,
   byte parity, zero packet mismatches, `mixed_plan_ratio` `0.154`,
   `mixed_packet_ratio` `1.016`, `hot_packet_ratio` `0.973`, and
   `udp_ceiling_packet_ratio` `1.006`. This is retained as query-boundary
   branch cleanup, not as a broad throughput claim.
   Active-zone count reporting now also reads a cached directory scalar instead
   of scanning published snapshot states; retained
   `target/zone-image-bench/zone-directory-cached-active-count.tsv` evidence
   passed with matching cached/linear checksums and cached active-count ratio
   `0.025`.
   Zone publication state now lives on `ZoneStoreEntry`, so `expire_zone()` no
   longer clones the full old `ZoneSnapshot` just to mark a zone expired.
   Exact snapshot access remains behind a lazy control/offline adapter that
   preserves expired-state compatibility for transfer and oracle callers. The
   retained `target/zone-image-bench/zone-entry-state-expire.tsv` checker passed
   at `target/zone-image-bench/zone-entry-state-expire-check.tsv` with matching
   entry-expire/snapshot-clone counts `1000`, matching serial checksums
   `500500`, zero semantic and packet mismatches, byte parity,
   `zone_directory_entry_state_expire_ratio` `337.370`, mixed packet ratio
   `1.004`, hot packet ratio `1.124`, trace packet ratio `0.963`, boundary
   packet ratio `1.008`, and UDP-ceiling packet ratio `1.006`. Treat the high
   expire ratio as expected ArcSwap directory-publication cost, not a packet
   hot-path regression; the retained cleanup removes full old-layout cloning
   from expiration.
   The follow-up
   `target/zone-image-bench/zone-entry-cached-origin-scalars.tsv` also keeps
   origin, origin label count, serial, and SOA timer scalars on
   `ZoneStoreEntry`; `PublishedZone`, suffix-index removal, and status/control
   metadata views now read those cached entry fields rather than reaching into
   `ZoneSnapshot`. Its checker
   passed at `target/zone-image-bench/zone-entry-cached-origin-scalars-check.tsv`
   with zero semantic and packet mismatches, byte parity,
   `zone_directory_suffix_lookup_ratio` `0.017`,
   `zone_directory_control_metadata_ratio` `0.773`,
   `zone_metadata_cached_origin_key_ratio` `0.284`,
   `zone_metadata_cached_origin_name_ratio` `0.227`, mixed packet ratio
   `0.972`, hot packet ratio `0.898`, trace packet ratio `1.001`, boundary
   packet ratio `0.934`, and UDP-ceiling packet ratio `0.965`. This is retained
   as old-layout scalar-boundary cleanup for query/status APIs, not a broad
   packet-throughput claim.
   The remaining
   transfer control checks for current NOTIFY serials, refresh-failure
   scheduling, and loading-warning state also use
   `exact_zone_control_metadata` instead of cloning full snapshots or
   status-only shape histograms. Refresh serial-hint and SOA-poll decisions now
   also read `exact_zone_control_metadata()` first and return narrow
   `ZoneMetadata` for current outcomes instead of carrying an
   `Arc<ZoneSnapshot>` through success handling. The retained
   `target/zone-image-bench/zone-control-metadata-no-shape-clone.tsv` run keeps
   matching full/control found counts and serial checksums, reports full shape
   count `200000`, control shape count `0`, and control/full metadata ratio
   `0.726`. Current serial-hint and SOA-poll outcomes consume the already-loaded
   control metadata when returning, and refresh success handling consumes the
   outcome into one metadata value plus an updated-only snapshot handle.
   IXFR-current outcomes read the current snapshot through a transfer-specific
   view that carries cached control metadata, so they still borrow the old
   layout for delta comparison while reading the current serial from cached
   metadata and returning that same metadata for unchanged IXFR outcomes. Newly
   transferred AXFR/IXFR builder state is published through one shared
   `Arc<ZoneSnapshot>` instead of a full snapshot clone, and
   `ZoneStore::insert_snapshot_arc_for_transfer` returns the published entry's
   cached control metadata. Updated refresh outcomes carry that metadata beside
   the snapshot handle so success handling consumes published-entry metadata
   instead of rebuilding it from the old layout. Transfer completion logging and
   updated-catalog detection also read the carried metadata rather than scalar
   fields from the updated snapshot. Catalog snapshot application also uses the
   carried metadata origin key for its configuration lookup and accepts a narrow
   `CatalogZoneView` over borrowed RRsets/RDATA for parsing, rather than a full
   `&ZoneSnapshot` parameter. Refresh success handling records scheduler state
   from narrow `ZoneMetadata`; full snapshot catalog reconciliation runs only
   for updated catalog snapshots, not for current/unchanged refresh outcomes.
   The retained
   `target/zone-image-bench/transfer-snapshot-arc-publication.tsv` run keeps
   this transfer-control cleanup inside the packet benchmark gates with zero
   mismatches and UDP-ceiling packet ratio `1.021`.
   The retained
   `target/zone-image-bench/transfer-snapshot-cached-metadata-view.tsv` run
   keeps the IXFR-current cached-metadata view inside the full benchmark gates
   with zero trace/boundary mismatches and UDP-ceiling packet ratio `0.988`.
   The follow-up
   `target/zone-image-bench/ixfr-serial-gated-transfer-view.tsv` makes that
   IXFR view serial-gated before snapshot exposure. Its checker passed at
   `target/zone-image-bench/ixfr-serial-gated-transfer-view-check.tsv` with
   `100000` serial-bearing transfer views, `100000` no-serial skips, serial
   checksum `50000000`, zero validation/packet mismatches, control-metadata
   ratio `0.775`, serial-gated transfer view ratio `1.527`, mixed plan ratio
   `0.146`, mixed packet ratio `1.002`, hot packet ratio `0.976`, trace packet
   ratio `0.981`, boundary packet ratio `1.008`, and UDP-ceiling packet ratio
   `0.988`. This removes one more broad old-layout exposure from IXFR setup
   while leaving the transfer snapshot available only after cached metadata has
   proved the current serial exists.
   Exact snapshot accessors are transfer/offline-oracle APIs; remaining cleanup
   targets are narrower transfer views where full snapshots are not needed.
   Transfer snapshot views no longer dereference implicitly to `ZoneSnapshot`,
   and their old-layout fields are private; callers must read cached metadata
   through explicit metadata accessors or borrow the old layout through
   `snapshot_for_transfer()`. The retained
   `target/zone-image-bench/transfer-snapshot-explicit-accessors.tsv` checker
   passed at
   `target/zone-image-bench/transfer-snapshot-explicit-accessors-check.tsv` with
   `100000` serial-bearing transfer views, `100000` no-serial skips, serial
   checksum `50000000`, zero validation/packet mismatches, control-metadata
   ratio `0.748`, explicit transfer-view ratio `1.351`, mixed plan ratio
   `0.133`, mixed packet ratio `0.993`, and UDP-ceiling packet ratio `0.996`.
   Catalog-zone reconciliation now parses a narrow `CatalogZoneView`
   over borrowed RRsets/RDATA instead of depending on a full snapshot parser
   parameter or materializing all snapshot records, and whole-snapshot
   `ResourceRecord` materialization is crate-internal and transfer-named rather
   than a generic serving-style API. The old broad `ZoneStore::snapshots()` clone iterator is
   also renamed to `offline_snapshots()` so benchmark/test oracle use is
   explicit. Public SOA access is now a borrowed `soa_record_view()` used by
   the server IXFR query path; owned SOA materialization is crate-internal and
   named for transfer validation. `Rrset` record materialization helpers are
   crate-internal too. The invariant audit now also keeps the
   remaining old query helpers
   behind the explicit `#[doc(hidden)]` `offline_oracle()` handle. Hidden
   benchmark/test oracle reliance still blocks deleting the remaining old
   unsigned query layout.
5. [~] Keep composer hardening ahead of transport work: fuzz malformed packets,
   checked arena bounds, wire-size accounting, compression correctness, and
   allocation discipline must stay green as templates become more aggressive.
   `ZoneImage` compilation now rejects RDATA lengths that cannot fit the DNS RR
   rdlength field before writing immutable preencoded wire, and the invariant
   audit guards against reintroducing the lossy cast.
   Boundary and UDP-ceiling packet cases now have retained timing/byte metrics
   in the prototype benchmark checker instead of only pass/fail mismatch
   checks. Request-side additional-record parsing now borrows EDNS and NOTIFY
   SOA RDATA directly from the packet instead of allocating a `Vec` for each
   parsed record, and request-side answer/authority record-header scans skip
   compressed owner names without materializing `DomainName` labels while
   looking for misplaced OPT records. The invariant audit rejects restoring the
   RDATA copy or the owner-name allocation in that header-scan path.
   The retained `target/zone-image-bench/edns-additional-borrowed-rdata.tsv`
   run passed the current benchmark checker at
   `target/zone-image-bench/edns-additional-borrowed-rdata-check.tsv` with
   zero optioned, boundary, UDP-ceiling, and NOTIFY SOA validation mismatches,
   NOTIFY SOA exact/mixed-case byte parity, mixed-case NOTIFY SOA validation
   ratio `0.984`, optioned packet ratio `0.962`, boundary packet ratio
   `1.020`, and UDP-ceiling packet ratio `1.007`. The follow-up
   `target/zone-image-bench/edns-record-header-skip-name.tsv` run passed
   `target/zone-image-bench/edns-record-header-skip-name-check.tsv` with zero
   mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
   mismatches, NOTIFY SOA exact/mixed-case byte parity, mixed packet ratio
   `0.995`, optioned packet ratio `0.999`, boundary packet ratio `1.013`, and
   UDP-ceiling packet ratio `1.014`. The follow-up
   `target/zone-image-bench/edns-notify-record-view-no-owner-alloc.tsv` run
   also makes the full parsed-record view owner-allocation-free: EDNS OPT root
   checks use scanned owner metadata, NOTIFY SOA owner validation compares
   compressed packet owner wire against the question labels, and SOA serial
   parsing skips MNAME/RNAME directly to the serial field. Its checker passed
   at
   `target/zone-image-bench/edns-notify-record-view-no-owner-alloc-check.tsv`
   with zero mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA
   validation mismatches, NOTIFY SOA exact/mixed-case byte parity, mixed packet
   ratio `1.008`, optioned packet ratio `1.007`, boundary packet ratio
   `1.022`, UDP-ceiling packet ratio `1.025`, and NOTIFY SOA mixed-case
   validation ratio `0.999`. The follow-up
   `target/zone-image-bench/notify-soa-single-owner-scan.tsv` run folds NOTIFY
   SOA owner matching into the borrowed record-view scan, so the compressed
   answer owner is no longer walked once for parsing and again for question
   comparison. Its checker passed at
   `target/zone-image-bench/notify-soa-single-owner-scan-check.tsv` with zero
   mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
   mismatches, NOTIFY SOA exact/mixed-case byte parity, mixed packet ratio
   `1.001`, optioned packet ratio `0.980`, boundary packet ratio `1.018`,
   UDP-ceiling packet ratio `1.006`, and NOTIFY SOA mixed-case validation ratio
   `1.002`. The follow-up
   `target/zone-image-bench/edns-fixed-option-prefixes-rerun.tsv` run removes
   repeated fixed network-order encoding from EDNS response option emission:
   the OPT owner/type bytes plus TCP keepalive, DNS Cookie, and EDE fixed
   option prefixes are copied from preencoded constants, while dynamic payload
   bytes and dynamic payload lengths stay on the runtime path. Its checker
   passed at
   `target/zone-image-bench/edns-fixed-option-prefixes-rerun-check.tsv` with
   zero mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA
   validation mismatches, packet byte parity for those corpora, mixed packet
   ratio `1.000`, hot packet ratio `1.044`, trace packet ratio `0.960`,
   optioned packet ratio `0.991`, boundary packet ratio `1.011`, UDP-ceiling
   packet ratio `0.997`, and NOTIFY SOA mixed-case validation ratio `0.999`.
   The follow-up `target/zone-image-bench/edns-padding-current-len.tsv` run
   removes redundant OPT-offset bookkeeping from EDNS padding sizing: padding
   length is computed from the current response buffer length plus the padding
   option header instead of carrying OPT-start and RDATA-start offsets into the
   padding helper. Its checker passed at
   `target/zone-image-bench/edns-padding-current-len-check.tsv` with zero
   mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
   mismatches, packet byte parity for those corpora, mixed packet ratio
   `0.967`, hot packet ratio `0.928`, trace packet ratio `0.978`, optioned
   packet ratio `0.982`, boundary packet ratio `1.018`, UDP-ceiling packet
   ratio `1.012`, and NOTIFY SOA mixed-case validation ratio `1.004`.
   The follow-up `target/zone-image-bench/edns-response-option-shape.tsv` run
   computes one carried EDNS response option shape before OPT emission, writes
   OPT RDLENGTH from the carried RDATA length, and has option emission consume
   carried TCP keepalive, NSID, Cookie, EDE, and padding decisions instead of
   rechecking response-option presence while writing. Its checker passed at
   `target/zone-image-bench/edns-response-option-shape-check.tsv` with zero
   mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
   mismatches, packet byte parity for those corpora, mixed packet ratio
   `1.003`, hot packet ratio `1.015`, trace packet ratio `0.995`, optioned
   packet ratio `1.002`, boundary packet ratio `1.005`, UDP-ceiling packet
   ratio `0.993`, and NOTIFY SOA mixed-case validation ratio `0.997`.
   The follow-up `target/zone-image-bench/zone-image-edns-sizing-bundle.tsv`
   run bundles the ZoneImage EDNS capacity hint and full-UDP-capacity reserve
   decision into one carried response sizing value, removes the old separate
   runtime helper split, and threads the bundled sizing through direct, generic,
   failure, and truncation response builders. Its checker passed at
   `target/zone-image-bench/zone-image-edns-sizing-bundle-check.tsv` with zero
   mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
   mismatches, packet byte parity for those corpora, mixed packet ratio
   `0.984`, hot packet ratio `0.990`, trace packet ratio `1.015`, optioned
   packet ratio `0.978`, boundary packet ratio `0.980`, UDP-ceiling packet
   ratio `0.990`, and NOTIFY SOA mixed-case validation ratio `0.995`.
   The follow-up `target/zone-image-bench/zone-image-edns-base-shape.tsv` run
   carries the fixed EDNS response option base shape inside the bundled
   ZoneImage EDNS sizing value. ZoneImage capacity sizing and OPT emission now
   share that base shape; only padding length remains computed from the final
   response length at emission time. Its checker passed at
   `target/zone-image-bench/zone-image-edns-base-shape-check.tsv` with zero
   mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA validation
   mismatches, packet byte parity for those corpora, mixed packet ratio
   `1.021`, hot packet ratio `1.035`, trace packet ratio `1.005`, optioned
   packet ratio `1.008`, boundary packet ratio `1.017`, UDP-ceiling packet
   ratio `1.020`, and NOTIFY SOA mixed-case validation ratio `0.996`.
   The follow-up `target/zone-image-bench/zone-image-edns-additional-count.tsv`
   run also carries the EDNS additional-record count inside the same bundled
   ZoneImage EDNS sizing value. Failure, direct, generic, and truncation-retry
   response builders now consume that carried 0/1 count instead of converting
   `metadata.edns` into an additional count again while assembling DNS section
   counts. Its checker passed at
   `target/zone-image-bench/zone-image-edns-additional-count-check.tsv` with
   zero mixed, hot, trace, optioned, boundary, UDP-ceiling, and NOTIFY SOA
   validation mismatches, packet byte parity for those corpora, mixed packet
   ratio `1.010`, hot packet ratio `0.900`, trace packet ratio `1.029`,
   optioned packet ratio `0.947`, boundary packet ratio `1.000`, UDP-ceiling
   packet ratio `1.001`, and NOTIFY SOA mixed-case validation ratio `0.990`.
   The follow-up
   `target/zone-image-bench/zone-image-dead-dnssec-count-retired.tsv` removes
   the now-dead DNSSEC response-metadata and record-count bookkeeping from the
   ZoneImage and legacy truncation composers plus `ZoneImageLookupPlan`. DNSSEC
   latency classification remains driven by final response bytes, so no wire
   behavior depends on the removed counters. Its checker passed at
   `target/zone-image-bench/zone-image-dead-dnssec-count-retired-check.tsv`
   with zero mixed, hot, trace, optioned, boundary, UDP-ceiling, and EDE
   fallback validation mismatches, packet byte parity for those corpora, mixed
   packet ratio `1.001`, hot packet ratio `1.014`, trace packet ratio `0.982`,
   optioned packet ratio `1.021`, boundary packet ratio `1.006`, UDP-ceiling
   packet ratio `1.001`, and NOTIFY SOA mixed-case validation ratio `1.006`.
   The follow-up `target/zone-image-bench/zone-image-ede-stripped-sizing.tsv`
   carries the recomputed stripped EDNS sizing into the truncation
   record-removal retry after an oversized EDE response remains too large even
   without the EDE option. The EDE fallback benchmark bucket now covers both
   loading-zone EDE and low-ceiling NSEC3-cap EDE truncation, and the invariant
   audit rejects keeping stripped metadata with stale OPT sizing. Its checker
   passed at `target/zone-image-bench/zone-image-ede-stripped-sizing-check.tsv`
   with two EDE fallback packet cases, zero mixed, hot, trace, optioned,
   boundary, UDP-ceiling, and EDE fallback validation mismatches, packet byte
   parity for those corpora, mixed packet ratio `0.974`, hot packet ratio
   `0.949`, trace packet ratio `0.977`, optioned packet ratio `0.964`,
   boundary packet ratio `0.997`, UDP-ceiling packet ratio `0.999`, and NOTIFY
   SOA mixed-case validation ratio `1.028`.
   The `zone_image_datagram`
   fuzz target now shapes DNAME, wildcard,
   referral/glue, additional-section, QTYPE=ANY, basic DNSSEC, EDNS, opaque
   unknown, and malformed known-name RDATA traffic through the required
   `ZoneImage` provider. A retained local 60-second nightly ASan campaign
   passed; longer overnight/release-window campaigns still remain separate
   release evidence.
6. [x] Establish the local no-XDP transport ceiling with the standard socket and
   UDP batch paths before server AF_XDP. The 2026-05-31 current-layout loopback
   trace replay keeps `udp_batch_size=32` ahead of batch size 1 locally, with
   zero drops/errors and zero ZoneImage serve failures. A bounded batch-32
   packet capture also retains matched DNS query/response samples. Physical
   10G/25G/40G promotion remains a separate-device phase.
   `scripts/sweep-udp-batch-benchmarks.sh` now wraps repeated local
   `benchmark-dns-clients.sh` runs across configured UDP batch sizes, replays
   one retained trace for all later runs, and writes a shared `summary.tsv`
   with QPS/latency ratios, drop/error counts, UDP receive/send batch counters,
   ZoneImage serve counters, and network-counter summaries. This makes local
   no-XDP batch-ceiling evidence reproducible without weakening the separate
   physical-NIC promotion gates. `scripts/check-udp-batch-sweep.py` validates
   retained sweep summaries for schema, unique ascending batch sizes, zero
   drops/errors and ZoneImage failures by default, positive served-hit
   counters, ratio math, and at least one larger batch size that increases both
   receive and send datagrams per UDP batch. The retained
   `target/evidence/udp-batch-sweep-current-local` run passed that checker at
   `target/evidence/udp-batch-sweep-current-local/check.tsv` with batch sizes
   `1`, `8`, and `32`, zero drops/errors, zero ZoneImage failures,
   `batching_gain_rows=2`, batch-8 QPS ratio `1.116`, batch-8 p50/p99 ratios
   `0.859`/`0.901`, batch-32 QPS ratio `1.101`, and batch-32 p50/p99 ratios
   `0.873`/`0.897`. This is retained loopback no-XDP evidence, not physical
   NIC promotion evidence. This closes the single-device local batch-ceiling
   gap; rerunning the sweep is useful only after code changes or on different
   hardware.
