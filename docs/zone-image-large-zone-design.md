# ZoneImage Large-Zone Design

Status: production layout decision, 2026-07-17.

This note records the measurements and reasoning behind the production
large-zone layout. Exact encoded and operational limits are specified in
`docs/zone-image-capacity-limits.md`.

## Decision

BoronDNS uses one immutable `ZoneImage` per zone. The production layout widens
only fields that grow with the entire image:

- label, owner-name, RDATA, and wire-arena offsets are `u64`;
- the first-record ordinal of an RRset is `u64`;
- relation record ordinals are `u64`; and
- relation-span starting ordinals are `u64`.

Query-local fields remain compact:

- node, edge, RRset, relation-span, bitmap, and child-hash IDs are `u32`;
- per-node RRset counts and per-RRset record/relation counts are `u16`; and
- child-hash slots use `u16` edge offsets until fanout requires `u32`.

Canonical range sharding was prototyped and rejected. It would add routing,
cross-range closest-encloser, wildcard, DNAME, delegation, glue, NSEC/NSEC3,
AXFR/IXFR, publication, and recovery contracts to every large-zone deployment.
The prototype source and benchmark were removed once physical-link testing
showed no material service-level penalty from selective `u64`.

## RRSIG Relation Scaling

The former relation builder scanned every discovered RRSIG covered-type entry
for every RRset and was quadratic on ordinary signed-zone shapes. The indexed
builder is linear in the generated relation input:

| Names | `oxidedns-1` old | `oxidedns-1` indexed | `oxidegun-1` old | `oxidegun-1` indexed |
|---:|---:|---:|---:|---:|
| 10,000 | 0.699 s | 0.024 s | 0.740 s | 0.029 s |
| 20,000 | 2.718 s | 0.059 s | 2.888 s | 0.068 s |
| 40,000 | 10.817 s | 0.153 s | 11.480 s | 0.174 s |
| 60,000 | 24.384 s | 0.265 s | 24.822 s | 0.297 s |

At 60,000 names this reduced relation-build time by 92x and 84x on the two
hosts and removed the approximately fourfold cost increase previously seen
when the name count doubled.

## Compact Child Indexes

At 50,000 signed names, adaptive child-hash slots avoided paying for wide local
indexes where no node needed them:

| Layout | Hot bytes | Total image bytes | Child-slot bytes | Total delta |
|---|---:|---:|---:|---:|
| Original `u16` capacity layout | 9,887,224 | 21,937,224 | 262,144 | baseline |
| Blanket `u32` child slots | 10,349,372 | 22,399,372 | 524,288 | +2.11% |
| Adaptive `u16`/`u32` child slots | 10,087,232 | 22,137,232 | 262,144 | +0.91% |

This is why the global `u64` migration does not widen local fanout fields.

## Medium-TLD Capacity Check

The adaptive layout compiled 900,000 signed synthetic names and 1.8 million
RRsets/records:

| Target | Compile | Image bytes | Peak RSS | Exact lookup |
|---|---:|---:|---:|---:|
| `oxidedns-1` | 5.871 s | 402,138,688 | 1,529,004 KiB | 77.5 ns |
| `oxidegun-1` | 6.365 s | 402,138,688 | 1,528,588 KiB | 93.4 ns |

This controlled shape is useful capacity evidence, not a substitute for a real
registry corpus containing delegations, DS, NSEC/NSEC3, glue, and multiple
signatures.

## Selective `u64` Cost

A literal promotion of old narrow local fields was rejected. It did not widen
the globally overflowing arenas or record ordinals, increased image size 6.3%,
and raised exact lookup by 3.0% on `oxidedns-1` and 20.9% on `oxidegun-1`.

The useful selective experiment widened only the production fields listed in
the decision above. Five paired runs used 100,000 owners with 15 A and 15 RRSIG
records per owner:

| Target/layout | Compile | Exact lookup | Hot bytes | Total image bytes |
|---|---:|---:|---:|---:|
| `oxidedns-1` adaptive | 0.723 s | 82.2 ns | 59,898,656 | 364,898,656 |
| `oxidedns-1` selective `u64` | 0.737 s | 104.5 ns | 96,698,656 | 401,698,656 |
| `oxidegun-1` adaptive | 0.829 s | 94.8 ns | 59,898,656 | 364,898,656 |
| `oxidegun-1` selective `u64` | 0.866 s | 101.3 ns | 96,698,656 | 401,698,656 |

The isolated exact-plan loop exposed 27.1% and 6.8% regressions. Complete
response work reduced that difference substantially:

| Target/layout | Mixed plan | Mixed wire | Mixed packet | Hot packet |
|---|---:|---:|---:|---:|
| `oxidedns-1` adaptive | 127.3 ns | 146.0 ns | 670.5 ns | 333.8 ns |
| `oxidedns-1` selective `u64` | 129.8 ns | 150.7 ns | 670.1 ns | 341.4 ns |
| `oxidegun-1` adaptive | 142.4 ns | 164.6 ns | 752.0 ns | 380.5 ns |
| `oxidegun-1` selective `u64` | 150.0 ns | 173.6 ns | 772.2 ns | 390.8 ns |

All response mismatch counts were zero. Packet-level cost was noise to 2.7%,
while plan/wire-only cost was 2% to 5.5%.

## Physical-Link UDP A/B

The decisive service check alternated adaptive and selective-`u64` release
servers on `oxidedns-1`. `oxidegun-1` generated traffic over their direct
`198.18.0.0/30` link. Both variants used four pinned dedicated UDP workers,
256-packet batches, four `SO_REUSEPORT` sockets, and the same 100,000-record
zone.

Three unsaturated six-second pairs completed 5.30 million queries per layout
with zero errors and zero dropped responses:

| Layout | Median responses/s | Median p50 | Median p99 | Drops |
|---|---:|---:|---:|---:|
| Adaptive | 292,073 | 112.4 us | 340.9 us | 0 |
| Selective `u64` | 293,510 | 112.0 us | 315.4 us | 0 |

Paired throughput changes were +0.3%, +1.0%, and +0.8%; paired p50 changes
were +0.9%, -1.0%, and -2.6%. Tail latency varied in both directions. A separate
drop-limited saturation run had a -1.2% median paired throughput change but a
wide -8.9% to +0.3% range, so it is retained only as a noisy bound.

The isolated exact-plan result is therefore a cache-sensitive microbenchmark
ceiling, not a measured end-to-end service regression.

## Memory And Registry-Scale Interpretation

The 30-record synthetic fixture consumed approximately 3,649 bytes per owner,
including 2,580 wire-arena bytes. Linear projection to 161 million names gives
approximately 587.5 GB for the adaptive layout and 646.7 GB for selective
`u64`. The fixture deliberately duplicates substantial wire data, so these are
stress projections rather than claims about `.com`.

The projected shape has 644 million RRsets and 4.83 billion records. Its RRset
and node counts fit the compact `u32` ID space, while its record ordinal and
arenas exceed `u32`; selective `u64` removes exactly those structural ceilings.

The next memory improvement should compact or deduplicate stored wire bodies
and then replay a representative registry corpus. Sharding is not part of the
planned query architecture. If a deployment cannot hold the source snapshot,
builder workspace, and immutable generations required for reload, it needs a
larger-memory host or a separately designed storage architecture rather than a
transparent change to ZoneImage semantics.
