# BoronGen validation report — July 2026

Status: validated for internal large-scale BoronDNS speed and memory testing

This report records the implementation and validation of BoronGen against
source commit `16782166787cc6cee03882cf68d5fb58aaf54f85`. The working tree was
intentionally dirty while BoronGen was developed. Every bounded run captured
the base commit, Git status, tracked diff, hashes of modified and untracked
source files, and binary hashes so the tested source state remains
reconstructable.

## Validated scope

BoronGen is a deterministic, bounded-memory synthetic DNS primary. It:

- derives catalog zones, member zones, owners, RRsets, and RDATA directly from
  scenario parameters without retaining generated zones;
- supports UDP/TCP SOA, bounded-message TCP AXFR, unchanged single-SOA IXFR,
  RFC 9432 catalog version 2 membership, and per-message TSIG;
- applies TCP backpressure and an explicit connection semaphore;
- provides `registry-nsec3`, `mixed`, and `large-rrset` profiles; and
- emits a strictly ordered and linked synthetic NSEC3 ring that exercises
  BoronDNS's indexed denial lookup.

The NSEC3 values are deliberately generated across the 160-bit namespace and
are not claimed to be SHA-1 preimages of ordinary generated owner names.
Structural RRSIG records are load-test records, not cryptographic signatures.
This validation is a transfer, compilation, query-path, speed, memory, and
containment test; it is not DNSSEC cryptographic-validity evidence.

The accompanying BoronDNS change adds
`limits.max_transfer_ingest_messages`, defaulting to 4,096, so large AXFR and
IXFR sessions must opt into a larger bounded message count instead of silently
removing the existing ingest limits.

## Static and functional gates

All of these gates passed on the captured source:

| Gate | Result |
| --- | --- |
| Full workspace tests | 1,091 passed |
| BoronGen tests | 17 passed |
| Formatting | `cargo fmt --all -- --check` passed |
| Lints | workspace Clippy with `-D warnings` passed |
| MSRV | Rust 1.95 `cargo check -p boron-gen --all-targets` passed |
| Documentation build | rustdoc warnings denied passed |
| Shell gate | 116 scripts passed ShellCheck/syntax validation |
| Documentation hygiene | 60 docs, 89 sources, and 148 scripts passed |
| Unsafe-prone dependency gate | passed |

The BoronGen tests include repeated byte-for-byte deterministic output,
checked hostile `u64` configuration rejection before generation, exact NSEC3
ordering/linkage/wrap, the maximum `u32` RRset input, production transfer
parser coverage, signed multi-message AXFR and IXFR, UDP SOA, and connection
limits.

A small independent AXFR was parsed by `dig`; `named-checkzone -i none`
accepted the resulting zone with `OK`. The normal policy check also exited
successfully while warning about delegation-glue interpretation. That check
supports wire and zone-file interoperability only and does not promote the
synthetic signatures into DNSSEC-valid data. Evidence is retained in
`target/evidence/boron-gen-independent-validation-20260727-r3`.

## Scale calibration

The same `registry-nsec3` formula was advanced through bounded calibration
steps. BoronGen remained within approximately 6–8 MiB while the secondary
image grew linearly:

| Names and NSEC3 records | Snapshot records | BoronDNS peak bytes | BoronGen peak bytes | Result |
| ---: | ---: | ---: | ---: | --- |
| 100,000 | 910,008 | 1,095,983,104 | 6,356,992 | ready |
| 500,000 | 4,550,008 | 5,512,888,320 | 8,044,544 | ready |
| 1,000,000 | 9,100,008 | 10,987,917,312 | 6,823,936 | ready |
| 2,000,000 | 18,200,008 | 22,226,169,856 | 7,802,880 | ready |

A separate 16-member catalog test published 16 zones of 1,000 generated names
and completed 17 AXFR sessions. Its BoronDNS and BoronGen peaks were
161,247,232 and 5,824,512 bytes.

## Capacity and containment gates

The first `large-rrset` boundary check showed that 65,535 records published
while 65,536 records produced `compact field capacity exceeded`. Review then
established that this was an internal `u16` count rather than an RFC RRset
cardinality limit. The retained rejected run is evidence of the defect that
prompted the `u32` correction; it is not the current intended capacity
contract. Current validation requires a 65,536-record RRset to publish and
keeps ordinary query message limits separate from storage and AXFR capacity.

An intentionally undersized 512 MiB server cgroup attempted the 100,000-name
scenario. BoronDNS reached the exact 536,870,912-byte hard limit and ended with
systemd result `oom-kill` and signal 9. The separately bounded BoronGen process
survived at a 5,369,856-byte peak. The harness classified this only as
`contained_oom_as_expected`, never as service readiness.

Evidence is retained in:

- `target/evidence/boron-gen-large-rrset-65535-accepted-20260727-r5`
- `target/evidence/boron-gen-large-rrset-65536-rejected-20260727-r4`
- `target/evidence/boron-gen-contained-oom-512m-20260727-r4`

The two large-RRset paths above predate the `u32` correction. Commit
`fd7cea5963c78163a86b5897bfb556fd1acf43ab` then widened the count and was
validated through the bounded post-correction matrix below.

| Scenario | Retained member records | BoronDNS peak bytes | BoronGen peak bytes | Result |
| --- | ---: | ---: | ---: | --- |
| One 65,536-member A RRset | 65,543 | 35,827,712 | 6,172,672 | Ready; 5,000/5,000 probe responses |
| One 1,000,000-member A RRset | 1,000,007 | 380,985,344 | 5,455,872 | Ready; 10,000/10,000 probe responses |
| Mixed, 250,000 names and 16 A records per name | 5,250,006 | 3,048,583,168 | 6,643,712 | Ready; 20,000/20,000 probe responses |
| Registry NSEC3, 32 zones of 20,000 names | 5,824,256 | 4,843,151,360 | 7,155,712 | Ready; 20,000/20,000 probe responses |
| Registry NSEC3, one zone of 2,000,000 names | 18,200,008 | 22,324,887,552 | 7,483,392 | Ready; 20,000/20,000 probe responses |
| Registry NSEC3 under a 512 MiB hard cap | 910,008 attempted | 536,870,912 | 6,000,640 | BoronDNS OOM-contained as expected; BoronGen survived |

Every positive query probe reported zero errors and zero unanswered packets.
Both registry runs required indexed NSEC3 publication with zero fallback
groups. The largest positive run used `MemoryHigh=30G`, `MemoryMax=32G`, and
`MemorySwapMax=0`. The negative run ended BoronDNS with systemd result
`oom-kill` and signal 9 at the exact hard limit while the separately bounded
generator stayed active.

Post-correction evidence is retained in:

- `target/evidence/boron-gen-post-u32-wide-20260727`
- `target/evidence/boron-gen-wide-rrset-1m-20260727`
- `target/evidence/boron-gen-mixed-dense-250k-r16-20260727`
- `target/evidence/boron-gen-registry-32x20k-20260727`
- `target/evidence/boron-gen-registry-nsec3-2m-post-u32-20260727`
- `target/evidence/boron-gen-contained-oom-post-u32-20260727`

## Fuzz campaign prerequisite

The two-host 24-hour campaign was terminal before the final 32 GiB test
started. Both remote trees were then copied locally and a checksum dry-run
reported no difference from either remote. The retained tree has a 108,815-file
SHA-256 manifest.

| Host | Passed/status 0 | Interrupted/status 15 | Total |
| --- | ---: | ---: | ---: |
| `oxidedns-1` | 54 | 0 | 54 |
| `oxidegun-1` | 32 | 49 | 81 |
| Total | 86 | 49 | 135 |

All 49 nonzero workers ended at the outer 88,200-second timeout while
libFuzzer's CPU-time duration lagged wall time under 81-way contention. Their
logs end with `libFuzzer: run interrupted; exiting`. The evidence has zero
nonempty crash artifacts and no ASan or UBSan marker.

This campaign is explicitly **not a clean fuzz pass**. Besides the 49
orchestration timeouts, the frozen strict collector found two evidence-contract
defects: the launcher created an empty `launch/` directory forbidden by its
validator, and the oxidedns sampler's first row appeared seven seconds after
startup where the validator allows two. The verified-empty remote directories
were removed without touching evidence, but the second condition still caused
the collector to return status 1. Both hosts are retained in the adjacent
forensic tree with a written disposition:
`target/evidence/fuzz-soak-two-host-20260726T112226Z-forensic-20260727`.

The final load result below must not be cited as curing or passing this
non-clean fuzz campaign.

## Final 32 GiB result

The final run used one `registry-nsec3` member zone with 2,500,000 ordinary
names and 2,500,000 ordered NSEC3 records:

| Measurement | Result |
| --- | ---: |
| Published snapshot records | 22,750,008 |
| Member AXFR records | 22,750,009 |
| Member AXFR messages | 39,240 |
| End-to-end elapsed time | 353 seconds |
| BoronDNS peak | 26,143,150,080 bytes (24.35 GiB) |
| BoronGen peak | 7,278,592 bytes (6.94 MiB) |
| UDP load responses | 10,000/10,000 NXDOMAIN |
| Query errors/unanswered | 0/0 |
| Observed DNSSEC-augmented queries | 10,001 |

BoronDNS used `MemoryHigh=30G`, `MemoryMax=32G`, and `MemorySwapMax=0`.
BoronGen used `MemoryHigh=768M` and `MemoryMax=1G`. Both transient units used
`OOMPolicy=stop` and systemd-oomd pressure handling. All cgroup
`memory.events` low, high, max, OOM, and OOM-kill counters remained zero.

The catalog and member AXFRs both completed with zero failed sessions. BoronDNS
compiled exactly one indexed NSEC3 group and zero fallback groups. The DNSSEC
negative probe included NSEC3 authority data, RRL dropped zero loopback
responses, and the bounded BoronGun probe received every response with zero
client or kernel-drop errors.

The sealed 27-file run evidence and SHA-256 manifest are retained in
`target/evidence/boron-gen-final-32g-2m5-20260727`.

## Disposition

BoronGen is ready for internal large-zone, large-RRset, mixed-record,
catalog/AXFR, ordered-NSEC3 lookup, speed, memory, and allocator-containment
testing within the documented synthetic-data boundaries. Future DNSSEC
validity work must continue to use genuinely hashed and cryptographically
signed zones. A future fuzz campaign must correct the worker deadline and
sampler/collector contracts before it can supply clean release evidence.
