# BoronGen validation — July 2026

The July 27 validation established BoronGen as a bounded-memory primary for
large transfer, lookup, memory, and containment tests. The final 32 GiB run
published 22,750,008 records while BoronGen retained 6.94 MiB. The separate
fuzz campaign was not a clean pass; its failures and evidence disposition are
recorded below.

This is a historical report, not the current runbook or release checklist.
Use the [BoronGen guide](boron-gen.md) for new runs and the
[two-host campaign report](boron-gen-two-host-campaign-2026-07.md) for the
subsequent 750 GiB-host results.

## Source and test scope

Initial development used base commit
`16782166787cc6cee03882cf68d5fb58aaf54f85` with a dirty working tree.
Each bounded run captured the base commit, Git status, tracked diff, modified
and untracked source-file hashes, and binary hashes. The base commit alone
does not identify the tested implementation. The later RRset-count correction
was committed as `fd7cea5963c78163a86b5897bfb556fd1acf43ab`.

The tested generator derived catalog and member zones directly from scenario
parameters. Its supported paths at the time were UDP/TCP SOA, bounded-message
TCP AXFR, unchanged single-SOA IXFR, RFC 9432 catalog version 2 membership,
and per-message TSIG. TCP backpressure and a connection semaphore bounded
active transfers. The profiles were `registry-nsec3`, `mixed`, and
`large-rrset`; changed IXFR was added later.

The NSEC3 ring was ordered and linked, but its generated hashes were not
claimed to be SHA-1 preimages of ordinary owner names. Structural RRSIGs were
load-test data, not cryptographic signatures. These results establish transfer
and lookup behavior, not DNSSEC cryptographic validity.

The initial implementation also added `limits.max_transfer_ingest_messages`
with a default of 4,096. Large test configurations explicitly raised that
allowance. This is the historical default, not a recommendation for current
configuration.

## Final 32 GiB run

One `registry-nsec3` member zone contained 2,500,000 ordinary names and
2,500,000 ordered NSEC3 records:

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

Catalog and member AXFR completed with no failed sessions. BoronDNS compiled
one indexed NSEC3 group and zero fallback groups. The negative query included
NSEC3 authority data; RRL dropped no loopback responses, and the bounded UDP
probe reported no client or kernel-drop errors.

The sealed 27-file evidence set and SHA-256 manifest are in
`target/evidence/boron-gen-final-32g-2m5-20260727`.

## Functional checks and scale calibration

The following checks passed on the captured development source:

| Check | Recorded result |
| --- | --- |
| Full workspace tests | 1,091 passed |
| BoronGen tests | 17 passed |
| Formatting | `cargo fmt --all -- --check` passed |
| Lints | workspace Clippy with `-D warnings` passed |
| MSRV | Rust 1.95 `cargo check -p boron-gen --all-targets` passed |
| Documentation build | rustdoc with warnings denied passed |
| Shell checks | 116 scripts passed ShellCheck/syntax validation |
| Documentation hygiene | 60 docs, 89 sources, and 148 scripts passed |
| Unsafe-prone dependency check | passed |

The generator tests covered byte-for-byte determinism, rejection of hostile
`u64` parameters before generation, NSEC3 ordering/linkage/wrap, the maximum
`u32` RRset input, production transfer parsing, signed multi-message AXFR
and IXFR, UDP SOA, and connection limits.

An independent small AXFR was parsed by `dig`.
`named-checkzone -i none` returned `OK`; the normal policy check also
succeeded, with delegation-glue warnings. This checked wire and zone-file
interoperability, not signature validity. Evidence:
`target/evidence/boron-gen-independent-validation-20260727-r3`.

The same `registry-nsec3` formula was then scaled through bounded runs:

| Names and NSEC3 records | Snapshot records | BoronDNS peak bytes | BoronGen peak bytes | Result |
| ---: | ---: | ---: | ---: | --- |
| 100,000 | 910,008 | 1,095,983,104 | 6,356,992 | ready |
| 500,000 | 4,550,008 | 5,512,888,320 | 8,044,544 | ready |
| 1,000,000 | 9,100,008 | 10,987,917,312 | 6,823,936 | ready |
| 2,000,000 | 18,200,008 | 22,226,169,856 | 7,802,880 | ready |

A separate 16-member catalog run used 1,000 names per zone and completed
17 AXFR sessions. BoronDNS peaked at 161,247,232 bytes and BoronGen at
5,824,512 bytes.

## RRset capacity and contained OOM

The first boundary test published a 65,535-record RRset but rejected 65,536
records with `compact field capacity exceeded`. That was an internal `u16`
count limit, not an RFC cardinality limit. The rejected run is retained as
evidence of the defect that led to the `u32` correction.

An intentionally undersized 512 MiB cgroup reached its exact
536,870,912-byte cap with the 100,000-name profile. BoronDNS ended with
systemd result `oom-kill` and signal 9; the separately bounded generator
survived at 5,369,856 bytes. The harness recorded
`contained_oom_as_expected`, not readiness.

Pre-correction evidence:

- `target/evidence/boron-gen-large-rrset-65535-accepted-20260727-r5`
- `target/evidence/boron-gen-large-rrset-65536-rejected-20260727-r4`
- `target/evidence/boron-gen-contained-oom-512m-20260727-r4`

After commit `fd7cea5963c78163a86b5897bfb556fd1acf43ab`:

| Scenario | Retained member records | BoronDNS peak bytes | BoronGen peak bytes | Result |
| --- | ---: | ---: | ---: | --- |
| One 65,536-member A RRset | 65,543 | 35,827,712 | 6,172,672 | Ready; 5,000/5,000 probe responses |
| One 1,000,000-member A RRset | 1,000,007 | 380,985,344 | 5,455,872 | Ready; 10,000/10,000 probe responses |
| Mixed, 250,000 names and 16 A records per name | 5,250,006 | 3,048,583,168 | 6,643,712 | Ready; 20,000/20,000 probe responses |
| Registry NSEC3, 32 zones of 20,000 names | 5,824,256 | 4,843,151,360 | 7,155,712 | Ready; 20,000/20,000 probe responses |
| Registry NSEC3, one zone of 2,000,000 names | 18,200,008 | 22,324,887,552 | 7,483,392 | Ready; 20,000/20,000 probe responses |
| Registry NSEC3 under a 512 MiB hard cap | 910,008 attempted | 536,870,912 | 6,000,640 | BoronDNS OOM-contained; BoronGen survived |

Positive probes reported no errors or unanswered packets. Both registry runs
published indexed NSEC3 with zero fallback groups. The largest positive run
used `MemoryHigh=30G`, `MemoryMax=32G`, and `MemorySwapMax=0`.
The negative run again ended at the exact hard cap with `oom-kill`/signal 9.

Post-correction evidence:

- `target/evidence/boron-gen-post-u32-wide-20260727`
- `target/evidence/boron-gen-wide-rrset-1m-20260727`
- `target/evidence/boron-gen-mixed-dense-250k-r16-20260727`
- `target/evidence/boron-gen-registry-32x20k-20260727`
- `target/evidence/boron-gen-registry-nsec3-2m-post-u32-20260727`
- `target/evidence/boron-gen-contained-oom-post-u32-20260727`

## Findings from the later large-memory runs

The first 100,000,000-member A RRset completed AXFR but failed publication:
its stored wire span exceeded the remaining `u32::MAX` byte limit in
`BlobRange`. The correction widened blob lengths to `u64` and removed
a redundant cached ownerless-wire length while preserving the 72-byte
`ImageRrset` layout. Direct-answer templates use record iteration above the
DNS `u16` section-count capacity. BoronGen can stream a `u32` RRset count
without materializing it. The later 100M publication result is recorded in
the [two-host report](boron-gen-two-host-campaign-2026-07.md), row 02;
that row did not complete its performance measurement.

Other failures led to these harness corrections:

| Finding | Correction |
| --- | --- |
| Readiness could precede completion of all catalog members | Require the requested ACTIVE count, zero LOADING/EXPIRED members, matching catalog metrics, and catalog-plus-member AXFR completions |
| A late UDP response could be mistaken for the current request | Discard and count stale IDs while preserving the current query's absolute deadline |
| Ancestor oomd policy could override the intended load policy | Use a dedicated system-manager slice and reject a lower ancestor pressure threshold |
| A stalled HTTP request could overrun readiness | Add separate connection and total request timeouts |
| Failed/interrupted rows lacked useful summaries | Emit failure stage, unit result, memory peaks, elapsed time, manager, slice, and pressure limit; retain sampler/unit-property fallback |
| Publication was mistaken for a stable performance state | Require stable cgroup memory, hard-cap headroom, host `MemAvailable`, CPU use, and full-memory-pressure `avg10` |

Every attempted stability window was retained in `quiescence-samples.tsv`;
the accepted window was summarized in `quiescence-summary.json`. Deterministic
compact-capacity failures also became an immediate stop condition.

The original 65M balanced row reached its exact 680 GiB `MemoryMax` and ended
with `oom-kill`/signal 9. Its old user-manager oomd placement and stalled HTTP
probe rule it out as readiness or performance evidence, though it remains
allocator-boundary evidence.

## Recorded two-host measurement setup

The performance runner used deterministic hot/spread queries, apex queries,
and DNSSEC negatives. Registry traces included delegation and glue referrals;
mixed traces used A/AAAA/TXT; wide-RRset traces accepted expected UDP
truncation while still validating response codes.

It warmed the image and ran three measured repetitions, recording QPS,
p50/p90/p99/p999, loss, CPU, network counters, softirqs, interrupts, routes,
and optional ethtool counters on both hosts. The SSH path checked architecture
and client digest, rejected loopback, and required physical-NIC packet deltas
without new NIC errors or drops.

The initial loss allowance of 10 queries per thousand rejected a
128–132 kQPS response rate at 136–140 kQPS offered load. Raising the saturation
allowance to 100 per thousand let the curve measure throughput under overload;
NIC errors/drops remained independently disallowed. Open-loop QPS steps later
provided an aggregate offered-rate schedule shared by all client workers.

The controller used independent SSH access to both hosts because oxidedns
held no private key for oxidegun. In `external` mode the server published a
request after the stability check; the controller ran the client on oxidegun,
verified its relative-file SHA-256 manifest and returned archive, then wrote
the completion marker atomically.

The recorded server profile was:

```bash
BORON_CAMPAIGN_ID=next-large \
BORON_CAMPAIGN_PERFORMANCE_MODE=external \
BORON_CAMPAIGN_DNS_LISTEN=198.18.0.1:15300 \
BORON_CAMPAIGN_PERFORMANCE_SERVER_DEVICE=eno1np0 \
BORON_CAMPAIGN_PERFORMANCE_CLIENT_BIND=198.18.0.2:0 \
BORON_CAMPAIGN_PERFORMANCE_CLIENT_SOURCE_CIDR=198.18.0.2/32 \
BORON_CAMPAIGN_PERFORMANCE_CLIENT_DEVICE=eno1np0 \
BORON_CAMPAIGN_UDP_BATCH_SIZE=64 \
BORON_CAMPAIGN_UDP_REUSEPORT_WORKERS=8 \
BORON_CAMPAIGN_UDP_RUNTIME=tokio \
BORON_CAMPAIGN_UDP_IDLE_STRATEGY=park \
BORON_CAMPAIGN_UDP_SOCKET_RECEIVE_BUFFER_BYTES=4194304 \
BORON_CAMPAIGN_UDP_SOCKET_SEND_BUFFER_BYTES=4194304 \
scripts/boron-gen-large-memory-campaign.sh run
```

The matching controller command was:

```bash
BORON_COORD_SERVER_SSH=oxidedns-1 \
BORON_COORD_CLIENT_SSH=oxidegun-1 \
BORON_COORD_REMOTE_ARTIFACT_ROOT=/home/codex/borondns/target/evidence/boron-gen-large-memory-next-large \
scripts/boron-gen-external-performance-coordinator.sh
```

Eight Tokio workers were selected to avoid a single receive queue limiting
the measurement. This profile was not an isolated lookup optimization; such
a comparison needs the single-worker baseline and per-repetition
`RcvbufErrors`, softnet drops, QPS, and latency. Dedicated-worker park loops
were a separate experiment because idle CPU use could fail the stability
check. The original registry curve selected 1M, 10M, 20M, 40M, 50M, and
60M names with matching NSEC3 counts, writing QPS/p99 medians and memory
peaks to `results.tsv`.

A one-second handshake smoke over `eno1np0` (`198.18.0.0/30`) received
42,501/42,501 responses with no client errors or drops. Both NICs recorded
exactly 42,501 RX and TX packets with no new error/drop counters. The measured
rate was 42,352 responses/s and p99 was 330 µs. This validated the path only;
it was too short for a capacity claim. Evidence:

- `target/evidence/boron-gen-physical-harness-smoke-20260728`
- The adjacent `boron-gen-external-coordinator-smoke-r2-*` directory

For a non-loopback listener the harness allowlisted both the local probe's
exact source address and the remote-client CIDR in RRL. UDP correctness
accepted authoritative NXDOMAIN or valid truncation; a separate TCP
`dig +dnssec` probe required NXDOMAIN with NSEC3 authority records.

## Fuzz campaign disposition

The earlier two-host 24-hour campaign had ended before the final 32 GiB
load run. Both remote evidence trees were copied locally; a checksum dry-run
found no difference. The retained tree had a 108,815-file SHA-256 manifest.

| Host | Passed/status 0 | Interrupted/status 15 | Total |
| --- | ---: | ---: | ---: |
| `oxidedns-1` | 54 | 0 | 54 |
| `oxidegun-1` | 32 | 49 | 81 |
| Total | 86 | 49 | 135 |

All 49 nonzero workers reached the outer 88,200-second timeout while
libFuzzer's CPU-time duration lagged wall time under 81-way contention.
Their logs ended with `libFuzzer: run interrupted; exiting`. No nonempty
crash artifacts or ASan/UBSan markers were found.

The strict collector also found two evidence defects: an empty `launch/`
directory forbidden by its validator, and the oxidedns sampler's first row
arriving after seven seconds instead of the allowed two. Removing the
verified-empty directories preserved the evidence but did not fix the timing
violation; collection still returned status 1. Both hosts' evidence and the
disposition are retained at
`target/evidence/fuzz-soak-two-host-20260726T112226Z-forensic-20260727`.

Follow-up harness changes separated the build timeout from the wall-clock
fuzz deadline, removed the unused directory, and derived first-sample
tolerance from the authenticated per-unit probe budget. Strict replay also
found blank process rows from a trailing here-string newline; the sampler was
changed to filter them. Those corrections did not turn the frozen campaign
into a pass, and the successful 32 GiB load test does not replace fuzz
evidence. See the [release evidence guide](release-evidence-guide.md) for the
current release-evidence process.
