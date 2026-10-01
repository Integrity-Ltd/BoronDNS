# GX10 multi-zone benchmark — 26–27 September 2026

With one million small zones loaded, BoronDNS sustained three fresh runs at
11M hot-name, 4M Zipf and 3M uniform queries/s below 0.01% loss. The earlier
single-zone setup reproduced 26.005M positive replies/s. These measure different
workloads, not a regression between server versions.

The important qualification is background work: at 100,000 zones, changing SOA
refresh to 60 seconds made the otherwise-passing 5M uniform workload lose
0.69–1.34% of replies. Loading and observability also became expensive. This
report separates those findings from the quiet-zone throughput figures.

The follow-up [Knot DNS comparison](gx10-knot-multi-zone-2026-09.md) measures
the same portfolio and query schedules on both servers, including proportional
throughput loss and configuration differences.

## Throughput

Each point below passed on three fresh server processes, using distinct empty
caches and new AXFR loads. All selected runs had zero DNS classification,
server RX-parse, requester and kernel TX-delivery errors. The
[per-run CSV](gx10-multi-zone-capacity-2026-09.csv) includes offered and positive
rates, loss, cold-probe results and queue balance for all 36 runs.

| Member zones | Distribution | Target, M QPS | Positive replies/s, M, range | Worst loss |
| ---: | --- | ---: | ---: | ---: |
| 1,000 | Hot name | 18.00 | 18.00113–18.00166 | 0.003136% |
| 1,000 | Zipf, s=1 | 14.75 | 14.74917–14.74921 | 0.000005% |
| 1,000 | Uniform | 12.50 | 12.49989–12.49994 | 0.000052% |
| 10,000 | Hot name | 18.00 | 18.00094–18.00163 | 0.004042% |
| 10,000 | Zipf, s=1 | 11.25 | 11.24851–11.24855 | 0% |
| 10,000 | Uniform | 7.50 | 7.49890–7.49901 | 0.001542% |
| 100,000 | Hot name | 15.25 | 15.25539–15.25539 | 0.000084% |
| 100,000 | Zipf, s=1 | 7.00 | 6.99984–7.00030 | 0.006779% |
| 100,000 | Uniform | 5.00 | 4.99988–4.99996 | 0.001792% |
| 1,000,000 | Hot name | 11.00 | 11.00078–11.00091 | 0.001843% |
| 1,000,000 | Zipf, s=1 | 4.00 | 3.99995–3.99999 | 0% |
| 1,000,000 | Uniform | 3.00 | 2.99981–2.99985 | 0% |

These are validated operating points, not exact ceilings. Short searches used
a 0.25M grid; longer validation began one grid step lower and backed off by
0.5M after a failed repeat. Failed higher-rate runs remain in the evidence.
Actual offered rates differ slightly from targets because of packet pacing.

The single-zone anchor returned 26.005172M positive replies/s with 0.009172%
loss. Its DNS reply was 120 bytes; every portfolio reply was 121 bytes and had
more name labels. The anchor also uses the server's shortcut for directories
of at most four entries, unlike every portfolio point. The whole difference
from 26M cannot therefore be assigned to cache-cold zone lookups alone.

## Workload and controls

This followed the 21 September multi-zone proposal, using the same two
ASUS GX10/GB10 machines and dedicated 200 Gbit/s ConnectX-7 link as the
[hot-query campaign](gx10-af-xdp-benchmark-2026-09.md). Each machine has
128 GB LPDDR5 memory and 20 heterogeneous ARM cores. The server ran Ubuntu
24.04.4, kernel `6.17.0-1014-nvidia`; the requester ran Ubuntu 24.04.3,
kernel `6.14.0-1013-nvidia`. No GPU was used.

NIC, IRQ and CPU-group settings stayed fixed across points: native AF_XDP
zero-copy, 20 queues, MTU 1500, batch 64, hardware RX/TX rings 2048/1024,
16,384 × 2048-byte UMEM frames per queue, and ten queue-local runtimes on
cores 5–9 and 15–19. IRQs used the ten slower cores. Server coalescing was
64 µs/128 frames, adaptive moderation and striding RX disabled. The referenced
hot-query report gives the complete ring and CPU-group settings. RRL remained
enabled with the requester exempt; Cookie policy was Lenient and detailed
hot-path metrics were off. There was no per-point retuning.

BoronGen's `portfolio` profile supplied 23 records per member: SOA, two NS,
two glue A records, and three hosts each containing four distinct A records,
AAAA and TXT. Every hundredth member was nested below the preceding member.
The catalog adds N+4 records, giving 24N+4 total stored records. It and all
member transfers were TSIG-authenticated over server-local loopback; measured
queries crossed only the direct link (`192.168.10.12` → `192.168.10.11:15353`).

Zone names use a reversible seeded permutation, not sequential labels.
Popularity rank is independently shuffled. Flat-zone host labels are padded
to equalize full question length with nested members. Queries ask only for A,
with EDNS 1232, RD and DO clear. This tests longest-match zone selection, not
delegation correctness or DNSSEC.

The hot workload selects the top-ranked name from each size's shuffled rank
map. That name is fixed for all comparisons at a given size, but changes
between sizes. Hot-name retention therefore includes name and directory
placement effects; it is not a pure measurement of adding more unrelated
zones around one unchanged query name.

- Zone seed: `0x626f726f6e67656e`; rank seed: `2026092101`; sample seed:
  `2026092102` (Zipf uses the next seed); requester seed: `20260921`.
- Every mixed workload uses a pre-sampled 2^24-entry compact index table over
  three unique queries per zone. Twenty workers use distinct phase offsets,
  independent of source ports. There is no per-packet Zipf sampling.
- All eight rank histograms matched theoretical cumulative probabilities
  within 0.000381. At one million zones, the Zipf table visited 883,349 zones;
  the uniform table visited all one million. Query lists, rank maps and
  schedules were SHA-256 checked on the requester.
- The requester achieved the 26M offered-rate search point even with the
  million-zone mixed corpus. Accepted runs were not requester-rate limited.
  Their busiest/quietest server queue ratio was at most 1.000734.
- Capacity runs used ten seconds of same-socket warm-up and thirty seconds
  of measurement. Positive QPS includes replies received during the final
  drain, divided by the sending interval. Count mode classifies responses but
  does not identity-match every packet; independent probes checked exact
  question, RDATA and TTL, including every nested child.

The server had cgroup MemoryHigh/MemoryMax of 80/88 GiB with no swap; requester
and primary limits were 16 and 4 GiB. No memory-limit or OOM events appeared in
1,562 retained unit-resource snapshots. The first million-zone attempt was
rejected by the conservative transfer reservation budget, not actual RAM
exhaustion. Its 8 GiB budget was increased to 32 GiB for million-zone instances
under the unchanged cgroup limits; smaller points retained 8 GiB.

## What the fixed-rate profiles show

Separate instances ran all twelve points at 2M QPS, each with zero measured
loss. A ten-second steady subwindow of a forty-second measured stage captured
99 Hz symbol samples and PMU counters. The denominator estimates queries in
the exact PMU interval from the surrounding NIC receive rate. Scope is the
server process and its threads, including background work, not whole-machine
CPU or IRQ work outside that process. These are approximate per-query costs.

| Zones | Distribution | Cycles/query | CPU µs/query | `LLC-load-misses`/query | `dTLB-load-misses`/query |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1,000 | Hot | 3,393 | 1.022 | 16.80 | 5.60 |
| 1,000 | Zipf | 5,380 | 1.511 | 20.66 | 19.74 |
| 1,000 | Uniform | 6,062 | 1.681 | 23.35 | 21.52 |
| 10,000 | Hot | 3,360 | 1.015 | 16.03 | 5.62 |
| 10,000 | Zipf | 6,316 | 1.747 | 24.00 | 21.38 |
| 10,000 | Uniform | 7,537 | 2.048 | 30.11 | 22.22 |
| 100,000 | Hot | 3,338 | 1.009 | 15.88 | 5.63 |
| 100,000 | Zipf | 7,077 | 1.943 | 26.53 | 22.01 |
| 100,000 | Uniform | 8,823 | 2.377 | 35.02 | 22.97 |
| 1,000,000 | Hot | 3,409 | 1.026 | 17.79 | 5.88 |
| 1,000,000 | Zipf | 8,318 | 2.249 | 32.53 | 22.38 |
| 1,000,000 | Uniform | 10,164 | 2.707 | 40.08 | 22.82 |

The event names are the generic perf events on `armv8_pmuv3_1`; the slower-core
PMU was not counted under the selected affinity. Counters were not multiplexed.
Instructions/query stayed between 7,738 and 7,775, while uniform cycles/query
rose by about 68% and cache misses by about 72% from 1k to 1M zones. This is
consistent with worsening memory locality, rather than substantially more
instructions. It does not measure what fraction of stall time each miss type
caused. There were no major faults and at most three minor faults per window.

At one million zones, the leading uniform self-costs were direct-answer lookup
(20.83%), suffix-directory lookup (19.13%), `memcmp` (12.92%), child lookup
(11.40%) and `memcpy` (5.49%). Zipf showed the same group of hotspots. These
make directory and in-zone data locality sensible follow-up targets. TLB miss
growth was much smaller; this campaign alone does not justify prioritizing
huge pages.

Hot-name average cost at 2M stayed nearly flat. These averages do **not** explain
the lower hot-name low-loss operating point at one million zones. Scheduler,
IRQ and burst-level traces near capacity would be needed to resolve that.
Source inspection found whole-registry refresh-scheduler scans every second,
but their causal contribution to high-rate loss was not established here.

## Loading and memory

| Member zones | Fresh release load range | Ready RSS, GiB | Gross RSS bytes/zone | Gross RSS bytes/record |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 3.3–3.9 s | 0.704 | 756,240 | 31,505 |
| 10,000 | 18.3–21.9 s | 0.964 | 103,502 | 4,313 |
| 100,000 | 178.3–199.4 s | 3.694 | 39,669 | 1,653 |
| 1,000,000 | 75.4–76.9 min | 34.435 | 36,975 | 1,541 |

Load ranges come from the fresh instances used in accepted capacity runs.
RSS is sampled at readiness on the separate symbol-rich profiling instances;
it includes the catalog, runtime, indexes and fixed UMEM allocation. The
bytes/record denominator is 24N+4, including catalog records. These are gross
ratios, not marginal storage costs. The first unprofiled million-zone load had
35.14 GiB RSS and 47.11 GiB cgroup charge; cgroup memory also includes charged
file cache and kernel memory.

BoronGen's measured cgroup peak stayed below 5.6 MiB at every size. The first
million-zone load used about 107.5 primary CPU seconds versus 3,582.9 server CPU
seconds. Its early catalog/persistence phase lasted roughly half an hour with
little primary activity. The primary was not the dominant CPU consumer.

A separate ten-second sample during million-zone member activation identified
copy-on-write directory publication costs: atomic reference increments took
35.20% self time, principally under the two `Arc<HashMap>::make_mut` paths in
`ZoneDirectory::insert`. Allocation, freeing and copying were also prominent.
This supports reducing per-publication shard copying as a follow-up. It is not
a measurement of the share of total load wall time, which also includes the
earlier persistence waits. Durability must be preserved in any loading fix.

## Refreshes, latency and safety checks

The additional 100k-zone variant used 60-second SOA refresh, unchanged serials,
and the same 5M uniform target as the quiet baseline. All three runs exceeded
the 0.01% loss threshold:

| Run | Positive replies/s, M | Loss | Cold-probe p99 | Cold-probe maximum |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 4.96542 | 0.69127% | 12.12 ms | 46.95 ms |
| 2 | 4.93276 | 1.34394% | 15.88 ms | 33.55 ms |
| 3 | 4.93398 | 1.31987% | 17.43 ms | 64.09 ms |

No DNS/parser/requester errors or wrong-content probes were observed. The
timestamp check found 65,588 of 100,001 tracked zones successfully refreshed
after the cutoff; the retained journal tail contains refresh-queue-full/deferred
warnings. This proves background refresh activity and backlog, not completion
of every zone's refresh on time. Fresh loading clusters deadlines, and 60 seconds
is an aggressive interval: this is a synchronized-refresh stress variant, not
evidence of the cost of staggered hourly refreshes. A refresh-enabled low-loss
capacity search was not performed.

Across the 36 quiet capacity runs, 92,767 independent cold-name probes recorded
one timeout and no wrong answers. At one million zones all probes succeeded;
successful-probe p99 ranged from 0.79 to 2.13 ms and the maximum was 20.51 ms.
These low-rate side probes are not a bulk-query latency histogram.

Separate uniform 2M stages checked TCP DNS and readiness during load. Maximum
readiness latency grew from 23.5 ms at 1k to 51.7 ms at 10k, 363 ms at 100k,
and 4.265 s at 1M. The million-zone stage completed six sequential checks in
25.16 seconds; maximum TCP response time was 5.45 ms. Readiness's whole-zone
metadata walk is an operational scaling problem even when DNS answers remain
fast. The helper used a five-second readiness timeout for 100k/1M, rather than
the earlier two-second timeout; actual latency is retained, not hidden by it.

Full `/metrics` rendering was another problem: the million-zone response body
was about 3.24 GB, with one render-and-prefix fetch taking 30.4 seconds. The
harness collected the verified global-counter prefix and closed before per-zone
detail. Server-side full rendering still occurred, outside timed query windows.
These measurements do not include frequent full Prometheus scraping under load.

The final post-load checks verified 3,000/3,342/6,054/33,066 exact answers across
the four sizes, including all nested children. Each size and the refresh variant
also passed 180 raw IPv4/UDP checksum checks across all 20 calibrated source
ports. No server algorithm was changed during the campaign.

## Evidence and limitations

Server source baseline: `4cdf7a64c1338ff46ad7c543662165ae68596a4b`. This was the
26M development binary, **not the published v1.0.1 binary**. Tested SHA-256s:

| Artifact | SHA-256 |
| --- | --- |
| Capacity server | `e1111af99b19aadd2d057231c46807e62bfecef1cb5bccc88e7c92b4eb923510` |
| Symbol-rich profile server | `f60b24c61aab5d346f06e1f0fb7d14af9a7b4d2ac1cfb5ae10077eb31f897874` |
| BoronGen | `80df0a4c4dc5feddf019e090d8838a0dfc9eede696ad62a954d3c880ec2583e6` |
| BoronGun | `618eb15f7ce76d4a2639164da85042796143b226f6767a6a30915c5571022f5b` |

The support tools gained deterministic portfolio generation, shared query pools,
compact schedules and same-socket warm-up. Their frozen source archive is
`benchmark-tool-source.tar.gz`, SHA-256
`287acdaa3531f3fd05a16af66949df24f459b302cd3b80cc63cde278a815f58d`.
After measurement, a regression-tested startup guard rejected unsupported
latency-tracking warm-up; it does not affect the count-mode campaign. Final
remote checks passed 67 tool tests, formatting and all-feature/all-target Clippy.
Cargo work used Rust 1.98.1 only on SSH, bounded to four CPUs/8 GiB, with no
build/load overlap.

Raw runs, rejected trials, manifests, scripts, configurations, profiles and
audits are retained in the operator state bundle
`borondns-gx10-zipf-20260926.WlCn9l`. Remote evidence archives have SHA-256
`5e1ddb1767105ceb9aa2c217dc94b402cd73b59d34bc22c637970dfb6fbb6a52`
(requester) and
`9aabfb062c7bc40a8520013af9ecd381f195eda155189ae639ba0a24bfacc190`
(server). The corpus generator and exact deployed harnesses are retained there;
large generated zone caches remain on the server outside those archives.

Two harness corrections are explicit in the retained evidence. The anchor's
initial verdict incorrectly treated TX-outstanding at drain time as an error.
The initial capacity harness also required zero cold-probe timeouts, beyond the
proposal's bulk-loss rule. That extra rule was removed before accepting any
million-zone repeat. The final audit applies the proposal consistently; the
1k hot 18M triplet includes one timeout, and its original false verdict remains
in the CSV. Earlier profile samples with a wider NIC-counter window were
replaced by the consistent final twelve-point series, not silently rewritten.

Both hosts' original NIC settings and server IRQ affinity were verified after
restoration; XDP was detached and all test services/watchdogs stopped. Installed
binaries and the pre-existing VPN were unchanged. Ordinary host services were
not disabled, so this is not a fully isolated hardware-ceiling measurement.

DNSSEC, negative answers, mixed response sizes, unexempt RRL, changed-zone IXFR,
TCP throughput, long soaks and other hardware remain outside this campaign.
The optional Zipf s=0.8/1.2 sensitivity runs were not performed. No Knot
comparison or general public-facing capacity claim follows from these results.
