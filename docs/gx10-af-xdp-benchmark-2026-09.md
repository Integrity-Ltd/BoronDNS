# GX10 AF_XDP tuning — September 2026

BoronDNS delivered **24.007–24.008 million positive replies/s** in three
fresh 30-second runs on a dedicated GX10/ConnectX-7 link. Loss was
0.0043–0.0082%, below the campaign's 0.01% acceptance threshold. A separate
three-run validation at 20.039–20.040M QPS had only 0.000032–0.000053% loss.
This is a hot-query microbenchmark, not a public-DNS capacity guarantee or
evidence of a new win over Knot.

## What was measured

BoronGen supplied a mixed zone with 10,000 generated owners and 60,003 records
by AXFR. A second GX10 ran BoronGun against one repeated name, asking for four
A records with EDNS. The DNS response was 120 bytes. All 20 queues were used;
source ports were checked against observed steering in both directions, not
just a calculated RSS hash. Traffic stayed on the dedicated 200 Gbit/s link.

The candidate includes the retained, uncommitted optimization work on base
`24858bff567aeef924c84a9f194d14a26f4bef23`. Release binary SHA-256:
`b0870a840a0418130dacedd992cfb9ea96c44fe74f6a1e5f9989921b680758df`.
It is not the published v1.0.1 binary. Cargo work ran only on the remote host,
with four build jobs, 8 GiB memory and 400% CPU limits, outside load tests.

The final tuning pass changed no Rust code. It used this same release binary
throughout the thread, CPU-affinity, IRQ-placement and hardware-ring sweeps.
Earlier retained code improvements include packet-bound parsing caches,
bounded reusable parsing buffers, small-directory lookup, ARM packet/checksum
work, Cookie-state reads and sharded AF_XDP counters. Software UDP checksums
remain enabled; a tested NIC checksum-offload prototype was slower and removed.

## Host-specific settings

| Setting | Value |
| --- | --- |
| Server backend | Native AF_XDP, zero-copy required, MTU 1500 |
| AF_XDP queues / batch | 20 / 64 packets |
| UMEM per queue | 16,384 frames, 2,048 bytes each |
| AF_XDP FILL / RX / TX / completion rings | 8,192 / 4,096 / 4,096 / 4,096 |
| Hardware RX / TX rings | 2,048 / 1,024 entries |
| Server runtime | `TOKIO_WORKER_THREADS=10` |
| Server process CPUs | Faster cores 5–9 and 15–19 |
| Dedicated NIC completion IRQ CPUs | Slower cores 0–4 and 10–14, two queues per core |
| NIC coalescing | Adaptive off, RX/TX 64 µs, 128 frames |
| NIC private flags | Striding RX off; CQE compression off |
| Requester | Batch 256, deadline pacing, count-mode response classification |
| Policy | Cookie Lenient; RRL enabled with the requester exempt |
| Detailed hot-path metrics | Off |

These are lab settings, **not new product defaults**. Core numbering and
capacities are specific to these heterogeneous CPUs. Do not apply IRQ or NIC
changes blindly to a shared interface. Readiness, TCP service and transfers
must still make progress when choosing a runtime-worker count.

The hardware rings and AF_XDP rings are different resources. With hardware
RX1024, separating interrupts from the serving cores reached 20.036M QPS but
still lost 0.017–0.018%. One run's 102,130 hardware `rx_out_of_buffer` drops
exactly matched requester TX minus server receive counts. RX2048 removed
almost all of this gap. RX4096 also passed a single run, but the smaller
successful setting was selected for repeated validation. Twelve or fourteen
runtime threads on the same ten faster cores increased loss.

See [the mlx5 buffer-reuse caveat](configuration.md#af_xdp-buffer-reuse-on-mlx5):
these clean runs do not prove every driver, frame-pool or ring combination safe.

## Repeated result

Each row starts a fresh server and reloads the zone. BoronGun targeted 20.05M
QPS; actual offered rate was about 20.040M. Positive QPS is received positive
answers divided by the sending interval, including answers received during
the final drain. Loss uses all submitted queries as its denominator.

| Target / run | Positive replies/s | Loss |
| --- | ---: | ---: |
| 20.05M / 1 | 20,039,903 | 0.00003194% |
| 20.05M / 2 | 20,039,433 | 0.00005323% |
| 20.05M / 3 | 20,039,950 | 0.00003194% |
| 24M / 1 | 24,008,361 | 0.00428147% |
| 24M / 2 | 24,007,427 | 0.00822905% |
| 24M / 3 | 24,008,300 | 0.00432396% |

The 24M repeats used the same settings, with about 24.009M actually offered.

Each run had zero server RX parse errors, requester errors and SERVFAIL replies.
Eight independent wire checks validated IPv4/UDP checksums, including the
computed-zero checksum's required `0xffff` wire representation. Readiness and
TCP DNS were checked once per second during load. Ordinary UDP probes after
each run received 100/100 positive replies across the calibrated source ports.

Count mode measures classified replies; it does not provide per-query latency
or full per-query identity matching at this rate. This workload does not
measure diverse cache-cold queries, large-zone IXFR under load, DNSSEC proofs,
unexempt rate limiting, or general Internet-facing traffic. It is not a soak.
The preceding low-loss baseline was about 18.001M QPS; the final 24M result is
roughly 33.4% higher, with host tuning explicitly included in that comparison.

## Overload recovery

A separate 15-second stress stage requested 32M QPS; the generator actually
submitted 28.095M QPS. BoronDNS returned 24.986M positive replies/s with 11.07%
loss. This is an overload result, not low-loss capacity. On the same server
process, subsequent stages returned 20.040M QPS with 0.00015% loss and 200k QPS
with zero loss. Final ordinary UDP recovery was 100/100, without a restart.
No parsing errors or SERVFAIL replies occurred; TCP DNS and readiness continued
responding during overload (maximum observed probe latencies about 20 and
21 ms respectively). The 200k-QPS stage's maximum TCP probe latency was 0.25 ms.

## Profiling and verification

Matched 199 Hz system-wide call-stack profiles used a freshly rebuilt profiling
binary, the same workload and 20.05M target. The original 20-thread/all-core/
original-IRQ/RX1024 setup delivered 18.682M positive QPS; the selected setup
delivered 20.040M. These diagnostic runs are separate from the unprofiled
capacity results above. Neither profile lost samples.

The slower-core PMU shows receive-driver/redirect work after placement changes;
the faster-core PMU shows DNS processing. In the latter, sampled self costs
include allocator free-path atomics (6.39%), zone-publication CAS (5.58%) and
UDP checksums (5.12%). These identify possible future work, not guaranteed
speedups. Percentages from the two PMU events must not be added together.

All 103 tracked Rust/Cargo/toolchain inputs matched the remote source tree.
The unchanged Rust sources retain the preceding successful gates: 783 core
tests plus one integration test, 480 standard-server tests, 535 AF_XDP-server
tests, Clippy with warnings denied and formatting (one ignored test in each
server suite). Documentation/link checks and the architecture audit with its
mutation regressions also passed. This pass added documentation and lab
harness evidence, not another untested production-code optimization.

Both hosts were restored to their original binaries, MTU, RSS, NIC flags,
coalescing, hardware rings and IRQ placement. No test services or XDP
attachments were left running. The pass-7 evidence bundle retains the raw
requester records, metrics, profiles, generated configurations, source hashes
and restoration logs under `borondns-gx10-opt7-20260920.b9dZ3E` in the
operator's local state directory.
