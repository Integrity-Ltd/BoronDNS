# GX10 AF_XDP tuning — September 2026

BoronDNS delivered **26.007 million positive replies/s** in three fresh
30-second runs on a dedicated GX10/ConnectX-7 link. Loss was
0.00061–0.00142%, below the campaign's 0.01% acceptance threshold. This used
opt-in queue-local runtimes; the preceding committed setup reached
24.007–24.008M QPS in its three-run validation.
This is a hot-query microbenchmark, not a public-DNS capacity guarantee or
evidence of a new win over Knot.

## What was measured

BoronGen supplied a mixed zone with 10,000 generated owners and 60,003 records
by AXFR. A second GX10 ran BoronGun against one repeated name, asking for four
A records with EDNS. The DNS response was 120 bytes. All 20 queues were used;
source ports were checked against observed steering in both directions, not
just a calculated RSS hash. Traffic stayed on the dedicated 200 Gbit/s link.

The optimizations were measured on base
`24858bff567aeef924c84a9f194d14a26f4bef23` and subsequently committed as
`813039fea0410570d9f4548480b984f20a10606f`. Release binary SHA-256:
`b0870a840a0418130dacedd992cfb9ea96c44fe74f6a1e5f9989921b680758df`.
It is not the published v1.0.1 binary. Cargo work ran only on the remote host,
with four build jobs, 8 GiB memory and 400% CPU limits, outside load tests.

The 24M tuning pass changed no Rust code. It used this same release binary
throughout the thread, CPU-affinity, IRQ-placement and hardware-ring sweeps.
Earlier retained code improvements include packet-bound parsing caches,
bounded reusable parsing buffers, small-directory lookup, ARM packet/checksum
work, Cookie-state reads and sharded AF_XDP counters. Software UDP checksums
remain enabled; a tested NIC checksum-offload prototype was slower and removed.

The 26M candidate adds `xdp.worker_cpu_groups` on top of `813039f`. Its release
binary SHA-256 is
`e1111af99b19aadd2d057231c46807e62bfecef1cb5bccc88e7c92b4eb923510`.
This identifies the tested source snapshot, not a released version.

## Host-specific settings

| Setting | Value |
| --- | --- |
| Server backend | Native AF_XDP, zero-copy required, MTU 1500 |
| AF_XDP queues / batch | 20 / 64 packets |
| UMEM per queue | 16,384 frames, 2,048 bytes each |
| AF_XDP FILL / RX / TX / completion rings | 8,192 / 4,096 / 4,096 / 4,096 |
| Hardware RX / TX rings | 2,048 / 1,024 entries |
| Server runtime | `TOKIO_WORKER_THREADS=10` |
| Queue-local runtimes, 26M candidate only | Ten one-worker groups, two adjacent queues per group |
| Server process CPUs | Faster cores 5–9 and 15–19 |
| Dedicated NIC completion IRQ CPUs | Slower cores 0–4 and 10–14, two queues per core |
| NIC coalescing | Adaptive off, RX/TX 64 µs, 128 frames |
| NIC private flags | Striding RX off; CQE compression off |
| Requester | Batch 256 for historical 20M/24M; batch 64 for 26M comparisons; deadline pacing, count-mode response classification |
| Policy | Cookie Lenient; RRL enabled with the requester exempt |
| Detailed hot-path metrics | Off |

These are lab settings, **not new product defaults**. Core numbering and
capacities are specific to these heterogeneous CPUs. Do not apply IRQ or NIC
changes blindly to a shared interface. Readiness, TCP service and transfers
must still make progress when choosing a runtime-worker count.

The selected 26M configuration adds this field to the existing `[xdp]` section:

```toml
worker_cpu_groups = [[5], [6], [7], [8], [9], [15], [16], [17], [18], [19]]
```

These ten serving threads are additional to the main runtime's ten workers,
which retain fallback UDP, TCP and control-plane work. Each queue adapter is
re-registered with its group's I/O reactor. The empty default retains shared
scheduling. This setting does not change IRQ placement or NIC settings; see
[configuration](configuration.md#optional-af_xdp-cpu-groups) for constraints and
the uneven-load and NUMA caveats. AF_XDP remains experimental and opt-in.

The hardware rings and AF_XDP rings are different resources. With hardware
RX1024, separating interrupts from the serving cores reached 20.036M QPS but
still lost 0.017–0.018%. One run's 102,130 hardware `rx_out_of_buffer` drops
exactly matched requester TX minus server receive counts. RX2048 removed
almost all of this gap. RX4096 also passed a single run, but the smaller
successful setting was selected for repeated validation. Twelve or fourteen
runtime threads on the same ten faster cores increased loss.

The later 26.1M-offered follow-up rejected hardware RX4096: that run recorded
1,917 RX parse errors with the same 16,384-frame pool and 8,192-entry FILL
ring. The harness stopped and restored the hosts. Its earlier clean 20M probe
must not be treated as validation at higher load; the cause is not established.

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

### Repeated 26M result

The integrated candidate met the target of at least 26M positive replies/s
with loss below 0.01% in three fresh 30-second runs. These runs used the
configuration above, without diagnostic instrumentation, targeting 26.02M:

| Run | Positive replies/s | Loss |
| --- | ---: | ---: |
| 1 | 26,007,422 | 0.00061161% |
| 2 | 26,007,292 | 0.00142124% |
| 3 | 26,007,381 | 0.00090665% |

Matched shared-runtime baseline runs bracketing these repeats returned
26,000,690 and 26,005,931 positive replies/s, losing 0.02668% and 0.00639%.
The second baseline also passed the single-run threshold: this is improved
repeatability and lower CPU cost, not a claim that the old code cannot reach
26M. Candidate server CPU time was about 5% lower over these measurement
windows, which include pre/post-load margins.

The earlier two-group prototype passed three repeats, but the integrated
two-group configuration subsequently failed one of three at 0.01779% loss.
Ten single-core groups were therefore selected and tested afresh. In that
failed run, requester TX minus server RX was 136,792 packets, exactly the
sum of NIC `rx_out_of_buffer` and `rx_xsk_xdp_drop`. The accepted repeats had
4,772, 10,449 and 7,074 such ingress drops; only the second also lost 640
replies after server transmission. No DNS processing loss, RX parsing errors,
requester errors or SERVFAIL replies were recorded in these repeats.

### Other experiments

| Follow-up experiment | Measured outcome |
| --- | --- |
| Requester batches and pacing | Reducing bursts from 256 to 64 packets usually lowered 26.1M-offered loss to about 0.012–0.04%. Smaller batches and disabling idle sleep did not improve it reliably. Relative pacing missed its offered-rate targets. |
| Allocator and publication reads | Bounded response-buffer recycling improved two overload comparisons, though actual offered rates differed slightly. Combined with a reader that revalidated publication on every query, it removed both leading atomic-operation hotspots from the profile's ≥1% list, but 26.1M-offered loss remained 0.030–0.040%. |
| Other code prototypes | Hybrid label hashing, fixed checksum folds, send-metrics scratch reuse, earlier response-buffer release, fewer completion drains and a shorter eBPF redirect path gave no repeatable QPS gain. Explicit async yields reduced throughput. |
| NIC and memory settings | Larger thread caches, frame pools, packet batches and interrupt-coalescing delays did not establish the target. Hardware RX4096 produced parsing errors and was rejected; RX2048 remains the tested setting. |
| Worker placement | Increasing to 20 runtime workers was worse than ten on the fast cores. Half-rate cache-locality probes suggested modest CPU savings, but do not prove a full-rate benefit. |
| Cache-local runtime groups | Four diagnostic prototype runs at 26.1M offered lost 0.0039–0.0061%, with no sampled cross-L3 queue movement. Keeping one separate ten-worker runtime instead lost 0.052–0.061%; separating control-plane work alone did not reproduce the improvement. The retained implementation and stronger per-core repeats are above. |

The combined allocator/publication prototype passed 792 core tests, an
integration test, a compile-fail lifetime test, both server suites, formatting
and Clippy. Mutation tests caught frozen publications and uncleared response
storage. Its small-zone standard-UDP results varied with client burst size;
there is no universal performance-win claim. The allocator/publication and
other unsuccessful code prototypes were archived outside the repository and
removed from the working source. Only the explicit runtime-placement feature
was integrated.

In the earlier IRQ-placement comparisons, requester TX minus server RX
exactly matched NIC `rx_out_of_buffer` plus `rx_xsk_xdp_drop` increments.
This places that loss before DNS processing, but does not distinguish slow
NIC polling from delayed userspace buffer recycling. Later-in-run drops also
rule out treating this solely as a startup warmup issue. Sampled profile
percentages identify investigation targets, not additive speedup promises.

Detailed notebooks and raw evidence are retained in the operator's local
state directory: `borondns-gx10-opt8-20260920.QUenxT`,
`borondns-gx10-opt9-20260920.eIxJ3m`,
`borondns-gx10-opt10-20260920.Ghv9sF`,
`borondns-gx10-opt11-20260920.B6jTHr`,
`borondns-gx10-opt12-20260920.9gSCpC`,
`borondns-gx10-opt13-20260920.2PZNHl`,
`borondns-gx10-opt14-20260920.X1BBqJ`,
`borondns-gx10-opt15-20260920.MlXeqo` and
`borondns-gx10-opt16-20260920.V7u9hu`. They include prototype candidates,
source and binary hashes, paired results, safety checks and restoration logs.

## Overload recovery

The queue-local candidate was tested in one process at three successive
30-second stages. It returned 27.834M positive replies/s from 28.011M actually
offered, losing 0.63249%; this is overload, not accepted low-loss capacity.
The following stages returned 20.040M and 200k QPS with zero loss. Final
ordinary UDP recovery was 100/100 without restarting the server. No parsing
errors, requester errors or SERVFAILs occurred. Maximum observed readiness
and TCP probe times were 26.7 and 22.6 ms during the overload stage.

For comparison, the earlier committed setup's 15-second stress stage requested
32M QPS; the generator actually
submitted 28.095M QPS. BoronDNS returned 24.986M positive replies/s with 11.07%
loss. This is an overload result, not low-loss capacity. On the same server
process, subsequent stages returned 20.040M QPS with 0.00015% loss and 200k QPS
with zero loss. Final ordinary UDP recovery was 100/100, without a restart.
No parsing errors or SERVFAIL replies occurred; TCP DNS and readiness continued
responding during overload (maximum observed probe latencies about 20 and
21 ms respectively). The 200k-QPS stage's maximum TCP probe latency was 0.25 ms.

## Profiling and verification

Matched 199 Hz system-wide call-stack profiles compared the committed shared
runtime and queue-local candidate at the same 20.05M target, batch64 and host
settings. Both returned 20.040M positive replies/s with zero loss; neither
profile lost samples. These are separate from the unprofiled capacity runs.

Measured server CPU time fell from 293.60 to 227.17 seconds (22.6%) over
windows including pre/post-load margins. The faster-core PMU's approximate
cycle count fell from 1.150 trillion to 0.935 trillion (18.7%). These are
different measurements, not interchangeable per-query cycle counts.

After aggregating across worker names, allocator free-path atomic self cost
fell from 7.50% to 1.33%, and the publication-associated CAS symbol from
5.92% to 1.60%. The latter symbol can include other callers. No allocator or
publication algorithm was changed: queue locality reduced the observed
contention. Checksum self cost was 4.77% versus 5.48%, but a larger share of
a smaller total does not establish a regression. Percentages from the slow-
and fast-core PMU events must not be added together.

### Small-zone standard UDP

Eight fresh servers compared baseline/candidate/baseline/candidate for each
of the Tokio and dedicated standard-UDP runtimes. Each loaded a 63-record
zone and ran two 10-second stages; requester batch size was one. The optional
AF_XDP groups were unset, as required for the standard backend.

| Setup | Baseline loss, two runs | Candidate loss, two runs |
| --- | --- | --- |
| Tokio, one worker, 20k offered QPS | 0%, 0% | 0%, 0% |
| Tokio, one worker, 100k offered QPS | 0.06570%, 0.09370% | 1.05020%, 0% |
| Dedicated, ten workers, 200k offered QPS | 0%, 0% | 0%, 0% |
| Dedicated, ten workers, 2.5M offered QPS | 8.00773%, 6.50125% | 4.21419%, 7.13411% |

There was no consistent slowdown, but this is not an equivalence proof.
The first candidate's worse 100k run lost 10,502 packets, exactly matching
its socket's receive-buffer drops; the repeat was lossless. Near saturation,
dedicated-runtime results also varied. No parsing, requester or SERVFAIL
errors occurred, and all post-load UDP probes passed. These short hot-query
checks do not establish performance on other CPUs, imbalanced RSS, NUMA
systems or different traffic. Keep CPU grouping opt-in and measure locally.

### Regression gates and evidence

All 119 Rust/Cargo/toolchain inputs matched the remote source tree. The
candidate passed 785 core tests plus one integration test, 480 standard-server
tests and 542 AF_XDP-server tests (one ignored test in each server suite),
workspace/all-target/all-feature Clippy with warnings denied, and formatting.
New regressions cover config rejection, CPU placement, reactor migration,
startup failure, descriptor ownership, cancellation, publication/expiry and
malformed-query handling across runtime groups. Documentation/link checks
and the architecture audit with mutation regressions also passed; the audit's
existing total-source-line advisory remains.

The pass-16 evidence audit covers 21 fresh server processes, 31 load stages,
168 wire/checksum cases and 703 readiness/TCP probes, including unsuccessful
controls. All processes drained without a shutdown timeout or error log.
The raw requester records, metrics, profiles, generated configurations,
source hashes and restoration logs are retained under
`borondns-gx10-opt16-20260920.V7u9hu` in the operator's local state directory.
Both hosts were restored to their original installed binaries, BPF object,
MTU, RSS, NIC flags, coalescing, rings and IRQ placement. No test services,
watchdog timers or XDP attachments remain. Raw host archives were downloaded
and their SHA-256 hashes verified against the remote copies.
