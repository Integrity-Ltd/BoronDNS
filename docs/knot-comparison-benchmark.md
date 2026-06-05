# Knot Comparison Benchmark Plan

This document defines how to compare OxideDNS against Knot DNS without mixing
different benchmark units or query mixes.

## Source-Derived Baseline

Knot's published response-rate benchmark uses two physical servers directly
connected by 40GbE. One server runs the authoritative implementation under
test; the other replays prepared DNS queries with `kxdpgun`.

The published setup records these control points:

- AMD EPYC 7702P server hardware and Intel XL710 40GbE NICs.
- SMT disabled.
- 64 active CPU cores, NIC channels, and nameserver threads for UDP.
- 16 active CPU cores, NIC channels, and nameserver threads for TCP.
- `CFLAGS="-O2 -g -DNDEBUG"` for source-built servers.
- `SO_REUSEPORT`, socket affinity, and minimal responses for Knot DNS.
- One server thread or process pinned to one CPU core.
- UDP measurement windows of 15 seconds.
- Deactivated connection tracking.

The `dns-benchmarking` source repository implements this as a three-host
workflow: controller, nameserver target, and traffic player. The UDP response
module runs:

```bash
sudo kxdpgun -t "$duration" -p "$PORT" -b 10 -Q "$rate" -i "$querydb" "$target" $KXDPGUN_OPTS
```

The dataset contains zone files, generated server configs, and a `querydb`
file. For NOERROR mixes, `querydb` is generated from zone contents by selecting
unique `NS`, `DS`, `A`, `AAAA`, `PTR`, `MX`, `SOA`, and `DNSKEY` rows.

## kxdpgun Semantics To Mirror

From Knot DNS `src/utils/kxdpgun`:

- kxdpgun sends and receives through XDP.
- It autodetects the number of parallel threads from the number of combined
  queues on the selected network interface.
- Total `--qps` is divided by detected thread count.
- Threads are pinned with `--affinity`; the default is CPU `0s1`.
- UDP default batch is 10.
- Source UDP/TCP ports are allocated from `2000..65535`.
- `--local ip/prefix` can vary source IPs across a subnet.
- Text query input is `qname qtype [flags]`, where `E` means EDNS and `D`
  means EDNS plus DO.
- Responses are counted and rcodes are tracked, but kxdpgun does not fully
  match each response to its original query.
- Plain output reports average DNS reply size, average L2 throughput, and
  average L1 throughput. L1 adds 20 bytes per received packet.
- JSON output reports counts and rcodes but not the plain throughput fields, so
  comparison runs should retain plaintext logs.

## OxideDNS Comparison Contract

Use the same zone data and query mix for both servers:

1. Generate or import a Knot-style `querydb`.
2. Use `querydb` directly for kxdpgun.
3. Convert `querydb` to OxideDNS `query-trace.tsv`.
4. Run OxideDNS and Knot DNS with the same destination IP, port, query rate,
   duration, and EDNS/DO mix.
5. Record both packet-rate and byte-rate metrics.

For quick local synthetic runs, use `scripts/benchmark-dns-clients.sh` with:

- `OXIDEDNS_BENCH_TRACE_FILE` pointing at the converted trace.
- `OXIDEDNS_BENCH_DURATION_SECONDS=15` for Knot-aligned UDP windows.
- `OXIDEDNS_BENCH_CLIENT_MODE=ssh` when using a separate traffic host.
- `OXIDEDNS_BENCH_NETWORK_DEVICE` set to the physical NIC.
- `OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true` for any hardware claim.

For Knot-aligned comparison runs, stage Knot as the primary and OxideDNS as a
secondary:

1. Start Knot with the benchmark zone and use it as the reference authoritative
   target.
2. Let OxideDNS transfer the same zone by AXFR from Knot.
3. Verify OxideDNS readiness and SOA response.
4. Stop Knot so OxideDNS is idle and serving from the transferred in-memory
   snapshot.
5. Benchmark OxideDNS with the same query mix.

This shape keeps the zone source, query input, and Knot tooling close to the
Knot reference benchmark while isolating OxideDNS serving performance from
primary-transfer activity.

## Prepared Helpers

Create a kxdpgun query file from a zone file:

```bash
scripts/prepare-knot-comparison-benchmark.sh querydb \
  --zone zones/example.zone \
  --out target/knot-comparison/example \
  --shuffle
```

Convert that file to the OxideDNS load-client trace format:

```bash
scripts/prepare-knot-comparison-benchmark.sh trace \
  --querydb target/knot-comparison/example/querydb \
  --out target/knot-comparison/example
```

Stage Knot as primary and OxideDNS as a secondary from one zone file:

```bash
scripts/prepare-knot-comparison-benchmark.sh stage-knot-primary \
  --zone zones/example.zone \
  --zone-name example. \
  --out target/knot-comparison/example \
  --workers 64 \
  --udp-runtime dedicated \
  --udp-batch-size 32 \
  --shuffle
```

The staged directory contains:

- `knot.conf`: Knot primary config for the source zone.
- `oxidedns.toml`: OxideDNS secondary config pointing at Knot.
- `querydb`: kxdpgun input.
- `query-trace.tsv`: equivalent OxideDNS `dns-load-client` trace.
- `runbook.sh`: validates configs, starts Knot, waits for OxideDNS AXFR
  readiness, stops Knot, and optionally runs the direct OxideDNS idle benchmark.

Run the staged transfer and idle benchmark:

```bash
cd target/knot-comparison/example
RUN_IDLE_BENCHMARK=true \
BENCH_DURATION=15 \
BENCH_THREADS=64 \
BENCH_WINDOW=64 \
BENCH_NETWORK_DEVICE=eth0 \
./runbook.sh
```

For a Knot reference run against the same staged zone and query mix, start Knot
with `knot.conf` and run kxdpgun from the player host:

```bash
sudo kxdpgun -t 15 -p 5301 -b 10 -Q "$rate" -i querydb "$target_ip" \
  2>&1 | tee kxdpgun-knot.log
```

For an OxideDNS kxdpgun run on the dedicated hardware, use the same `querydb`,
the OxideDNS service port, and the same `-t`, `-b`, `-Q`, source-address, and
affinity settings as the Knot reference run. The generated `runbook.sh` local
load-client path is useful for local and preflight evidence; physical
Knot-comparison claims should use kxdpgun/NIC counters.

For repeatable OxideDNS socket-path sweeps on the two physical hosts, use the
checked-in wrapper instead of ad-hoc SSH commands:

```bash
OXIDEDNS_PHYSICAL_WORKERS="12 16 24" \
OXIDEDNS_PHYSICAL_RATES="2000000 2500000 3000000" \
OXIDEDNS_PHYSICAL_HOT_PATH_DETAILS="reduced off" \
OXIDEDNS_PHYSICAL_IDLE_STRATEGIES="park spin" \
scripts/physical-udp-knot-comparison.sh
```

The wrapper expects a staged Knot-primary comparison directory on the server
host, copies the staged OxideDNS config for each run, applies the selected
worker count, hot-path metric detail, and dedicated-worker idle strategy, starts
Knot only long enough for OxideDNS to transfer the zone, then runs `kxdpgun`
from the player host against the idle OxideDNS secondary. It writes one
artifact directory under the staged directory's `evidence/` folder and emits a
`summary.tsv` containing offered rate, UDP batch size, replies per second, reply
percentage, average DNS reply size, Ethernet reply bit rate, server RX/TX packet
deltas, Linux UDP `InDatagrams`/`OutDatagrams`/`InErrors`/`RcvbufErrors`/
`SndbufErrors` deltas, and aggregate softnet drop and time-squeeze deltas. Each
artifact directory also includes `host/` context files for server CPU topology,
server NIC driver/channel/RSS/offload state, server interrupts/softirqs, and
player host/NIC context.

The wrapper also accepts host-tuning knobs for repeatable packet-loss
experiments:

- `OXIDEDNS_PHYSICAL_WORKER_CPUS="0,2,4,..."` writes
  `limits.udp_worker_cpu_affinity` into each run config. On the current 48-CPU
  25G server, pinning 16 workers to sibling-free even CPUs improved the 3M
  offered-QPS saturation profile from about 2.33M replies/s and 77.6% reply
  rate to about 2.69M replies/s and 89.7% reply rate.
- `OXIDEDNS_PHYSICAL_SOCKET_BUFFER_BYTES=4194304` writes both UDP socket buffer
  settings into each run config. This is host specific: the first 4 MiB test on
  the current server was worse than the default, so retain the setting only when
  the run evidence proves it helps.
- `OXIDEDNS_PHYSICAL_SOCKET_RECEIVE_BUFFER_BYTES=2097152` and
  `OXIDEDNS_PHYSICAL_SOCKET_SEND_BUFFER_BYTES=4194304` override receive and send
  buffers independently. Use these for send-side loss experiments where
  `SndbufErrors` is non-zero but receive counters are clean.
- `OXIDEDNS_PHYSICAL_UDP_BATCH_SIZES="16 32 64"` sweeps
  `[limits].udp_batch_size` in the staged config. The default `staged` value
  preserves the staged directory's existing batch size.
- `OXIDEDNS_PHYSICAL_SERVER_BIN=target/profiling/oxidedns` runs a symbolized
  profiling build instead of the stripped release binary.
- `OXIDEDNS_PHYSICAL_SERVER_PREFIX="numactl --interleave=all"` prefixes both
  validation and serve commands on the server host. This is intended for
  evidence-gated NUMA experiments; leave it unset for baseline comparisons.
- `OXIDEDNS_PHYSICAL_PERF_RECORD=true` captures `perf.data` and retained
  `perf-report-*.txt` files beside the run logs on the server host.

The first retained perf-guided UDP pass showed that the counters-off,
CPU-pinned profile was dominated by standard UDP receive setup and disabled RRL
checks rather than ZoneImage response composition. Reusing stable `recvmmsg`
receive layout and skipping disabled RRL state/category work moved the current
3M offered-QPS profile to about 2.87M replies/s and 95.8% reply rate, with the
3.5M offered-QPS profile reaching about 3.09M replies/s but only 88.3% reply
rate. That is progress on throughput, but packet loss remains above the
comparison gate.

The first send-side packet-loss pass at 4.5M offered QPS showed a clean receive
path and persistent send pressure: 24 workers with pinned CPUs, counters off,
park idle strategy, and 2 MiB receive/send socket buffers reached about 4.45M
replies/s and 98.97% reply rate with zero receive errors and about 231k
`SndbufErrors`. A send-only 4 MiB buffer test was worse, and the first 16/32/64
UDP batch-size sweep did not remove send-buffer errors. Treat send-side socket
pressure as the next measured gate before returning to ZoneImage composition
work.

A follow-up worker-placement sweep showed that unbound 32-36 worker profiles
are currently better than the earlier 24-worker pinned profile at 4.5M offered
QPS. The best observed row was 36 unbound workers with counters off, spin idle,
and 2 MiB receive/send buffers at about 4.46M replies/s and 99.12% reply rate,
but repeat rows varied from about 98.4% to 99.1% and the 4.6M offered-QPS row
fell to about 98.74%. A 40-worker spin profile and the accidental
single-socket/sibling CPU placement were worse. The send-loss gate remains: the
best rows still show Linux UDP `SndbufErrors`, while NIC TX queue drops and
softnet drops are not the dominant signal.

Use `[metrics].hot_path_detail = "reduced"` for observability-preserving runs.
Use `"off"` only for saturation profiling where per-query counters would distort
the transport result; post-run benchmark logs and kernel packet counters remain
available, but DNS query, UDP packet-I/O, ZoneImage serve, rcode, DNS Cookie,
RRL, and per-zone hot-path counters are no longer representative while that
profile is active. `limits.udp_idle_strategy =
"spin"` is only valid with `limits.udp_runtime = "dedicated"` and should remain
an evidence-gated knob because it burns CPU while idle.

Normalize an OxideDNS benchmark artifact:

```bash
scripts/prepare-knot-comparison-benchmark.sh normalize-oxidedns \
  --artifact target/knot-comparison/example/evidence/oxidedns-idle-after-knot-transfer \
  --out target/knot-comparison/example/oxidedns-normalized.tsv
```

Normalize a retained kxdpgun plaintext log:

```bash
scripts/prepare-knot-comparison-benchmark.sh normalize-kxdpgun \
  --log target/knot-comparison/example/kxdpgun-knot.log \
  --duration 15 \
  --out target/knot-comparison/example/knot-normalized.tsv
```

## Metrics

The comparison table uses these fields:

- `qps`: sent queries per second for kxdpgun, received responses per second for
  OxideDNS local harness rows unless an external sender reports offered load.
- `responses_per_second`: answered responses per second.
- `rx_gbps`: received L2 or interface-counter throughput.
- `sum_gbps`: kxdpgun L1 throughput or summed interface-counter throughput.
- `rx_gigabytes_per_second`: GB/s equivalent of received throughput.
- `sum_gigabytes_per_second`: GB/s equivalent of L1 or summed throughput.
- `rx_bytes_per_response`: average received DNS payload or interface-counter
  bytes per response.
- `drops_or_lost`: dropped responses or kxdpgun lost sends.
- `errors`: client/generator socket errors.
- `throughput_scope`: metric provenance.

For physical NIC claims, prefer kxdpgun L1/L2 output plus NIC byte/packet
counters. Loopback `rx+tx` sums are useful only as engineering diagnostics and
must not be described as wire throughput.

## Dedicated Hardware Run Shape

On the server host:

1. Disable SMT for the formal profile, or record that it stayed enabled.
2. Disable connection tracking for the benchmark interface.
3. Disable `irqbalance`.
4. Set NIC combined queues equal to the worker count.
5. Pin NIC IRQs and server workers deliberately.
6. Fix CPU governor and power policy.
7. Record `uname`, NIC driver/firmware, `ethtool -i`, `ethtool -k`,
   `ethtool -l`, `ethtool -S`, `/proc/interrupts`, and `/proc/softirqs`.

On the player host:

1. Install kxdpgun and verify native or zero-copy XDP mode.
2. Use the same `querydb` for Knot and OxideDNS runs.
3. Sweep offered rates rather than reporting one point.
4. Keep the same `-b`, `-F`, source IP range, target port, and duration across
   implementations.

The meaningful result is the saturation knee: the highest offered rate where
response percentage, drops/errors, p99/p999 latency, and byte throughput remain
inside the claimed acceptance envelope.
