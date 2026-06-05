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
`summary.tsv` containing offered rate, kxdpgun batch/mode, OxideDNS UDP batch
size, replies per second, reply percentage, average DNS reply size, Ethernet
reply bit rate, effective server `txqueuelen`, effective per-queue server TX
ring size, effective per-queue server TX qdisc, effective `fq` limit/flow
limit, requested UDP socket pacing rate, effective server `net.core.wmem_max`,
server RX/TX packet deltas, Linux UDP
`InDatagrams`/`OutDatagrams`/`InErrors`/`RcvbufErrors`/`SndbufErrors` deltas,
retained OxideDNS dedicated-worker mmsg counters when hot-path counters are
enabled, root or child qdisc drop and requeue deltas, and aggregate softnet drop
and time-squeeze deltas. Each artifact directory also includes `host/` context
files for server CPU topology, server NIC driver/channel/RSS/offload state,
server link/qdisc state, server interrupts/softirqs, and player host/NIC
context.

The wrapper uses temporary SSH ControlMaster sockets for the server and player
hosts during one invocation. This keeps long physical sweeps from repeatedly
performing SSH key exchange for every setup, finish, and artifact-copy step.
The timed `kxdpgun` step is started as a detached player-host process that
writes `kxdpgun.log`, `status`, and a done marker; the local wrapper polls and
collects those files afterward. A transient SSH disconnect during the timed
window should not kill the benchmark process. The control sockets are closed
during local cleanup.

For long multi-row batches, start the same physical wrapper through the local
detached runner and read the files later:

```sh
OXIDEDNS_PHYSICAL_WORKERS="48" \
OXIDEDNS_PHYSICAL_RATES="4750000 4800000" \
OXIDEDNS_PHYSICAL_UDP_BATCH_SIZES="64" \
OXIDEDNS_PHYSICAL_SERVER_TX_QDISC=fq \
OXIDEDNS_PHYSICAL_SERVER_TX_FQ_LIMIT=50000 \
scripts/physical-udp-detached-batch.sh start
```

The start command prints a local `detached_run_dir`. Check it after reconnecting
with:

```sh
scripts/physical-udp-detached-batch.sh status target/physical-detached-runs/YYYYMMDDTHHMMSSZ
```

Each detached run retains `command.txt`, `environment.txt`, `monitor.log`,
`harness.log`, the fetched `summary.tsv` when the physical harness reaches the
remote artifact, and post-run server/player cleanup checks.

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
- `OXIDEDNS_PHYSICAL_SOCKET_MAX_PACING_RATE_BYTES_PER_SECOND=75000000` writes
  `limits.udp_socket_max_pacing_rate_bytes_per_second` into each run config.
  This requests Linux `SO_MAX_PACING_RATE` per UDP socket, so use it with `fq`
  qdisc rows where aggregate send bursts are the active hypothesis. Retained
  rows record the requested `socket_max_pacing_rate_bytes_per_second`. Use
  `OXIDEDNS_PHYSICAL_SOCKET_MAX_PACING_RATES_BYTES_PER_SECOND="9000000 12000000"`
  to sweep multiple per-socket pacing rates in one retained artifact.
- `OXIDEDNS_PHYSICAL_SERVER_TXQUEUELEN=5000` temporarily sets the server
  interface transmit queue length for the comparison run and restores the
  original value during cleanup. Use it only for retained packet-loss
  experiments where qdisc drops or `SndbufErrors` identify transmit queueing as
  the active gate.
- `OXIDEDNS_PHYSICAL_SERVER_TX_RING=4096` temporarily sets the server NIC TX
  ring size with `ethtool -G` and restores the original TX ring during cleanup.
  Use it only for retained rows where send-side loss occurs after `sendmmsg`
  acceptance; retained rows record the effective `server_tx_ring`.
- `OXIDEDNS_PHYSICAL_SERVER_TX_QDISC=fq` temporarily replaces each existing
  per-queue child qdisc on the server interface and restores the original child
  qdisc kinds during cleanup. The current wrapper accepts `fq`, `fq_codel`, and
  `pfifo_fast`; use it only for send-side queueing experiments where the
  retained qdisc before/after files prove the host state was restored.
- `OXIDEDNS_PHYSICAL_SERVER_TX_FQ_LIMIT=50000` sets the aggregate `fq limit`
  when `OXIDEDNS_PHYSICAL_SERVER_TX_QDISC=fq` is active. The default is
  `10000`, matching the previously retained `fq` rows. Retained rows record the
  effective `server_tx_fq_limit`.
- `OXIDEDNS_PHYSICAL_SERVER_TX_FQ_FLOW_LIMIT=1000` sets `fq flow_limit` when
  `OXIDEDNS_PHYSICAL_SERVER_TX_QDISC=fq` is active. Retained rows record the
  effective `server_tx_fq_flow_limit`. Leave it unset for baseline rows unless
  child `fq` drops or `flows_plimit` counters are the active hypothesis.
- `OXIDEDNS_PHYSICAL_SERVER_WMEM_MAX=33554432` temporarily raises the server
  `net.core.wmem_max` sysctl and restores the original value during cleanup.
  Use it with a matching `OXIDEDNS_PHYSICAL_SOCKET_SEND_BUFFER_BYTES` value when
  proving send-buffer headroom; retained rows record the effective
  `server_wmem_max`.
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
  `OXIDEDNS_PHYSICAL_PERF_REPORT_TIMEOUT=30s` bounds each retained
  `perf report` pass so slow callgraph expansion cannot stall cleanup.
  `OXIDEDNS_PHYSICAL_PERF_REPORT_CHILDREN=false` skips the children report when
  the symbol report is sufficient for a sweep.
- `OXIDEDNS_PHYSICAL_SOCKET_SAMPLE=true` captures repeated
  `ss -u -n -m` samples for the OxideDNS UDP service port during the kxdpgun
  window. Use this when `SndbufErrors` is the active gate and per-socket queue
  state is needed; `OXIDEDNS_PHYSICAL_SOCKET_SAMPLE_INTERVAL=0.25` controls the
  sample interval in seconds.
- `OXIDEDNS_PHYSICAL_INCLUDE_KNOT=true` adds a Knot reference row for each
  offered rate before the OxideDNS sweeps. The Knot row uses the same staged
  `querydb`, target IP, kxdpgun batch/mode/source settings, and kernel packet
  counters as the OxideDNS rows.

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

A retained 4.5M offered-QPS run with `txqueuelen=5000` measured Knot at about
4.42M replies/s and 98.35% reply rate, while OxideDNS with 36 unbound workers,
batch size 8, counters off, spin idle, and 2 MiB receive/send buffers measured
about 4.47M replies/s and 99.40% reply rate. Manual repeats with the same
OxideDNS profile reached about 99.7% reply rate, so the transmit queue length
is the first clearly positive packet-loss gate fix on the 25G comparison host.
The same profile at 4.6M offered QPS remained below 99%, and 4.75M collapsed,
so this is not yet evidence for a higher saturation target.

The next server qdisc pass found that increasing the NIC TX ring from 1024 to
4096 was negative: the default-queue row stayed near 98.7%, and combining the
larger TX ring with `txqueuelen=5000` fell below the earlier queue-length-only
result. Replacing each per-queue `pfifo_fast` child qdisc with `fq limit 10000`
was positive in a controlled pair: `fq` reached about 4.48M replies/s and
99.65% reply rate at default `txqueuelen=1000`, while the restored
`pfifo_fast` control row returned to about 4.44M replies/s and 98.65% reply
rate. A follow-up same-artifact run with `OXIDEDNS_PHYSICAL_SERVER_TX_QDISC=fq`
measured Knot at about 4.35M replies/s and 96.80% reply rate, while OxideDNS
measured about 4.49M replies/s and 99.86% reply rate; cleanup restored the
server interface to `pfifo_fast:48` and `txqueuelen=1000`. Two additional
OxideDNS-only `fq` repeats measured about 99.60% and 99.84% reply rate. Combining
`fq` with `txqueuelen=5000` still beat Knot in the same artifact, but the
OxideDNS row fell to about 99.73%, below the best `fq`-only row, so prefer
`fq` alone for the next repeated comparison pass. Treat `fq` as a strong
evidence-gated candidate, but repeat the row before making a final
hardware-profile claim. The first higher-rate `fq` sweep moved the previous
ceiling upward but did not remove the saturation cliff: 4.6M and 4.65M offered
QPS stayed above 99% reply rate, while 4.7M fell to about 98.2% and 4.75M fell
to about 96.5%, with receive-buffer errors and `SndbufErrors` rising together.
A small worker sweep at 4.7M showed that 40 workers was better than 32 or 36
under `fq`, reaching about 99.0% reply rate, but 40 workers still fell below
99% at 4.75M and collapsed by 4.8M. Treat 40 workers as the next 4.7M candidate
and keep 36 workers for the more stable 4.5M comparison point until repeated
rows prove otherwise. Follow-up socket-buffer rows under the 40-worker `fq`
profile did not remove the 4.7M/4.75M gate: increasing only the receive buffer
to 4 MiB made the 4.7M row worse at about 97.5% reply rate, while increasing
only the send buffer to 4 MiB was roughly neutral at 4.7M and improved 4.75M
only to about 98.4%. A 40-worker `fq` batch-size sweep at 4.7M favored batch
16 over batch 4 and 8, reaching about 99.33% reply rate with lower receive and
send error counts than the batch-8 row in the same artifact. The same batch-16
profile still fell below 98% at 4.75M, so it improves the 4.7M comparison point
without removing the next saturation boundary. A same-artifact 4.7M comparison
with Knot under `fq` measured Knot at about 94.82% reply rate and OxideDNS at
about 99.29% reply rate. A follow-up 40/44/48 worker sweep at 4.7M and batch
16 was noisy: 44 workers won that artifact at about 99.14%, while 40 and 48
were below 99%. The 44-worker profile still missed the gate at 4.75M, measuring
about 98.26%, so the higher-rate boundary remains unresolved.

At 4.75M under `fq`, increasing the server UDP batch size helped more than
additional workers: 48 workers with batch 32 reached about 98.66%, batch 64
reached about 98.96% in the first row, and batch 128 regressed to about 98.57%.
The same-artifact Knot comparison at 4.75M with the 48-worker batch-64 profile
measured Knot at about 92.21% reply rate and OxideDNS at about 98.72%, so
OxideDNS stayed clearly ahead but still below the packet-loss gate. Batch 64
did not carry 4.8M, which fell to about 95.54%, and combining batch 64 with
`txqueuelen=5000` was worse than `fq` alone at about 98.31%.
Socket sampling at the 4.75M batch-64 `fq` edge did not show sustained
per-socket queue buildup: sampled OxideDNS sockets stayed at zero receive/send
queue and zero `skmem` write/drop occupancy while the row still accumulated
about 2.77M `SndbufErrors`. Treat the send loss as transient burst or pacing
pressure, not a stable queue that remains visible between 100ms samples.
Raising the server send-buffer ceiling was the first host knob to materially
reduce the edge loss. The default server `net.core.wmem_max=4194304` capped the
2 MiB requested send buffer at `skmem` `tb4194304`; with
`net.core.wmem_max=16777216` and an 8 MiB requested send buffer, socket samples
confirmed `tb16777216`, receive errors dropped to zero, and one 4.75M row
reached about 99.02% reply rate with about 231k `SndbufErrors`. Unsampled
repeats were still below the gate at about 97.92% and 97.52%, but retained the
lower send-error profile. With `net.core.wmem_max=33554432` and a 16 MiB
requested send buffer, a 48-worker repeat reached about 99.04% with only 156
receive errors and about 228k `SndbufErrors`; 40 and 44 workers were worse, and
4.8M still fell to about 90.96%. A committed-harness same-artifact comparison
with `server_wmem_max=33554432` measured Knot at about 92.06% and OxideDNS at
about 95.90%, so OxideDNS still led Knot but did not stably clear the
packet-loss gate. Raising the ceiling again to `server_wmem_max=67108864` with
a 32 MiB requested send buffer produced two 4.75M rows at about 98.47% and
99.22% reply rate with zero receive errors and about 362k/185k `SndbufErrors`.
That setting improved the 4.8M row to about 95.16%, but still left about 1.16M
`SndbufErrors`. Treat larger `wmem_max` plus send buffer as the current
strongest 4.75M follow-up, not as proof that the next saturation boundary is
solved.
Inspecting child `fq` qdisc stats showed that `SndbufErrors` at this edge track
qdisc drops closely. With the summary parser updated to include child qdisc
drops, raising `fq flow_limit` from the default 100 to 1000 still left about
699k/216k qdisc drops in two 4.75M rows, with reply rates about 97.05% and
99.05%. Raising `flow_limit` to 10000 was worse at about 98.16% and 97.83%,
with about 433k/942k qdisc drops. Increasing the aggregate `fq limit` from
10000 to 50000 was more useful: 4.75M rows reached about 98.42% and 99.37%,
and a 4.8M row reached about 98.12% with zero receive errors and about 445k
qdisc/send-buffer drops. A same-artifact 4.8M comparison with the same tuning
measured Knot at about 91.34% and OxideDNS at about 97.83%, so OxideDNS widened
the comparison lead but still missed the packet-loss gate. Raising `fq limit`
to 200000 was worse at about 97.33% with about 629k drops. Treat `fq limit`
50000 as a useful qdisc-depth candidate, but not a stable pass: a detached
10-second, three-repeat 4.8M batch retained at
`physical-udp-knot-comparison-20260605T191048Z` measured only about 96.45%,
97.42%, and 97.87% reply rate. The same rows restored host state afterward, but
still accumulated about 1.69M/1.15M/1.02M qdisc-send-buffer drops and occasional
receive errors. Keep the default `fq` flow-limit unless a more targeted
pacing/queueing design is measured.
Reducing worker concurrency at the same 4.8M/`fq limit=50000`/32 MiB send-buffer
profile also did not solve the boundary. A retained 36/40/44/48 worker sweep at
`physical-udp-knot-comparison-20260605T191333Z` measured about 93.91%, 96.39%,
97.11%, and 98.48% reply rate respectively. The lower-worker rows reduced some
send-buffer drops but traded them for much larger receive errors, while the
48-worker row still had about 359k `SndbufErrors` and remained below the
packet-loss gate.
Static UDP batch-size tuning around 64 also did not clear the 4.8M boundary.
With the same 48-worker/`fq limit=50000`/32 MiB send-buffer profile, the
retained `physical-udp-knot-comparison-20260605T191533Z` sweep measured batch
48 at about 97.08%, batch 56 at about 98.44%, batch 64 at about 98.86%, and
batch 80 at about 97.06% reply rate. Keep batch 64 as the best static setting
until an adaptive pacing or backpressure change is measured.
Linux `SO_MAX_PACING_RATE` socket pacing is now configurable, but the first
retained pacing sweep was also negative. At the same 48-worker/4.8M/batch-64/
`fq limit=50000` profile, `physical-udp-knot-comparison-20260605T192656Z`
measured per-socket pacing rates 8M/9M/10M/11M/12M bytes/s at about 96.44%,
97.60%, 97.30%, 97.08%, and 97.25% reply rate respectively. The best paced row
was below the unpaced short batch-64 row, so keep the pacing knob for future
host experiments but do not treat fixed socket pacing as the current fix.
A reduced-metrics diagnostic row at
`physical-udp-knot-comparison-20260605T193038Z` confirmed that the dedicated
worker `sendmmsg` path was not seeing direct syscall backpressure: it retained
543778 send syscalls, 22435263 accepted datagrams, zero partial send syscalls,
and zero WouldBlock retries. That row was not a comparable performance
candidate because reduced counters shifted the 4.8M profile down to about
93.45% with about 1.45M receive-buffer errors. Treat this as evidence that the
send-side loss in hot-path-off rows is happening after syscall acceptance in the
kernel/qdisc/NIC path, not as a retry-loop failure in user space.
Increasing the NIC TX ring at the same 48-worker/4.8M/batch-64/`fq
limit=50000` profile was negative. Retained rows at
`physical-udp-knot-comparison-20260605T193659Z` and
`physical-udp-knot-comparison-20260605T193803Z` measured TX rings 4096 and 8192
at about 96.86% and 95.65% reply rate respectively. Larger rings reduced
qdisc/`SndbufErrors` to about 194k and 88k, but receive-buffer errors rose to
about 144k and 372k and softnet `time_squeeze` rose to 403 and 618. Cleanup
restored the server interface to TX ring 1024. Keep the default TX ring for the
current 4.8M profile unless a separate interrupt/queue-affinity change makes a
larger ring useful.
Changing the kxdpgun sender batch also did not remove the boundary. With the
summary now retaining kxdpgun batch/mode, batch 1 fell to about 93.95% reply
rate, batch 5 to about 97.11%, and batch 20 to about 97.88% at the same
4.75M/48-worker/OxideDNS-batch-64/`fq` profile. Keep the default kxdpgun batch
10 for retained comparison rows unless a new player-side hypothesis is being
tested.
Splitting receive and send batch shape inside the standard UDP backend was also
negative. Keeping `recvmmsg` at batch 64 while capping each `sendmmsg` call at
32 packets produced about 98.21% and 97.39% reply rate in two 4.75M `fq` rows,
with `SndbufErrors` still in the 3.0M-3.4M range. Keep the single batch-64
receive/send path until a stronger pacing design is measured.
Changing the standard UDP `sendmmsg` `WouldBlock` retry constant was not a
useful code fix for this boundary: reducing retries from 256 to 64 nearly
eliminated receive errors but dropped the 4.75M batch-64 `fq` row to about
97.46%, while increasing retries to 512 stayed near 98.91% and did not clearly
beat the original constant. Keep the current retry policy until a stronger
send/receive pacing change is measured.
Removing the per-query `Arc<ZoneStoreEntry>` clone/drop from the borrowed
published-zone lookup also did not improve the primary 4.75M batch-64 `fq`
gate. The retained perf profile showed the refcount path as visible CPU work,
but three unprofiled edge rows with the borrowed lookup measured about 97.63%,
98.84%, and 98.39% reply rate. Treat that ownership cleanup as neutral for the
current transport-loss boundary rather than a retained performance fix.
Server NIC feature and coalescing experiments were also negative at the same
profile. Disabling generic receive offload fell to about 98.35%. Disabling
adaptive coalescing and forcing `rx-usecs=0`, `tx-usecs=0`, and one frame
collapsed the row to about 74%, while a higher fixed coalescing profile
(`rx-usecs=16`, `tx-usecs=16`, 256 frames) fell to about 96.57%. Keep the
current server NIC adaptive coalescing and GRO settings for this profile.
Full 48-worker CPU pinning to CPUs `0..47` was also worse than unbound
scheduling for the 4.75M batch-64 `fq` profile, measuring about 98.04% reply
rate. Keep worker CPU affinity unset for this profile unless a new IRQ/RSS-aware
placement is measured.
A topology-guided NIC-local placement was also negative. The server NIC reports
NUMA node 0 and local CPUs `0,2,4,...,46`, while its 48 completion queues are
spread across both sockets. Pinning 24 workers to those NIC-local even CPUs at
the 4.75M batch-64 `fq` edge collapsed to about 73.85% reply rate with about
6.21M receive-buffer errors and no send-buffer errors. That profile starves
receive capacity before the send-side gate, so cross-socket/unbound scheduling
remains the retained baseline.

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
