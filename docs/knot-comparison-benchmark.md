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
load-client path is useful for local and preflight evidence. The physical
wrapper can also run the project-owned `oxide-gun` requester for AF_XDP
diagnostic and promotion-adjacent rows; keep kxdpgun rows in retained promotion
sweeps until repeated `oxide-gun` runs cover the same rate range and host roles.

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
`summary.tsv` containing offered rate, player tool, kxdpgun batch/mode, OxideDNS
UDP batch size, replies per second, reply percentage, average DNS reply size,
Ethernet reply bit rate, effective server `txqueuelen`, effective per-queue
server TX ring size, effective per-queue server TX qdisc, effective `fq`
limit/flow limit, requested UDP socket pacing rate, effective server
`net.core.rmem_max` and `net.core.wmem_max`, server RX/TX packet deltas, Linux UDP
`InDatagrams`/`OutDatagrams`/`InErrors`/`RcvbufErrors`/`SndbufErrors` deltas,
retained OxideDNS dedicated-worker mmsg counters when hot-path counters are
enabled, including successful and empty nonblocking `recvmmsg` calls, root or
child qdisc drop and requeue deltas, child `fq` `flows_plimit` deltas when
present, and aggregate softnet drop and time-squeeze deltas. Each artifact
directory also includes `host/` context files for server
CPU topology, server NIC driver/channel/RSS/offload state, server link/qdisc
state, server IRQ affinity, RPS/XPS queue steering, interrupt coalescing,
server interrupts/softirqs, and player host/NIC context.
AF_XDP server rows also retain aggregate packet-I/O counters in `summary.tsv`
when hot-path counters are enabled: RX ring recv calls, empty RX calls, packets
returned by RX, parser drops, TX ring send calls, queued packets, zero-packet TX
send calls, TX wakeups, `poll_write` calls/readiness, completion dequeues, and
completed packets. These counters are intentionally suppressed by
`[metrics].hot_path_detail = "off"` so candidate saturation rows keep the
lowest-overhead profile.

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
- `OXIDEDNS_PHYSICAL_SERVER_TX_FQ_QUANTUM=1514` and
  `OXIDEDNS_PHYSICAL_SERVER_TX_FQ_INITIAL_QUANTUM=1514` pass `quantum` and
  `initial_quantum` to each child `fq` qdisc. The retained
  `server-link-tuning.txt` and `server-tx-qdisc-after.txt` files record the
  requested and effective qdisc state. Use these only for qdisc burst-shaping
  experiments after `fq limit` and `flow_limit` rows identify child qdisc drops
  as the active gate.
- `OXIDEDNS_PHYSICAL_SERVER_TX_FQ_PACING=nopacing` appends `nopacing` to each
  child `fq` qdisc, while `pacing` explicitly requests the default pacing mode.
  Use this to distinguish `fq` flow isolation from the scheduler's
  non-work-conserving pacing behavior; retained rows record the requested value
  in `server-link-tuning.txt` and the effective qdisc state in
  `server-tx-qdisc-after.txt`.
- `OXIDEDNS_PHYSICAL_SERVER_WMEM_MAX=33554432` temporarily raises the server
  `net.core.wmem_max` sysctl and restores the original value during cleanup.
  Use it with a matching `OXIDEDNS_PHYSICAL_SOCKET_SEND_BUFFER_BYTES` value when
  proving send-buffer headroom; retained rows record the effective
  `server_wmem_max`.
- `OXIDEDNS_PHYSICAL_SERVER_RMEM_MAX=16777216` temporarily raises the server
  `net.core.rmem_max` sysctl and restores the original value during cleanup.
  Use it with a matching `OXIDEDNS_PHYSICAL_SOCKET_RECEIVE_BUFFER_BYTES` value
  when rows shift from qdisc/`SndbufErrors` into Linux UDP `RcvbufErrors`;
  retained rows record the effective `server_rmem_max`.
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
- `OXIDEDNS_PHYSICAL_INCLUDE_KNOT_XDP=true` adds a Knot XDP reference row for
  each offered rate. The harness copies the staged `knot.conf`, appends an
  `xdp:` section for the benchmark interface/port, and starts Knot through
  `sudo` because XDP attach normally requires elevated capabilities.
  `OXIDEDNS_PHYSICAL_KNOT_BIN=/path/to/knotd` selects a source-built Knot
  binary without replacing the packaged system daemon.
- `OXIDEDNS_PHYSICAL_OXIDEDNS_UDP_BACKENDS="std af_xdp"` selects which OxideDNS
  packet backends to sweep. `std` preserves the existing standard UDP matrix.
  `af_xdp` forces the valid AF_XDP config shape: Tokio runtime,
  `udp_idle_strategy = "park"`, the configured XDP interface, ring/UMEM sizes,
  and the project-built redirect object. In AF_XDP mode,
  `OXIDEDNS_PHYSICAL_WORKERS` maps to contiguous XDP queue workers starting at
  `OXIDEDNS_PHYSICAL_XDP_QUEUE_ID`; it is not a SO_REUSEPORT worker count.
- XDP rows are controlled with `OXIDEDNS_PHYSICAL_XDP_MODE=drv`,
  `OXIDEDNS_PHYSICAL_XDP_ZERO_COPY=require`,
  `OXIDEDNS_PHYSICAL_XDP_QUEUE_ID=0`, `OXIDEDNS_PHYSICAL_XDP_RING_SIZE=4096`,
  `OXIDEDNS_PHYSICAL_XDP_UMEM_FRAME_COUNT=16384`,
  `OXIDEDNS_PHYSICAL_XDP_BATCH_SIZE=1024`,
  `OXIDEDNS_PHYSICAL_XDP_RX_DRAIN_PASSES=1`,
  `OXIDEDNS_PHYSICAL_XDP_TX_WAKEUP_INTERVAL=8`, and optionally
  `OXIDEDNS_PHYSICAL_XDP_REDIRECT_OBJECT` when the object is not under the
  server checkout. AF_XDP rows are started through `sudo` and set
  `process.run_as_user` to `OXIDEDNS_PHYSICAL_XDP_RUN_AS_USER=codex` by default
  so the process does not continue serving as root. Use
  `OXIDEDNS_PHYSICAL_XDP_MTU=1500` when the benchmark NIC is configured with a
  jumbo MTU that the native XDP driver rejects. The harness restores the
  original MTU during cleanup. Knot XDP omits the `zero-copy` config item by
  default (`OXIDEDNS_PHYSICAL_KNOT_XDP_ZERO_COPY=__omit__`) and uses
  `OXIDEDNS_PHYSICAL_KNOT_XDP_RING_SIZE=2048`. The generated Knot XDP config
  drops privileges to `OXIDEDNS_PHYSICAL_KNOT_XDP_RUN_AS_USER=codex:codex` so
  it can read and write the staged benchmark artifacts after the privileged XDP
  attach.
  The summary rows retain `server_udp_backend`, `xdp_mode`, `xdp_zero_copy`,
  `xdp_rx_drain_passes`, `xdp_tx_wakeup_interval`, and
  `oxide_gun_response_timeout_ms` so standard, Knot-XDP, OxideDNS-AF_XDP, and
  requester-drain timeout rows cannot be confused.
- The requester-side XDP mode is controlled with
  `OXIDEDNS_PHYSICAL_KXDPGUN_MODE=generic|copy|auto`. Use
  `OXIDEDNS_PHYSICAL_KXDPGUN_MTU=1500` when trying `auto` on a jumbo-MTU NIC;
  the harness detaches stale requester XDP programs, records the original and
  effective requester MTU in `host/player-link-tuning.txt`, and restores the
  original requester MTU during cleanup.
- `OXIDEDNS_PHYSICAL_COMPARISON_RUN_ORDER=knot-first|oxidedns-first` controls
  whether Knot reference rows run before or after OxideDNS rows in the same
  artifact. The default `knot-first` preserves the original comparison flow;
  use `oxidedns-first` to check for XDP attach/detach or NIC-state order
  effects.
- `OXIDEDNS_PHYSICAL_PLAYER_TOOL=kxdpgun|oxide-gun` selects the requester. The
  default remains `kxdpgun` for promotion rows. `oxide-gun` runs the
  project-owned AF_XDP requester with the staged `querydb` as `--query-list`,
  `OXIDEDNS_PHYSICAL_OXIDE_GUN_BIN` or the default
  `$player_workdir/xdp-template-slice/oxide-gun`, and
  `OXIDEDNS_PHYSICAL_OXIDE_GUN_XDP_REDIRECT_OBJECT` or the default
  `$player_workdir/xdp-template-slice/oxide-gun-xdp.bpf.o`. The dedicated-host
  defaults use `OXIDEDNS_PHYSICAL_OXIDE_GUN_QUEUE_COUNT=__auto__`, which
  detects the requester interface RX queue count so forward and reversed host
  roles do not reuse the wrong 63-queue assumption. The default source MAC is
  `b8:59:9f:4b:73:2c`, target MAC is `1c:34:da:60:67:00`, XDP copy mode is
  used, one source port is auto-assigned per queue starting at 53000, and
  summary parsing comes from the JSON `summary` record. The effective requester
  queue count is retained in `host/player-link-tuning.txt`.
  `OXIDEDNS_PHYSICAL_OXIDE_GUN_SOURCE_PORT_LIST=port,port,...` passes an
  explicit per-worker source-port list to `oxide-gun`; use it after queue
  calibration when contiguous source ports do not hash back to their owning
  AF_XDP RX queues. RSS includes the UDP destination port on the dedicated
  hosts, so source-port lists should be calibrated per server target port:
  `OXIDEDNS_PHYSICAL_OXIDE_GUN_KNOT_SOURCE_PORT_LIST=...` for Knot rows and
  `OXIDEDNS_PHYSICAL_OXIDE_GUN_OXIDEDNS_SOURCE_PORT_LIST=...` for OxideDNS
  rows. After a reduced AF_XDP calibration row, run
  `scripts/select-oxide-gun-source-ports.py <row-artifact> --existing-list ...`
  on the row that contains `metrics-after.prom` and the oxide-gun
  `kxdpgun.log` JSON summary. The helper selects a source-port list that keeps
  one reply stream per requester RX queue while also balancing requests across
  server AF_XDP workers. For Knot rows, where no OxideDNS server-worker metric
  exists, use `--requester-only` against a low-rate Knot-XDP calibration row to
  select one source port per requester RX queue for that target port.
  `OXIDEDNS_PHYSICAL_OXIDE_GUN_RESPONSE_TIMEOUT_MS=1000` controls the final
  reply-drain timeout after the offered send window; raising it is useful when
  separating late requester RX drain from true packet loss.

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
receive errors, leaving per-flow queueing as the next measured target.
Adding `flows_plimit` to the summary confirmed that the remaining child `fq`
drops at this boundary are mostly per-flow-limit drops rather than requeues or
scheduler throttling. Raising `fq flow_limit` to 500 under the same 48-worker/
4.8M/batch-64/`fq limit=50000`/32 MiB send-buffer profile produced the first
strong 4.8M row: `physical-udp-knot-comparison-20260605T204230Z` measured about
99.70% reply rate, with about 55k qdisc/`SndbufErrors`, only 63 receive-buffer
errors, and about 9k `flows_plimit` drops. A same-tuning comparison artifact at
`physical-udp-knot-comparison-20260605T204346Z` still had OxideDNS ahead of
Knot, about 98.65% versus 90.32%, but OxideDNS missed the packet-loss gate as
loss shifted into about 129k receive-buffer errors.
Raising the receive-buffer ceiling then reduced that shifted receive loss. With
`net.core.rmem_max=16777216`, an 8 MiB requested receive buffer, the same 32 MiB
send buffer, and `fq flow_limit=500`, `physical-udp-knot-comparison-20260605T204624Z`
measured about 99.50% reply rate at 4.8M. A three-row OxideDNS-only repeat at
`physical-udp-knot-comparison-20260605T204808Z` measured about 99.87%, 99.96%,
and 99.97%, with qdisc drops down to about 4k/6k/7k and low receive loss. Treat
the combined `fq limit=50000`, `flow_limit=500`, 16 MiB receive ceiling, and
64 MiB send ceiling profile as the current retained 4.8M candidate. The clean
same-artifact comparison at `physical-udp-knot-comparison-20260605T205029Z`
then measured Knot at about 88.35% reply rate and OxideDNS at about 99.96%,
with OxideDNS qdisc drops down to about 1.5k, receive-buffer errors about 7.5k,
and `flows_plimit` about 1.5k. A previous same-tuning comparison at
`physical-udp-knot-comparison-20260605T204713Z` was noisy, with both rows far
below their normal reply rates, so retain `205029Z` as the passing comparison
artifact.
A role-reversed validation pass shows that the passing forward-role profile is
not yet portable across the two dedicated hosts. For this pass `oxidegun-1`
served `198.18.0.2` and `oxidedns-1` generated traffic from `198.18.0.1`; Knot
was installed and disabled on `oxidegun-1`, the staged zone and query database
were mirrored to the opposite hosts, a stale generic XDP program was detached,
and the server NIC's zero-handle `mq` root was normalized to a replaceable
`mq 8001:` root with `pfifo_fast` children. With the retained forward tuning
at 48 workers and 4.8M offered QPS,
`physical-udp-knot-comparison-20260605T211343Z` measured Knot at about 97.41%
reply rate but OxideDNS at only about 51.22%, with about 9.54M
`RcvbufErrors`, no send-buffer errors, and no qdisc drops. This makes the
reversed loss a receive/CPU path problem rather than the previous forward-role
qdisc/send-buffer gate.
The follow-up reversed tuning did not recover the 4.8M packet-loss gate.
`physical-udp-knot-comparison-20260605T211502Z` found 72 workers best among
56/63/64/72, at about 89.37% reply rate. Raising the receive-buffer ceiling to
64 MiB at `20260605T211616Z` was worse at about 61.02%, batch 128 in
`20260605T211704Z` reached only about 87.69%, and all-CPU pinning in
`20260605T211826Z` reached about 88.94%. A rate sweep at
`physical-udp-knot-comparison-20260605T211910Z` with 72 workers passed 4.0M and
4.25M at about 99.998% reply rate, then fell to about 92.38% at 4.5M and
58.83% at 4.75M. The bracket artifact `20260605T212028Z` confirmed the cliff:
4.35M measured about 96.58% and 4.40M about 71.19%. Treat 4.25M as the current
role-reversed OxideDNS ceiling on `oxidegun-1`; reaching 4.8M on both host
directions likely needs receive-loop, queue/IRQ-affinity, or AF_XDP/XDP work
rather than more retained send-buffer/qdisc tuning.
The retained reverse-role IRQ/RSS/queue-affinity slice then ruled out several
host-only fixes for the 4.8M goal. The live baseline on `oxidegun-1` had 63
combined queues, UDP RSS hashing over source/destination IP and UDP ports,
completion IRQs for `0000:19:00.0` spread over CPUs
`0,2,...,70,1,3,...,53`, RPS disabled on all RX queues, and per-queue XPS
already set. Pinning 72 workers in that IRQ CPU order at
`physical-udp-knot-comparison-20260605T214542Z` still missed the gate, with
about 91.03% at 4.35M, 95.45% at 4.40M, 75.38% at 4.50M, and 90.71% at 4.8M.
Using exactly 63 workers pinned to the 63 completion-IRQ CPUs at
`20260605T214657Z` was worse: about 98.99% at 4.25M, 86.21% at 4.35M, 92.32%
at 4.50M, and 81.37% at 4.8M. A temporary 4096-entry RX ring at
`20260605T214824Z` produced one near-pass 4.50M row at about 98.80%, but it
regressed 4.25M/4.35M and still reached only about 88.85% at 4.8M. Reducing RX
interrupt coalescing to `adaptive-rx off rx-usecs 0 rx-frames 1` at
`20260605T214943Z` was not useful: it removed receive-buffer errors by reducing
effective received traffic to roughly 15.8M packets per 5-second row, leaving
reply rates around 77-79%. Enabling RPS across CPUs 0-71 at
`20260605T215114Z` also failed, adding softnet drops/time-squeeze and falling
from about 89.28% at 4.25M to about 67.17% at 4.8M. Restore RPS disabled, RX
ring 1024, and adaptive RX coalescing as the reverse-role baseline; the next
reverse-role work should be application receive-loop/AF_XDP evidence rather
than more IRQ/RSS/RPS/XPS placement.
A reverse-role receive-path profiling slice confirmed that the remaining
standard UDP cliff is not a simple worker-placement issue. Perf rows at
`physical-udp-knot-comparison-20260605T221215Z` and
`physical-udp-knot-comparison-20260605T221553Z` were too perturbing to use as
candidate performance numbers, but their symbol mix was dominated by syscall
return, `recvmmsg`, kernel UDP enqueue/receive, and send-side kernel work rather
than ZoneImage response construction. The reduced-counter rows also showed only
about three received datagrams per successful `recvmmsg` call, but reduced
counters themselves depressed reply rate.
Adding a retained empty-`recvmmsg` counter and expanding per-worker packet-I/O
slots to cover the 72-worker physical profile made the receive loop shape clear.
With a local metrics build at `physical-udp-knot-comparison-20260605T222216Z`,
the 72-worker, 4.35M, reduced-counter row recorded all 72 workers active and
balanced within about 6.3% max/mean, but also recorded about 5.73M successful
receive syscalls and about 103.8M empty nonblocking receive polls in a 5-second
window. That identifies spin-idle empty polling as a large CPU consumer, not
reuseport imbalance. However replacing spin with the existing park strategy was
negative at `physical-udp-knot-comparison-20260605T222310Z`, and a temporary
local yield-after-short-spin experiment at `physical-udp-knot-comparison-20260605T222548Z`
was also negative. Keep the new counters for the next physical run, but do not
treat idle sleeping/yielding as the reverse-role fix; the next substantial
receive-path step should be a different packet-I/O design, most likely AF_XDP,
unless a more targeted nonblocking poll/backoff design can be proven without
losing responsiveness.
The first reverse-role `oxide-gun` requester pass exposed two harness/profile
issues before it produced comparable AF_XDP evidence. With the forward
requester default of 63 queues, `physical-udp-knot-comparison-20260606T022927Z`
failed on `oxidedns-1` because AF_XDP queue 48 did not exist. With the
requester capped to 48 queues but the reverse server still capped to 48
workers, `physical-udp-knot-comparison-20260606T023020Z` showed an artificial
75% OxideDNS AF_XDP reply ceiling because `oxidegun-1` has 63 RX queues and the
unbound server queues were still reachable by RSS. Matching the reverse server
to 63 workers removed that ceiling:
`physical-udp-knot-comparison-20260606T023338Z` measured Knot XDP at 1187197
replies/s and 100.000000%, while OxideDNS AF_XDP measured 1185281 replies/s and
99.942922% at requested 1.2M. Reducing the AF_XDP server batch to 512 and using
`xdp.tx_wakeup_interval = 1` fixed the low-rate loss gate:
`physical-udp-knot-comparison-20260606T023606Z` measured 1186135 replies/s at
100.000000%, and the auto-queue proof row
`physical-udp-knot-comparison-20260606T024404Z` retained
`oxide_gun_effective_queue_count=48`.
The same reverse profile is still not a clean retained-QPS win at higher rates.
At requested 1.5M, `physical-udp-knot-comparison-20260606T023643Z` measured
Knot XDP at 1478476 replies/s and 99.992577%, while OxideDNS AF_XDP measured
1476928 replies/s and 100.000000%. At requested 2.0M,
`physical-udp-knot-comparison-20260606T023745Z` measured Knot XDP at 1966958
replies/s and 99.878854%, while OxideDNS AF_XDP measured 1965472 replies/s and
99.991203%. At requested 2.5M,
`physical-udp-knot-comparison-20260606T023846Z` was effectively tied but still
favored Knot on both retained QPS and reply percentage. Treat the current
reverse AF_XDP profile as stronger than the old standard-UDP reverse path, but
not yet sufficient for the full "better than Knot XDP in both roles" gate.
The first reduced-metrics AF_XDP diagnostic row,
`physical-udp-knot-comparison-20260606T025324Z`, showed that the reverse 2.5M
loss is not caused by zero-descriptor server TX sends or server TX wakeup waits:
the row recorded 7407616 AF_XDP packets received by the server, 7407616 queued
to TX, zero parser drops, zero empty TX sends, zero `poll_write` calls, and
7407330 completion packets observed by metrics scrape time. The requester sent
7408640 queries and received 7406592 replies, so the retained loss was roughly
one batch before server RX plus one batch after server TX rather than a large
server-side ring stall. Follow-up saturation rows with intermediate batch sizes
did not recover a retained-QPS win: `physical-udp-knot-comparison-20260606T025426Z`
with batch 192 measured 2452906 replies/s at 99.990927%, and
`physical-udp-knot-comparison-20260606T025459Z` with batch 224 measured 2449503
replies/s at 99.977184%. The next server-side work should use the new counters
to separate requester ingress, server egress completion timing, and AF_XDP
batch latency rather than continue blind IRQ/RSS or MTU tuning.
A later requester-drain probe kept both reverse-role NICs at effective MTU 1500
during native XDP and restored them to 9000 after cleanup, which makes MTU an
unlikely explanation for the remaining small loss tail. With
`OXIDEDNS_PHYSICAL_OXIDE_GUN_RESPONSE_TIMEOUT_MS=3000`,
`physical-udp-knot-comparison-20260606T030335Z` measured OxideDNS AF_XDP at
2454002 replies/s and 99.995237% at requested 2.5M, leaving 353 unanswered
queries out of 7410688. Extending the same timeout to 5000 ms in
`physical-udp-knot-comparison-20260606T030430Z` regressed to 2452074 replies/s
and 99.977453%, so the remaining issue is not a simple final-drain timeout
setting; keep investigating requester RX distribution or AF_XDP queue service
variance.
To make that visible, the project-owned requester summary now includes a
`queue_stats` array for multi-queue XDP runs. The first high-rate diagnostic
with that field, `physical-udp-knot-comparison-20260606T031149Z`, measured
7398982 replies from 7406592 sent queries at requested 2.5M, and showed the
requester RX imbalance directly: several queues received zero replies while
others received about twice their own sent-query count. A rejected follow-up
experiment that tried to redirect replies to the source-port owner queue
returned zero replies, consistent with AF_XDP XSKMAP requiring the target XSK
to match the packet's hardware RX queue. Treat the next requester work as
RSS/source-port steering or queue-service balancing, not cross-queue XDP
redirect or MTU tuning.
Reducing worker concurrency at the same 4.8M/`fq limit=50000`/32 MiB send-buffer
profile also did not solve the boundary. A retained 36/40/44/48 worker sweep at
`physical-udp-knot-comparison-20260605T191333Z` measured about 93.91%, 96.39%,
97.11%, and 98.48% reply rate respectively. The lower-worker rows reduced some
send-buffer drops but traded them for much larger receive errors, while the
48-worker row still had about 359k `SndbufErrors` and remained below the
packet-loss gate.
Oversubscribing reuseport workers above the 48 logical CPUs was also negative,
so extra sockets did not improve the queue-distribution boundary. A retained
52/56/60/64 worker sweep at `physical-udp-knot-comparison-20260605T203222Z`
measured about 93.40%, 92.44%, 95.70%, and 94.19% reply rate respectively.
All rows accumulated large receive-buffer errors, and qdisc/`SndbufErrors` also
remained high. Keep 48 unbound workers as the current 4.8M worker-count
baseline.
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
Extending that pacing range higher also did not clear the 4.8M gate. The
retained `physical-udp-knot-comparison-20260605T203429Z` sweep measured
14M/16M/20M/24M bytes/s per socket at about 96.66%, 98.12%, 97.85%, and 97.91%
reply rate respectively. The 16M row had zero receive errors but still had
about 449k qdisc/`SndbufErrors`, while higher pacing rates accumulated even
more qdisc drops. Keep the unpaced socket setting for the current retained
profile.
Disabling the `fq` scheduler's pacing mode was also not enough. The retained
`physical-udp-knot-comparison-20260605T203858Z` row used `fq limit 50000
nopacing` at the same 48-worker/4.8M/batch-64/32 MiB send-buffer profile and
measured about 98.42% reply rate, with about 359k qdisc/`SndbufErrors` and
tiny receive loss. The qdisc artifact confirmed `nopacing` on each child qdisc
and cleanup restored the server interface to `pfifo_fast`. Keep the default
`fq` pacing mode unless a more targeted queue-affinity design changes the loss
shape.
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
Rechecking qdisc alternatives with the large 64 MiB `wmem_max` and 32 MiB
requested send buffer kept `fq limit=50000` as the least-bad current queueing
profile. The retained `fq_codel` row at
`physical-udp-knot-comparison-20260605T194231Z` reached about 97.29% reply rate:
it reduced qdisc drops to about 203k but shifted loss to about 182k
receive-buffer errors and 1268 softnet `time_squeeze` events. The matched
`pfifo_fast` control row at `physical-udp-knot-comparison-20260605T194318Z`
fell to about 86.36% reply rate with about 3.27M qdisc/`SndbufErrors`. Keep
`fq limit=50000` for 4.8M comparison rows until a stronger queue-affinity,
interrupt, or pacing design is measured.
Reducing child `fq` burst parameters was also negative at that boundary. The
harness now supports `fq quantum` and `initial_quantum` so those rows are
repeatable, but setting both to 1514 bytes at
`physical-udp-knot-comparison-20260605T203018Z` fell to about 96.86% reply rate
with about 465k qdisc/`SndbufErrors`, about 219k receive-buffer errors, and
elevated softnet time-squeeze. Leave both quantum knobs unset for the retained
4.8M profile.
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
Removing the per-query `Arc<ZoneStoreEntry>` clone/drop from the DNS query path
also did not improve the primary 4.75M-4.8M batch-64 `fq` gate. The retained
perf profile showed the refcount path as visible CPU work, but three unprofiled
edge rows with the borrowed lookup measured about 97.63%, 98.84%, and 98.39%
reply rate. A later symbolized 4.8M profiling row with `target/profiling/oxidedns`
reached about 98.54% and attributed about 1.6%-1.7% of samples to the
published-zone clone/drop subpaths; retaining the borrowed lookup then measured
about 98.28% at `physical-udp-knot-comparison-20260605T200338Z`. Keep the
ownership cleanup because it removes profile-visible refcount work, but treat it
as neutral for the current transport-loss boundary rather than a proven
reply-rate improvement.
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
The current 4.8M host state also has 48 combined queues, an even RSS
indirection table, RPS disabled, irqbalance inactive, and IRQ/XPS CPU order
`0,2,4,...,46,1,3,...,47`. Pinning 48 workers to that exact IRQ/XPS order at
`physical-udp-knot-comparison-20260605T194518Z` was still negative: reply rate
fell to about 96.17%, with about 905k qdisc/`SndbufErrors` and almost no
receive-buffer loss. Keep unbound scheduling for the current 4.8M/`fq
limit=50000` profile; the next placement experiment should change kernel queue
mapping or worker/socket ownership rather than only pinning the existing worker
set.
Skipping `QueryMetricObservation::started_at` construction when hot-path
counters are off removes one per-query timestamp read from the saturation
profile, but it did not clear the 4.8M gate. Retained rows at
`physical-udp-knot-comparison-20260605T195012Z` and
`physical-udp-knot-comparison-20260605T195103Z` measured about 98.00% and 98.68%
reply rate with the same 48-worker/batch-64/`fq limit=50000`/32 MiB send-buffer
profile. Keep the cleanup because it removes discarded work from the benchmark
path, but treat it as a small hot-path hygiene change rather than a proven
transport fix.
A symbolized profile after the borrowed published-zone lookup at
`physical-udp-knot-comparison-20260605T200945Z` showed the refcount bucket gone
and kept `recv_batch_linux` as the largest user-space bucket, with the expected
empty nonblocking `recvmmsg` poll path still visible through `std::io::Error`
drop work. Mapping `EAGAIN`/`EWOULDBLOCK` to an empty receive batch removes that
per-idle-poll error construction, but it did not clear the 4.8M packet-loss
gate: the retained non-profiled row at
`physical-udp-knot-comparison-20260605T201401Z` measured about 98.17% reply
rate with about 428k qdisc/`SndbufErrors`. Keep it as receive-loop cleanup, not
as a proven transport-loss fix. A follow-up profile at
`physical-udp-knot-comparison-20260605T201614Z` confirmed the error-drop bucket
was gone; `recv_batch_linux` remained the largest user-space bucket at about
9.9%, so the next application-side experiment should target receive message
setup or packet ownership in the dedicated standard UDP loop rather than
ZoneImage composition.
Moving the standard UDP inbound packet buffers into `StdUdpMmsg` and prebinding
receive-side `mmsghdr`/`iovec` state was negative despite targeting that bucket.
Two 4.8M rows at `physical-udp-knot-comparison-20260605T202558Z` and
`physical-udp-knot-comparison-20260605T202640Z` measured about 97.10% and 97.64%
reply rate, with receive-buffer errors appearing in both rows and the first row
showing elevated softnet time-squeeze. Keep the caller-owned inbound batch
layout until a receive change also improves packet-loss behavior.
AF_XDP server TX wakeup cadence is now a retained tuning axis. Before the
server stopped polling for TX writability ahead of every AF_XDP ring send, it
was not a stable win by itself. In the OxideGun AF_XDP requester comparison at 630k
packets with requester `--xdp-tx-wakeup-interval 4`, the prior Knot XDP row
`knot-xdp-oxidegun-wakeup4-630k-20260606T011511Z` measured 591585 positive
replies. OxideDNS with server `xdp.tx_wakeup_interval = 4` at
`oxidegun-xdp-serverwakeup4-shortknot-latency-630k-20260606T012743Z` regressed
to 570479 replies. Server interval 8 at
`oxidegun-xdp-serverwakeup8-shortknot-latency-630k-20260606T012840Z` reached
592332 replies, narrowly beating that Knot row, but an immediate repeat
`oxidegun-xdp-serverwakeup8-repeat-latency-630k-20260606T012916Z` fell back to
571061. The same-binary interval-1 control
`oxidegun-xdp-serverwakeup1-shortknot-latency-630k-20260606T012946Z` measured
574223.
Removing unused per-packet redirect counters from the OxideDNS server redirect
object and the OxideGun reply redirect object reduces shared XDP fast-path work,
but it does not close the server gap. With the counter-free objects, OxideDNS
interval 1 at `oxidegun-xdp-nocounters-serverwakeup1-630k-20260606T013355Z`
measured 579837 positive replies, up from the same-binary countered interval-1
control at 574223. The same counter-free requester against Knot XDP at
`knot-xdp-nocounters-oxidegun-wakeup4-630k-20260606T013446Z` measured 607583
positive replies, so the common requester-side improvement widened the
apples-to-apples Knot lead. OxideDNS interval 8 with counter-free objects at
`oxidegun-xdp-nocounters-serverwakeup8-630k-20260606T013549Z` measured 572831.
Keep the counter-free redirect objects because they remove unused packet work,
but treat the remaining deficit as server AF_XDP queue/packet-I/O behavior.
Server AF_XDP receive-drain passes are also a retained tuning axis with a
conservative default of 1. The 630k counter-free requester rows did not improve
when the server attempted extra nonblocking AF_XDP RX drains before dispatching
each DNS batch: `oxidegun-xdp-rxdrain2-nocounters-630k-20260606T014722Z`
measured 574681 positive replies and
`oxidegun-xdp-rxdrain4-nocounters-630k-20260606T014806Z` measured 567271,
both below the interval-1 counter-free control at 579837 and below the current
Knot XDP counter-free row at 607583. Keep `xdp.rx_drain_passes = 1` for the
current profile unless a later queue ownership or worker placement change makes
larger receive drains useful.
After removing the unconditional AF_XDP server TX `poll_write` before each ring
send, the retained `kxdpgun` copy-mode requester rows moved the current profile
to practical Knot-XDP parity and a narrow repeat win with
`xdp.tx_wakeup_interval = 8`. In
`physical-udp-knot-comparison-20260606T015447Z` at 630k, Knot XDP measured
629869 replies/s and OxideDNS AF_XDP with interval 1 measured 629848 replies/s,
both at 99.998413% replies. In
`physical-udp-knot-comparison-20260606T015652Z` at 900k, Knot XDP measured
899740 replies/s and OxideDNS interval 1 measured 899751 replies/s, both at
99.998422%. At 1.2M, interval 1 still trailed Knot in
`physical-udp-knot-comparison-20260606T015741Z` with 1199614 replies/s versus
1199750, and interval 4 at
`physical-udp-knot-comparison-20260606T015831Z` only reached 1199627. Interval
8 then reached 1199799 replies/s in
`physical-udp-knot-comparison-20260606T015903Z`, and the same-directory
Knot/OxideDNS comparison
`physical-udp-knot-comparison-20260606T015938Z` measured Knot XDP at 1199613
replies/s and OxideDNS AF_XDP at 1199624 replies/s with equal 99.998417% reply
rate. Use `xdp.tx_wakeup_interval = 8` for the current AF_XDP comparison
profile, but keep treating the margin as narrow until a broader rate/repeat
sweep shows a larger saturation-knee lead.
The physical wrapper can now run `oxide-gun` as the requester. The first
retained rows exposed two requester bugs before it became useful: an explicit
53000-53062 source-port range disabled per-queue prebuilt packet templates and
capped the requester at one 4096-descriptor TX-ring fill per queue, and then the
requester needed to poll TX writability on zero-descriptor AF_XDP sends. Even
after that, reply retention stayed poor because each queue slept through the
whole paced batch window without draining RX; `physical-udp-knot-comparison-
20260606T021325Z` retained only 13.255288% replies against Knot XDP, and
`physical-udp-knot-comparison-20260606T021449Z` retained only 12.183415% against
Knot with requester `xdp.rx_drain_passes = 64`. Draining requester RX during
paced waits fixed the loss gate, and `oxide-gun` now emits
`send_duration_seconds` so the harness reports rates over the offered send
window rather than the final drain timeout. In
`physical-udp-knot-comparison-20260606T022205Z` at requested 900k, Knot XDP
measured 891911 replies/s at 100.000000% and OxideDNS AF_XDP measured 891732
replies/s at 99.999114%. In
`physical-udp-knot-comparison-20260606T022319Z` at requested 1.2M, Knot XDP
measured 1183863 replies/s at 100.000000%, while OxideDNS AF_XDP measured
1184869 replies/s at 100.000000%. Keep retaining kxdpgun rows for historical
promotion continuity, but `OXIDEDNS_PHYSICAL_PLAYER_TOOL=oxide-gun` is now
usable for project-owned requester comparisons.
Reverse-role 25G testing showed that source-port steering is target-port
specific and must also cover the server NIC queue count. The first fair
per-target source-list comparison,
`physical-udp-knot-comparison-20260606T034145Z`, calibrated Knot port 5301 and
OxideDNS port 5300 separately, but bound OxideDNS AF_XDP to only 48 queues on a
63-RX-queue server NIC; several requester queues received zero replies and the
row retained only 77.083247%. Repeating with 63 AF_XDP server workers and
`xdp.tx_wakeup_interval = 1` in
`physical-udp-knot-comparison-20260606T034338Z` restored OxideDNS to 2454930
replies/s at 99.942036%, but Knot XDP still measured 2456673 replies/s at
99.998824%. Treat this as evidence that MTU was controlled, not causal: both
hosts were run at temporary MTU 1500 for native XDP and restored to 9000 by the
harness. The next XDP slice needs to reduce the remaining scattered AF_XDP
reply misses before this reverse-role profile can be promoted as a Knot-XDP
win. After retaining AF_XDP packet-I/O counters under `hot_path_detail = "off"`,
`physical-udp-knot-comparison-20260606T035249Z` showed the remaining 793
unanswered queries matching the NIC `rx_out_of_buffer` delta: OxideDNS received
12332263 AF_XDP packets and queued 12332263 AF_XDP TX packets, so the immediate
loss is before userspace receives the request, not in server response TX.
The next calibration pass also made MTU a hard setup check:
`physical-udp-knot-comparison-20260606T041346Z` failed AF_XDP bind with
`EINVAL` when zero-copy was attempted on the jumbo-MTU server link. Re-running
with `OXIDEDNS_PHYSICAL_XDP_MTU=1500` and
`OXIDEDNS_PHYSICAL_KXDPGUN_MTU=1500` in
`physical-udp-knot-comparison-20260606T041857Z` succeeded at 495049 replies/s
and 100.000000% for a low-rate calibration row, produced 512
`oxidedns_udp_worker_source_port_datagrams_total` entries, and mapped the
previous 48-port OxideDNS reverse list onto only 27 server RX workers with as
many as three ports on one worker. A matched replacement list that used 48
distinct server RX workers did not improve saturation:
`physical-udp-knot-comparison-20260606T042049Z` measured Knot XDP at 2456814
replies/s and 99.999400%, while OxideDNS AF_XDP measured 2454059 replies/s and
99.898743%; the row still showed request-side AF_XDP loss before userspace, so
future tuning should use the source-port map to avoid saturated or poorly
serviced queues rather than merely maximizing distinct server workers.
The follow-up single-port substitution attempt was invalid as a fair comparison
when `physical-udp-knot-comparison-20260606T042816Z` failed before traffic:
the standard Knot primary inside the OxideDNS row could not bind TCP 5301, then
OxideDNS stayed in `LOADING`. The physical harness cleanup now kills recorded
artifact pid files before name-based cleanup so renamed benchmark binaries do
not survive failed AF_XDP runs and keep ports or XDP state pinned.
After that cleanup fix, the previous 48-port reverse OxideDNS list remained the
best source-port baseline but still missed the reply-percent gate:
`physical-udp-knot-comparison-20260606T043500Z` measured Knot XDP at 2455879
replies/s and 100.000000%, while OxideDNS AF_XDP measured 2457000 replies/s and
99.994033%; only ports 53496 and 53501 missed replies, and the root
`rx_out_of_buffer` delta matched the 736 unanswered queries. Capacity knobs
were mixed: `OXIDEDNS_PHYSICAL_XDP_UMEM_FRAME_COUNT=32768` alone regressed to
99.979601% in `physical-udp-knot-comparison-20260606T043655Z`;
`OXIDEDNS_PHYSICAL_XDP_RING_SIZE=8192` alone produced a 100.000000% Oxide-only
row in `physical-udp-knot-comparison-20260606T043819Z` but failed the fair
Knot-XDP row at 99.988168% in `physical-udp-knot-comparison-20260606T043912Z`.
Combining ring size 8192 with UMEM frame count 32768 nearly cleared an
Oxide-only row at 99.999951% in
`physical-udp-knot-comparison-20260606T044042Z`, but still failed in both fair
orders: Knot-first `physical-udp-knot-comparison-20260606T044138Z` measured
OxideDNS at 99.932622%, and OxideDNS-first
`physical-udp-knot-comparison-20260606T044354Z` measured OxideDNS at
99.985772% versus Knot XDP at 99.998395%. Treat the remaining loss as AF_XDP
fill/recycle or queue service behavior, not a simple ring/UMEM capacity
default. A receive-path attempt to replenish the fill ring immediately after
TX completion drains was also negative and was not kept:
`physical-udp-knot-comparison-20260606T044810Z` measured 99.990393% with the
baseline 4096 rings, while `physical-udp-knot-comparison-20260606T044913Z`
measured 99.991437% with ring size 8192 and UMEM frame count 32768. That
suggests the missing work is not just exposing already completed TX frames to
the fill ring a few calls earlier.
AF_XDP per-worker transport counters are now retained even when
`hot_path_detail = "off"` so saturation runs can keep queue-distribution
evidence without enabling the higher-cost UDP hot-path counters. The physical
summary adds active-worker and min/max packet columns for
`oxidedns_af_xdp_worker_received_packets_total` and
`oxidedns_af_xdp_worker_sent_packets_total`. The reverse-role diagnostic row
`physical-udp-knot-comparison-20260606T045650Z` measured OxideDNS AF_XDP at
2455876 replies/s and 99.960788%; the server received and queued 12328220
AF_XDP packets, but only 27 of 63 server workers were active. Active workers
ranged from 256000 to 772096 received packets, with matching sent-packet
counts. That keeps MTU lower on the suspect list for this row because the run
used temporary native-XDP MTU 1500 and the server worker received/sent totals
matched; the next useful receive-path work should instead target queue service,
fill lifecycle, or source-port lists that avoid overloading the hot AF_XDP
workers without repeating the distinct-worker regression.
The physical harness now performs targeted row-local cleanup before every Knot,
Knot-XDP, and OxideDNS row. This was needed after
`physical-udp-knot-comparison-20260606T050523Z`: the Knot-XDP row completed, but
the following OxideDNS row failed before traffic because TCP 5301 was still
unavailable for the local Knot primary. With the cleanup fix,
`physical-udp-knot-comparison-20260606T050912Z` completed the same Knot-first
reverse-role comparison. Knot XDP measured 2457197 replies/s at 100.000000%;
OxideDNS AF_XDP with `xdp.tx_wakeup_interval = 8` measured 2454981 replies/s at
99.998044%. The opposite order in
`physical-udp-knot-comparison-20260606T051026Z` was worse for OxideDNS
AF_XDP, at 2456094 replies/s and 99.972494%, while Knot XDP again reached
100.000000%. Further wakeup-cadence probes did not promote a stable win:
`physical-udp-knot-comparison-20260606T051129Z` with interval 4 fell to
99.932661%; `physical-udp-knot-comparison-20260606T051211Z` with interval 16
cleared an Oxide-only row at 100.000000%, but the fair Knot-first row
`physical-udp-knot-comparison-20260606T051259Z` measured OxideDNS at
99.974414% versus Knot XDP at 99.997892%. Keep `xdp.tx_wakeup_interval` as a
tuning axis, but do not treat wakeup cadence alone as the remaining fix.
A follow-up experiment made AF_XDP fill-ring wakeup cadence configurable and
reported fill enqueue/wakeup counters, but the change was not kept because it
did not move the reverse-role gate in the right direction. With the same
48-port reverse list and server `xdp.tx_wakeup_interval = 8`,
`physical-udp-knot-comparison-20260606T052125Z` disabled explicit fill wakeups
and measured 2455605 replies/s at 99.983648%.
`physical-udp-knot-comparison-20260606T052209Z` used a fill wakeup interval of
16 and regressed to 2454457 replies/s at 99.885465%, including 2068 AF_XDP
parse errors. Repeating the current fill-wakeup behavior with the extra fill
counters in `physical-udp-knot-comparison-20260606T052254Z` measured 2454423
replies/s at 99.929599%. Treat fill-wakeup suppression and extra fill counters
as negative evidence for the saturation profile unless a later XDP socket API
can use kernel need-wakeup state instead of blind wakeup cadence.
A reduced calibration row then found a reverse-role source list that balanced
both sides of the packet path instead of only the requester. Running
`scripts/select-oxide-gun-source-ports.py` on
`physical-udp-knot-comparison-20260606T041857Z` selected 48 ports with
48 active requester RX queues, one source port per requester queue, 48 active
server AF_XDP workers, and one calibrated source port per active server worker:
`53321,53072,53133,53397,53243,53132,53310,53105,53082,53036,53453,53204,53118,53410,53000,53113,53088,53125,53185,53342,53208,53399,53110,53095,53244,53130,53358,53327,53111,53305,53426,53163,53487,53401,53299,53345,53206,53152,53015,53349,53061,53364,53296,53199,53220,53237,53020,53052`.
The previous reverse list was already balanced on requester ingress
(48 requester queues active, max one port per requester queue), but only hit
27 server workers and placed up to three ports on a single server worker.
With the balanced list, an Oxide-only reverse-role row,
`physical-udp-knot-comparison-20260606T052658Z`, measured OxideDNS AF_XDP at
2456483 replies/s and 100.000000%; the server reported 48 active AF_XDP
workers with received and sent packet ranges of 256000 to 258048 packets.
The fair Knot-first comparison,
`physical-udp-knot-comparison-20260606T052751Z`, measured Knot XDP at
2457093 replies/s and 99.983058%, while OxideDNS AF_XDP measured
2454219 replies/s and 100.000000%. The reverse order,
`physical-udp-knot-comparison-20260606T052910Z`, measured OxideDNS AF_XDP at
2456797 replies/s and 100.000000%, while Knot XDP measured 2454823 replies/s
and 99.980519%. This makes the reverse-role AF_XDP profile stronger on the
reply-percentage gate in both orders and stronger on retained replies/s in the
OxideDNS-first order, but reply-rate dominance remains order-sensitive until
the forward role is repeated with the same per-target calibration discipline.
MTU remains a hard setup requirement, not the current receive-path explanation:
jumbo MTU failed zero-copy bind in the earlier `041346Z` row, while all of the
successful native-XDP rows above forced MTU 1500 during traffic and restored
MTU 9000 during cleanup.
Forward-role calibration uses the same per-target discipline but has a
different queue-count shape: `oxidedns-1` has 48 server RX queues and
`oxidegun-1` has 63 requester RX queues. The OxideDNS reduced calibration row
`physical-udp-knot-comparison-20260606T053738Z` measured 495954 replies/s at
100.000000% and produced a 63-port list with 63 active requester queues,
48 active server AF_XDP workers, and at most two source ports on any server
worker:
`53079,53159,53262,53600,53099,53376,53726,53248,53105,53432,53288,53225,53360,53073,53408,53588,53399,53603,53628,53244,53445,53401,53685,53409,53040,53167,53353,53533,53122,53653,53642,53058,53170,53032,53130,53345,53046,53044,53349,53140,53336,53421,53505,53548,53001,53410,53644,53116,53351,53295,53368,53017,53270,53626,53061,53087,53711,53388,53165,53300,53530,53254,53544`.
The Knot-XDP requester-only calibration row
`physical-udp-knot-comparison-20260606T053906Z` measured 496257 replies/s at
100.000000% and selected 63 requester queues for Knot port 5301:
`53007,53089,53029,53011,53136,53075,53015,53003,53143,53076,53008,53004,53157,53094,53026,53054,53024,53081,53021,53052,53010,53078,53141,53006,53013,53073,53138,53001,53031,53091,53152,53051,53016,53084,53151,53005,53009,53077,53142,53055,53019,53087,53148,53048,53028,53088,53155,53002,53014,53074,53035,53000,53139,53072,53012,53050,53145,53082,53022,53053,53158,53093,53025`.
With those lists at requested 1.2M, the forward role cleared the reply-percent
gate and narrowly beat Knot XDP in both run orders:
`physical-udp-knot-comparison-20260606T054454Z` measured Knot XDP at
1186767 replies/s and 100.000000%, while OxideDNS AF_XDP measured
1186917 replies/s and 100.000000%; `physical-udp-knot-comparison-20260606T054612Z`
measured OxideDNS AF_XDP at 1187820 replies/s and 100.000000%, while Knot XDP
measured 1186803 replies/s and 100.000000%.
The forward ceiling is still lower than the reverse-role 2.5M proof point.
At requested 1.8M in `physical-udp-knot-comparison-20260606T055210Z`, both rows
kept 100.000000%, but Knot XDP retained 1770170 replies/s while OxideDNS AF_XDP
retained 1768573 replies/s. Server TX wakeup probes at the same rate were
close but not promoted: interval 1 reached 1769056 replies/s, interval 4
reached 1767983, and interval 16 reached 1769979. At requested 2.5M in
`physical-udp-knot-comparison-20260606T054110Z`, Knot XDP measured
2002643 replies/s at 99.344390%, while OxideDNS AF_XDP measured
1915610 replies/s at 98.907538%; the requester only transmitted about
2.02M qps to Knot and about 1.94M qps to OxideDNS, so the high-rate row is also
limited by oxide-gun AF_XDP requester service, not only by server DNS work.
Two negative counterprobes should not be repeated as fixes: a 48-port list with
requester `queue_count=48` gave perfect 48-worker server balance but only
76.973998% replies in `physical-udp-knot-comparison-20260606T054357Z`, and an
absolute-deadline requester pacer overran requester RX. The latter sent enough
traffic for OxideDNS to queue 12200233 AF_XDP replies in
`physical-udp-knot-comparison-20260606T054928Z`, but both Knot and OxideDNS
fell to about 60% replies; increasing requester RX drain to 64 in
`physical-udp-knot-comparison-20260606T055048Z` still only reached 63.255592%.
The next forward-rate work should keep the relative paced-wait requester shape
and instead reduce per-queue AF_XDP service cost or improve requester TX/RX
co-scheduling without starving reply drain.

Use `[metrics].hot_path_detail = "reduced"` for observability-preserving runs.
Reduced mode also exposes
`oxidedns_udp_worker_source_port_datagrams_total{worker,source_port}`, which is
intended for low-rate AF_XDP source-port/RSS calibration: combine it with
oxide-gun reply queue counts to select ports that both return to the intended
requester queue and distribute requests across server RX queues. Do not use that
profile for final saturation rows.
Use `"off"` only for saturation profiling where per-query counters would distort
the transport result; post-run benchmark logs and kernel packet counters remain
available, and AF_XDP packet-I/O counters are still retained for transport
diagnostics. DNS query, standard UDP packet-I/O, ZoneImage serve, rcode, DNS
Cookie, RRL, and per-zone hot-path counters are no longer representative while
that profile is active. `limits.udp_idle_strategy =
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

For XDP promotion claims, include both `OXIDEDNS_PHYSICAL_INCLUDE_KNOT_XDP=true`
and `OXIDEDNS_PHYSICAL_OXIDEDNS_UDP_BACKENDS="af_xdp"` in the retained run, and
record whether OxideDNS `zero_copy=require` succeeds or fails on the selected
NIC/queue, plus the server `xdp.rx_drain_passes` and
`xdp.tx_wakeup_interval` used for each row. If zero-copy has to be relaxed to
`auto` or disabled, the row is engineering evidence only and should not be
described as the final Knot-XDP comparison.

The meaningful result is the saturation knee: the highest offered rate where
response percentage, drops/errors, p99/p999 latency, and byte throughput remain
inside the claimed acceptance envelope.
