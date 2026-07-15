# Knot Comparison Benchmark Plan

This document defines how to compare BoronDNS against Knot DNS without mixing
different benchmark units or query mixes.

Historical rows below retain the `xdp.tx_wakeup_interval` values used to collect
their evidence. They are not current-safe configuration guidance: the server
now requires interval `1` and kicks every non-empty TX enqueue because its AF_XDP
dependency enables `XDP_USE_NEED_WAKEUP` without exposing the kernel ring flag.
The retained low-rate evidence at the interval-1 transition demonstrated why a
periodic counter cannot safely replace that flag.

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

## BoronDNS Comparison Contract

Use the same zone data and query mix for both servers:

1. Generate or import a Knot-style `querydb`.
2. Use `querydb` directly for kxdpgun.
3. Convert `querydb` to BoronDNS `query-trace.tsv`.
4. Run BoronDNS and Knot DNS with the same destination IP, port, query rate,
   duration, and EDNS/DO mix.
5. Record both packet-rate and byte-rate metrics.

For quick local synthetic runs, use `scripts/benchmark-dns-clients.sh` with:

- `BORONDNS_BENCH_TRACE_FILE` pointing at the converted trace.
- `BORONDNS_BENCH_DURATION_SECONDS=15` for Knot-aligned UDP windows.
- `BORONDNS_BENCH_CLIENT_MODE=ssh` when using a separate traffic host.
- `BORONDNS_BENCH_NETWORK_DEVICE` set to the physical NIC.
- `BORONDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true` for any hardware claim.

For Knot-aligned comparison runs, stage Knot as the primary and BoronDNS as a
secondary:

1. Start Knot with the benchmark zone and use it as the reference authoritative
   target.
2. Let BoronDNS transfer the same zone by AXFR from Knot.
3. Verify BoronDNS readiness and SOA response.
4. Stop Knot so BoronDNS is idle and serving from the transferred in-memory
   snapshot.
5. Benchmark BoronDNS with the same query mix.

This shape keeps the zone source, query input, and Knot tooling close to the
Knot reference benchmark while isolating BoronDNS serving performance from
primary-transfer activity.

## Prepared Helpers

Create a kxdpgun query file from a zone file:

```bash
scripts/prepare-knot-comparison-benchmark.sh querydb \
  --zone zones/example.zone \
  --out target/knot-comparison/example \
  --shuffle
```

Convert that file to the BoronDNS load-client trace format:

```bash
scripts/prepare-knot-comparison-benchmark.sh trace \
  --querydb target/knot-comparison/example/querydb \
  --out target/knot-comparison/example
```

Stage Knot as primary and BoronDNS as a secondary from one zone file:

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
- `borondns.toml`: BoronDNS secondary config pointing at Knot.
- `querydb`: kxdpgun input.
- `query-trace.tsv`: equivalent BoronDNS `dns-load-client` trace.
- `runbook.sh`: validates configs, starts Knot, waits for BoronDNS AXFR
  readiness, stops Knot, and optionally runs the direct BoronDNS idle benchmark.

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

Hardware XDP comparison defaults are intentionally different from the veth and
generic smoke profiles. `scripts/physical-udp-knot-comparison.sh` defaults
`BORONDNS_PHYSICAL_KXDPGUN_MODE=auto` so kxdpgun can select native driver XDP
and zero-copy when the NIC supports it, and defaults
`BORONDNS_PHYSICAL_OXIDE_GUN_XDP_ZERO_COPY=auto` for the project-owned requester.
Use `copy` or `generic` only as an explicit compatibility or driver-debug
fallback; do not use those modes for a headline hardware XDP claim. Packaged
Knot 3.5.3 exposes XDP support but rejects the newer server-side
`xdp.zero-copy` config item, so Knot XDP rows omit that item by default. Set
`BORONDNS_PHYSICAL_KNOT_XDP_ZERO_COPY=on` only with a Knot build whose
configuration parser accepts it, and retain `knot-version.txt` plus the
generated `knot-xdp.conf` with the row.

Knot XDP busy-poll experiments are opt-in through
`BORONDNS_PHYSICAL_KNOT_XDP_BUSYPOLL_BUDGET` and
`BORONDNS_PHYSICAL_KNOT_XDP_BUSYPOLL_TIMEOUT`. When those are used, also set
the documented interface prerequisites with
`BORONDNS_PHYSICAL_SERVER_NAPI_DEFER_HARD_IRQS` and
`BORONDNS_PHYSICAL_SERVER_GRO_FLUSH_TIMEOUT`; the wrapper records and restores
those sysfs values in `host/server-link-tuning.txt`. XDP rows also retain
`server-ip-link-*-benchmark.txt` and `server-bpftool-net-*-benchmark.txt` so the
attached program mode can be audited after the fact.
Use `BORONDNS_PHYSICAL_PLAYER_MTU=1500` for native-XDP requester rows on this
hardware; the legacy `BORONDNS_PHYSICAL_KXDPGUN_MTU` name is still accepted for
older command lines.

For a Knot reference run against the same staged zone and query mix, start Knot
with `knot.conf` and run kxdpgun from the player host:

```bash
sudo kxdpgun -t 15 -p 5301 -b 10 -Q "$rate" -i querydb "$target_ip" \
  2>&1 | tee kxdpgun-knot.log
```

For an BoronDNS kxdpgun run on the dedicated hardware, use the same `querydb`,
the BoronDNS service port, and the same `-t`, `-b`, `-Q`, source-address, and
affinity settings as the Knot reference run. The generated `runbook.sh` local
load-client path is useful for local and preflight evidence. The physical
wrapper can also run the project-owned `oxide-gun` requester for AF_XDP
diagnostic and promotion-adjacent rows; keep kxdpgun rows in retained promotion
sweeps until repeated `oxide-gun` runs cover the same rate range and host roles.

For repeatable BoronDNS socket-path sweeps on the two physical hosts, use the
checked-in wrapper instead of ad-hoc SSH commands:

```bash
BORONDNS_PHYSICAL_WORKERS="12 16 24" \
BORONDNS_PHYSICAL_RATES="2000000 2500000 3000000" \
BORONDNS_PHYSICAL_HOT_PATH_DETAILS="reduced off" \
BORONDNS_PHYSICAL_IDLE_STRATEGIES="park spin" \
scripts/physical-udp-knot-comparison.sh
```

The wrapper expects a staged Knot-primary comparison directory on the server
host, copies the staged BoronDNS config for each run, applies the selected
worker count, hot-path metric detail, and dedicated-worker idle strategy, starts
Knot only long enough for BoronDNS to transfer the zone, then runs `kxdpgun`
from the player host against the idle BoronDNS secondary. It writes one
artifact directory under the staged directory's `evidence/` folder and emits a
`summary.tsv` containing offered rate, player tool, kxdpgun batch/mode, BoronDNS
UDP batch size, replies per second, reply percentage, average DNS reply size,
Ethernet reply bit rate, effective server `txqueuelen`, effective per-queue
server TX ring size, effective per-queue server TX qdisc, effective `fq`
limit/flow limit, requested UDP socket pacing rate, effective server
`net.core.rmem_max` and `net.core.wmem_max`, server RX/TX packet deltas, Linux UDP
`InDatagrams`/`OutDatagrams`/`InErrors`/`RcvbufErrors`/`SndbufErrors` deltas,
retained BoronDNS dedicated-worker mmsg counters when hot-path counters are
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
BORONDNS_PHYSICAL_WORKERS="48" \
BORONDNS_PHYSICAL_RATES="4750000 4800000" \
BORONDNS_PHYSICAL_UDP_BATCH_SIZES="64" \
BORONDNS_PHYSICAL_SERVER_TX_QDISC=fq \
BORONDNS_PHYSICAL_SERVER_TX_FQ_LIMIT=50000 \
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

- `BORONDNS_PHYSICAL_WORKER_CPUS="0,2,4,..."` writes
  `limits.udp_worker_cpu_affinity` into each run config. On the current 48-CPU
  25G server, pinning 16 workers to sibling-free even CPUs improved the 3M
  offered-QPS saturation profile from about 2.33M replies/s and 77.6% reply
  rate to about 2.69M replies/s and 89.7% reply rate.
- `BORONDNS_PHYSICAL_SOCKET_BUFFER_BYTES=4194304` writes both UDP socket buffer
  settings into each run config. This is host specific: the first 4 MiB test on
  the current server was worse than the default, so retain the setting only when
  the run evidence proves it helps.
- `BORONDNS_PHYSICAL_SOCKET_RECEIVE_BUFFER_BYTES=2097152` and
  `BORONDNS_PHYSICAL_SOCKET_SEND_BUFFER_BYTES=4194304` override receive and send
  buffers independently. Use these for send-side loss experiments where
  `SndbufErrors` is non-zero but receive counters are clean.
- `BORONDNS_PHYSICAL_SOCKET_MAX_PACING_RATE_BYTES_PER_SECOND=75000000` writes
  `limits.udp_socket_max_pacing_rate_bytes_per_second` into each run config.
  This requests Linux `SO_MAX_PACING_RATE` per UDP socket, so use it with `fq`
  qdisc rows where aggregate send bursts are the active hypothesis. Retained
  rows record the requested `socket_max_pacing_rate_bytes_per_second`. Use
  `BORONDNS_PHYSICAL_SOCKET_MAX_PACING_RATES_BYTES_PER_SECOND="9000000 12000000"`
  to sweep multiple per-socket pacing rates in one retained artifact.
- `BORONDNS_PHYSICAL_SERVER_TXQUEUELEN=5000` temporarily sets the server
  interface transmit queue length for the comparison run and restores the
  original value during cleanup. Use it only for retained packet-loss
  experiments where qdisc drops or `SndbufErrors` identify transmit queueing as
  the active gate.
- `BORONDNS_PHYSICAL_SERVER_TX_RING=4096` temporarily sets the server NIC TX
  ring size with `ethtool -G` and restores the original TX ring during cleanup.
  Use it only for retained rows where send-side loss occurs after `sendmmsg`
  acceptance; retained rows record the effective `server_tx_ring`.
- `BORONDNS_PHYSICAL_SERVER_TX_QDISC=fq` temporarily replaces each existing
  per-queue child qdisc on the server interface and restores the original child
  qdisc kinds during cleanup. The current wrapper accepts `fq`, `fq_codel`, and
  `pfifo_fast`; use it only for send-side queueing experiments where the
  retained qdisc before/after files prove the host state was restored.
- `BORONDNS_PHYSICAL_SERVER_TX_FQ_LIMIT=50000` sets the aggregate `fq limit`
  when `BORONDNS_PHYSICAL_SERVER_TX_QDISC=fq` is active. The default is
  `10000`, matching the previously retained `fq` rows. Retained rows record the
  effective `server_tx_fq_limit`.
- `BORONDNS_PHYSICAL_SERVER_TX_FQ_FLOW_LIMIT=1000` sets `fq flow_limit` when
  `BORONDNS_PHYSICAL_SERVER_TX_QDISC=fq` is active. Retained rows record the
  effective `server_tx_fq_flow_limit`. Leave it unset for baseline rows unless
  child `fq` drops or `flows_plimit` counters are the active hypothesis.
- `BORONDNS_PHYSICAL_SERVER_TX_FQ_QUANTUM=1514` and
  `BORONDNS_PHYSICAL_SERVER_TX_FQ_INITIAL_QUANTUM=1514` pass `quantum` and
  `initial_quantum` to each child `fq` qdisc. The retained
  `server-link-tuning.txt` and `server-tx-qdisc-after.txt` files record the
  requested and effective qdisc state. Use these only for qdisc burst-shaping
  experiments after `fq limit` and `flow_limit` rows identify child qdisc drops
  as the active gate.
- `BORONDNS_PHYSICAL_SERVER_TX_FQ_PACING=nopacing` appends `nopacing` to each
  child `fq` qdisc, while `pacing` explicitly requests the default pacing mode.
  Use this to distinguish `fq` flow isolation from the scheduler's
  non-work-conserving pacing behavior; retained rows record the requested value
  in `server-link-tuning.txt` and the effective qdisc state in
  `server-tx-qdisc-after.txt`.
- `BORONDNS_PHYSICAL_SERVER_WMEM_MAX=33554432` temporarily raises the server
  `net.core.wmem_max` sysctl and restores the original value during cleanup.
  Use it with a matching `BORONDNS_PHYSICAL_SOCKET_SEND_BUFFER_BYTES` value when
  proving send-buffer headroom; retained rows record the effective
  `server_wmem_max`.
- `BORONDNS_PHYSICAL_SERVER_RMEM_MAX=16777216` temporarily raises the server
  `net.core.rmem_max` sysctl and restores the original value during cleanup.
  Use it with a matching `BORONDNS_PHYSICAL_SOCKET_RECEIVE_BUFFER_BYTES` value
  when rows shift from qdisc/`SndbufErrors` into Linux UDP `RcvbufErrors`;
  retained rows record the effective `server_rmem_max`.
- `BORONDNS_PHYSICAL_UDP_BATCH_SIZES="16 32 64"` sweeps
  `[limits].udp_batch_size` in the staged config. The default `staged` value
  preserves the staged directory's existing batch size.
- `BORONDNS_PHYSICAL_SERVER_BIN=target/profiling/borondns` runs a symbolized
  profiling build instead of the stripped release binary.
- `BORONDNS_PHYSICAL_SERVER_PREFIX="numactl --interleave=all"` prefixes both
  validation and serve commands on the server host. This is intended for
  evidence-gated NUMA experiments; leave it unset for baseline comparisons.
- `BORONDNS_PHYSICAL_PERF_RECORD=true` captures `perf.data` and retained
  `perf-report-*.txt` files beside the run logs on the server host.
  `BORONDNS_PHYSICAL_PERF_SCOPE=process|system` controls whether `perf record`
  attaches to the row's server process PID or records system-wide on the server
  for that row. Use `system` when process-PID sampling misses worker threads.
  `BORONDNS_PHYSICAL_PERF_EVENT=cpu-clock` selects software CPU-clock sampling;
  the default leaves perf's event selection unchanged.
  `BORONDNS_PHYSICAL_PERF_REPORT_TIMEOUT=30s` bounds each retained
  `perf report` pass so slow callgraph expansion cannot stall cleanup.
  `BORONDNS_PHYSICAL_PERF_REPORT_CHILDREN=false` skips the children report when
  the symbol report is sufficient for a sweep.
- `BORONDNS_PHYSICAL_SOCKET_SAMPLE=true` captures repeated
  `ss -u -n -m` samples for the BoronDNS UDP service port during the kxdpgun
  window. Use this when `SndbufErrors` is the active gate and per-socket queue
  state is needed; `BORONDNS_PHYSICAL_SOCKET_SAMPLE_INTERVAL=0.25` controls the
  sample interval in seconds.
- `BORONDNS_PHYSICAL_INCLUDE_KNOT=true` adds a Knot reference row for each
  offered rate before the BoronDNS sweeps. The Knot row uses the same staged
  `querydb`, target IP, kxdpgun batch/mode/source settings, and kernel packet
  counters as the BoronDNS rows.
- `BORONDNS_PHYSICAL_INCLUDE_KNOT_XDP=true` adds a Knot XDP reference row for
  each offered rate. The harness copies the staged `knot.conf`, appends an
  `xdp:` section for the benchmark interface/port, and starts Knot through
  `sudo` because XDP attach normally requires elevated capabilities.
  `BORONDNS_PHYSICAL_KNOT_BIN=/path/to/knotd` selects a source-built Knot
  binary without replacing the packaged system daemon.
- `BORONDNS_PHYSICAL_BORONDNS_UDP_BACKENDS="std af_xdp"` selects which BoronDNS
  packet backends to sweep. `std` preserves the existing standard UDP matrix.
  `af_xdp` forces the valid AF_XDP config shape: Tokio runtime,
  `udp_idle_strategy = "park"`, the configured XDP interface, ring/UMEM sizes,
  and the project-built redirect object. In AF_XDP mode,
  `BORONDNS_PHYSICAL_WORKERS` maps to contiguous XDP queue workers starting at
  `BORONDNS_PHYSICAL_XDP_QUEUE_ID`; it is not a SO_REUSEPORT worker count.
- XDP rows are controlled with `BORONDNS_PHYSICAL_XDP_MODE=drv`,
  `BORONDNS_PHYSICAL_XDP_ZERO_COPY=require`,
  `BORONDNS_PHYSICAL_XDP_QUEUE_ID=0`, `BORONDNS_PHYSICAL_XDP_RING_SIZE=8192`,
  `BORONDNS_PHYSICAL_XDP_UMEM_FRAME_COUNT=32768`,
  `BORONDNS_PHYSICAL_XDP_BATCH_SIZE=1024`,
  `BORONDNS_PHYSICAL_XDP_RX_DRAIN_PASSES=1`,
  `BORONDNS_PHYSICAL_XDP_TX_WAKEUP_INTERVAL=8`, and optionally
  `BORONDNS_PHYSICAL_XDP_REDIRECT_OBJECT` when the object is not under the
  server checkout. Set `BORONDNS_PHYSICAL_XDP_QUEUE_IDS=0,1,...` to bind a
  sparse AF_XDP queue set instead of the contiguous range starting at
  `BORONDNS_PHYSICAL_XDP_QUEUE_ID`. AF_XDP rows are started through `sudo` and set
  `process.run_as_user` to `BORONDNS_PHYSICAL_XDP_RUN_AS_USER=codex` by default
  so the process does not continue serving as root. Use
  `BORONDNS_PHYSICAL_XDP_MTU=1500` when the benchmark NIC is configured with a
  jumbo MTU that the native XDP driver rejects. The harness restores the
  original MTU during cleanup. Knot XDP omits the server-side `zero-copy` item
  by default for packaged Knot 3.5.3 compatibility
  (`BORONDNS_PHYSICAL_KNOT_XDP_ZERO_COPY=__omit__`) and uses
  `BORONDNS_PHYSICAL_KNOT_XDP_RING_SIZE=2048`. Set
  `BORONDNS_PHYSICAL_KNOT_XDP_ZERO_COPY=on` only after confirming the selected
  `BORONDNS_PHYSICAL_KNOT_BIN` accepts the config item. Busy polling is disabled
  unless `BORONDNS_PHYSICAL_KNOT_XDP_BUSYPOLL_BUDGET` or
  `BORONDNS_PHYSICAL_KNOT_XDP_BUSYPOLL_TIMEOUT` is set. The generated Knot XDP
  config drops privileges to `BORONDNS_PHYSICAL_KNOT_XDP_RUN_AS_USER=codex:codex`
  so it can read and write the staged benchmark artifacts after the privileged
  XDP attach.
  The summary rows retain `server_udp_backend`, `xdp_mode`, `xdp_zero_copy`,
  `xdp_rx_drain_passes`, `xdp_tx_wakeup_interval`, and
  `oxide_gun_response_timeout_ms` so standard, Knot-XDP, BoronDNS-AF_XDP, and
  requester-drain timeout rows cannot be confused.
- The requester-side XDP mode is controlled with
  `BORONDNS_PHYSICAL_KXDPGUN_MODE=auto|copy|generic` and defaults to `auto` for
  physical hardware comparisons. Use `BORONDNS_PHYSICAL_PLAYER_MTU=1500` when
  trying native XDP on a jumbo-MTU NIC; the legacy
  `BORONDNS_PHYSICAL_KXDPGUN_MTU=1500` name is still accepted. The harness
  detaches stale requester XDP programs, records the original and effective
  requester MTU in `host/player-link-tuning.txt`, and restores the original
  requester MTU during cleanup.
- `BORONDNS_PHYSICAL_COMPARISON_RUN_ORDER=knot-first|borondns-first` controls
  whether Knot reference rows run before or after BoronDNS rows in the same
  artifact. The default `knot-first` preserves the original comparison flow;
  use `borondns-first` to check for XDP attach/detach or NIC-state order
  effects.
- `scripts/physical-xdp-source-knot-profile.sh` is a narrow repeat wrapper for
  the current source-built Knot XDP comparison. It defaults to the 2.5M
  requester-owned AF_XDP profile, source-built Knot 3.5.4, server/requester
  native XDP MTU 1500, requester zero-copy forced, server AF_XDP batch 512,
  server `xdp.tx_wakeup_interval = 8`, requester batch 64, requester final
  response drain timeout 2000 ms, and both comparison run orders. Use
  `BORONDNS_SOURCE_KNOT_REPEATS=N` and, when needed,
  `BORONDNS_SOURCE_KNOT_ORDERS="borondns-first knot-first"` to capture variance
  before changing transport code.
- `BORONDNS_PHYSICAL_PLAYER_TOOL=kxdpgun|oxide-gun` selects the requester. The
  default remains `kxdpgun` for promotion rows. `oxide-gun` runs the
  project-owned AF_XDP requester with the staged `querydb` as `--query-list`,
  `BORONDNS_PHYSICAL_OXIDE_GUN_BIN` or the default
  `$player_workdir/xdp-template-slice/oxide-gun`, and
  `BORONDNS_PHYSICAL_OXIDE_GUN_XDP_REDIRECT_OBJECT` or the default
  `$player_workdir/xdp-template-slice/oxide-gun-xdp.bpf.o`. The dedicated-host
  defaults use `BORONDNS_PHYSICAL_OXIDE_GUN_QUEUE_COUNT=__auto__`, which
  detects the requester interface RX queue count so forward and reversed host
  roles do not reuse the wrong 63-queue assumption. The default source MAC is
  `b8:59:9f:4b:73:2c`, target MAC is `1c:34:da:60:67:00`, XDP copy mode is
  used, `BORONDNS_PHYSICAL_OXIDE_GUN_XDP_BATCH_SIZE=64` is used to avoid
  zero-copy requester bursts when copy mode is overridden, one source port is
  auto-assigned per queue starting at 53000, and summary parsing comes from the
  JSON `summary` record. The effective requester queue count is retained in
  `host/player-link-tuning.txt`.
  `BORONDNS_PHYSICAL_OXIDE_GUN_SOURCE_PORT_LIST=port,port,...` passes an
  explicit per-worker source-port list to `oxide-gun`; use it after queue
  calibration when contiguous source ports do not hash back to their owning
  AF_XDP RX queues. RSS includes the UDP destination port on the dedicated
  hosts, so source-port lists should be calibrated per server target port:
  `BORONDNS_PHYSICAL_OXIDE_GUN_KNOT_SOURCE_PORT_LIST=...` for Knot rows and
  `BORONDNS_PHYSICAL_OXIDE_GUN_BORONDNS_SOURCE_PORT_LIST=...` for BoronDNS
  rows. After a reduced AF_XDP calibration row, run
  `scripts/select-oxide-gun-source-ports.py <row-artifact> --existing-list ...`
  on the row that contains `metrics-after.prom` and the oxide-gun
  `kxdpgun.log` JSON summary. The helper emits both `queue_list=...` and
  `source_port_list=...`; pass both to OxideGun when the selected requester
  queues are sparse. The physical wrapper accepts
  `BORONDNS_PHYSICAL_OXIDE_GUN_KNOT_QUEUE_LIST=...` and
  `BORONDNS_PHYSICAL_OXIDE_GUN_BORONDNS_QUEUE_LIST=...` alongside the
  target-specific source-port list variables. The selected source-port list
  keeps one reply stream per requester RX queue while also balancing requests
  across server AF_XDP workers.
  For Knot rows, where no BoronDNS server-worker metric exists, use
  `--requester-only` against a low-rate Knot-XDP calibration row to select one
  source port per requester RX queue for that target port. For a follow-up
  weighted BoronDNS list, pass `--requester-weight-log <kxdpgun.log>` from a
  saturation row so requester queues are weighted by observed
  `tx_packets_total` while the selected ports are mapped through the low-rate
  server-worker calibration. Add `--server-exact` when the goal is exactly one
  flow per server AF_XDP worker; this is a diagnostic mode, not necessarily the
  highest-throughput mode. If a saturation row misses replies on a small set of
  requester queues that map to a specific server worker, rerun the selector with
  `--repair-existing --repair-server-worker <worker>` and the known high-rate
  `--existing-list`; this preserves the list shape and emits targeted
  source-port repair candidates, but the repaired list still needs physical
  A/B validation because better balance is not always better QPS.
  `BORONDNS_PHYSICAL_OXIDE_GUN_XDP_PACE_WAIT_FRACTION=0.875` passes
  `--xdp-pace-wait-fraction` to a new enough `oxide-gun` requester. Leave it
  unset for promotion rows unless a local probe shows that shortening the
  paced-wait window preserves the reply-percentage gate.
  `BORONDNS_PHYSICAL_OXIDE_GUN_RESPONSE_TIMEOUT_MS=1000` controls the final
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
4.42M replies/s and 98.35% reply rate, while BoronDNS with 36 unbound workers,
batch size 8, counters off, spin idle, and 2 MiB receive/send buffers measured
about 4.47M replies/s and 99.40% reply rate. Manual repeats with the same
BoronDNS profile reached about 99.7% reply rate, so the transmit queue length
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
rate. A follow-up same-artifact run with `BORONDNS_PHYSICAL_SERVER_TX_QDISC=fq`
measured Knot at about 4.35M replies/s and 96.80% reply rate, while BoronDNS
measured about 4.49M replies/s and 99.86% reply rate; cleanup restored the
server interface to `pfifo_fast:48` and `txqueuelen=1000`. Two additional
BoronDNS-only `fq` repeats measured about 99.60% and 99.84% reply rate. Combining
`fq` with `txqueuelen=5000` still beat Knot in the same artifact, but the
BoronDNS row fell to about 99.73%, below the best `fq`-only row, so prefer
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
with Knot under `fq` measured Knot at about 94.82% reply rate and BoronDNS at
about 99.29% reply rate. A follow-up 40/44/48 worker sweep at 4.7M and batch
16 was noisy: 44 workers won that artifact at about 99.14%, while 40 and 48
were below 99%. The 44-worker profile still missed the gate at 4.75M, measuring
about 98.26%, so the higher-rate boundary remains unresolved.

At 4.75M under `fq`, increasing the server UDP batch size helped more than
additional workers: 48 workers with batch 32 reached about 98.66%, batch 64
reached about 98.96% in the first row, and batch 128 regressed to about 98.57%.
The same-artifact Knot comparison at 4.75M with the 48-worker batch-64 profile
measured Knot at about 92.21% reply rate and BoronDNS at about 98.72%, so
BoronDNS stayed clearly ahead but still below the packet-loss gate. Batch 64
did not carry 4.8M, which fell to about 95.54%, and combining batch 64 with
`txqueuelen=5000` was worse than `fq` alone at about 98.31%.
Socket sampling at the 4.75M batch-64 `fq` edge did not show sustained
per-socket queue buildup: sampled BoronDNS sockets stayed at zero receive/send
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
with `server_wmem_max=33554432` measured Knot at about 92.06% and BoronDNS at
about 95.90%, so BoronDNS still led Knot but did not stably clear the
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
measured Knot at about 91.34% and BoronDNS at about 97.83%, so BoronDNS widened
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
`physical-udp-knot-comparison-20260605T204346Z` still had BoronDNS ahead of
Knot, about 98.65% versus 90.32%, but BoronDNS missed the packet-loss gate as
loss shifted into about 129k receive-buffer errors.
Raising the receive-buffer ceiling then reduced that shifted receive loss. With
`net.core.rmem_max=16777216`, an 8 MiB requested receive buffer, the same 32 MiB
send buffer, and `fq flow_limit=500`, `physical-udp-knot-comparison-20260605T204624Z`
measured about 99.50% reply rate at 4.8M. A three-row BoronDNS-only repeat at
`physical-udp-knot-comparison-20260605T204808Z` measured about 99.87%, 99.96%,
and 99.97%, with qdisc drops down to about 4k/6k/7k and low receive loss. Treat
the combined `fq limit=50000`, `flow_limit=500`, 16 MiB receive ceiling, and
64 MiB send ceiling profile as the current retained 4.8M candidate. The clean
same-artifact comparison at `physical-udp-knot-comparison-20260605T205029Z`
then measured Knot at about 88.35% reply rate and BoronDNS at about 99.96%,
with BoronDNS qdisc drops down to about 1.5k, receive-buffer errors about 7.5k,
and `flows_plimit` about 1.5k. A previous same-tuning comparison at
`physical-udp-knot-comparison-20260605T204713Z` was noisy, with both rows far
below their normal reply rates, so retain `205029Z` as the passing comparison
artifact.
A role-reversed validation pass shows that the passing forward-role profile is
not yet portable across the two dedicated hosts. For this pass `oxidegun-1`
served `198.18.0.2` and `borondns-1` generated traffic from `198.18.0.1`; Knot
was installed and disabled on `oxidegun-1`, the staged zone and query database
were mirrored to the opposite hosts, a stale generic XDP program was detached,
and the server NIC's zero-handle `mq` root was normalized to a replaceable
`mq 8001:` root with `pfifo_fast` children. With the retained forward tuning
at 48 workers and 4.8M offered QPS,
`physical-udp-knot-comparison-20260605T211343Z` measured Knot at about 97.41%
reply rate but BoronDNS at only about 51.22%, with about 9.54M
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
role-reversed BoronDNS ceiling on `oxidegun-1`; reaching 4.8M on both host
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
failed on `borondns-1` because AF_XDP queue 48 did not exist. With the
requester capped to 48 queues but the reverse server still capped to 48
workers, `physical-udp-knot-comparison-20260606T023020Z` showed an artificial
75% BoronDNS AF_XDP reply ceiling because `oxidegun-1` has 63 RX queues and the
unbound server queues were still reachable by RSS. Matching the reverse server
to 63 workers removed that ceiling:
`physical-udp-knot-comparison-20260606T023338Z` measured Knot XDP at 1187197
replies/s and 100.000000%, while BoronDNS AF_XDP measured 1185281 replies/s and
99.942922% at requested 1.2M. Reducing the AF_XDP server batch to 512 and using
`xdp.tx_wakeup_interval = 1` fixed the low-rate loss gate:
`physical-udp-knot-comparison-20260606T023606Z` measured 1186135 replies/s at
100.000000%, and the auto-queue proof row
`physical-udp-knot-comparison-20260606T024404Z` retained
`oxide_gun_effective_queue_count=48`.
The same reverse profile is still not a clean retained-QPS win at higher rates.
At requested 1.5M, `physical-udp-knot-comparison-20260606T023643Z` measured
Knot XDP at 1478476 replies/s and 99.992577%, while BoronDNS AF_XDP measured
1476928 replies/s and 100.000000%. At requested 2.0M,
`physical-udp-knot-comparison-20260606T023745Z` measured Knot XDP at 1966958
replies/s and 99.878854%, while BoronDNS AF_XDP measured 1965472 replies/s and
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
`BORONDNS_PHYSICAL_OXIDE_GUN_RESPONSE_TIMEOUT_MS=3000`,
`physical-udp-knot-comparison-20260606T030335Z` measured BoronDNS AF_XDP at
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
4.75M/48-worker/BoronDNS-batch-64/`fq` profile. Keep the default kxdpgun batch
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
reply rate. A later symbolized 4.8M profiling row with `target/profiling/borondns`
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
replies. BoronDNS with server `xdp.tx_wakeup_interval = 4` at
`oxidegun-xdp-serverwakeup4-shortknot-latency-630k-20260606T012743Z` regressed
to 570479 replies. Server interval 8 at
`oxidegun-xdp-serverwakeup8-shortknot-latency-630k-20260606T012840Z` reached
592332 replies, narrowly beating that Knot row, but an immediate repeat
`oxidegun-xdp-serverwakeup8-repeat-latency-630k-20260606T012916Z` fell back to
571061. The same-binary interval-1 control
`oxidegun-xdp-serverwakeup1-shortknot-latency-630k-20260606T012946Z` measured
574223.
Removing unused per-packet redirect counters from the BoronDNS server redirect
object and the OxideGun reply redirect object reduces shared XDP fast-path work,
but it does not close the server gap. With the counter-free objects, BoronDNS
interval 1 at `oxidegun-xdp-nocounters-serverwakeup1-630k-20260606T013355Z`
measured 579837 positive replies, up from the same-binary countered interval-1
control at 574223. The same counter-free requester against Knot XDP at
`knot-xdp-nocounters-oxidegun-wakeup4-630k-20260606T013446Z` measured 607583
positive replies, so the common requester-side improvement widened the
apples-to-apples Knot lead. BoronDNS interval 8 with counter-free objects at
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
629869 replies/s and BoronDNS AF_XDP with interval 1 measured 629848 replies/s,
both at 99.998413% replies. In
`physical-udp-knot-comparison-20260606T015652Z` at 900k, Knot XDP measured
899740 replies/s and BoronDNS interval 1 measured 899751 replies/s, both at
99.998422%. At 1.2M, interval 1 still trailed Knot in
`physical-udp-knot-comparison-20260606T015741Z` with 1199614 replies/s versus
1199750, and interval 4 at
`physical-udp-knot-comparison-20260606T015831Z` only reached 1199627. Interval
8 then reached 1199799 replies/s in
`physical-udp-knot-comparison-20260606T015903Z`, and the same-directory
Knot/BoronDNS comparison
`physical-udp-knot-comparison-20260606T015938Z` measured Knot XDP at 1199613
replies/s and BoronDNS AF_XDP at 1199624 replies/s with equal 99.998417% reply
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
measured 891911 replies/s at 100.000000% and BoronDNS AF_XDP measured 891732
replies/s at 99.999114%. In
`physical-udp-knot-comparison-20260606T022319Z` at requested 1.2M, Knot XDP
measured 1183863 replies/s at 100.000000%, while BoronDNS AF_XDP measured
1184869 replies/s at 100.000000%. Keep retaining kxdpgun rows for historical
promotion continuity, but `BORONDNS_PHYSICAL_PLAYER_TOOL=oxide-gun` is now
usable for project-owned requester comparisons.
Reverse-role 25G testing showed that source-port steering is target-port
specific and must also cover the server NIC queue count. The first fair
per-target source-list comparison,
`physical-udp-knot-comparison-20260606T034145Z`, calibrated Knot port 5301 and
BoronDNS port 5300 separately, but bound BoronDNS AF_XDP to only 48 queues on a
63-RX-queue server NIC; several requester queues received zero replies and the
row retained only 77.083247%. Repeating with 63 AF_XDP server workers and
`xdp.tx_wakeup_interval = 1` in
`physical-udp-knot-comparison-20260606T034338Z` restored BoronDNS to 2454930
replies/s at 99.942036%, but Knot XDP still measured 2456673 replies/s at
99.998824%. Treat this as evidence that MTU was controlled, not causal: both
hosts were run at temporary MTU 1500 for native XDP and restored to 9000 by the
harness. The next XDP slice needs to reduce the remaining scattered AF_XDP
reply misses before this reverse-role profile can be promoted as a Knot-XDP
win. After retaining AF_XDP packet-I/O counters under `hot_path_detail = "off"`,
`physical-udp-knot-comparison-20260606T035249Z` showed the remaining 793
unanswered queries matching the NIC `rx_out_of_buffer` delta: BoronDNS received
12332263 AF_XDP packets and queued 12332263 AF_XDP TX packets, so the immediate
loss is before userspace receives the request, not in server response TX.
The next calibration pass also made MTU a hard setup check:
`physical-udp-knot-comparison-20260606T041346Z` failed AF_XDP bind with
`EINVAL` when zero-copy was attempted on the jumbo-MTU server link. Re-running
with `BORONDNS_PHYSICAL_XDP_MTU=1500` and
`BORONDNS_PHYSICAL_KXDPGUN_MTU=1500` in
`physical-udp-knot-comparison-20260606T041857Z` succeeded at 495049 replies/s
and 100.000000% for a low-rate calibration row, produced 512
`borondns_udp_worker_source_port_datagrams_total` entries, and mapped the
previous 48-port BoronDNS reverse list onto only 27 server RX workers with as
many as three ports on one worker. A matched replacement list that used 48
distinct server RX workers did not improve saturation:
`physical-udp-knot-comparison-20260606T042049Z` measured Knot XDP at 2456814
replies/s and 99.999400%, while BoronDNS AF_XDP measured 2454059 replies/s and
99.898743%; the row still showed request-side AF_XDP loss before userspace, so
future tuning should use the source-port map to avoid saturated or poorly
serviced queues rather than merely maximizing distinct server workers.
The follow-up single-port substitution attempt was invalid as a fair comparison
when `physical-udp-knot-comparison-20260606T042816Z` failed before traffic:
the standard Knot primary inside the BoronDNS row could not bind TCP 5301, then
BoronDNS stayed in `LOADING`. The physical harness cleanup now kills recorded
artifact pid files before name-based cleanup so renamed benchmark binaries do
not survive failed AF_XDP runs and keep ports or XDP state pinned.
After that cleanup fix, the previous 48-port reverse BoronDNS list remained the
best source-port baseline but still missed the reply-percent gate:
`physical-udp-knot-comparison-20260606T043500Z` measured Knot XDP at 2455879
replies/s and 100.000000%, while BoronDNS AF_XDP measured 2457000 replies/s and
99.994033%; only ports 53496 and 53501 missed replies, and the root
`rx_out_of_buffer` delta matched the 736 unanswered queries. Capacity knobs
were mixed: `BORONDNS_PHYSICAL_XDP_UMEM_FRAME_COUNT=32768` alone regressed to
99.979601% in `physical-udp-knot-comparison-20260606T043655Z`;
`BORONDNS_PHYSICAL_XDP_RING_SIZE=8192` alone produced a 100.000000% Oxide-only
row in `physical-udp-knot-comparison-20260606T043819Z` but failed the fair
Knot-XDP row at 99.988168% in `physical-udp-knot-comparison-20260606T043912Z`.
Combining ring size 8192 with UMEM frame count 32768 nearly cleared an
Oxide-only row at 99.999951% in
`physical-udp-knot-comparison-20260606T044042Z`, but still failed in both fair
orders: Knot-first `physical-udp-knot-comparison-20260606T044138Z` measured
BoronDNS at 99.932622%, and BoronDNS-first
`physical-udp-knot-comparison-20260606T044354Z` measured BoronDNS at
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
`borondns_af_xdp_worker_received_packets_total` and
`borondns_af_xdp_worker_sent_packets_total`. Despite the stable historical
metric name, that counter means packets admitted to AF_XDP TX rings, not
confirmed wire delivery; kick delivery failures are reported separately by
`borondns_af_xdp_tx_delivery_failures_total`. The reverse-role diagnostic row
`physical-udp-knot-comparison-20260606T045650Z` measured BoronDNS AF_XDP at
2455876 replies/s and 99.960788%; the server received and queued 12328220
AF_XDP packets, but only 27 of 63 server workers were active. Active workers
ranged from 256000 to 772096 received packets, with matching TX-ring admission
counts. That keeps MTU lower on the suspect list for this row because the run
used temporary native-XDP MTU 1500 and the server worker receive/admission totals
matched; the next useful receive-path work should instead target queue service,
fill lifecycle, or source-port lists that avoid overloading the hot AF_XDP
workers without repeating the distinct-worker regression.
The physical harness now performs targeted row-local cleanup before every Knot,
Knot-XDP, and BoronDNS row. This was needed after
`physical-udp-knot-comparison-20260606T050523Z`: the Knot-XDP row completed, but
the following BoronDNS row failed before traffic because TCP 5301 was still
unavailable for the local Knot primary. With the cleanup fix,
`physical-udp-knot-comparison-20260606T050912Z` completed the same Knot-first
reverse-role comparison. Knot XDP measured 2457197 replies/s at 100.000000%;
BoronDNS AF_XDP with `xdp.tx_wakeup_interval = 8` measured 2454981 replies/s at
99.998044%. The opposite order in
`physical-udp-knot-comparison-20260606T051026Z` was worse for BoronDNS
AF_XDP, at 2456094 replies/s and 99.972494%, while Knot XDP again reached
100.000000%. Further wakeup-cadence probes did not promote a stable win:
`physical-udp-knot-comparison-20260606T051129Z` with interval 4 fell to
99.932661%; `physical-udp-knot-comparison-20260606T051211Z` with interval 16
cleared an Oxide-only row at 100.000000%, but the fair Knot-first row
`physical-udp-knot-comparison-20260606T051259Z` measured BoronDNS at
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
`physical-udp-knot-comparison-20260606T052658Z`, measured BoronDNS AF_XDP at
2456483 replies/s and 100.000000%; the server reported 48 active AF_XDP
workers with received and sent packet ranges of 256000 to 258048 packets.
The fair Knot-first comparison,
`physical-udp-knot-comparison-20260606T052751Z`, measured Knot XDP at
2457093 replies/s and 99.983058%, while BoronDNS AF_XDP measured
2454219 replies/s and 100.000000%. The reverse order,
`physical-udp-knot-comparison-20260606T052910Z`, measured BoronDNS AF_XDP at
2456797 replies/s and 100.000000%, while Knot XDP measured 2454823 replies/s
and 99.980519%. This makes the reverse-role AF_XDP profile stronger on the
reply-percentage gate in both orders and stronger on retained replies/s in the
BoronDNS-first order, but reply-rate dominance remains order-sensitive until
the forward role is repeated with the same per-target calibration discipline.
MTU remains a hard setup requirement, not the current receive-path explanation:
jumbo MTU failed zero-copy bind in the earlier `041346Z` row, while all of the
successful native-XDP rows above forced MTU 1500 during traffic and restored
MTU 9000 during cleanup.
Forward-role calibration uses the same per-target discipline but has a
different queue-count shape: `borondns-1` has 48 server RX queues and
`oxidegun-1` has 63 requester RX queues. The BoronDNS reduced calibration row
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
1186767 replies/s and 100.000000%, while BoronDNS AF_XDP measured
1186917 replies/s and 100.000000%; `physical-udp-knot-comparison-20260606T054612Z`
measured BoronDNS AF_XDP at 1187820 replies/s and 100.000000%, while Knot XDP
measured 1186803 replies/s and 100.000000%.
The forward ceiling is still lower than the reverse-role 2.5M proof point.
At requested 1.8M in `physical-udp-knot-comparison-20260606T055210Z`, both rows
kept 100.000000%, but Knot XDP retained 1770170 replies/s while BoronDNS AF_XDP
retained 1768573 replies/s. Server TX wakeup probes at the same rate were
close but not promoted: interval 1 reached 1769056 replies/s, interval 4
reached 1767983, and interval 16 reached 1769979. At requested 2.5M in
`physical-udp-knot-comparison-20260606T054110Z`, Knot XDP measured
2002643 replies/s at 99.344390%, while BoronDNS AF_XDP measured
1915610 replies/s at 98.907538%; the requester only transmitted about
2.02M qps to Knot and about 1.94M qps to BoronDNS, so the high-rate row is also
limited by oxide-gun AF_XDP requester service, not only by server DNS work.
Two negative counterprobes should not be repeated as fixes: a 48-port list with
requester `queue_count=48` gave perfect 48-worker server balance but only
76.973998% replies in `physical-udp-knot-comparison-20260606T054357Z`, and an
absolute-deadline requester pacer overran requester RX. The latter sent enough
traffic for BoronDNS to queue 12200233 AF_XDP replies in
`physical-udp-knot-comparison-20260606T054928Z`, but both Knot and BoronDNS
fell to about 60% replies; increasing requester RX drain to 64 in
`physical-udp-knot-comparison-20260606T055048Z` still only reached 63.255592%.
The explicit requester pace-wait fraction knob is retained as a diagnostic
control but is not promoted for this profile. Fractions below the default 1.0
showed the same starvation curve at requested 2.5M: 0.875 in
`physical-udp-knot-comparison-20260606T060112Z` reached 1957581 replies/s but
only 97.625263%, 0.75 in `physical-udp-knot-comparison-20260606T060137Z`
reached 1956853 replies/s at 95.454946%, and 0.625 in
`physical-udp-knot-comparison-20260606T060202Z` fell to 1907030 replies/s at
89.960603%. Smaller requester batches were not a fix either: batch 512 in
`physical-udp-knot-comparison-20260606T055803Z` measured 1953259 replies/s at
98.507922%, and batch 256 in `physical-udp-knot-comparison-20260606T055828Z`
measured 1944505 replies/s at 98.810773%. Extending final reply drain to
3000 ms in `physical-udp-knot-comparison-20260606T060423Z` measured
1960352 replies/s at 98.841880%, and server ring size 8192 with UMEM frame
count 32768 in `physical-udp-knot-comparison-20260606T060449Z` measured
1931262 replies/s at 98.401731%, so the forward 2.5M miss is not just late
drain timeout or a simple server ring-capacity issue. An elapsed-aware variant
that subtracted worker packet-build/TX/RX time from the paced wait but kept a
minimum RX-drain fraction was also negative and was not kept:
`physical-udp-knot-comparison-20260606T060944Z` with a 0.5 minimum drain
fraction measured 1951746 replies/s at 94.338649%, and
`physical-udp-knot-comparison-20260606T061009Z` with a 0.25 minimum drain
fraction measured 1872723 replies/s at 90.398396%.
The next forward-rate work should keep the relative paced-wait requester shape
and instead reduce per-queue AF_XDP service cost or improve requester TX/RX
co-scheduling without starving reply drain. Weighted source-list selection is
useful but not sufficient by itself. Weighting the `053738Z` calibration with
the original 2.5M `054110Z` requester TX counts selected a list with modeled
server weight max 299008 instead of 344064; the Oxide-only row
`physical-udp-knot-comparison-20260606T061301Z` improved to 1984720 replies/s
and 99.161520%, but still did not clear the retained Knot-XDP row. Reweighting
again from `061301Z` did not promote a win:
`physical-udp-knot-comparison-20260606T061429Z` measured 1963786 replies/s and
99.082266%.
Requester-side packet counters now make the forward 2.5M loss mode concrete.
The physical wrapper retains per-row requester `/proc/net/dev`,
`/proc/net/softnet_stat`, and `ethtool -S` before/after snapshots, and the
summary includes requester packet, PHY, softnet, and selected XSK deltas.
With the first weighted list repeated in
`physical-udp-knot-comparison-20260606T062221Z`, BoronDNS AF_XDP measured
1974391 replies/s at 99.080636%; the requester reported 10017792 AF_XDP TX
packets, but its NIC `tx_packets_phy` delta was only 9925696 and the server
reported 9925692 AF_XDP packets received and queued for TX. The 92096
requester-TX-minus-physical gap matched the 92100 unanswered queries, while
requester/server PHY counters showed zero discards and no oversize packets.
That rules out MTU, fragmentation, and server receive loss for this row; the
lost denominator is before or inside the requester AF_XDP TX path.
`oxide-gun` now also reports AF_XDP TX completion counters. Repeating the same
row with the completion-instrumented requester in
`physical-udp-knot-comparison-20260606T062634Z` measured 1956164 replies/s at
99.205756%; the requester reported 9912320 submitted TX packets, 9577445 TX
completions dequeued by summary time, 334875 outstanding completions, and
9833596 requester PHY TX packets. Completion dequeue lag is therefore larger
than the unanswered gap and should be treated as a frame-reclamation pressure
signal, not as a direct physical-TX counter. Continue forward 2.5M work in
oxide-gun's AF_XDP TX service/pacing path before spending time on additional
MTU tuning.
The requester now performs a bounded final AF_XDP TX kick/dequeue pass after
the active send window and before the final reply drain. With the original
weighted list in `physical-udp-knot-comparison-20260606T063620Z`, BoronDNS
AF_XDP measured 1996807 replies/s at 99.998747%; requester
`tx_packets_total` was 10054656, requester `tx_packets_phy` was 10054662, the
server received 10054530 AF_XDP packets, and only 126 queries were unanswered.
That confirms the previous 80k-90k unanswered gap was primarily unflushed
requester TX descriptors rather than MTU, link, or server receive loss.
Under a same-requester Knot-XDP comparison in
`physical-udp-knot-comparison-20260606T063825Z`, Knot XDP measured
1998934 replies/s at 100.000000%, while BoronDNS AF_XDP measured
1970490 replies/s at 100.000000%. Server `xdp.tx_wakeup_interval = 16`
improved the cleaned Oxide-only row in
`physical-udp-knot-comparison-20260606T063946Z` to 1997976 replies/s at
100.000000%, but interval 32 regressed in
`physical-udp-knot-comparison-20260606T064033Z` to 1980765 replies/s.
Reweighting the source list from the cleaned `063620Z` row also regressed:
`physical-udp-knot-comparison-20260606T063730Z` measured 1950940 replies/s at
100.000000%. Keep the final requester flush because it restores a truthful
reply-percent denominator; do not claim the forward 2.5M goal is complete until
BoronDNS clears the same-requester Knot row in both run orders.
Repeating the full comparison with server `xdp.tx_wakeup_interval = 16` cleared
that forward-role gate in both orders. In
`physical-udp-knot-comparison-20260606T064300Z` with Knot first, Knot XDP
measured 1976298 replies/s at 100.000000%, while BoronDNS AF_XDP measured
1982288 replies/s at 100.000000%. In
`physical-udp-knot-comparison-20260606T064408Z` with BoronDNS first, BoronDNS
AF_XDP measured 1975927 replies/s at 100.000000%, while Knot XDP measured
1950136 replies/s at 100.000000%. Promote `xdp.tx_wakeup_interval = 16` for the
cleaned forward 2.5M profile, while keeping interval 8 as historical evidence
for earlier requester shapes.

A refreshed reverse-role pass with the fixed requester moved the remaining
miss back to server AF_XDP receive pressure rather than requester TX drain or
MTU. `physical-udp-knot-comparison-20260606T064802Z` used the reverse balanced
source list with the original 4096-ring/16384-frame profile and measured Knot
XDP at 2456713 replies/s and 99.982406%, while BoronDNS AF_XDP measured
2452517 replies/s and 99.906255%. The requester reported all 12322816 packets
completed with zero outstanding TX completions, while the server NIC reported
`rx_xsk_buff_alloc_err=6846` and `rx_out_of_buffer=9289`; this makes the miss a
server receive/fill shortage before userspace, not a final requester-flush or
MTU symptom. Increasing BoronDNS to ring size 8192, UMEM frame count 32768, and
`xdp.tx_wakeup_interval = 16` improved the loss mode but did not clear the
Knot-first row: `physical-udp-knot-comparison-20260606T065117Z` measured Knot
XDP at 2457188 replies/s and 99.988122%, while BoronDNS AF_XDP measured
2454751 replies/s and 99.991690%; the remaining 1024 unanswered queries matched
the server NIC `rx_out_of_buffer` delta. A larger 16384-ring/65536-frame probe
regressed to 2453818 replies/s at 99.997662%, so treat 8192/32768 as the useful
capacity step for this reverse host.

The next receive-path slice replenishes the AF_XDP fill ring before returning a
full userspace receive batch. This keeps spare UMEM frames visible to the NIC
while the worker builds responses for the current full batch, addressing the
single-batch `rx_out_of_buffer` signature without changing partial-batch return
paths. With the same reverse 8192/32768, interval-16 profile,
`physical-udp-knot-comparison-20260606T071132Z` measured BoronDNS AF_XDP at
2456286 replies/s and 100.000000% in an Oxide-only row. The fair Knot-first
row, `physical-udp-knot-comparison-20260606T071226Z`, measured Knot XDP at
2458300 replies/s and 99.998444%, while BoronDNS AF_XDP measured
2456011 replies/s and 100.000000%. This improves the reverse reply-percentage
gate but does not yet make reverse retained QPS dominant in Knot-first order.
An explicit reverse source-list recalibration
(`physical-udp-knot-comparison-20260606T070302Z`) confirmed the old reverse list
was already one port per requester queue and one port per active server worker;
the newly selected 48-port list regressed slightly at high rate
(`physical-udp-knot-comparison-20260606T070416Z`, 2454957 replies/s at
100.000000%). A reverse 48-worker server probe was invalid for this port list
because packets targeted queues above 47 and reply percentage fell to
87.494803%. The harness now supports explicit sparse server queue ids through
`BORONDNS_PHYSICAL_XDP_QUEUE_IDS`, but binding only the 48 calibrated active
queues was also not a QPS win: sorted sparse queue order measured
2454072 replies/s at 100.000000% in
`physical-udp-knot-comparison-20260606T072347Z`, while source-port order
measured 2455770 replies/s at 100.000000% in
`physical-udp-knot-comparison-20260606T072440Z`. Keep the contiguous 63-queue
profile for the current reverse comparison. Interval 32 also regressed
(`physical-udp-knot-comparison-20260606T070506Z`, 2453259 replies/s at
99.969691%).

MTU remains a setup gate rather than the active reverse bottleneck. All
successful native-XDP rows above forced the server and requester links to MTU
1500 during traffic and restored them to MTU 9000 during cleanup; the failing
reverse rows instead correlate with AF_XDP fill counters. Code-generation probes
also do not explain the gap yet: a workstation `target-cpu=native` binary failed
on the Intel reverse server with `Illegal instruction`, and an explicit
`target-cpu=skylake-avx512` binary was compatible but regressed to 2453199
replies/s at 99.969088%. The follow-up reverse work should focus on reducing
userspace AF_XDP packet cost or changing the requester/server batching model,
not more MTU or RSS port-list tuning. A forward Oxide-only replay with the
actual `064300Z` calibrated port list and the full-batch refill binary,
`physical-udp-knot-comparison-20260606T071525Z`, measured 2015954 replies/s at
100.000000%, so this receive-path slice does not invalidate the existing
forward-role proof.

The requester zero-copy follow-up confirmed that burst shape, not MTU, explains
the next reverse-role failure mode. With both hosts forced to temporary MTU
1500, `BORONDNS_PHYSICAL_OXIDE_GUN_XDP_ZERO_COPY=force`, and the previous
requester batch size 1024, `physical-udp-knot-comparison-20260606T073704Z`
measured Knot XDP at 2447952 replies/s and 99.813565%, but BoronDNS AF_XDP fell
to 1946130 replies/s and 79.431881%. The BoronDNS row still completed all
requester TX descriptors, but the server only received 9851056 AF_XDP packets
and the NIC reported 2299123 `rx_xsk_xdp_drop` deltas plus link pause frames,
which points to burst-induced server RX pressure. Repeating the same reverse
Knot-first row with requester batch size 64 in
`physical-udp-knot-comparison-20260606T073956Z` removed that loss signature:
Knot XDP measured 2359830 replies/s at 99.990240%, while BoronDNS AF_XDP
measured 2369759 replies/s at 100.000000%. The same reverse profile is not
BoronDNS-first clean: `physical-udp-knot-comparison-20260606T085700Z` measured
BoronDNS AF_XDP at 2369246 replies/s and 99.999460%, while Knot XDP reached
2364411 replies/s and 100.000000%; repeating it in
`physical-udp-knot-comparison-20260606T085831Z` measured BoronDNS AF_XDP at
2368449 replies/s and 99.995138%, while Knot XDP reached 2370729 replies/s and
100.000000%. Keep requester batch 64 as the least-bad zero-copy reverse setting
for the older requester binary, but do not treat that binary as a retained
both-order reverse win. Rebuilding and deploying the current committed
`oxide-gun` requester, while keeping the same source list and server profile,
made the reverse zero-copy row gate-clean in both orders:
`physical-udp-knot-comparison-20260606T090123Z` measured BoronDNS-first at
2363658 replies/s and 100.000000%, while Knot XDP reached 2362726 replies/s and
100.000000%; `physical-udp-knot-comparison-20260606T090249Z` measured Knot-first
at 2363575 replies/s and 100.000000%, while BoronDNS AF_XDP reached
2370320 replies/s and 100.000000%. Promote the current requester binary plus
batch 64 as the reverse zero-copy comparison profile, but keep the margin caveat
because both wins are narrow.

Forward-role zero-copy steering checks on 2026-06-06 did not identify MTU as
the active limiter. `physical-udp-knot-comparison-20260606T080632Z` used
OxideGun sparse queue binding with 48 calibrated requester queues and one source
port per server AF_XDP worker at XDP MTU 1500; it reached 2288619 replies/s at
100.000000%, with AF_XDP worker packet counts tightly spread from 236224 to
241984. Increasing requester fanout while keeping calibrated queue/source-port
ordering improved throughput but did not beat the forward Knot XDP reference:
56 queues in `physical-udp-knot-comparison-20260606T080851Z` reached 2317499
replies/s at 100.000000%, and 60 queues in
`physical-udp-knot-comparison-20260606T080942Z` reached 2321292 replies/s at
100.000000%. In the same comparison setup, the retained forward Knot XDP row in
`physical-udp-knot-comparison-20260606T075217Z` was 2349033 replies/s at
100.000000%. Treat source-port/RSS steering as exhausted for this forward
zero-copy slice; the next improvement needs a server/requester packet-I/O
change rather than MTU or multi-buffer work for these small DNS packets.

Keeping the earlier 63-flow high-rate BoronDNS source list while moving the
server AF_XDP capacity profile to ring size 8192 and UMEM frame count 32768
restored forward-role headroom. The Oxide-only probe
`physical-udp-knot-comparison-20260606T082354Z` reached 2404179 replies/s at
100.000000%. The fair Knot-first comparison
`physical-udp-knot-comparison-20260606T082449Z` measured Knot XDP at 2341327
replies/s and 100.000000%, while BoronDNS AF_XDP measured 2400687 replies/s and
100.000000%. The first BoronDNS-first attempt with that exact source list was
not order-robust:
`physical-udp-knot-comparison-20260606T082612Z` measured BoronDNS-first at
2393526 replies/s and 99.997862%, then Knot XDP at 2401280 replies/s and
100.000000%. Parsing the requester queue JSON showed only requester queues 5
and 41 missed replies, by 128 replies each, and both calibrated source ports
mapped to server AF_XDP worker 40. Replacing the queue-5 source port `53727`
with the weighted calibration alternative `53087` kept the high-rate list
mostly intact and passed both run orders at the same temporary XDP MTU 1500:
`physical-udp-knot-comparison-20260606T083657Z` measured BoronDNS-first at
2398763 replies/s and 100.000000%, then Knot XDP at 2397750 replies/s and
100.000000%; `physical-udp-knot-comparison-20260606T084306Z` measured
Knot-first at 2367847 replies/s and 100.000000%, then BoronDNS AF_XDP at
2402461 replies/s and 100.000000%. More aggressive one-port repairs that moved
other doubled workers also cleared loss but reduced BoronDNS to 2.30-2.34M
replies/s. The selector-targeted worker-40 repair candidate `53727` -> `53205`
behaved the same way in `physical-udp-knot-comparison-20260606T085330Z`:
BoronDNS AF_XDP reached 2326578 replies/s at 100.000000%, while Knot XDP
reached 2362108 replies/s at 100.000000%. Treat `--repair-existing
--repair-server-worker` as a candidate generator, not a promotion rule. The
retained conclusion is source-port/queue weighting, not MTU or multi-buffer
work, for these small DNS packets. Promote 8192/32768 plus the weighted queue-5
source-port repair `53087` as the current forward physical comparison profile,
but keep requiring repeated 100% reply rows because the raw QPS margin can be
narrow in BoronDNS-first order.

Rechecking the promoted forward profile after rebuilding both the server binary
and the project-owned requester kept the same conclusion and exposed one Knot
packaging caveat. Ubuntu-packaged Knot 3.5.3 reports `XDP support: libxdp` and
starts XDP in native mode, but rejects the newer `xdp.zero-copy` configuration
item; keep `BORONDNS_PHYSICAL_KNOT_XDP_ZERO_COPY=__omit__` for that package and
use `knot-version.txt` plus `server-bpftool-net-*-benchmark.txt` to retain the
actual mode evidence. With BoronDNS commit `acd8c7fb`, current `oxide-gun`, the
extracted high-rate source-port list, requester zero-copy forced, server
ring-size 8192, UMEM frame count 32768, server batch 1024, and
`xdp.tx_wakeup_interval = 16`, both run orders passed at requested 2.5M:
`physical-udp-knot-comparison-20260606T191956Z` measured BoronDNS-first at
2399795 replies/s and 100.000000%, then Knot XDP at 2337671 replies/s and
100.000000%; `physical-udp-knot-comparison-20260606T192112Z` measured
Knot-first at 2331951 replies/s and 100.000000%, then BoronDNS AF_XDP at
2402522 replies/s and 100.000000%. A deliberately untuned default-source run at
`physical-udp-knot-comparison-20260606T191530Z` still showed order-sensitive
loss, and the low-rate calibration list in
`physical-udp-knot-comparison-20260606T191831Z` cleared loss but lost retained
QPS to Knot; do not replace the high-rate list with the earlier calibration
list for promotion rows.

Running the same high-rate profile against the existing source-built Knot
install at `/home/codex/knot-xdp-3.5.4/sbin/knotd` reversed that packaged-Knot
result. The source build reports Knot DNS 3.5.4 configured with
`--enable-xdp=yes`, `XDP support: libxdp`, and accepts `zero-copy: on` in the
generated XDP config. In
`physical-udp-knot-comparison-20260606T194258Z`, BoronDNS-first measured
BoronDNS AF_XDP at 2328733 replies/s and 100.000000%, while source-built Knot
XDP reached 2345938 replies/s and 100.000000%. In
`physical-udp-knot-comparison-20260606T194416Z`, Knot-first measured
source-built Knot XDP at 2366863 replies/s and 100.000000%, while BoronDNS
AF_XDP reached 2325380 replies/s and 100.000000%. Treat the packaged-Knot rows
above as a useful compatibility comparison, not the final "better than Knot XDP"
claim. The active performance gap is now against source-built Knot XDP with
server-side zero-copy enabled.

Repeating the source-built Knot profile twice in both orders with
`scripts/physical-xdp-source-knot-profile.sh` confirmed that the active gap is
small but still order-sensitive, and that reply percentage remains a gate. In
BoronDNS-first artifacts `physical-udp-knot-comparison-20260606T200457Z` and
`physical-udp-knot-comparison-20260606T200627Z`, BoronDNS AF_XDP measured
2356012 and 2346111 replies/s while source-built Knot XDP measured 2399713 and
2400083 replies/s. The second BoronDNS-first row returned 99.998909% replies,
so it does not satisfy the promotion gate even though server qdisc drops,
softnet drops, and requester PHY drops stayed at zero. In knot-first artifacts
`physical-udp-knot-comparison-20260606T200541Z` and
`physical-udp-knot-comparison-20260606T200713Z`, source-built Knot XDP measured
2367680 and 2390959 replies/s while BoronDNS AF_XDP measured 2405783 and
2404190 replies/s, all at 100.000000% replies. Across the four artifacts,
BoronDNS averaged 2378024 replies/s and source-built Knot averaged 2389609
replies/s; do not claim parity or a win until both orders clear the 100% reply
gate with lower variance.

A profiling/counter pass on the same source-built profile found that process-PID
`perf record` produced no samples for the BoronDNS worker threads, so the
physical wrapper now supports row-local system-wide profiling with
`BORONDNS_PHYSICAL_PERF_SCOPE=system` and explicit software sampling through
`BORONDNS_PHYSICAL_PERF_EVENT=cpu-clock`. With a locally deployed unstripped
profiling binary at `/home/codex/borondns-tools/xdp-profile/borondns`,
`physical-udp-knot-comparison-20260606T201444Z` captured 22458 cpu-clock
samples. Most system-wide samples were idle CPUs, but the symbolized BoronDNS
worker samples were led by
`borondns_core::dns::DomainName::parse_with_ascii_lowercase`,
`borondns_server::udp::handle_udp_datagram`,
`borondns_server::af_xdp::write_udp_ip_response`,
`borondns_server::af_xdp::parse_udp_ip_frame`, ZoneImage lookup, hashing, and
allocator/free paths. That evidence supports later packet/DNS hot-path work,
but the row also missed 128 requester replies while the server AF_XDP worker
received/sent counters matched, so the next slice first tested transport
cadence and requester drain knobs rather than changing DNS layout.

The no-code source-built sweep found a gate-clean profile. Raising
`BORONDNS_PHYSICAL_OXIDE_GUN_RESPONSE_TIMEOUT_MS` from 1000 to 2000 cleared the
reply gate in `physical-udp-knot-comparison-20260606T201657Z`, but BoronDNS
still trailed source-built Knot narrowly. Keeping the 2000 ms drain and lowering
server `xdp.tx_wakeup_interval` from 16 to 8 cleared the gate and improved the
overall average, but the repeated `1024`-batch profile still lost the
knot-first average: artifacts `physical-udp-knot-comparison-20260606T201900Z`,
`201948Z`, `202045Z`, and `202143Z` all returned 100.000000%, with BoronDNS
averaging 2395169 replies/s and source-built Knot averaging 2389879 replies/s,
but BoronDNS trailed the two knot-first rows on average. Reducing the server
AF_XDP batch to 512 while keeping `xdp.tx_wakeup_interval = 8` and requester
drain timeout 2000 ms then passed both orders in two consecutive passes:
`physical-udp-knot-comparison-20260606T202300Z` measured knot-first Knot XDP at
2354014 replies/s and BoronDNS AF_XDP at 2394584 replies/s;
`physical-udp-knot-comparison-20260606T202348Z` measured BoronDNS-first
BoronDNS at 2404016 replies/s and Knot XDP at 2398056 replies/s;
`physical-udp-knot-comparison-20260606T202500Z` measured BoronDNS-first
BoronDNS at 2406179 replies/s and Knot XDP at 2401377 replies/s; and
`physical-udp-knot-comparison-20260606T202558Z` measured knot-first Knot XDP at
2396931 replies/s and BoronDNS AF_XDP at 2401565 replies/s. All four rows
returned 100.000000% replies with no requester/server PHY discards or softnet
drops. Promote the source-built comparison profile to server batch 512,
`xdp.tx_wakeup_interval = 8`, and requester final drain timeout 2000 ms; keep
the symbolized perf evidence as the next code-path map if the margin regresses.
The requester final-drain loop now waits for AF_XDP RX readiness instead of
blindly sleeping after an empty drain pass. This is a measurement-quality fix,
not a promoted server-throughput change: with the response timeout reduced back
to 1000 ms, the candidate still returned 100.000000% replies in both run orders
in `physical-udp-knot-comparison-20260606T203907Z`,
`physical-udp-knot-comparison-20260606T203953Z`,
`physical-udp-knot-comparison-20260606T204220Z`, and
`physical-udp-knot-comparison-20260606T204306Z`, but throughput remained within
the same noisy source-built Knot comparison band. Keep the source-built
promotion wrapper at 2000 ms unless shorter-drain rows are explicitly being
tested.

Follow-up probes after that slice did not find another no-code promotion knob.
The fresh symbolized profiling row
`physical-udp-knot-comparison-20260606T210427Z`, using an unstripped server
binary built from commit `136a4a9d`, measured BoronDNS AF_XDP at 2403738
replies/s and 100.000000%. System-wide `cpu-clock` captured 240256 samples with
no lost samples; most samples were idle CPUs, and the visible BoronDNS worker
costs remained `DomainName::parse_with_ascii_lowercase`, allocator
`malloc`/`cfree`, `udp::handle_udp_datagram`,
`af_xdp::write_udp_ip_response`, `af_xdp::parse_udp_ip_frame`, ZoneImage
lookup, and hashing. Server AF_XDP batch probes around the promoted 512 point
did not improve it: `physical-udp-knot-comparison-20260606T210755Z` with batch
384 measured 2290696 replies/s, `physical-udp-knot-comparison-20260606T210824Z`
with batch 640 measured 2329985 replies/s, and
`physical-udp-knot-comparison-20260606T210855Z` with batch 768 measured
2402146 replies/s, all at 100.000000%. An allocator preload probe using
`LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2` in
`physical-udp-knot-comparison-20260606T210954Z` regressed to 2331010 replies/s
at 100.000000%. Treat the next plausible gain as response ownership/copy
avoidance or DNS name/layout work; do not keep cycling allocator preloads or
nearby batch values without new profile evidence.
A bounded reusable-response-buffer prototype was also tested and rejected. The
prototype added a direct ZoneImage answer path that wrote into caller-owned
buffers and recycled per-worker UDP response buffers after each send batch, but
kept the existing fallback composer for other response shapes. It passed local
core/server tests and built an AF_XDP release candidate, but the physical
same-profile comparison did not improve the source-built Knot gate:
`physical-udp-knot-comparison-20260606T213040Z` measured BoronDNS AF_XDP at
2365876 replies/s and source-built Knot XDP at 2393271 replies/s, both
100.000000%; `physical-udp-knot-comparison-20260606T213130Z` measured
source-built Knot XDP at 2403218 replies/s and BoronDNS AF_XDP at 2399560
replies/s, again both 100.000000%. Do not reintroduce that partial buffer-pool
shape without a stronger direct-to-frame or broader composer redesign.
A follow-up direct-to-frame prototype was also rejected. That candidate skipped
the intermediate response `Vec` for AF_XDP-only direct ZoneImage answers by
copying the request payload aside, composing the DNS answer directly into the
received UMEM frame, and rewriting the UDP/IP headers in place. It passed local
core/server tests and an AF_XDP release build, but both source-built Knot
comparison orders regressed versus the promoted profile:
`physical-udp-knot-comparison-20260606T224214Z` measured BoronDNS AF_XDP at
2319432 replies/s and source-built Knot XDP at 2400236 replies/s, both
100.000000%; `physical-udp-knot-comparison-20260606T224312Z` measured
source-built Knot XDP at 2371387 replies/s and BoronDNS AF_XDP at 2322708
replies/s, again both 100.000000%. Treat direct-to-frame UMEM composition as a
negative slice unless a future design removes more orchestration cost than the
extra eligibility/probe/copy work adds.
A retained AF_XDP fixed-response diagnostic can be enabled with
`BORONDNS_BENCH_AF_XDP_FIXED_RESPONSE=1`. It is not production DNS behavior: it
bypasses request parsing, ZoneImage lookup, RRL, cookies, TSIG, and response
composition, then patches the incoming DNS ID into a fixed one-record positive
answer plus a minimal OPT record before the normal AF_XDP UDP/IP header
rewrite. Use it only to bound packet-I/O and frame-lifecycle cost on benchmark
hosts. After correcting the template to match the source-built profile's
65-byte DNS response size, it still did not expose a higher server ceiling:
`physical-udp-knot-comparison-20260606T233413Z` measured fixed-response
BoronDNS AF_XDP at 2330077 replies/s and 99.996705% while source-built Knot XDP
reached 2400926 replies/s and 100.000000%;
`physical-udp-knot-comparison-20260606T233500Z` measured source-built Knot XDP
at 2366292 replies/s and fixed-response BoronDNS AF_XDP at 2390161 replies/s,
both 100.000000%. Treat this as evidence that the present hardware/profile is
bounded mostly by AF_XDP userspace transport orchestration and requester/server
queue interaction, not ZoneImage composition, while preserving the diagnostic
for a future larger host pair. A system-wide CPU-clock perf comparison in
`physical-udp-knot-comparison-20260606T233726Z` successfully captured both Knot
XDP and BoronDNS AF_XDP rows; process-PID perf in
`physical-udp-knot-comparison-20260606T234106Z` produced no samples for either
server process on this host, so prefer `BORONDNS_PHYSICAL_PERF_SCOPE=system`
for this profile. A symbolized profiling BoronDNS row at
`physical-udp-knot-comparison-20260606T233949Z` still showed
`DomainName::parse_with_ascii_lowercase`, `udp::handle_udp_datagram`, malloc/
free, ZoneImage child lookup, `af_xdp::write_udp_ipv4_response`, and
`af_xdp::parse_udp_ip_frame`; the source-built Knot system row exposed
`knot_xdp_recv`, `knot_xdp_send`, `knot_xdp_reply_alloc`, and its DNS lookup/
packet assembly symbols. Knot's source XDP handler uses an explicit
prepare/receive/reply-allocate/receive-finish/send/send-finish batch lifecycle;
use that as the next packet-I/O design comparison point.
A separate-TX-frame prototype modeled that Knot ownership boundary and was
rejected. The candidate allocated a fresh UMEM frame for each AF_XDP reply,
copied the Ethernet/IP/UDP headers and DNS response into that TX frame, and
returned the RX frame before enqueueing TX, while falling back to same-frame
rewrite if the UMEM allocator was empty. It passed local AF_XDP server tests and
built a release binary, but the source-built Knot profile regressed:
`physical-udp-knot-comparison-20260607T003449Z` measured BoronDNS AF_XDP at
2290109 replies/s and source-built Knot XDP at 2316556 replies/s, both
100.000000%; `physical-udp-knot-comparison-20260607T003547Z` measured
source-built Knot XDP at 2400258 replies/s and BoronDNS AF_XDP at 2349159
replies/s, both 100.000000%. Treat separate TX frame allocation as negative
unless a future design also removes the extra userspace header copy and
allocation overhead.
An AF_XDP borrowed-RX-payload prototype was also rejected as not a clear gain.
That candidate kept the generic UDP path intact but routed bound AF_XDP
listeners through an AF_XDP-specific loop that parsed DNS directly from retained
UMEM payload bytes instead of copying the request payload into `UdpInbound`.
It passed local AF_XDP server tests and built a release binary, but the physical
rows stayed within noise or regressed: `physical-udp-knot-comparison-20260607T004311Z`
measured BoronDNS AF_XDP at 2361280 replies/s and source-built Knot XDP at
2389869 replies/s, both 100.000000%; `physical-udp-knot-comparison-20260607T004358Z`
measured source-built Knot XDP at 2367170 replies/s and BoronDNS AF_XDP at
2399427 replies/s, both 100.000000%. Do not reintroduce the raw borrowed-payload
loop unless profiling shows the inbound payload copy has become a primary cost.
Transport knob sweeps on the restored same-frame baseline did not produce a
default-worthy improvement. With `xdp.rx_drain_passes = 1`,
`xdp.tx_wakeup_interval = 1` measured 2400911 replies/s and 100.000000%;
interval 4 measured 2401046 replies/s and 100.000000%; interval 8 regressed to
2350451 replies/s and 100.000000%; and interval 16 measured 2398508 replies/s
and 100.000000%. Holding interval 4 and increasing RX drain pushed QPS higher
only by spending reply percentage: drain 1 measured 2402028 replies/s at
99.996804%, drain 2 measured 2405111 replies/s at 99.999468%, drain 4 measured
2401901 replies/s at 99.996804%, and drain 8 measured 2346102 replies/s at
99.990184%. A full source-built Knot comparison for drain 2 / interval 4 also
failed the primary gate: `physical-udp-knot-comparison-20260607T005018Z`
measured BoronDNS AF_XDP at 2401846 replies/s and 99.997869% while Knot XDP
held 2398198 replies/s and 100.000000%;
`physical-udp-knot-comparison-20260607T005117Z` measured Knot XDP at 2374210
replies/s and 100.000000% while BoronDNS AF_XDP reached 2398918 replies/s and
99.998400%. Keep the promoted AF_XDP profile at the lossless settings unless a
future host or requester pacing change removes this reply-percent tradeoff.

Use `[metrics].hot_path_detail = "reduced"` for observability-preserving runs.
Reduced mode also exposes
`borondns_udp_worker_source_port_datagrams_total{worker,source_port}`, which is
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

Normalize an BoronDNS benchmark artifact:

```bash
scripts/prepare-knot-comparison-benchmark.sh normalize-borondns \
  --artifact target/knot-comparison/example/evidence/borondns-idle-after-knot-transfer \
  --out target/knot-comparison/example/borondns-normalized.tsv
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
  BoronDNS local harness rows unless an external sender reports offered load.
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
2. Use the same `querydb` for Knot and BoronDNS runs.
3. Sweep offered rates rather than reporting one point.
4. Keep the same `-b`, `-F`, source IP range, target port, and duration across
   implementations.

For XDP promotion claims, include both `BORONDNS_PHYSICAL_INCLUDE_KNOT_XDP=true`
and `BORONDNS_PHYSICAL_BORONDNS_UDP_BACKENDS="af_xdp"` in the retained run, and
record whether BoronDNS `zero_copy=require` succeeds or fails on the selected
NIC/queue, plus the server `xdp.rx_drain_passes` and
`xdp.tx_wakeup_interval` used for each row. If zero-copy has to be relaxed to
`auto` or disabled, the row is engineering evidence only and should not be
described as the final Knot-XDP comparison.

The meaningful result is the saturation knee: the highest offered rate where
response percentage, drops/errors, p99/p999 latency, and byte throughput remain
inside the claimed acceptance envelope.
