# Comparing BoronDNS with Knot

Use one zone, one query mix, and a recorded host profile for both servers.
Measure answered queries as well as offered load: a higher send rate with
more lost replies is not automatically an improvement.

This page is the runbook. The [June 2026 tuning record](knot-tuning-2026-06.md)
holds the historical measurements, calibrated source-port lists, rejected
experiments, and artifact identifiers. Those results do not describe the
throughput of the current release.

## Choose the comparison

For a serving-path comparison, load BoronDNS by AXFR from Knot, wait for
readiness, then stop the primary before measuring the secondary. This keeps
transfer work out of the query measurement. Use the
[IXFR scaling report](ixfr-scaling-2026-08.md) when the workload includes live
updates, or the [BoronGen guide](boron-gen.md) for large synthetic zones.

Keep these controls equal or record why they differ:

| Control | What to retain |
| --- | --- |
| Workload | Source zone, serial, `querydb`, EDNS/DO mix, response sizes |
| Network path | Host roles, source/target IPs and ports, physical NIC, MTU, packet backend |
| Load | Requester version, offered rate, duration, batch size, source-port list, final drain time |
| CPU and queues | SMT, governor, IRQ/worker affinity, RSS, queue counts, RPS/XPS, NUMA policy |
| Server | Binary hash/commit, generated configuration, worker count, metrics detail, socket/XDP settings |
| Repetition | Both run orders and enough repeated rows to expose variation |

The wrapper defaults to port 5301 for Knot and 5300 for BoronDNS.
Since RSS can include the destination port, calibrate source-port lists
separately for each target. Repeat in reversed host roles before attributing a
host-specific improvement to the server implementation.

## Prepare the zone and query files

Run the preparation helper on the benchmark host with a real source zone:

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

The stage contains `primary.zone`, `knot.conf`, `borondns.toml`,
`querydb`, `query-trace.tsv`, and `runbook.sh`. Address defaults are
loopback; the physical wrapper prepares per-row configurations for the selected
link. Choose a worker count suitable for the host.

For query files alone:

```bash
scripts/prepare-knot-comparison-benchmark.sh querydb \
  --zone zones/example.zone --out target/knot-comparison/example --shuffle
scripts/prepare-knot-comparison-benchmark.sh trace \
  --querydb target/knot-comparison/example/querydb \
  --out target/knot-comparison/example
```

The generated runbook validates both configurations, transfers the zone,
checks SOA before and after stopping Knot, and optionally runs the local
load client:

```bash
cd target/knot-comparison/example
RUN_IDLE_BENCHMARK=true \
BENCH_DURATION=15 \
BENCH_THREADS=8 \
BENCH_WINDOW=64 \
BENCH_NETWORK_DEVICE=lo \
./runbook.sh
```

This is a local preflight. It expects a built BoronDNS release binary and
builds the load client with `rustc`; use the designated build/test host.
Setting `RUN_IDLE_BENCHMARK=false` checks transfer/readiness without a load
run. Loopback measurements are not physical-link throughput.

## Run the two-host socket comparison

Prepare the stage on the server and the requester tools on the traffic host.
The lab uses a direct 25 Gbit/s link at `198.18.0.1` and `198.18.0.2`.
Both SSH targets must work noninteractively, and the wrapper needs privileges
for its configured host/XDP setup.

```bash
BORONDNS_PHYSICAL_SERVER_SSH=oxidedns-1 \
BORONDNS_PHYSICAL_PLAYER_SSH=oxidegun-1 \
BORONDNS_PHYSICAL_SERVER_ROOT='~/borondns' \
BORONDNS_PHYSICAL_PLAYER_WORKDIR='~/borondns-tools/bench' \
BORONDNS_PHYSICAL_STAGE=target/knot-comparison/example \
BORONDNS_PHYSICAL_TARGET_IP=198.18.0.1 \
BORONDNS_PHYSICAL_SOURCE_IP=198.18.0.2 \
BORONDNS_PHYSICAL_INTERFACE=eno1np0 \
BORONDNS_PHYSICAL_INCLUDE_KNOT=true \
BORONDNS_PHYSICAL_WORKERS="12 16 24" \
BORONDNS_PHYSICAL_RATES="2000000 2500000 3000000" \
BORONDNS_PHYSICAL_DURATION=15 \
BORONDNS_PHYSICAL_HOT_PATH_DETAILS=off \
BORONDNS_PHYSICAL_IDLE_STRATEGIES=spin \
scripts/physical-udp-knot-comparison.sh
```

These are explicit example settings, not a universal best profile. The wrapper
defaults to server alias `borondns-1`, one 24-worker selection, a 2M offered
rate, five-second rows, and no Knot reference row unless enabled.

Each run gets an artifact directory under the stage's `evidence/` directory.
The wrapper starts Knot for the secondary's transfer, checks readiness,
stops the primary, then drives the measured row from the player. It retains
`summary.tsv`, server/client logs, configurations, version information, and
before/after host counters. It uses SSH control sockets during the run and
starts the timed player process independently of the polling connection.

For a long batch, `scripts/physical-udp-detached-batch.sh start` accepts the
same environment and prints its local run directory. Reconnect with:

```sh
scripts/physical-udp-detached-batch.sh status target/physical-detached-runs/YYYYMMDDTHHMMSSZ
```

That directory retains `command.txt`, `environment.txt`, `monitor.log`,
`harness.log`, the collected summary, and cleanup checks.

## Run an AF_XDP comparison

Select both `BORONDNS_PHYSICAL_INCLUDE_KNOT_XDP=true` and
`BORONDNS_PHYSICAL_BORONDNS_UDP_BACKENDS=af_xdp`. The AF_XDP path uses
Tokio/`park`; its worker count selects XDP queues, not reuseport sockets.
Bind all queues reachable by the chosen RSS/source-port setup, or supply an
explicit calibrated set with `BORONDNS_PHYSICAL_XDP_QUEUE_IDS`.

The main wrapper defaults to native driver mode, server zero-copy
`require`, ring size 8192, UMEM frame count 32768, batch size 1024,
RX drain passes 1, and TX wakeup interval 1. Native XDP on the recorded lab
NICs needed MTU 1500; set both server and requester MTUs explicitly when
reproducing that setup.

The source-built Knot convenience profile still contains a historical server
TX wakeup default of 8, which the current server rejects. Override it:

```bash
BORONDNS_PHYSICAL_SERVER_SSH=oxidedns-1 \
BORONDNS_PHYSICAL_PLAYER_SSH=oxidegun-1 \
BORONDNS_PHYSICAL_XDP_TX_WAKEUP_INTERVAL=1 \
BORONDNS_SOURCE_KNOT_REPEATS=3 \
BORONDNS_SOURCE_KNOT_ORDERS="borondns-first knot-first" \
scripts/physical-xdp-source-knot-profile.sh
```

Inspect that script's lab-specific binary paths, stage, and calibrated
source-port lists before running it. Its other defaults include source-built
Knot at `/home/codex/knot-xdp-3.5.4/sbin/knotd`, a 2.5M offered rate,
server batch 512, requester batch 64, forced requester zero-copy, MTU 1500
on both hosts, and a 2000 ms final requester drain. The interval-1 override
makes the configuration valid; it does not reproduce the historical
interval-8 performance result.

Retain the selected Knot version and generated `knot-xdp.conf`. The recorded
packaged Knot 3.5.3 rejected `xdp.zero-copy`, while the recorded source build
accepted it. The main wrapper omits that item by default; set
`BORONDNS_PHYSICAL_KNOT_XDP_ZERO_COPY=on` only for a compatible selected
binary. Requester defaults are `kxdpgun` with mode `auto`, or BoronGun
zero-copy `auto` when selected. Record copy/generic fallbacks explicitly.

## Calibrate the requester

Set `BORONDNS_PHYSICAL_PLAYER_TOOL=boron-gun` to use the project requester.
The wrapper detects its RX queue count by default. Keep
`BORONDNS_PHYSICAL_BORON_GUN_BIN` and
`BORONDNS_PHYSICAL_BORON_GUN_XDP_REDIRECT_OBJECT` explicit if the binaries
are outside the player tools directory.

For calibration, use a low-rate row with `hot_path_detail = "reduced"`.
Combine `borondns_udp_worker_source_port_datagrams_total{worker,source_port}`
with BoronGun's per-queue summary through:

```sh
scripts/select-boron-gun-source-ports.py /path/to/row-artifact \
  --existing-list '53000,53001,53002'
```

Retain both outputs, `queue_list=...` and `source_port_list=...`; a sparse
queue list cannot be replaced by a contiguous queue count. Pass target-specific
lists through `BORONDNS_PHYSICAL_BORON_GUN_KNOT_SOURCE_PORT_LIST` and
`BORONDNS_PHYSICAL_BORON_GUN_BORONDNS_SOURCE_PORT_LIST`, plus their matching
`*_QUEUE_LIST` settings. The selector supports `--requester-only` for Knot,
`--requester-weight-log` for saturation weighting, and `--server-exact` for
a one-flow-per-server-worker diagnostic. A `--repair-existing`
`--repair-server-worker` result is a candidate to measure, not evidence of
an improvement.

## Diagnose a regression

Start from a repeated baseline and change one hypothesis at a time. The
[historical ledger](knot-tuning-2026-06.md) records why many larger buffers,
different worker counts, pacing settings, and ownership prototypes were not
kept.

| Question | Relevant wrapper settings and evidence |
| --- | --- |
| Is time spent in the server or kernel? | `BORONDNS_PHYSICAL_SERVER_BIN` for an unstripped binary; `PERF_RECORD=true`, `PERF_SCOPE=system`, `PERF_EVENT=cpu-clock`; retained `perf.data` and reports |
| Are socket sends accepted but later dropped? | `SOCKET_SAMPLE=true` (`SOCKET_SAMPLE_INTERVAL=0.25`), UDP `SndbufErrors`, qdisc drops/`flows_plimit`, and NIC TX counters |
| Is receive capacity limiting? | UDP `RcvbufErrors`, softnet drops/time-squeeze, IRQ/RSS/RPS/XPS state, and per-worker counts |
| Is AF_XDP losing packets? | Compare requester submissions, PHY TX/RX, server RX, TX-ring admissions, delivery failures, and completions; they measure different stages |
| Does queueing help? | `SERVER_TX_QDISC`, `SERVER_TX_FQ_LIMIT`, `SERVER_TX_FQ_FLOW_LIMIT`, socket send/receive buffers, and matching `SERVER_WMEM_MAX`/`SERVER_RMEM_MAX` |
| Does placement help? | `WORKER_CPUS`, `SERVER_PREFIX`, NIC queue/IRQ state; keep a matched unbound control |
| Is an XDP mode or setup change involved? | `server-ip-link-*-benchmark.txt`, `server-bpftool-net-*-benchmark.txt`, `host/server-link-tuning.txt`, and `host/player-link-tuning.txt` |

Abbreviated setting names in this table all have the
`BORONDNS_PHYSICAL_` prefix. The script source is the full variable
reference. Host-tuning experiments must retain the original and effective
settings and the post-run cleanup evidence.

Use metrics `reduced` for calibration and diagnostics. Use `off` for a
chosen saturation profile when per-query instrumentation changes throughput;
DNS, rcode, cookie, RRL, zone, and standard-UDP hot-path counters then do not
represent the full traffic. AF_XDP transport counters remain available.
AF_XDP `sent_packets_total` records admission to TX rings, not confirmed wire
delivery; check `borondns_af_xdp_tx_delivery_failures_total` separately.
The `spin` idle strategy requires the dedicated UDP runtime and consumes
CPU when idle.

## Read and normalize the results

```bash
scripts/prepare-knot-comparison-benchmark.sh normalize-borondns \
  --artifact target/knot-comparison/example/evidence/borondns-idle-after-knot-transfer \
  --out target/knot-comparison/example/borondns-normalized.tsv
scripts/prepare-knot-comparison-benchmark.sh normalize-kxdpgun \
  --log target/knot-comparison/example/kxdpgun-knot.log \
  --duration 15 \
  --out target/knot-comparison/example/knot-normalized.tsv
```

Compare `responses_per_second`, not the normalized `qps` column alone:
the kxdpgun normalizer puts sent queries/s in `qps`, while the BoronDNS
normalizer puts responses/s there. BoronGun physical rows use
`send_duration_seconds` so the final drain timeout does not dilute the
offered-window rate.

| Field | Interpretation |
| --- | --- |
| Response percentage, errors/loss | Report with rate; distinguish lost sends, unanswered queries, and client errors |
| `rx_gbps`, `sum_gbps` | kxdpgun L2/L1 rates or interface-counter rates, as identified by `throughput_scope` |
| `*_gigabytes_per_second` | Byte-rate equivalents; GB/s and Gbit/s are different units |
| `rx_bytes_per_response` | DNS payload size for kxdpgun, interface-counter bytes for the local normalizer |
| p99/p999 | Use a requester that measures latency; do not infer percentiles from QPS |
| PHY and kernel counters | Locate loss and check that the recorded physical path carried the traffic |

Keep kxdpgun plaintext logs because normalization uses their reply-size and
L1/L2 fields. Never label loopback RX+TX sums as wire throughput.

Report the highest offered rate that stays within a declared response-loss
and latency limit, together with repetitions and host/profile details. Keep
lossless and allowed-loss results separate, and retain failed rows when
showing where throughput stops increasing.
