# DNS Client Benchmark

Use `scripts/benchmark-dns-clients.sh` for a bounded local DNS client benchmark
against OxideDNS. The script starts a synthetic TCP AXFR primary, loads a
`perf.test.` zone into OxideDNS, pins OxideDNS to four CPUs with `taskset` when
available, and drives direct-hit UDP or TCP A queries with the checked-in
`tools/dns-load-client.rs` load client.

Default run:

```bash
scripts/benchmark-dns-clients.sh
```

Useful overrides:

```bash
OXIDEDNS_BENCH_SERVER_THREADS=4 \
OXIDEDNS_BENCH_TRANSPORT=udp \
OXIDEDNS_BENCH_CLIENT_THREADS=8 \
OXIDEDNS_BENCH_CLIENT_WINDOW=64 \
OXIDEDNS_BENCH_UDP_BATCH_SIZE=1 \
OXIDEDNS_BENCH_UDP_REUSEPORT_WORKERS=1 \
OXIDEDNS_BENCH_RECORDS=10000 \
OXIDEDNS_BENCH_DURATION_SECONDS=10 \
OXIDEDNS_BENCH_HOT_PATH_DETAIL=full \
OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED=false \
OXIDEDNS_BENCH_ZONE_SHAPE_METRICS_ENABLED=false \
OXIDEDNS_BENCH_TRACE_ENABLED=false \
OXIDEDNS_BENCH_LISTEN_ADDRESS=127.0.0.1 \
OXIDEDNS_BENCH_CLIENT_SERVER=127.0.0.1 \
OXIDEDNS_BENCH_CLIENT_BIND=127.0.0.1:0 \
scripts/benchmark-dns-clients.sh
```

For DNS-over-TCP, use persistent client connections with pipelined queries:

```bash
OXIDEDNS_BENCH_TRANSPORT=tcp \
OXIDEDNS_BENCH_CLIENT_THREADS=8 \
OXIDEDNS_BENCH_CLIENT_WINDOW=16 \
scripts/benchmark-dns-clients.sh
```

To measure the opt-in Phase B cache-planning metric overhead, run the same
profile once with `OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED=false` and once with
`OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED=true`. The enabled run exports query
pipeline stage histograms and response-cache candidate counters in
`metrics-after.prom`.

To capture scrape-time zone-shape gauges and histograms for layout tuning, set
`OXIDEDNS_BENCH_ZONE_SHAPE_METRICS_ENABLED=true`. Keep it disabled for
throughput-only runs because the metric family walks active zone snapshots
during metrics scrapes.

To measure detailed hot-path metric overhead, run the same profile once with
`OXIDEDNS_BENCH_HOT_PATH_DETAIL=full` and once with
`OXIDEDNS_BENCH_HOT_PATH_DETAIL=reduced`. The reduced profile keeps coarse
process-wide counters but suppresses detailed mutex-backed query, RCODE,
latency, and cookie-prefix metric updates.

Immutable `ZoneImage` serving is always enabled in live runtime benchmarks. The
generated `run.env`, `benchmark-results.tsv`, and capability summary retain the
`zone_image_serve_enabled=true` evidence field for historical comparator
compatibility.

To compare the standard UDP batch adapter against the original one-datagram
socket path, run the same UDP profile once with
`OXIDEDNS_BENCH_UDP_BATCH_SIZE=1` and once with a larger value such as `32` or
`64`. For `OXIDEDNS_BENCH_UDP_RUNTIME=dedicated` on Linux, the batch size feeds
the `recvmmsg`/`sendmmsg` slab size; local loopback evidence has favored larger
values such as `256` or `512`, but this is host and workload specific. Retained
artifacts record `udp_batch_size`,
`udp_receive_batches`, `udp_received_datagrams`, `udp_send_batches`, and
`udp_sent_datagrams` so the result can be checked against actual listener
batching rather than only client-side throughput. Dedicated Linux runs also
record `udp_mmsg_*` syscall counters plus per-worker active-slot and imbalance
summary rows, which make it easier to distinguish syscall batching from
`SO_REUSEPORT` distribution effects.

To make local `SO_REUSEPORT` tests use more UDP 4-tuples, set
`OXIDEDNS_BENCH_UDP_CLIENT_SOCKETS_PER_THREAD` above `1`. The load client then
opens that many connected UDP sockets per worker thread and round-robins sends
across them. This is especially useful on loopback, where one client socket per
thread can hash to fewer server workers than configured.

To compare one standard UDP listener against multiple `SO_REUSEPORT` workers,
run the same UDP profile with `OXIDEDNS_BENCH_UDP_REUSEPORT_WORKERS=1` and
then with a larger value such as `4`. Set `OXIDEDNS_BENCH_UDP_RUNTIME=dedicated`
to run standard UDP workers on dedicated OS threads instead of Tokio tasks. On
Linux, dedicated workers can also use
`OXIDEDNS_BENCH_UDP_WORKER_CPU_AFFINITY=0,1,2,3` to request explicit CPU
affinity for four workers. Retained artifacts record `udp_runtime`,
`udp_reuseport_workers`, and `udp_worker_cpu_affinity`.

For a reproducible local sweep across several UDP batch sizes, use:

```bash
OXIDEDNS_UDP_BATCH_SWEEP_SIZES="1 8 32 64" \
scripts/sweep-udp-batch-benchmarks.sh
```

For a broader local data-plane sweep across runtimes, worker counts, batch
sizes, and optional affinity, use:

```bash
OXIDEDNS_UDP_RUNTIME_SWEEP_RUNTIMES="tokio dedicated" \
OXIDEDNS_UDP_RUNTIME_SWEEP_WORKERS="1 4" \
OXIDEDNS_UDP_RUNTIME_SWEEP_BATCH_SIZES="32 128 256 512" \
OXIDEDNS_UDP_RUNTIME_SWEEP_CLIENT_SOCKETS_PER_THREAD="1 4" \
OXIDEDNS_UDP_RUNTIME_SWEEP_AFFINITY_MODES="none auto" \
scripts/sweep-udp-runtime-benchmarks.sh
```

The runtime sweep writes `summary.tsv` for the full matrix and `best.tsv` for
the highest-throughput rows. Affinity mode `auto` is only applied to dedicated
standard UDP workers and expands to CPU IDs `0..workers-1`. Client socket
counts control UDP source-port diversity in the load generator.

To retain Linux profiler evidence for a selected local profile, set
`OXIDEDNS_BENCH_PERF_STAT=true` and optionally
`OXIDEDNS_BENCH_PERF_RECORD=true`. `OXIDEDNS_BENCH_PERF_EVENTS` defaults to
`cycles,instructions,branches,branch-misses`. The benchmark attaches `perf` to
the OxideDNS server process for the client load window and retains
`perf-stat.txt`, `perf.data`, `perf.script`, and, when Inferno tools are
installed, `flamegraph.svg`. These captures are local engineering evidence and
are still subject to the host kernel's `perf_event_paranoid` policy.

On hosts where direct `perf -p` attach is blocked, install the narrow
root-owned helper once:

```bash
scripts/install-oxidedns-perf-helper.sh
```

The installer uses one `pkexec` authorization, installs
`/usr/local/libexec/oxidedns-perf-capture`, and adds a sudoers rule for the
current user to run only that helper without a password. The helper validates
that the profiled PID is owned by the invoking user and that output is written
under a directory owned by that user. To use it in benchmark runs:

```bash
OXIDEDNS_BENCH_PERF_PRIVILEGED_HELPER=true \
OXIDEDNS_BENCH_PERF_STAT=true \
scripts/benchmark-dns-clients.sh
```

The sweep wrapper retains one artifact per batch size under a shared
`target/evidence/udp-batch-sweep-*` directory and writes `summary.tsv` with
QPS/latency ratios, drop/error counts, UDP receive/send batch counters, and
ZoneImage serve counters. The first run generates or accepts the retained query
trace; later runs replay the same `query-trace.tsv` so the sweep compares UDP
adapter batching under one query mix. Use
`OXIDEDNS_UDP_BATCH_SWEEP_PREFLIGHT_ONLY=true` to validate the profile without
running it, and `OXIDEDNS_UDP_BATCH_SWEEP_TRACE_FILE=/path/to/query-trace.tsv`
to supply an explicit trace.

Validate the retained sweep summary with:

```bash
scripts/check-udp-batch-sweep.py \
  --input target/evidence/udp-batch-sweep-*/summary.tsv \
  --output target/evidence/udp-batch-sweep-*/check.tsv
```

The checker validates the summary schema, unique ascending batch sizes, zero
drops/errors and ZoneImage failures by default, positive served-hit counters,
ratio math, and at least one non-baseline batch size that increases both
receive and send datagrams per UDP batch. It does not require a generic QPS win
because local loopback throughput thresholds are host-sensitive.

This sweep is local no-XDP evidence by default. It is not physical NIC
promotion evidence unless the underlying benchmark profile also uses
`OXIDEDNS_BENCH_CLIENT_MODE=ssh`,
`OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true`, and non-loopback
listen/client settings that satisfy the stricter comparator checks.
Set `OXIDEDNS_BENCH_PACKET_CAPTURE_ENABLED=true` to retain a bounded UDP DNS
capture for the selected `OXIDEDNS_BENCH_NETWORK_DEVICE`; the harness prefers
`dumpcap` when available and falls back to `tcpdump`. Use
`OXIDEDNS_BENCH_PACKET_CAPTURE_COUNT=N` to control the stop count. Capture
artifacts include `packet-capture/dns-udp.pcapng`, `dns-summary.tsv`, and
`dns-sample.tsv`, and `benchmark-results.tsv` records capture status plus DNS
query/response packet counts.

Retained loopback UDP batch smoke from 2026-05-29:

| Profile | UDP batch size | Responses/s | p50 us | p99 us | Dropped | Errors | Receive batches | Send batches | Artifact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 4 clients x window 16 | 1 | 303,943 | 190.8 | 252.3 | 0 | 0 | 304,985 | 304,985 | `target/evidence/udp-batch-loopback-baseline-1` |
| 4 clients x window 16 | 32 | 350,738 | 157.3 | 242.7 | 0 | 0 | 11,013 | 11,013 | `target/evidence/udp-batch-loopback-batch-32` |

Retained current-layout trace replay from 2026-05-31, with 1,000 records,
128 delegation/DNAME stress candidates, four server threads, four client
threads, client window 16, and always-on `ZoneImage` serving:

| Profile | UDP batch size | Responses/s | p50 us | p99 us | Dropped | Errors | Receive batches | Send batches | Artifact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| trace replay | 1 | 350,726 | 164.3 | 209.5 | 0 | 0 | 1,054,765 | 1,054,765 | `target/evidence/udp-batch-loopback-current-1` |
| trace replay | 32 | 367,297 | 150.6 | 205.7 | 0 | 0 | 34,530 | 34,530 | `target/evidence/udp-batch-loopback-current-32` |

The current-layout loopback run is still not physical NIC evidence, but it
keeps standard UDP batching ahead of the one-datagram socket path locally:
`udp_batch_size=32` recorded 1,104,781 received datagrams over 34,530 receive
batches, while keeping `zone_image_serve_failures=0` and rollback count `0`.

Retained checked UDP batch sweep from 2026-06-01, with 1,000 records,
128 delegation/DNAME stress candidates, four server threads, four client
threads, client window 16, three-second runs, and always-on `ZoneImage`
serving:

| UDP batch size | Responses/s | QPS ratio | p50 us | p50 ratio | p99 us | p99 ratio | Dropped | Errors | Receive datagrams/batch | Send datagrams/batch | ZoneImage failures | Artifact |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 347,390 | 1.000 | 166.8 | 1.000 | 204.7 | 1.000 | 0 | 0 | 1.000 | 1.000 | 0 | `target/evidence/udp-batch-sweep-current-local/batch-1` |
| 8 | 387,609 | 1.116 | 143.3 | 0.859 | 184.4 | 0.901 | 0 | 0 | 8.000 | 8.000 | 0 | `target/evidence/udp-batch-sweep-current-local/batch-8` |
| 32 | 382,367 | 1.101 | 145.6 | 0.873 | 183.6 | 0.897 | 0 | 0 | 31.993 | 31.993 | 0 | `target/evidence/udp-batch-sweep-current-local/batch-32` |

Retained hot-path metrics comparison from 2026-06-02, with 1,000 records,
128 delegation/DNAME stress candidates, four server threads, four client
threads, client window 16, three-second runs, UDP batch size 32, and always-on
`ZoneImage` serving:

| Metrics detail | Run | Responses/s | Per core responses/s | p50 us | p99 us | Dropped | Errors | Artifact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| full | 1 | 398,924 | 99,731 | 139.7 | 191.0 | 0 | 0 | `target/evidence/hot-path-metrics-full` |
| reduced | 1 | 471,893 | 117,973 | 115.8 | 135.6 | 0 | 0 | `target/evidence/hot-path-metrics-reduced` |
| full | 2 | 423,405 | 105,851 | 130.3 | 177.7 | 0 | 0 | `target/evidence/hot-path-metrics-full-r2` |
| reduced | 2 | 486,006 | 121,502 | 110.8 | 130.1 | 0 | 0 | `target/evidence/hot-path-metrics-reduced-r2` |

The two-run local average was about 411,165 responses/s for full detail and
478,950 responses/s for reduced detail, or about 102,791 and 119,737
responses/s per configured server thread. That is a local loopback gain of
about 16.5% for this profile, not physical NIC evidence.

Retained standard UDP `SO_REUSEPORT` worker comparison from 2026-06-02, with
reduced hot-path metrics, 1,000 records, 128 delegation/DNAME stress
candidates, four server threads, four client threads, client window 16,
three-second runs, UDP batch size 32, and always-on `ZoneImage` serving:

| UDP workers | Affinity | Responses/s | Per worker responses/s | p50 us | p99 us | Dropped | Errors | Artifact |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | none | 482,351 | 482,351 | 109.3 | 170.3 | 0 | 0 | `target/evidence/reuseport-workers-baseline-1` |
| 4 | none | 951,119 | 237,780 | 34.1 | 174.0 | 0 | 0 | `target/evidence/reuseport-workers-4` |
| 4 | none | 844,600 | 211,150 | 42.8 | 177.5 | 0 | 0 | `target/evidence/reuseport-workers-4-r2` |
| 4 | `0,1,2,3` | 781,915 | 195,479 | 45.2 | 220.2 | 0 | 0 | `target/evidence/reuseport-workers-4-affinity` |

The two no-affinity four-worker runs averaged about 898k responses/s locally,
or about 224k responses/s per UDP worker. Explicit affinity was slower on this
Tokio runtime profile, so treat affinity as host-specific tuning rather than a
default recommendation. This remains loopback evidence only.

The sweep checker passed at
`target/evidence/udp-batch-sweep-current-local/check.tsv` with
`batching_gain_rows=2`, confirming that both larger batch sizes increased
actual receive and send datagrams per UDP batch. This remains local loopback
evidence only; it does not replace physical NIC promotion. Treat it as the
current single-device no-XDP batch ceiling; rerun the sweep after code changes
or on different hardware, not as a substitute for the separate-client NIC gate.

Retained packet-capture sample from 2026-05-31:

| Profile | UDP batch size | Client threads x window | DNS packets | DNS queries | DNS responses | Dropped | Errors | Artifact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| trace replay capture | 32 | 1 x 1 | 128 | 64 | 64 | 0 | 0 | `target/evidence/udp-batch-loopback-current-32-pcap-sampled` |

This capture is intentionally low-window so the bounded packet sample contains
matched responses rather than only the first client burst. The same artifact
retains `packet-capture/dns-sample.tsv` with response rcodes and answer counts.

To replay an explicit query trace through the live runtime path, set
`OXIDEDNS_BENCH_TRACE_ENABLED=true`. The script generates and retains
`query-trace.tsv` in the artifact directory, then passes it to
`tools/dns-load-client.rs` with `--trace`. To replay a caller-supplied trace,
set `OXIDEDNS_BENCH_TRACE_FILE=/path/to/query-trace.tsv`; rows use:

```text
qname qtype qclass [none|edns|do] [rcode=NOERROR|NXDOMAIN|N] [answers=N] [label]
```

The default expectation is `rcode=NOERROR answers=1`, which preserves the
direct-hit benchmark behavior. Add `answers=0` for NODATA rows and
`rcode=NXDOMAIN answers=0` for negative rows. The generated trace includes hot
and spread positive A rows, EDNS positive A, apex NS/SOA, glue, an opaque
unknown RR type, NODATA, and NXDOMAIN rows.
Set `OXIDEDNS_BENCH_STRESS_CANDIDATES=N` to also load `N` delegation and DNAME
candidate pairs into the synthetic primary and generated trace. The stress rows
alternate referral queries under delegated names with DNAME synthesis queries,
which makes the live benchmark exercise the same name-graph shape as the
in-process ZoneImage stress benchmark.

After recording a current-path artifact and a ZoneImage artifact for the same
profile, compare them with:

```bash
scripts/compare-zone-image-benchmarks.py \
  --current target/evidence/zone-image-evidence-gate-loopback-stress-metrics-smoke/current \
  --zone-image target/evidence/zone-image-evidence-gate-loopback-stress-metrics-smoke/zone-image \
  --min-qps-ratio 1.25 \
  --max-p50-ratio 0.80 \
  --output target/evidence/zone-image-evidence-gate-loopback-stress-metrics-smoke/comparison.tsv
```

The comparator verifies matching profile metadata, matching retained trace hash
for trace-mode runs, always-on ZoneImage serving, drop/error limits, ZoneImage
served-hit counters, and the configured throughput and latency ratios. The
served-hit counters include total, direct-answer, semantic, failure, and
rollback counts; the direct/semantic counts must add up to total served hits,
ZoneImage failures must be zero unless an explicit
`--max-zone-image-failures` value is supplied, and ZoneImage rollbacks must
always be zero. When failures are allowed for diagnostics, inspect the fixed
failure-reason counters before treating the artifact as retirement evidence. Add
`--require-direct-and-semantic` when the retained trace must prove that both the
guarded direct-answer hot path and semantic planner were used.
Add `--require-non-loopback` for physical NIC promotion evidence; that mode
also requires both artifacts to record the same non-loopback network device and
to have been captured with `require_non_loopback_device=true`, matching
listen/client provenance, matching build provenance, matching `client_mode`,
matching `remote_client_ssh`, a concrete non-loopback `client_server`,
matching local/remote client architecture,
`remote_client_allow_arch_mismatch=false`, distinct local/remote host identity,
matching local and remote
`dns-load-client` binary SHA-256 digests, and retained
`network/proc-net-dev-delta.tsv` files showing positive RX/TX packet and byte
deltas, with zero RX/TX drop and error deltas, for both artifacts. Physical
promotion mode requires `client_mode=ssh` and a non-empty remote SSH target so
same-host local traffic cannot be promoted as physical server-NIC evidence; it
also rejects architecture-override artifacts because the promoted result must
prove the copied load-generator binary ran on a compatible client. Build
provenance includes the Git revision and dirty-state, kernel, Rust toolchain,
build profile, server binary digest, and load-client binary digest. The
benchmark summary rows for RX/TX packet deltas must match the retained
`proc-net-dev` delta file so mixed or stale network snapshots cannot satisfy the
physical promotion gate. By default, RX and TX packet deltas must each be at
least `0.25` packets per measured response so incidental background traffic
cannot satisfy the physical promotion gate; use
`--min-network-packets-per-response` only when the retained artifact explains a
lower packet-per-response shape.
For the common two-run workflow, `scripts/zone-image-evidence-gate.sh` wraps
both live runs and the comparator:

```bash
OXIDEDNS_ZONE_IMAGE_GATE_MIN_QPS_RATIO=1.25 \
OXIDEDNS_ZONE_IMAGE_GATE_MAX_P50_RATIO=0.75 \
OXIDEDNS_BENCH_STRESS_CANDIDATES=128 \
scripts/zone-image-evidence-gate.sh
```

The wrapper writes `current/`, `zone-image/`, `comparison.tsv`, and a README
under one evidence directory. It uses the trace retained by the current-path
run for the ZoneImage run, requires both direct-answer and semantic served-hit
counters to be positive, and refuses to reuse a non-empty gate directory unless
`OXIDEDNS_ZONE_IMAGE_GATE_OVERWRITE=true` is set.

The in-process prototype benchmark has a separate checker:

```bash
scripts/check-zone-image-prototype-benchmark.py \
  --input target/zone-image-bench/prototype-latest.tsv \
  --output target/zone-image-bench/prototype-check-latest.tsv
```

Use it after `scripts/benchmark-zone-image-prototype.sh` to verify the retained
TSV before comparing live runtime artifacts. The prototype TSV includes an
isolated high-fanout exact-lookup mix with first, middle, last, and absent child
labels under the same large parent, plus retained `zone_image_max_child_fanout`
and `zone_shape_*_bucket_*` rows for layout-tuning decisions.

The comparator and promotion checks have a synthetic regression test:

```bash
python3 scripts/check-zone-image-evidence-tools.py
```

It builds temporary current/ZoneImage artifacts and verifies normal loopback
comparison, physical-NIC comparison, loopback rejection under
`--require-non-loopback`, network-device mismatch rejection, direct/semantic
coverage rejection, local-client and remote-client mismatch rejection,
ZoneImage failure rejection, zero network-counter rejection, stale
benchmark-summary counter rejection, and drop-counter rejection.

For NIC-facing evidence, run the same harness from a client host or namespace
that reaches the OxideDNS host address and set:

```bash
OXIDEDNS_BENCH_LISTEN_ADDRESS=192.0.2.10 \
OXIDEDNS_BENCH_CLIENT_SERVER=192.0.2.10 \
OXIDEDNS_BENCH_CLIENT_BIND=0.0.0.0:0 \
OXIDEDNS_BENCH_NETWORK_DEVICE=enp1s0 \
OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true \
scripts/benchmark-dns-clients.sh
```

`OXIDEDNS_BENCH_LISTEN_ADDRESS` controls the OxideDNS UDP/TCP listener, while
`OXIDEDNS_BENCH_CLIENT_SERVER` controls the load-client destination. Use a
concrete destination address, not `0.0.0.0`. `OXIDEDNS_BENCH_CLIENT_BIND`
controls the UDP source bind only; TCP source address selection is left to the
OS. `OXIDEDNS_BENCH_NETWORK_DEVICE=auto` records `lo` for loopback and otherwise
uses `ip route get` against the client destination when available.
`OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true` fails fast if the destination
or resolved network device is loopback or unknown, which prevents accidentally
recording loopback evidence as NIC-facing evidence. It also verifies that the
resolved or configured `OXIDEDNS_BENCH_NETWORK_DEVICE` exists on the server
host before starting services, so a stale or misspelled interface name fails
during preflight instead of after a useless benchmark run.

For physical NIC promotion evidence, prefer running the harness on the
OxideDNS host and driving load from a second machine over SSH:

```bash
OXIDEDNS_BENCH_CLIENT_MODE=ssh \
OXIDEDNS_BENCH_REMOTE_CLIENT_SSH=bench-client.example.net \
OXIDEDNS_BENCH_LISTEN_ADDRESS=192.0.2.10 \
OXIDEDNS_BENCH_CLIENT_SERVER=192.0.2.10 \
OXIDEDNS_BENCH_CLIENT_BIND=0.0.0.0:0 \
OXIDEDNS_BENCH_NETWORK_DEVICE=enp1s0 \
OXIDEDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true \
scripts/benchmark-dns-clients.sh
```

In SSH mode the server host still starts the synthetic primary and OxideDNS,
captures `network/` before and after the load window, and writes the final
artifact locally. The script copies the compiled `dns-load-client` binary and
the retained trace, when present, to
`OXIDEDNS_BENCH_REMOTE_CLIENT_WORKDIR` on the remote client and records the
exact remote command in `remote-client-command.txt`. This is the intended path
for evidence where `/proc/net/dev` deltas need to prove traffic crossed a
physical server NIC. The remote client must be a distinct host: SSH-mode runs
hash local and remote host identity from `/proc/sys/kernel/random/boot_id` when
available, falling back to hostname, and physical-promotion preflight rejects a
remote target that resolves back to the local server host. The remote client
should be the same CPU architecture as the server for the copied benchmark
binary. SSH-mode runs check `uname -m` on both hosts and fail before starting
local services if they differ. Set
`OXIDEDNS_BENCH_REMOTE_CLIENT_ALLOW_ARCH_MISMATCH=true` only when you intend to
replace the copied binary or run a compatible remote binary manually with the
captured command. The benchmark artifact records the local architecture, remote
architecture, hashed local/remote host identities, same-host result, and
whether the override was enabled.
Direct SSH-mode benchmark runs perform a non-interactive SSH reachability check
before building tools or starting local services; tune that timeout with
`OXIDEDNS_BENCH_REMOTE_CLIENT_SSH_CONNECT_TIMEOUT_SECONDS`.
When `OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true`, the wrapper fails
before starting either run unless `OXIDEDNS_BENCH_CLIENT_MODE=ssh` and
`OXIDEDNS_BENCH_REMOTE_CLIENT_SSH` are set. In SSH mode the wrapper defaults
the client bind to `0.0.0.0:0`; in local mode it defaults to `127.0.0.1:0`.
The wrapper also performs a non-interactive SSH reachability check before
starting either benchmark run, and applies the same remote architecture guard;
tune the timeout with `OXIDEDNS_ZONE_IMAGE_GATE_SSH_CONNECT_TIMEOUT_SECONDS`.
Unless `OXIDEDNS_BENCH_REMOTE_CLIENT_SSH_CONNECT_TIMEOUT_SECONDS` is set
explicitly, the wrapper propagates that timeout to the two benchmark runs.

Before occupying ports or starting the benchmark services, validate a proposed
physical run with:

```bash
OXIDEDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY=true \
OXIDEDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true \
OXIDEDNS_BENCH_CLIENT_MODE=ssh \
OXIDEDNS_BENCH_REMOTE_CLIENT_SSH=bench-client.example.net \
OXIDEDNS_BENCH_LISTEN_ADDRESS=192.0.2.10 \
OXIDEDNS_BENCH_CLIENT_SERVER=192.0.2.10 \
OXIDEDNS_BENCH_NETWORK_DEVICE=enp1s0 \
scripts/zone-image-evidence-gate.sh
```

The preflight validates wrapper options, SSH reachability, local/remote
architecture compatibility, distinct local/remote host identity, concrete
non-loopback listen/client settings, and toolchain/build provenance without
starting the synthetic primary or OxideDNS.
It writes a small `*.preflight.env` file next to the planned gate directory and
leaves the actual gate directory untouched. For direct benchmark preflight, use
`OXIDEDNS_BENCH_PREFLIGHT_ONLY=true scripts/benchmark-dns-clients.sh`.

The script writes retained artifacts under
`target/evidence/dns-client-benchmark-<timestamp>/`, including server logs,
client output, the generated configuration, Prometheus metrics before and after
the run, optional `query-trace.tsv`, `benchmark-results.tsv`, and a `network/`
directory with before/after route, address, `/proc/net/dev`, softirq, interrupt,
and optional `ethtool` snapshots for the recorded network device. The
`network/proc-net-dev-delta.tsv` file summarizes packet and error counter
deltas for the selected device; `network/ethtool-delta.tsv` is also written
when ethtool data is available. `benchmark-results.tsv` also records Git,
kernel, Rust toolchain, build profile, and local binary SHA-256 provenance. In
SSH mode, `remote-client-command.txt` records the remote command plus the local
and remote load-client binary digests.

## Large Catalog Benchmark

Use `scripts/benchmark-large-catalog-zones.sh` for the opt-in large-zone
performance harness. It generates an RFC 9432 catalog zone plus a mixed
large/small member-zone set, serves the catalog and members from BIND with
TSIG-authenticated AXFR, starts OxideDNS pinned to four CPUs when `taskset` is
available, waits for catalog readiness, then drives randomized UDP or TCP direct
hit queries across the whole zone mix.

The default target is an 8 GiB OxideDNS resident set after catalog load:

```bash
scripts/benchmark-large-catalog-zones.sh
```

For a 16 GiB target with TCP queries and Linux `perf record` samples:

```bash
OXIDEDNS_LARGE_BENCH_TARGET_RSS_MIB=16384 \
OXIDEDNS_LARGE_BENCH_TRANSPORT=tcp \
OXIDEDNS_LARGE_BENCH_SERVER_CPUS=4 \
OXIDEDNS_LARGE_BENCH_CLIENT_THREADS=16 \
OXIDEDNS_LARGE_BENCH_CLIENT_WINDOW=64 \
OXIDEDNS_LARGE_BENCH_DURATION_SECONDS=60 \
OXIDEDNS_LARGE_BENCH_PERF_RECORD=true \
scripts/benchmark-large-catalog-zones.sh
```

Useful sizing knobs:

- `OXIDEDNS_LARGE_BENCH_ZONES` controls the catalog member count.
- `OXIDEDNS_LARGE_BENCH_BIG_ZONES` selects how many members receive the large
  record count.
- `OXIDEDNS_LARGE_BENCH_BIG_NAMES` overrides the computed large-zone owner-name
  count when exact sizing matters.
- `OXIDEDNS_LARGE_BENCH_SMALL_NAMES` controls the small-zone owner-name count.
- `OXIDEDNS_LARGE_BENCH_TXT_BYTES` adjusts per-owner TXT payload size and is the
  simplest way to move the resident set up or down without changing query
  cardinality.
- `OXIDEDNS_LARGE_BENCH_ADDRESS_RECORDS_PER_NAME` controls how many A records
  are generated for each synthetic host owner. The default is `1`; values above
  `1` intentionally create multi-RDATA A RRsets for validating the `SmallVec`
  inline-capacity assumption.

The script writes retained artifacts under
`target/evidence/large-catalog-benchmark-<timestamp>/`. The important machine
readable files are:

- `benchmark-phases.tsv` for phase timing, including
  `oxidedns_startup_to_ready` catalog transfer/load time, `warmup_serve`, and
  `measured_serve`.
- `benchmark-results.tsv` for QPS, latency, RSS, sizing values, and the folded
  `phase_*_duration_ms` rows.
- `metrics-before.prom`, `metrics-after-warmup.prom`, and `metrics-after.prom`
  for Prometheus snapshots before serving, after warmup, and after the measured
  run.
- `zone-shape.prom` for the loaded active-zone shape: RRset count, RDATA count,
  single- versus multi-RDATA RRsets, SmallVec spill count, RDATA payload bytes,
  owner-name count, empty non-terminal count, and canonical-name key interning
  savings. `benchmark-results.tsv` also includes aggregate `zone_shape_*` rows.
  The benchmark enables `[metrics].zone_shape_enabled` explicitly; normal
  deployments leave this scrape-time O(zone-size) metric family disabled unless
  they are collecting memory-layout evidence.
- `resource-samples.tsv`, `/proc` status snapshots, optional `perf-stat.csv`,
  and optional `flamegraph.svg` when `perf record` plus Inferno tooling are
  available.

This harness is intentionally not executed by `scripts/check.sh`; only shell
syntax is checked continuously. It is for local data-layout and serving-path
optimization work, not Engineering MVP or release-acceptance evidence by
itself.

Interpretation:

- `responses_per_second` is the observed direct-hit response rate for the
  selected transport.
- `latency_us_p99` and `latency_us_p999` are client-observed round-trip
  latencies.
- TCP loopback runs are useful for isolating OxideDNS in-memory lookup,
  response composition, Tokio scheduling, DNS-over-TCP framing, and local socket
  write cost. They are not a substitute for NIC-facing UDP/TCP capacity testing
  on the Reference Hardware/Profile.
- When the load client runs with a large per-thread window, client-observed
  latency includes queue depth. Compare it with `client_window * client_threads
  / responses_per_second` before treating p50/p99 as pure per-query CPU time.
- With `OXIDEDNS_LARGE_BENCH_PIPELINE_TIMING_ENABLED=true`, the Prometheus
  `oxidedns_query_pipeline_duration_seconds_*` metrics split server-side parse,
  lookup, compose, and send time. These are the main evidence source for deciding
  whether a tuning pass should target data layout, response composition,
  transport, or client/kernel effects.
- For hot packet-path experiments where detailed observability is itself a
  suspected bottleneck, set `[metrics].hot_path_detail = "reduced"` in the
  generated or edited server config. That keeps coarse process-wide counters but
  suppresses per-zone query maps, RCODE maps, query latency histograms, DNS
  Cookie prefix maps, and pipeline/cache-planning histograms. Do not compare a
  reduced-detail run against a full-detail run without noting the metrics mode.
- The `zone_shape_single_rdata_rrsets`, `zone_shape_multi_rdata_rrsets`, and
  `zone_shape_spilled_rdata_rrsets` rows show whether `SmallVec<[T; 1]>` matches
  the loaded corpus or whether a wider inline capacity should be tested. The
  `zone_shape_name_key_*_bytes` rows quantify canonical-name key duplication
  avoided by interning inside each `ZoneSnapshot`.
- Non-zero `dropped` means the offered load exceeded the local server/client
  path or kernel buffers for that run.
- This is a local engineering benchmark. The full SRS Reference Hardware/Profile
  acceptance campaign still requires the release benchmark handoff and operator
  sign-off artifacts.

## Engineering Tuning Boundary

This benchmark guide owns local measurement and tuning evidence only. It does
not promote future packet-I/O, packed-store, or response-cache work into current
OxideDNS server scope.

- keep the authoritative in-memory design and avoid eBPF/XDP/NSD-style packet
  cache work until `docs/future-optimization-tracks.md` re-entry conditions are
  met;
- keep `ZoneStore` publication through the `ArcSwap` immutable suffix-indexed
  directory and avoid adding DashMap, a custom RCU layer, or a more complex trie
  until contention or canonical label-key evidence justifies it;
- keep the large-catalog benchmark as the primary local data-layout harness;
- use the in-process ZoneImage prototype benchmark for focused name-edge layout
  timing and `ZoneDirectory` suffix-index timing before adding adaptive-radix,
  trie, or perfect-hash structures;
- keep release-build tuning history in `CHANGELOG.md`; use this guide for the
  commands and artifacts that reproduce or challenge a tuning decision;
- retain a profiling build profile with line tables and symbols for perf/flame
  graph runs;
- prefer compact indexes and data-layout changes that preserve current query
  behavior and are validated by focused tests plus before/after benchmark
  artifacts.

The current evidence indicates that the first-order query bottleneck was full
zone scanning during response composition, not mutex contention or packet I/O.
Future eBPF/XDP work still belongs behind the documented packet-I/O adapter and
privileged deployment boundary.
