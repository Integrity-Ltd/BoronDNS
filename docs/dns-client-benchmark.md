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
OXIDEDNS_BENCH_RECORDS=10000 \
OXIDEDNS_BENCH_DURATION_SECONDS=10 \
OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED=false \
OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=false \
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

To compare the experimental immutable ZoneImage serving path against the
current snapshot path, run the same profile once with
`OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=false` and once with
`OXIDEDNS_BENCH_ZONE_IMAGE_SERVE_ENABLED=true`. The generated configuration,
`run.env`, `benchmark-results.tsv`, and capability summary record the selected
value.

To compare the standard UDP batch adapter against the original one-datagram
socket path, run the same UDP profile once with
`OXIDEDNS_BENCH_UDP_BATCH_SIZE=1` and once with a larger value such as `32` or
`64`. Retained artifacts record `udp_batch_size`,
`udp_receive_batches`, `udp_received_datagrams`, `udp_send_batches`, and
`udp_sent_datagrams` so the result can be checked against actual listener
batching rather than only client-side throughput.

Retained loopback UDP batch smoke from 2026-05-29:

| Profile | UDP batch size | Responses/s | p50 us | p99 us | Dropped | Errors | Receive batches | Send batches | Artifact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 4 clients x window 16 | 1 | 303,943 | 190.8 | 252.3 | 0 | 0 | 304,985 | 304,985 | `target/evidence/udp-batch-loopback-baseline-1` |
| 4 clients x window 16 | 32 | 350,738 | 157.3 | 242.7 | 0 | 0 | 11,013 | 11,013 | `target/evidence/udp-batch-loopback-batch-32` |

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
for trace-mode runs, expected `zone_image_serve_enabled` values, drop/error
limits, ZoneImage served-hit counters, and the configured throughput and
latency ratios. The served-hit counters include total, direct-answer, semantic,
and fallback counts; the direct/semantic counts must add up to total served
hits, and ZoneImage fallbacks must be zero unless an explicit
`--max-zone-image-fallbacks` value is supplied. Add
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
TSV before comparing live runtime artifacts.

The comparator and promotion checks have a synthetic regression test:

```bash
python3 scripts/check-zone-image-evidence-tools.py
```

It builds temporary current/ZoneImage artifacts and verifies normal loopback
comparison, physical-NIC comparison, loopback rejection under
`--require-non-loopback`, network-device mismatch rejection, direct/semantic
coverage rejection, local-client and remote-client mismatch rejection,
ZoneImage fallback rejection, zero network-counter rejection, stale
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
- keep `ZoneStore` snapshot publication through `Arc<ZoneSnapshot>` rather than
  introducing DashMap or ArcSwap until contention evidence justifies it;
- keep the large-catalog benchmark as the primary local data-layout harness;
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
