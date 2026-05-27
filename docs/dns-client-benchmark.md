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
OXIDEDNS_BENCH_RECORDS=10000 \
OXIDEDNS_BENCH_DURATION_SECONDS=10 \
OXIDEDNS_BENCH_PIPELINE_TIMING_ENABLED=false \
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

The script writes retained artifacts under
`target/evidence/dns-client-benchmark-<timestamp>/`, including server logs,
client output, the generated configuration, Prometheus metrics before and after
the run, and `benchmark-results.tsv`.

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
