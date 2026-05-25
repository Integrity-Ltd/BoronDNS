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

Interpretation:

- `responses_per_second` is the observed direct-hit response rate for the
  selected transport.
- `latency_us_p99` and `latency_us_p999` are client-observed round-trip
  latencies.
- Non-zero `dropped` means the offered load exceeded the local server/client
  path or kernel buffers for that run.
- This is a local engineering benchmark. The full SRS Reference Hardware/Profile
  acceptance campaign still requires the release benchmark handoff and operator
  sign-off artifacts.
