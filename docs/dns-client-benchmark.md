# DNS client benchmarks

Use [benchmark-dns-clients.sh](../scripts/benchmark-dns-clients.sh) for small,
controlled UDP or TCP measurements. It starts a synthetic AXFR primary and
BoronDNS, loads `perf.test.`, and drives queries with
`tools/dns-load-client.rs`. By default everything runs on loopback.

This is a tuning harness, not the highest-QPS hardware profile. For capacity
comparisons use the [Knot comparison](knot-comparison-benchmark.md) and
[loss matrix](dns-server-loss-matrix-benchmark.md). For large synthetic zones
and concurrent updates, use [BoronGen](boron-gen.md).

## Run a baseline

Run on the intended compute host, with the pinned toolchain and dependencies
from [the build guide](devops-getting-started.md). The harness builds its tools
and starts local services; reserve the ports and resources before running it.

```sh
scripts/benchmark-dns-clients.sh
```

The defaults are 10,000 records, 10 seconds, four server threads, eight client
threads, client window 64, one Tokio UDP worker, batch size 1, and full hot-path
metrics. It uses `taskset` when available. These harness defaults are not
production tuning recommendations.

For persistent, pipelined TCP connections:

```sh
BORONDNS_BENCH_TRANSPORT=tcp \
BORONDNS_BENCH_CLIENT_THREADS=8 \
BORONDNS_BENCH_CLIENT_WINDOW=16 \
scripts/benchmark-dns-clients.sh
```

Use `BORONDNS_BENCH_PREFLIGHT_ONLY=true` to check a profile without starting
the primary or server. Results normally go to
`target/evidence/dns-client-benchmark-<timestamp>/`.

## Choose the workload

The default queries are direct A-record hits. Enable
`BORONDNS_BENCH_TRACE_ENABLED=true` for a retained mixed query trace, or set
`BORONDNS_BENCH_TRACE_FILE=/path/to/query-trace.tsv` to replay one. Trace rows
use this format:

```text
qname qtype qclass [none|edns|do] [rcode=NOERROR|NXDOMAIN|N] [answers=N] [label]
```

Expectations default to `rcode=NOERROR answers=1`. Use `answers=0` for
NODATA and `rcode=NXDOMAIN answers=0` for negative answers. The generated
trace includes hot and spread A queries, EDNS, apex NS/SOA, glue, an opaque RR
type, NODATA, and NXDOMAIN. `BORONDNS_BENCH_STRESS_CANDIDATES=N` adds
delegation and DNAME candidate pairs to both the zone and trace.

Keep the trace, offered load, thread count, client window, and metrics mode
fixed between candidates. A client-observed latency includes queueing:
`client_window × client_threads / responses_per_second` is a useful
queue-depth sanity check, not a measure of per-query CPU cost.

## Compare runtime settings

All names below have the prefix `BORONDNS_BENCH_`.

| Setting | What it controls |
| --- | --- |
| `UDP_RUNTIME` | `tokio` or dedicated OS threads (`dedicated`). |
| `UDP_BATCH_SIZE` | Datagram batch capacity; Linux dedicated workers use `recvmmsg`/`sendmmsg`. |
| `UDP_REUSEPORT_WORKERS` | Number of UDP listeners. |
| `UDP_WORKER_CPU_AFFINITY` | Explicit CPU IDs for dedicated workers, such as `0,1,2,3`. |
| `UDP_CLIENT_SOCKETS_PER_THREAD` | Source-port diversity; one socket per thread can hash unevenly across reuseport workers. |
| `HOT_PATH_DETAIL` | `full`, `reduced`, or `off`; retain the mode with every result. |
| `PIPELINE_TIMING_ENABLED` | Stage histograms and cache-planning diagnostics. |
| `ZONE_SHAPE_METRICS_ENABLED` | Scrape-time zone scans; leave disabled for throughput-only measurements. |

Reduced metrics omit detailed per-zone, RCODE, latency, and cookie-prefix
updates. Off mode also removes coarse per-query counters, so it is unsuitable
for comparisons that depend on those counters. Timing instrumentation itself
has a cost.

Use the sweep wrappers for repeatable matrices:

```sh
BORONDNS_UDP_BATCH_SWEEP_SIZES="1 8 32 64" \
scripts/sweep-udp-batch-benchmarks.sh

BORONDNS_UDP_RUNTIME_SWEEP_RUNTIMES="tokio dedicated" \
BORONDNS_UDP_RUNTIME_SWEEP_WORKERS="1 4" \
BORONDNS_UDP_RUNTIME_SWEEP_BATCH_SIZES="32 128 256 512" \
BORONDNS_UDP_RUNTIME_SWEEP_CLIENT_SOCKETS_PER_THREAD="1 4" \
BORONDNS_UDP_RUNTIME_SWEEP_AFFINITY_MODES="none auto" \
scripts/sweep-udp-runtime-benchmarks.sh
```

The batch sweep retains and reuses a query trace, then writes `summary.tsv`.
It supports `BORONDNS_UDP_BATCH_SWEEP_PREFLIGHT_ONLY=true` and an explicit
`BORONDNS_UDP_BATCH_SWEEP_TRACE_FILE`. The runtime sweep also writes
`best.tsv`; its automatic affinity maps dedicated workers to CPU IDs
`0..workers-1`, which may not suit a restricted CPU allocation.

Validate a batch sweep using its exact evidence directory:

```sh
scripts/check-udp-batch-sweep.py \
  --input 'target/evidence/<sweep>/summary.tsv' \
  --output 'target/evidence/<sweep>/check.tsv'
```

The checker requires consistent rows, ratio calculations, increased datagrams
per batch, and (by default) no drops, errors, or ZoneImage failures. It does not
require a host-independent QPS improvement.

## Measure across a physical link

Run the harness on the DNS host and select a different host for the client.
Replace these documentation addresses, interface, and SSH name:

```sh
BORONDNS_BENCH_CLIENT_MODE=ssh \
BORONDNS_BENCH_REMOTE_CLIENT_SSH=bench-client.example.net \
BORONDNS_BENCH_LISTEN_ADDRESS=192.0.2.10 \
BORONDNS_BENCH_CLIENT_SERVER=192.0.2.10 \
BORONDNS_BENCH_CLIENT_BIND=0.0.0.0:0 \
BORONDNS_BENCH_NETWORK_DEVICE=enp1s0 \
BORONDNS_BENCH_REQUIRE_NON_LOOPBACK_DEVICE=true \
scripts/benchmark-dns-clients.sh
```

SSH mode checks reachability and architecture, then copies the compiled client
and trace. It records the command and both binary digests. Physical comparison
requires distinct host identities, matching architectures, concrete
non-loopback addresses, and real NIC counters. The diagnostic
`REMOTE_CLIENT_ALLOW_ARCH_MISMATCH` override disqualifies such evidence.

`CLIENT_BIND` controls UDP only; TCP source selection belongs to the OS.
`NETWORK_DEVICE=auto` records loopback or uses a route lookup, but setting
the physical device explicitly is clearer. Merely choosing a non-loopback
listen address with a local client does not prove traffic crossed the NIC.

Server and client route, interface, CPU, interrupt, softirq, and packet-counter
snapshots are retained. Inspect drops and errors on both ends before attributing
a throughput plateau to DNS lookup. Nonzero requester loss may originate in the
generator, network, kernel, or server.

## Profile a selected run

Set `BORONDNS_BENCH_PERF_STAT=true` and optionally
`BORONDNS_BENCH_PERF_RECORD=true`. Default events are
`cycles,instructions,branches,branch-misses`; override with
`BORONDNS_BENCH_PERF_EVENTS`. The harness retains `perf-stat.txt`,
`perf.data`, `perf.script`, and a flame graph when Inferno is available.
Kernel perf permissions still apply.

If ordinary attachment is denied, the optional
`scripts/install-borondns-perf-helper.sh` uses a one-time `pkexec`
authorization to install a root-owned helper and a narrow sudoers rule.
`BORONDNS_BENCH_PERF_PRIVILEGED_HELPER=true` selects it. The helper checks
process and output ownership; read it before granting the privilege.

For packet samples, set `BORONDNS_BENCH_PACKET_CAPTURE_ENABLED=true`,
choose `BORONDNS_BENCH_NETWORK_DEVICE`, and bound the capture with
`BORONDNS_BENCH_PACKET_CAPTURE_COUNT=N`. The harness prefers dumpcap and
falls back to tcpdump. Small client windows make a bounded capture more likely
to contain matched queries and responses.

## Interpret and compare artifacts

Keep `run.env`, generated configuration, server logs, client output,
`benchmark-results.tsv`, Prometheus snapshots, query trace, and network
counter deltas together. The results include revision, dirty state, toolchain,
kernel, build profile, and binary digests. Do not infer those identities from
the current checkout.

ZoneImage serving is always enabled. The legacy names `current/` and
`zone-image/` in `scripts/zone-image-evidence-gate.sh` now identify two
runs of the same live path, not old and new storage implementations. The wrapper
checks repeatability and direct/semantic path coverage by replaying one trace.
Its default minimum QPS ratio is 1.0; repeated runs can still vary. Choose a
justified tolerance before running, not after inspecting the winner.

`scripts/compare-zone-image-benchmarks.py` checks profile and trace parity,
served-hit accounting, failures, rollbacks, and requested performance bounds.
`--require-non-loopback` additionally checks SSH/host/build provenance and
retained NIC deltas. RX and TX must each exceed the configured packets-per-
response floor (default 0.25), with no new drops or errors. Loopback results
cannot satisfy this mode.

For a physical wrapper preflight, combine the SSH profile above with
`BORONDNS_ZONE_IMAGE_GATE_PREFLIGHT_ONLY=true` and
`BORONDNS_ZONE_IMAGE_GATE_REQUIRE_NON_LOOPBACK=true`, then run
`scripts/zone-image-evidence-gate.sh`. It writes preflight metadata without
starting the services. Use a new evidence directory for a real comparison.

For isolated name-edge and suffix-directory timings, use
`scripts/benchmark-zone-image-prototype.sh` followed by
`scripts/check-zone-image-prototype-benchmark.py`. These are microbenchmarks,
not substitutes for live QPS. Comparator regression fixtures are in
`scripts/check-zone-image-evidence-tools.py`.

## BIND-backed large catalogs

`scripts/benchmark-large-catalog-zones.sh` generates an RFC 9432 catalog
and mixed member zones in BIND, transfers them with TSIG, and runs randomized
direct hits. Its default sizing target is 8 GiB BoronDNS RSS, 128 members
(16 large), four server CPUs, and TCP queries. This also consumes memory and
disk for BIND and generated zones; the RSS target is not a host resource cap.
Use a dedicated resource-bounded host. For streaming generation without that
primary-side storage cost, use [BoronGen](boron-gen.md).

Example 16 GiB target:

```sh
BORONDNS_LARGE_BENCH_TARGET_RSS_MIB=16384 \
BORONDNS_LARGE_BENCH_TRANSPORT=tcp \
BORONDNS_LARGE_BENCH_PERF_RECORD=true \
scripts/benchmark-large-catalog-zones.sh
```

The `BORONDNS_LARGE_BENCH_` settings `ZONES`, `BIG_ZONES`,
`BIG_NAMES`, `SMALL_NAMES`, `TXT_BYTES`, and
`ADDRESS_RECORDS_PER_NAME` control the corpus. A memory target is estimated
from that shape, then measured; do not assume it predicts transfer peaks.

Retain `benchmark-phases.tsv` (load, warmup, serve), `benchmark-results.tsv`
(QPS, latency, RSS), `resource-samples.tsv`, metrics, and optional perf data.
This harness enables expensive zone-shape metrics explicitly. They describe
the loaded corpus; old snapshot/SmallVec diagnostics are not a direct measure
of the current compact serving layout. See [the storage design](memory-io-data-plane-design.md).

Neither this harness nor a loopback result establishes full SRS performance
acceptance. Use the [reference profile](reference-verification-profile.md) and
record any deviations.

## Historical loopback measurements

These May–June 2026 results motivated early tuning. They are not current
throughput claims and do not establish physical-NIC capacity. Evidence paths
are identifiers for retained lab artifacts, not files shipped in the repository.

<details>
<summary>May 29–June 2, 2026: batch sizes, metrics, reuseport, and packet samples</summary>

Retained loopback UDP batch smoke from 2026-05-29:

| Profile | UDP batch size | Responses/s | p50 us | p99 us | Dropped | Errors | Receive batches | Send batches | Artifact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 4 clients x window 16 | 1 | 303,943 | 190.8 | 252.3 | 0 | 0 | 304,985 | 304,985 | `target/evidence/udp-batch-loopback-baseline-1` |
| 4 clients x window 16 | 32 | 350,738 | 157.3 | 242.7 | 0 | 0 | 11,013 | 11,013 | `target/evidence/udp-batch-loopback-batch-32` |

Retained trace replay from 2026-05-31, with 1,000 records,
128 delegation/DNAME stress candidates, four server threads, four client
threads, client window 16, and always-on `ZoneImage` serving:

| Profile | UDP batch size | Responses/s | p50 us | p99 us | Dropped | Errors | Receive batches | Send batches | Artifact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| trace replay | 1 | 350,726 | 164.3 | 209.5 | 0 | 0 | 1,054,765 | 1,054,765 | `target/evidence/udp-batch-loopback-current-1` |
| trace replay | 32 | 367,297 | 150.6 | 205.7 | 0 | 0 | 34,530 | 34,530 | `target/evidence/udp-batch-loopback-current-32` |

The May 31 loopback run is still not physical NIC evidence, but it
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
evidence only; it does not replace physical NIC promotion. It is evidence for that
single-device socket profile; rerun after code changes or on different hardware.

Retained packet-capture sample from 2026-05-31:

| Profile | UDP batch size | Client threads x window | DNS packets | DNS queries | DNS responses | Dropped | Errors | Artifact |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| trace replay capture | 32 | 1 x 1 | 128 | 64 | 64 | 0 | 0 | `target/evidence/udp-batch-loopback-current-32-pcap-sampled` |

This capture is intentionally low-window so the bounded packet sample contains
matched responses rather than only the first client burst. The same artifact
retains `packet-capture/dns-sample.tsv` with response rcodes and answer counts.

</details>

Further changes should follow measured bottlenecks and matched before/after
runs; see [future optimization work](future-optimization-tracks.md).
