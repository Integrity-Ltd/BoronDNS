# Health and metrics

BoronDNS exposes HTTP probes and Prometheus metrics on its management
listeners. Keep those listeners on loopback or a private management network;
these endpoints are plain HTTP and unauthenticated. The optional
[observability API](observability-api.md) has separate bearer-token support.

## Listener configuration

```toml
[health]
bind_address = "127.0.0.1"
bind_port = 8080
metrics_rate_limit_per_minute = 60
metrics_rate_limit_idle_seconds = 300
max_connections = 128
```

An explicit bind address and port must be set together. They override legacy
`server.health`, which in turn overrides `interfaces.mgmt`. Management
interface IPs use `health.default_port` (8080 by default), not the port written
in those interface entries. With no configured source, no management listener
is opened.

## Probes

| GET path | Meaning | Response |
| --- | --- | --- |
| `/livez` | The process can answer a probe, including during initial loading and drain. | 200 |
| `/readyz` | At least one served zone is ACTIVE and the runtime is running. | 200 if ready; otherwise 503 |
| `/healthz` | Alias for `/readyz`. | Same as readiness |
| `/metrics` | Prometheus scrape. | 200, or 429 when rate-limited |

Readiness is not an all-zones check. A secondary serving one active zone can
return 200 while other zones are loading or expired. Use per-zone metrics and
external DNS probes for complete coverage.

All probe bodies use `Content-Type: application/json`. Typical responses:

```json
{"status":"alive","version":"<version>","uptime_seconds":12345}
```

```json
{"status":"ready","version":"<version>","zones_active":12,"zones_loading":0,"zones_expired":0}
```

```json
{"status":"not-ready","reason":"loading","version":"<version>","zones_active":0,"zones_loading":12,"zones_expired":0}
```

The not-ready reasons are `loading`, `expired`, and `no_active_zones`.
During shutdown:

```json
{"status":"draining","version":"<version>","grace_period_remaining_seconds":15}
```

An unhealthy runtime returns:

```json
{"status":"unhealthy","version":"<version>"}
```

Use liveness to detect a non-responsive process and readiness to decide whether
it should receive traffic. Do not restart a healthy process merely because its
primary is temporarily unavailable and readiness is false.

## Metrics

A scrape returns Prometheus text with
`Content-Type: text/plain; version=0.0.4; charset=utf-8`. An explicit
`Accept-Encoding: gzip` request enables gzip and adds
`Content-Encoding: gzip` and `Vary: accept-encoding`; `gzip;q=0` leaves the
body uncompressed.

Start with these metric families:

| What to monitor | Metrics |
| --- | --- |
| Zone counts | `borondns_zones_total`, `borondns_zones_active` |
| Per-zone availability | `borondns_secondary_zone_state`, `borondns_secondary_zone_loading_seconds` |
| Serial and freshness | `borondns_secondary_zone_soa_serial`, `borondns_secondary_zone_last_refresh_seconds`, `borondns_secondary_zone_next_refresh_seconds`, `borondns_secondary_zone_refresh_failures` |
| Transfer outcomes | `borondns_transfer_sessions_started_total`, `borondns_transfer_sessions_completed_total`, `borondns_transfer_sessions_failed_total`, with AXFR/IXFR protocol labels |
| Query volume | `borondns_queries_received_total`, `borondns_secondary_queries_total{zone="..."}` |
| Response codes | `borondns_query_responses_total`, `borondns_zone_query_responses_total`, `borondns_secondary_query_responses_total` |
| Latency | `borondns_secondary_query_duration_seconds` |
| RRL outcomes | `borondns_rrl_responses_subject_total`, `borondns_rrl_responses_dropped_total`, `borondns_rrl_responses_truncated_total` |
| Catalog membership | `borondns_catalog_member_info{catalog_zone="...",zone="...",managed="..."}` |
| Configuration/build | `borondns_secondary_configuration_warnings_total`, `borondns_secondary_build_info` |

The scrape's HELP and TYPE lines describe the remaining counters, including
NOTIFY authorization, TSIG outcomes, DNS Cookies, truncation, CNAME loops,
UDP batch/datagram I/O, and query-image serving. Metrics are process-local;
restart resets counters and does not restore monitoring history.

`borondns_secondary_zone_loading_seconds` reports process uptime for a zone
still LOADING, and zero for ACTIVE or EXPIRED zones. It is useful for initial
loading alerts, not a durable duration across restarts. The scheduler also logs
`zone_loading_threshold_exceeded` at
`limits.zsm_loading_warning_threshold_secs` (default 3600 seconds).

Latency buckets are configured in `metrics.latency_histogram_buckets`:
at most 64 strictly increasing boundaries, in seconds. Measurements are server
processing observations, not a substitute for client end-to-end latency.

`borondns_dnssec_nsec3_iterations_exceed_cap_total` counts lookup-time NSEC3
iteration-cap failures even when `edns.extended_dns_errors = "off"`.
It does not require an emitted EDE option.

### Metrics detail

`metrics.hot_path_detail` controls the cost and completeness of query-path
instrumentation:

| Mode | Use and effect |
| --- | --- |
| `full` (default) | Detailed query, RCODE, latency, per-zone, and DNS Cookie prefix series. |
| `reduced` | Coarse counters remain; per-zone query maps, RCODE maps, latency histograms, Cookie prefix maps, and pipeline detail are suppressed. |
| `off` | Also suppresses coarse hot-path updates. Intended for saturation profiling, not operational monitoring. |

Reduced/off series must not be interpreted as complete traffic counts. In
saturation tests, retain generator results and kernel/NIC drop counters.

Leave `metrics.zone_shape_enabled` and `metrics.pipeline_timing_enabled`
disabled unless investigating a specific problem. Zone-shape metrics walk
active snapshots; pipeline timing adds query-path work. The opt-in families
include `borondns_zone_shape_*` and
`borondns_zone_image_denial_range_groups{proof,mode}`. The latter distinguishes
indexed denial rings from conservative fallback lookup. Response-cache
candidate metrics are diagnostic; enabling them does not enable a response
cache.

`borondns_zone_image_serve_*` counters distinguish image hits, direct and
semantic paths, and failures. Investigate internal plan/build failures that
produce SERVFAIL. See [architecture](architecture.md) for compact images and
large-zone overlay behavior.

## Limits and errors

Probe endpoints are never rate-limited. `/metrics` is limited per source IP
using the two settings above. A proxy may therefore share one budget across
many downstream scrapers. An over-limit scrape returns HTTP 429 with
`Retry-After: <seconds>` and:

```json
{"error":"rate_limited","retry_after_seconds":60}
```

`health.max_connections` bounds accepted connections across all management
listeners. Excess connections close immediately. Fixed five-second absolute
request-read and response-write deadlines disconnect stalled clients; progress
does not extend either deadline.

Unknown paths return HTTP 404:

```json
{"error":"not_found","path":"/unknown"}
```

Known paths with a non-GET method, including HEAD, return HTTP 405:

```json
{"error":"method_not_allowed","path":"/readyz"}
```

Error bodies also use `application/json`.

## Implementation and checks

The handlers and metric emission are in
[health_metrics.rs](../crates/borondns-server/src/health_metrics.rs).
[Runtime tests](../crates/borondns-server/src/tests/health_observability_runtime.rs)
cover startup readiness, drain, HTTP errors, gzip, connection deadlines, and
scrape rate limiting. `scripts/capture-health-metrics-evidence.sh` captures
the interface from a running test deployment.
