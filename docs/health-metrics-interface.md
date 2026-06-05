# Health and Metrics Interface

Status: current interface contract for `ODS-IF-HEALTH-001..006` and
`ODS-NFR-OBS-003..009`.

This document owns the concrete HTTP shape of the OxideDNS health and metrics
endpoint. The SRS owns the normative requirement IDs; this document keeps the
path, body, header, rate-limit, and evidence details in one place so the SRS and
operator guide do not duplicate them.

## Scope

The endpoint is plain HTTP/1.1, unauthenticated, and intended for private
management networks, local probes, or an orchestrator-side proxy. It is enabled
only when configured. When enabled, bind precedence is:

1. Explicit `[health].bind_address` and `[health].bind_port`.
2. `interfaces.mgmt` with `[health].default_port`.
3. Localhost addresses with `[health].default_port`.

`/livez`, `/readyz`, and `/healthz` are probe endpoints and are never
rate-limited. `/metrics` is rate-limited per source IP.

## Paths

| Path | Method | Success status | Failure status | Body type | Notes |
| --- | --- | --- | --- | --- | --- |
| `/livez` | `GET` | `200` | no response or HTTP 5xx only when the endpoint task cannot answer | JSON | Liveness only. It remains live while zones are loading and while shutdown is draining. |
| `/readyz` | `GET` | `200` when at least one explicit or catalog-derived zone is ACTIVE and the process is not draining | `503` for not-ready, draining, or unhealthy | JSON | Readiness for receiving authoritative DNS traffic. |
| `/healthz` | `GET` | Same as `/readyz` | Same as `/readyz` | JSON | Readiness alias kept for compatibility. |
| `/metrics` | `GET` | `200` | `429` when per-source scrape limit is exceeded | Prometheus text or JSON error | Emits uncompressed text by default and gzip when requested. |
| all other paths | `GET` or other methods | none | `404` | JSON | Unknown path. |
| known paths with non-`GET` methods | non-`GET` | none | `405` | JSON | `HEAD` is intentionally rejected like other non-`GET` methods. |

## Probe Bodies

`/livez` returns:

```json
{"status":"alive","version":"<version>","uptime_seconds":12345}
```

`/readyz` and `/healthz` return one of the following bodies.

Ready:

```json
{"status":"ready","version":"<version>","zones_active":1234,"zones_loading":12,"zones_expired":0}
```

Not ready:

```json
{"status":"not-ready","reason":"loading","version":"<version>","zones_active":0,"zones_loading":42,"zones_expired":0}
```

The stable `reason` values currently include `loading` and `no_active_zones`.

Draining:

```json
{"status":"draining","version":"<version>","grace_period_remaining_seconds":15}
```

Unhealthy:

```json
{"status":"unhealthy","version":"<version>"}
```

All probe responses use `Content-Type: application/json`.

## Metrics

`/metrics` emits Prometheus text exposition with
`Content-Type: text/plain; version=0.0.4; charset=utf-8`. If the request
contains an `Accept-Encoding` value that allows `gzip`, the response includes
`Content-Encoding: gzip` and `Vary: accept-encoding`. A request that sets
`gzip;q=0` receives uncompressed text.

The metrics endpoint exposes these implemented metric families:

- configured and active zone gauges;
- first-party metrics use the `oxidedns_` prefix; selected stable
  SRS-facing compatibility families retain the `oxidedns_secondary_` prefix
  where named below;
- SRS v0.9.1 per-zone status series:
  `oxidedns_secondary_zone_state`,
  `oxidedns_secondary_zone_soa_serial`,
  `oxidedns_secondary_zone_last_refresh_seconds`,
  `oxidedns_secondary_zone_next_refresh_seconds`,
  `oxidedns_secondary_zone_refresh_failures`, and
  `oxidedns_secondary_queries_total{zone="..."}`;
- catalog membership gauges:
  `oxidedns_catalog_member_info{catalog_zone="...",zone="...",managed="..."}`;
- transfer counters (`oxidedns_transfer_sessions_started_total`,
  `oxidedns_transfer_sessions_completed_total`,
  `oxidedns_transfer_sessions_failed_total`), query counters, truncation
  counters, CNAME limit/loop counters, global and per-zone RCODE counters
  (`oxidedns_query_responses_total`,
  `oxidedns_zone_query_responses_total`,
  `oxidedns_secondary_query_responses_total`), NOTIFY counters, TSIG
  verification counters for authorized NOTIFY, DNS Cookie counters, RRL
  counters, the `oxidedns_secondary_build_info` gauge, the
  `oxidedns_dnssec_nsec3_iterations_exceed_cap_total` DNSSEC cap counter, and
  the `oxidedns_chaos_queries_total` outcome counter for CH-class diagnostics;
- standard UDP packet I/O counters:
  `oxidedns_udp_receive_batches_total`,
  `oxidedns_udp_received_datagrams_total`, `oxidedns_udp_send_batches_total`,
  and `oxidedns_udp_sent_datagrams_total`;
- `oxidedns_secondary_query_duration_seconds` query latency histogram, with
  buckets configured by `[metrics].latency_histogram_buckets`;
- opt-in active-zone shape gauges and fixed-bucket layout histograms under
  `oxidedns_zone_shape_*`, including child-name fan-out, RRsets per owner name,
  RDATA records per RRset, and RDATA payload bytes per RRset;
- immutable-zone-image serving counters under `oxidedns_zone_image_serve_*`;
- opt-in query-pipeline histograms and response-cache candidate counters.

`[metrics].hot_path_detail = "full"` is the default and preserves all detailed
query, RCODE, latency, zone, and DNS Cookie prefix metric series. For high-rate
benchmark or packet-I/O experiments, `[metrics].hot_path_detail = "reduced"`
keeps coarse process-wide counters such as received queries, truncation,
DNS Cookie case totals, UDP batch/datagram totals, and ZoneImage serve
counters, but suppresses mutex-backed hot-path detail: per-zone query maps,
global and per-zone RCODE maps, query latency histograms, DNS Cookie
source-prefix maps, and pipeline/cache-planning histograms. Reduced mode is an
observability/performance tradeoff and does not change DNS answer behavior.
`[metrics].hot_path_detail = "off"` also suppresses coarse query, UDP packet-I/O,
and ZoneImage serve counters and is reserved for saturation profiling where
counter contention would distort packet-path results. Use external benchmark
logs and kernel packet-drop counters as the packet-loss source of truth in this
profile.

The current `oxidedns_dnssec_nsec3_iterations_exceed_cap_total` evidence is
driven by lookup-time NSEC3 proof-omission observation rather than serialized
EDE options. Over-cap NSEC3 proof omissions remain counted with
`edns.extended_dns_errors = "off"` even when EDE INFO-CODE 27 is absent from
the response.

The opt-in metric families may walk active zone snapshots or collect extra
pipeline timing. Keep `[metrics].zone_shape_enabled` and
`[metrics].pipeline_timing_enabled` disabled outside benchmark or diagnostic
captures, and use `[metrics].hot_path_detail = "reduced"` only when the loss of
detailed hot-path series is acceptable. These metrics do not enable a response
cache or change the served answer path. Supported query shapes are served from
immutable `ZoneImage` wire
sections; plan, DNSSEC-plan, or response-build failures return an explicit
ZoneImage SERVFAIL instead of falling back to the ordinary active-snapshot
response path, while oversized supported UDP responses are truncated directly by
the `ZoneImage` composer.
Full-ANY response mode now serves supported QTYPE ANY queries through
`ZoneImage`; non-ANY queries remain eligible for `ZoneImage`. The served-hit
and failure counters
make retained benchmark artifacts auditable: a ZoneImage-enabled run must show
hits to prove it exercised the optimized path. Direct-answer and semantic-hit
sub-counters distinguish the guarded hot direct-answer emitter from the generic
semantic ZoneImage planner. Failures are also split by fixed reasons, so any
remaining serve-error dependence can be ordered without adding per-query dynamic
metric labels. Rollback responses are counted separately and should stay zero
for ZoneImage-enabled retirement evidence.

## Rate Limiting

`/metrics` uses `[health].metrics_rate_limit_per_minute` and
`[health].metrics_rate_limit_idle_seconds`. Over-limit responses are:

- status `429`;
- `Content-Type: application/json`;
- `Retry-After: <seconds>`;
- body:

```json
{"error":"rate_limited","retry_after_seconds":60}
```

The limiter is per source IP address, not per RRL source prefix.

## Error Bodies

Unknown paths return:

```json
{"error":"not_found","path":"<requested_path>"}
```

Known paths requested with a non-`GET` method return:

```json
{"error":"method_not_allowed","path":"<requested_path>"}
```

The `path` field is the current implemented body contract. The response status
is intentionally specified by the SRS; generic HTTP compatibility details beyond
the headers listed in this document are handled as interface hardening work when
they are promoted into a requirement.

## Evidence

Current code and local tests for this interface live in
`crates/oxidedns-server/src/lib.rs`:

- `health_router`, `livez`, `readyz`, `healthz`, `metrics`,
  `rate_limited_response`, and `readiness_response`;
- `health_endpoint_reports_starting_until_zone_active`;
- `health_endpoint_handles_readyz_metrics_404_and_405`;
- `metrics_endpoint_rate_limits_per_source_without_limiting_health`;
- `health_endpoint_reports_draining_and_unready_during_shutdown`.

Retained script evidence is captured by
`scripts/capture-health-metrics-evidence.sh` and release snapshots.

## References

- Kubernetes liveness/readiness/startup probe documentation:
  <https://kubernetes.io/docs/concepts/workloads/pods/probes/>
- Prometheus exposition formats:
  <https://prometheus.io/docs/instrumenting/exposition_formats/>
- Prometheus scrape protocol content negotiation:
  <https://prometheus.io/docs/instrumenting/content_negotiation/>
