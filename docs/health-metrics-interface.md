# Health and Metrics Interface

Status: current interface contract for `ODS-IF-HEALTH-001..006` and
`ODS-NFR-OBS-003..008`.

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
- SRS v0.9.1 per-zone status series:
  `oxidedns_secondary_zone_state`,
  `oxidedns_secondary_zone_soa_serial`,
  `oxidedns_secondary_zone_last_refresh_seconds`,
  `oxidedns_secondary_zone_next_refresh_seconds`,
  `oxidedns_secondary_zone_refresh_failures`, and
  `oxidedns_secondary_queries_total{zone="..."}`;
- catalog membership gauges:
  `oxidedns_catalog_member_info{catalog_zone="...",zone="...",managed="..."}`;
- transfer counters, query counters, truncation counters, CNAME limit/loop
  counters, global and per-zone RCODE counters, NOTIFY counters, TSIG
  verification counters for authorized NOTIFY, DNS Cookie counters, RRL
  counters, the `oxidedns_secondary_build_info` gauge, the
  `oxidedns_dnssec_nsec3_iterations_exceed_cap_total` DNSSEC cap counter, and
  the `oxidedns_chaos_queries_total` outcome counter for CH-class diagnostics;
- `oxidedns_secondary_query_duration_seconds` query latency histogram, with
  buckets configured by `[metrics].latency_histogram_buckets`;
- opt-in active-zone shape gauges under `oxidedns_zone_shape_*`;
- opt-in query-pipeline histograms and response-cache candidate counters.

The opt-in metric families may walk active zone snapshots or collect extra
pipeline timing. Keep `[metrics].zone_shape_enabled` and
`[metrics].pipeline_timing_enabled` disabled outside benchmark or diagnostic
captures. These metrics do not enable a response cache; the current server
still assembles authoritative responses from the active in-memory zone snapshot
on demand.

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
