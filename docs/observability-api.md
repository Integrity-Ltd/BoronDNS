# Observability API

The optional observability API exposes read-only JSON snapshots on the existing
management HTTP listener. Use it for node status, troubleshooting, or collectors
that need more context than the [health probes](health-metrics-interface.md).
It does not perform transfers, change configuration, or retain historical data.

## Enable and protect it

First configure a private management listener, then enable:

```toml
[observability]
enabled = true
path_prefix = "/observability/v1"
rate_limit_per_minute = 60
rate_limit_idle_seconds = 300
bearer_token_file = "/etc/borondns-secondary/observability.token"
```

The API is disabled by default. A token is optional, but the API exposes zone
names and operational metadata even though it redacts secrets. Use a token and
a TLS/authenticated proxy for remotely reachable management access. BoronDNS
itself serves plain HTTP.

The token file is read at listener startup, trimmed of surrounding ASCII
whitespace, and limited to 8 KiB. It must be non-empty and regular; on Unix it
must have owner-only permissions and its final path component cannot be a
symlink. Make it readable by the runtime user. Rotation requires a restart.

Clients send `Authorization: Bearer <token>`. Missing or incorrect tokens
return HTTP 401 with `WWW-Authenticate: Bearer` and an error of
`missing_bearer_token` or `invalid_bearer_token`. The per-source rate limit is
checked before authentication, so failed attempts also consume the budget.

The token protects only observability routes. It does not protect `/livez`,
`/readyz`, `/healthz`, or `/metrics`. Keep the listener isolated as a whole.

## Endpoints

Paths below use the default prefix. All accept GET and return
`Content-Type: application/json`.

| Path | Current contents |
| --- | --- |
| `/observability/v1` | Endpoint links and enabled check families. |
| `/observability/v1/summary` | Zone/catalog counts, transfer outcomes, selected security counters, and query-image counters. |
| `/observability/v1/runtime` | Version, commit/compiler/build labels, uptime, runtime status, and drain time remaining. |
| `/observability/v1/resources` | Process memory/CPU ticks/file descriptors and root-filesystem capacity. |
| `/observability/v1/time` | `unknown` when enabled: no time-sync source is currently implemented. |
| `/observability/v1/certificates` | Configured XoT certificate metadata, expiry status, and SHA-256 fingerprints. |
| `/observability/v1/zones` | Zone counts and, when enabled, a per-zone collection. |
| `/observability/v1/zones/{zone}` | State, serial, SOA timers, source kind, and query count for one zone. |
| `/observability/v1/catalogs` | Catalog settings and membership counts, including static overlaps. |
| `/observability/v1/transfers` | Aggregate outcomes, per-zone refresh scheduling, and transfer-material counts. |
| `/observability/v1/security` | NOTIFY, TSIG-NOTIFY, DNS Cookie, RRL, and recursion-refusal observations. |
| `/observability/v1/config` | Observability settings, metrics detail, and zone/catalog counts. |

These are implemented snapshots, not a complete host inventory or a full dump
of effective configuration. In-flight transfer sessions and recent-session
history are not retained: transfers report `active.status = "not_tracked"`.
The security endpoint likewise reports wrong-interface observations as
`not_tracked`; it cannot verify external firewall exposure.

Zone lookup is case-insensitive and accepts a name with or without its trailing
dot. An unknown zone currently returns HTTP 200 with
`data.error = "zone_not_found"`; clients must inspect the payload rather than
treat every 200 as a successful lookup. Unknown routes return 404, and a
non-GET method on a known route, including HEAD, returns 405.

## Response envelope

Successful snapshots share this envelope:

```json
{
  "schema_version": 1,
  "generated_at_unix_seconds": 1791133200,
  "server": {
    "version": "1.0.0",
    "status": "running",
    "uptime_seconds": 86400,
    "draining": false
  },
  "metrics_detail": "full",
  "data": {}
}
```

The version comes from the running binary. Status is `running`, `draining`,
or `unhealthy`. Endpoint-specific fields appear under `data`. The generation
timestamp records when the response was assembled; it does not assert that
all observed state changed at that instant.

`metrics_detail` is `full`, `reduced`, or `off`, following
`metrics.hot_path_detail`. In reduced/off mode, per-zone query counts and
RCODE-derived details may be the string `"reduced"`, not numeric zero.
Coarse hot-path counters are incomplete in off mode. Collectors must handle
these types and avoid interpreting disabled instrumentation as idle traffic.

A zone payload contains `zone`, `source` (`configured`, `catalog_derived`,
or `catalog_zone`), `state` (`loading`, `active`, or `expired`),
`serial`, `soa_refresh_seconds`, `soa_retry_seconds`,
`soa_expire_seconds`, and `queries`. Refresh timestamps and
`failures_since_success` are reported by the transfer scheduler view.

## Optional detail and its cost

These settings default to `true`:

| Setting | Effect |
| --- | --- |
| `include_filesystems` | Root-filesystem capacity and descriptor-limit information. |
| `include_process_resources` | Process memory, CPU ticks, thread and open-descriptor counts. |
| `include_time_sync_status` | Return the time check, currently `unknown`. |
| `include_certificate_status` | Inspect configured XoT certificate material. |
| `include_zone_detail` | Include per-zone entries in the `/zones` collection. |
| `include_config_summary` | Include the limited `/config` summary. |

Disabled resource/time/certificate/config families report `disabled`.
Unavailable resource data can be `unknown` or `partial`. The filesystem view
currently measures `/` through `statvfs`; it does not enumerate the cache,
credential mounts, or every configured filesystem. Process data comes from
`/proc/self/status`, `stat`, `fd`, and `limits`; CPU values are cumulative
ticks, not a sampled utilization percentage.

Disabling `include_zone_detail` suppresses the `/zones` collection entries
but does not disable the single-zone route, catalog membership view, or
per-zone transfer scheduler view. It is a collection-cost setting, not an
access-control boundary.

Direct XoT certificate status inspects configured PEM files. Named secret-store
profiles use certificate metadata from the active immutable secret generation,
so a failed reload or replacement file cannot misrepresent the active profile.
The time endpoint does not read time-service status files, spawn commands,
or implement NTP/SNTP. Monitor clock synchronization through host monitoring.

Zone collections and scheduler views scale with the number of known zones.
Scrape at a deliberate interval, avoid repeated full collections for large
estates, and measure their cost before using them for frequent polling.
Resource and certificate work is dispatched off the async worker; all routes
share the management connection limit and five-second request/write deadlines.
There is no guarantee that arbitrary inspection load has zero cost.

Over-limit requests return HTTP 429, a `Retry-After` header, and the same
`rate_limited` JSON shape as the metrics endpoint. Rates are keyed by source IP,
so collectors behind one proxy share its budget.

## Monitoring responsibilities

The API never returns TSIG secrets, private-key bytes, PEM contents, bearer
tokens, or complete zone contents. Zone names, key names, primary-related
metadata, and certificate identity can still be sensitive.

Use external DNS probes for answer correctness and reachability, a supervisor
for process death, host monitoring for clocks and disks, and an external
collector for history and alerting. This API supplies the process's view; it
cannot answer when the process is down.

Implementation: [HTTP handlers](../crates/borondns-server/src/health_metrics.rs)
and [resource/certificate readers](../crates/borondns-server/src/observability.rs).
