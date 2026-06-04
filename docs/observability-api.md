# Optional Observability API

Status: implemented initial optional OxideDNS observability API. The current
implementation exposes the endpoint family below as compact JSON snapshots on
the existing management HTTP listener when `[observability].enabled = true`.
Host resource, time-sync, and certificate checks currently return explicit
`unknown` or `disabled` status values rather than performing external probes.

This document defines the shape for the in-process OxideDNS observability API.
It replaces the idea of a separate on-node monitoring agent with a narrower
product-native surface: OxideDNS exposes read-only facts about
its own runtime, transfer state, catalog state, local resource posture, and
serving-relevant environment checks when explicitly enabled.

The existing [Health and Metrics Interface](health-metrics-interface.md)
continues to own `/livez`, `/readyz`, `/healthz`, and `/metrics`. This document
owns the proposed richer JSON inspection endpoints.

## Scope

The observability API is optional, in-process, and GET-only. It is intended for
private management networks, local collectors, control-plane node-status
ingestion, operator debugging, and external probe correlation.

In scope:

- current OxideDNS runtime status beyond liveness/readiness;
- zone, catalog, transfer, NOTIFY, TSIG, DNS Cookie, RRL, DNSSEC-serving, and
  `ZoneImage` summary facts already known by the process;
- per-zone transfer progress and last-result state;
- compact resource summaries similar to coarse `df -h`, process memory, process
  CPU, open-file, and file-descriptor-limit views;
- serving-relevant certificate expiry summaries for configured XoT/mTLS
  material;
- host time-synchronization status as reported by existing OS services, without
  implementing an NTP/SNTP client in OxideDNS;
- redacted configuration and build/runtime identity facts.

Out of scope:

- remediation, restart, reload, reconfiguration, or any mutating endpoint;
- a general host-monitoring daemon;
- log scraping as a replacement for the system journal or centralized logs;
- implementing NTP, SNTP, or time-service probing inside OxideDNS;
- external black-box DNS probing from Internet, zone-sync, or management
  vantage points;
- alert routing, de-duplication, escalation, or long-term event storage;
- control-plane tenant/auth/RBAC/audit functions.

OxideDNS remains a secondary-only authoritative data-plane backend. The
observability API must not create a runtime administration API and must not put
OxideDNS in charge of tenant, billing, ownership, policy, or alert workflow.

## Relationship To Other Monitoring

The observability API provides inside-the-process facts. It does not replace:

- systemd, Kubernetes, Icinga, Prometheus scrape absence, or another supervisor
  for detecting that the OxideDNS process is down;
- external black-box DNS probes that verify real answers, DNSSEC chains,
  latency, public exposure, recursion refusal, and transfer refusal from the
  network;
- the control plane or another management-plane service that correlates
  expected state, node state, external probe results, tenant context, and
  operator workflow.

If OxideDNS is not running, this API cannot answer. That failure mode is
deliberately left to existing supervisors and external collectors.

## Configuration

The proposed configuration uses the existing management HTTP listener selected
by `[health]` bind precedence. The richer observability endpoints are disabled
unless `[observability].enabled = true`.

```toml
[observability]
# Enable richer JSON observability endpoints on the management HTTP listener.
# Default: false.
enabled = false

# Path prefix for the JSON API. Default: "/observability/v1".
path_prefix = "/observability/v1"

# Rate limit for JSON observability endpoints. Probe endpoints remain governed
# by the existing health contract and /metrics keeps its existing rate limit.
# Default: 60 requests per minute.
rate_limit_per_minute = 60

# Idle seconds before a per-source rate-limit bucket can be evicted.
# Default: 300.
rate_limit_idle_seconds = 300

# Include coarse local filesystem capacity summaries for configured paths.
# Default: true.
include_filesystems = true

# Include coarse process memory/CPU/open-file summaries.
# Default: true.
include_process_resources = true

# Include host time-synchronization status from OS services such as timedatectl,
# chronyc, or ntpq when available. OxideDNS must not implement NTP/SNTP itself.
# Default: true.
include_time_sync_status = true

# Include certificate expiry summaries for configured XoT/mTLS files.
# Default: true.
include_certificate_status = true

# Include per-zone detailed state. When false, only aggregate counts are
# returned from collection endpoints. Default: true.
include_zone_detail = true

# Include redacted effective configuration summaries. Secrets, key material,
# and TSIG values must never be returned. Default: true.
include_config_summary = true

# Reserved optional static bearer token file for direct deployments that cannot
# place the listener behind an authenticated management proxy. The current
# implementation reports whether it is configured but does not enforce bearer
# auth yet; put remotely reachable listeners behind an authenticated management
# proxy. Default: unset.
# bearer_token_file = "/etc/oxidedns-secondary/observability.token"
```

Authentication is deployment-dependent. Localhost-only and private management
network deployments may keep the listener unauthenticated like the current
health endpoints. Any remotely reachable deployment should either place the
listener behind an authenticated/TLS management proxy or configure a future
first-party authentication mode. This API exposes operational metadata and is
not suitable for public DNS listener addresses.

## Endpoint Summary

All endpoints are `GET`. JSON responses use `Content-Type: application/json`.
Unknown paths and wrong methods should follow the existing health-interface
error style unless a later interface revision defines a richer error contract.

| Path | Purpose |
| --- | --- |
| `/observability/v1` | API index, enabled feature flags, endpoint links. |
| `/observability/v1/summary` | One-page runtime, readiness, zone, transfer, catalog, and resource summary. |
| `/observability/v1/runtime` | Process uptime, version/build labels, listener roles, worker mode, shutdown/drain state. |
| `/observability/v1/resources` | Coarse local filesystem, memory, CPU, file-descriptor, and limit posture. |
| `/observability/v1/time` | Host time-sync status from OS services and timestamp of last status refresh. |
| `/observability/v1/certificates` | Expiry/status summary for configured XoT/mTLS trust/client material. |
| `/observability/v1/zones` | Per-zone serving, serial, refresh, expire, query, and DNSSEC-serving state. |
| `/observability/v1/zones/{zone}` | Detailed state for one configured or catalog-derived zone. |
| `/observability/v1/catalogs` | Configured catalog zones, last transfer, member counts, caps, and reconciliation state. |
| `/observability/v1/transfers` | Current and recent transfer sessions, primary choice, AXFR/IXFR fallback, and failures. |
| `/observability/v1/security` | TSIG, NOTIFY, recursion-refusal, DNS Cookie, RRL, and wrong-interface exposure summaries. |
| `/observability/v1/config` | Redacted effective configuration summary and interface role map. |

The path prefix is configurable, but endpoint names under the prefix should be
stable once implemented.

The current implementation wires all paths in the table. `/resources`,
`/time`, and `/certificates` are intentionally non-blocking placeholders until
bounded host-local probes are added; they return `unknown` when the check family
is enabled and `disabled` when the corresponding configuration toggle is false.

## Response Principles

Responses should be compact snapshots rather than event streams. OxideDNS does
not persist transfer history or runtime state to disk; any recent-history fields
are bounded in memory and may reset on process restart.

Every response should include:

- `schema_version`;
- `generated_at_unix_seconds`;
- build/runtime identity labels;
- enough status fields for the control plane or an operator to decide whether the data is
  fresh, partial, or disabled by configuration.

Every implemented response also reports `metrics_detail` as `full` or
`reduced`. In reduced metrics mode, aggregate atomic counters remain available,
but hot-path detail maps and per-zone query counters are intentionally reduced.
JSON zone entries therefore report `"queries": "reduced"` instead of forcing
the disabled per-zone counter maps back onto the hot path.

Secrets must be redacted. Responses must not expose:

- plaintext TSIG secrets;
- DNSSEC private keys;
- private-key bytes or PEM contents;
- bearer tokens;
- full transferred zone contents;
- customer tenant/RBAC data.

Zone names, primary addresses, TSIG key names, catalog names, and operational
metadata are still sensitive in some deployments. Operators should treat this
API as management-plane-only even when no secret values are returned.

## Summary Response Shape

Example:

```json
{
  "schema_version": 1,
  "generated_at_unix_seconds": 1791133200,
  "server": {
    "name": "edge-sec-1",
    "version": "0.1.4",
    "uptime_seconds": 86400,
    "status": "ready",
    "draining": false
  },
  "zones": {
    "configured": 12,
    "catalog_derived": 240,
    "active": 252,
    "loading": 0,
    "expired": 0,
    "rrsig_expiring_soon": 1
  },
  "transfers": {
    "active": 2,
    "last_failure_unix_seconds": 1791132000,
    "recent_failures": 1,
    "ixfr_fallbacks_recent": 3
  },
  "catalogs": {
    "configured": 3,
    "active": 3,
    "members_applied": 240,
    "members_dropped_by_cap": 0
  },
  "resources": {
    "filesystems": [
      {
        "path": "/var/log/oxidedns",
        "size_human": "20G",
        "used_human": "8.1G",
        "available_human": "11G",
        "used_percent": 43
      }
    ],
    "process_memory_rss_bytes": 187695104,
    "process_cpu_percent": 2.4,
    "open_fds": 218,
    "fd_limit": 65536
  },
  "time": {
    "source": "system",
    "synchronized": true,
    "service": "chronyd",
    "last_checked_unix_seconds": 1791133190
  }
}
```

The resource block is intentionally coarse. It is acceptable for a Rust
implementation to read `/proc`, `statvfs`, or equivalent Linux APIs for a small
`df -h`-style view and process resource counters. It should not grow into full
host inventory.

## Zone And Transfer State

The zone endpoints should expose data-plane-native state that is already
tracked by OxideDNS:

- zone apex and source kind: static, catalog-derived, or catalog zone;
- serving state: active, loading, expired, withdrawn, draining;
- current served SOA serial where known;
- last successful transfer time and transfer kind;
- next refresh time and SOA expire horizon;
- selected primary and fallback order, redacted where policy requires;
- last transfer failure code and short reason;
- IXFR unsupported/cooldown state and AXFR fallback counters;
- minimum remaining RRSIG validity if the zone is signed and the computation is
  cheap from served records;
- query counters already available through metrics, summarized for JSON users.

The transfer endpoints should expose active and recent in-memory transfer
sessions with bounded retention. They should not persist long-term history;
the control plane or another collector owns durable history if needed.

## Catalog State

Catalog observability should expose:

- configured catalog zones;
- last successful catalog transfer serial/time;
- parsed RFC 9432 version;
- member count parsed from the transferred catalog;
- member count applied after caps and static-zone precedence;
- dropped members with bounded reason counts;
- whether `serve_catalog_zone` is enabled;
- whether optional member-transfer metadata extensions were observed.

This supports control-plane catalog correlation without making OxideDNS an
administrative catalog editor.

## Security And Exposure State

The security endpoint should report only observations OxideDNS can make from
its own runtime:

- recursion-refusal behavior for the authoritative server configuration;
- TSIG verification counters by outcome, without key material;
- unauthorized or TSIG-failed NOTIFY counters;
- transfer ACL/source rejection counts;
- DNS Cookie policy and outcome counters;
- RRL policy and limited/drop/slip counters;
- listener/interface role map and whether management endpoints are bound only
  to management/local addresses.

External facts such as "hidden primary is unreachable from the Internet" or
"public secondaries answer correctly from multiple regions" belong to external
black-box probes, not this API.

## Time And Certificate Checks

Clock correctness matters for TSIG and DNSSEC signature validity, but OxideDNS
should not implement its own NTP/SNTP protocol client. The proposed time
endpoint should only summarize status available from existing host services or
OS interfaces, for example:

- `timedatectl show` / D-Bus equivalent;
- `chronyc tracking` when chrony is installed;
- `ntpq`/`ntpstat` where deployed;
- container-provided host-time status where available.

If no status source is available, the endpoint should return `unknown`, not
`ok`.

Certificate status should be limited to configured files OxideDNS already uses,
such as XoT trust anchors and client certificates. The response should expose
subject/issuer fingerprints and not-before/not-after timestamps, not PEM bytes.

## Non-Interference Requirements

The observability API must be designed so that inspection cannot degrade DNS
serving:

- all endpoints are read-only;
- expensive endpoints are rate-limited;
- scrape-time zone walking is bounded or disabled by configuration;
- responses are produced from snapshots or cached summaries where practical;
- no endpoint performs outbound DNS transfers or external network checks as a
  side effect;
- resource checks must use small, bounded OS reads;
- unavailable optional checks return `disabled` or `unknown` rather than
  blocking.

## Fit With The Control Plane

The control plane should consume this API as one input to its monitoring and
assurance model. The control plane remains the owner of:

- expected zone state;
- tenant/customer context;
- node inventory and provisioning metadata;
- persistent audit/event history;
- operator-visible alert state;
- retry/pause/resume workflows;
- correlation with external probes.

The intended data flow is:

1. The control plane publishes configuration/catalog state.
2. OxideDNS serves as a secondary and exposes read-only observability facts.
3. External probes verify black-box behavior.
4. The control plane correlates expected state, OxideDNS facts, and probe results.

This keeps OxideDNS small enough to remain a data-plane component while giving
the control plane better material than generic process metrics alone.
